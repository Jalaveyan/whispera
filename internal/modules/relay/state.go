package relay

import (
	"fmt"
	"sync"
)

type State int

const (
	StateIdle       State = iota
	StateConnecting
	StateConnected
	StateHalfClosed
	StateClosed
	StateError
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateConnecting:
		return "Connecting"
	case StateConnected:
		return "Connected"
	case StateHalfClosed:
		return "HalfClosed"
	case StateClosed:
		return "Closed"
	case StateError:
		return "Error"
	default:
		return "Unknown"
	}
}

type Event int

const (
	EventStartConnect Event = iota
	EventConnectOK
	EventConnectFail
	EventData
	EventPeerClose
	EventLocalClose
	EventTimeout
	EventError
)

func (e Event) String() string {
	switch e {
	case EventStartConnect:
		return "StartConnect"
	case EventConnectOK:
		return "ConnectOK"
	case EventConnectFail:
		return "ConnectFail"
	case EventData:
		return "Data"
	case EventPeerClose:
		return "PeerClose"
	case EventLocalClose:
		return "LocalClose"
	case EventTimeout:
		return "Timeout"
	case EventError:
		return "Error"
	default:
		return "Unknown"
	}
}

type Transition struct {
	NextState State
	Action    func(*Stream) error
}

type FSM struct {
	Current State
	mu      sync.RWMutex

	transitions map[State]map[Event]Transition

	stream *Stream
}

func NewFSM(stream *Stream) *FSM {
	fsm := &FSM{
		Current:     StateIdle,
		transitions: make(map[State]map[Event]Transition),
		stream:      stream,
	}
	fsm.initTransitions()
	return fsm
}

func (f *FSM) initTransitions() {
	f.addTransition(StateIdle, EventStartConnect, StateConnecting, func(s *Stream) error {
		return nil
	})

	f.addTransition(StateConnecting, EventConnectOK, StateConnected, nil)

	f.addTransition(StateConnecting, EventConnectFail, StateClosed, func(s *Stream) error {
		s.sendFrame(NewConnectFailFrame(s.ID, "connection failed"))
		s.cleanupResources()
		return nil
	})

	f.addTransition(StateConnecting, EventTimeout, StateClosed, func(s *Stream) error {
		s.sendFrame(NewConnectFailFrame(s.ID, "connection timeout"))
		s.cleanupResources()
		return nil
	})

	f.addTransition(StateConnected, EventData, StateConnected, nil)

	f.addTransition(StateConnected, EventPeerClose, StateHalfClosed, func(s *Stream) error {
		return s.sendFrame(NewCloseFrame(s.ID))
	})

	f.addTransition(StateConnected, EventLocalClose, StateClosed, func(s *Stream) error {
		s.cleanupResources()
		return nil
	})
	f.addTransition(StateConnected, EventError, StateClosed, func(s *Stream) error {
		s.cleanupResources()
		return nil
	})

	f.addTransition(StateHalfClosed, EventLocalClose, StateClosed, func(s *Stream) error {
		s.cleanupResources()
		return nil
	})

}

func (f *FSM) addTransition(from State, event Event, to State, action func(*Stream) error) {
	if _, ok := f.transitions[from]; !ok {
		f.transitions[from] = make(map[Event]Transition)
	}
	f.transitions[from][event] = Transition{
		NextState: to,
		Action:    action,
	}
}

func (f *FSM) Event(event Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	stateTrans, ok := f.transitions[f.Current]
	if !ok {
		return fmt.Errorf("no transitions from state %s", f.Current)
	}

	trans, ok := stateTrans[event]
	if !ok {
		return fmt.Errorf("invalid transition: %s + %s -> ???", f.Current, event)
	}

	prev := f.Current
	f.Current = trans.NextState

	if trans.Action != nil {
		if err := trans.Action(f.stream); err != nil {
			return fmt.Errorf("action failed during transition %s->%s: %v", prev, f.Current, err)
		}
	}

	return nil
}

func (f *FSM) CurrentState() State {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.Current
}

func (f *FSM) IsClosed() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.Current == StateClosed || f.Current == StateError
}

func (f *FSM) SelfCheck() error {
	f.mu.RLock()
	defer f.mu.RUnlock()

	switch f.Current {
	case StateIdle, StateConnecting, StateConnected, StateHalfClosed, StateClosed, StateError:
		return nil
	default:
		return fmt.Errorf("FSM in unknown state: %d", f.Current)
	}
}
