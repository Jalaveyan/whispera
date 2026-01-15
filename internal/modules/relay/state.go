package relay

import (
	"fmt"
	"sync"
)

// State definition
type State int

const (
	StateIdle       State = iota // Initial state
	StateConnecting              // Dialing target
	StateConnected               // Connection established
	StateHalfClosed              // Remote closed, waiting for local close
	StateClosed                  // Fully closed
	StateError                   // Error state
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

// Event definition
type Event int

const (
	EventStartConnect Event = iota // Start connection attempt
	EventConnectOK                 // Connection successful
	EventConnectFail               // Connection failed
	EventData                      // Data received/sent
	EventPeerClose                 // Peer (remote) closed connection
	EventLocalClose                // Local side (client) closed
	EventTimeout                   // Operation timed out
	EventError                     // Generic error
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

// Transition represents a state transition
type Transition struct {
	NextState State
	Action    func(*Stream) error // Action to perform during transition
}

// FSM manages the state machine
type FSM struct {
	Current State
	mu      sync.RWMutex

	// Transitions table: State -> Event -> Transition
	transitions map[State]map[Event]Transition

	// Stream reference for actions
	stream *Stream
}

// NewFSM creates a new FSM for a stream
func NewFSM(stream *Stream) *FSM {
	fsm := &FSM{
		Current:     StateIdle,
		transitions: make(map[State]map[Event]Transition),
		stream:      stream,
	}
	fsm.initTransitions()
	return fsm
}

// initTransitions defines the strict state transition table
func (f *FSM) initTransitions() {
	// Idle -> Connecting
	f.addTransition(StateIdle, EventStartConnect, StateConnecting, func(s *Stream) error {
		// Action: Start dialing (handled by caller usually, but could be here)
		return nil
	})

	// Connecting -> Connected
	f.addTransition(StateConnecting, EventConnectOK, StateConnected, func(s *Stream) error {
		// Action: Send CONNECT_OK frame
		return s.sendFrame(NewConnectOKFrame(s.ID))
	})

	// Connecting -> Closed (Fail)
	f.addTransition(StateConnecting, EventConnectFail, StateClosed, func(s *Stream) error {
		// Action: Send CONNECT_FAIL frame and cleanup
		s.sendFrame(NewConnectFailFrame(s.ID, "connection failed"))
		s.cleanupResources()
		return nil
	})

	// Connecting -> Closed (Timeout)
	f.addTransition(StateConnecting, EventTimeout, StateClosed, func(s *Stream) error {
		s.sendFrame(NewConnectFailFrame(s.ID, "connection timeout"))
		s.cleanupResources()
		return nil
	})

	// Connected -> Connected (Data)
	f.addTransition(StateConnected, EventData, StateConnected, nil)

	// Connected -> HalfClosed (Peer Close)
	f.addTransition(StateConnected, EventPeerClose, StateHalfClosed, func(s *Stream) error {
		// Send CLOSE frame
		return s.sendFrame(NewCloseFrame(s.ID))
	})

	// Connected -> Closed (Local Close/Error)
	f.addTransition(StateConnected, EventLocalClose, StateClosed, func(s *Stream) error {
		s.cleanupResources()
		return nil
	})
	f.addTransition(StateConnected, EventError, StateClosed, func(s *Stream) error {
		s.cleanupResources()
		return nil
	})

	// HalfClosed -> Closed
	f.addTransition(StateHalfClosed, EventLocalClose, StateClosed, func(s *Stream) error {
		s.cleanupResources()
		return nil
	})

	// Any -> Closed (Force Close)
	// Handled by default/generic logic if needed, or repeated for states
}

// addTransition helper
func (f *FSM) addTransition(from State, event Event, to State, action func(*Stream) error) {
	if _, ok := f.transitions[from]; !ok {
		f.transitions[from] = make(map[Event]Transition)
	}
	f.transitions[from][event] = Transition{
		NextState: to,
		Action:    action,
	}
}

// Event triggers a state transition
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

	// Calculate transition
	prev := f.Current
	f.Current = trans.NextState

	// Execute action
	if trans.Action != nil {
		if err := trans.Action(f.stream); err != nil {
			// If action fails, what do we do?
			// For now, log/return error. In strict FSM, maybe transition to Error state?
			return fmt.Errorf("action failed during transition %s->%s: %v", prev, f.Current, err)
		}
	}

	return nil
}

// CurrentState returns current state safely
func (f *FSM) CurrentState() State {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.Current
}

// IsClosed returns true if FSM is in a terminal state
func (f *FSM) IsClosed() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.Current == StateClosed || f.Current == StateError
}

// SelfCheck validates FSM is in a valid, reachable state
func (f *FSM) SelfCheck() error {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Validate current state is known
	switch f.Current {
	case StateIdle, StateConnecting, StateConnected, StateHalfClosed, StateClosed, StateError:
		return nil
	default:
		return fmt.Errorf("FSM in unknown state: %d", f.Current)
	}
}
