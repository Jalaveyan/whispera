package tunnel

import (
	"sync"
)

type tunnelStateMachine struct {
	mu        sync.RWMutex
	state     TunnelState
	lastError error
	onChange  func(old, new TunnelState)
}

func newTunnelStateMachine(onChange func(old, new TunnelState)) *tunnelStateMachine {
	return &tunnelStateMachine{
		state:    StateDisconnected,
		onChange: onChange,
	}
}

func (sm *tunnelStateMachine) Get() TunnelState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

func (sm *tunnelStateMachine) Set(state TunnelState) {
	sm.mu.Lock()
	old := sm.state
	sm.state = state
	if state != StateError {
		sm.lastError = nil
	}
	sm.mu.Unlock()
	if old != state && sm.onChange != nil {
		sm.onChange(old, state)
	}
}

func (sm *tunnelStateMachine) CompareAndSet(newState TunnelState, blockedStates ...TunnelState) (current TunnelState, wasBlocked bool) {
	sm.mu.Lock()
	current = sm.state
	for _, blocked := range blockedStates {
		if current == blocked {
			sm.mu.Unlock()
			return current, true
		}
	}
	old := current
	sm.state = newState
	if newState != StateError {
		sm.lastError = nil
	}
	sm.mu.Unlock()
	if old != newState && sm.onChange != nil {
		sm.onChange(old, newState)
	}
	return old, false
}

func (sm *tunnelStateMachine) SetError(err error) {
	sm.mu.Lock()
	sm.state = StateError
	sm.lastError = err
	sm.mu.Unlock()
}

func (sm *tunnelStateMachine) LastError() error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.lastError
}

func (sm *tunnelStateMachine) IsConnected() bool {
	s := sm.Get()
	return s == StateConnected || s == StateRotating
}
