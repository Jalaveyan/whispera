package manager

import (
	"fmt"
	"log"
	"net"
	"sync"
	"whispera/core/config"
)

type Manager struct {
	mu        sync.RWMutex
	listeners map[string]net.Listener

	startCallback func(config.InboundConfig) error
	stopCallback  func(string) error
}

func New() *Manager {
	return &Manager{
		listeners: make(map[string]net.Listener),
	}
}

func (m *Manager) SetCallbacks(start func(config.InboundConfig) error, stop func(string) error) {
	m.startCallback = start
	m.stopCallback = stop
}

func (m *Manager) StartInbound(inbound config.InboundConfig) error {
	if m.startCallback == nil {
		return fmt.Errorf("start callback not set")
	}

	if m.IsRunning(inbound.Tag) {
		log.Printf("[DynamicManager] Inbound %s already running, skipping start", inbound.Tag)
		return nil
	}

	ports := inbound.AllPorts()
	if len(ports) <= 1 {
		log.Printf("[DynamicManager] Starting inbound %s on port %d", inbound.Tag, inbound.Port)
		return m.startCallback(inbound)
	}

	var startedTags []string
	for _, p := range ports {
		derived := inbound
		derived.Port = p
		derived.Ports = nil
		if p != inbound.Port {
			derived.Tag = fmt.Sprintf("%s-%d", inbound.Tag, p)
		}
		log.Printf("[DynamicManager] Starting inbound %s on port %d (multiport)", derived.Tag, p)
		if err := m.startCallback(derived); err != nil {
			for _, tag := range startedTags {
				if m.stopCallback != nil {
					_ = m.stopCallback(tag)
				}
			}
			return fmt.Errorf("port %d: %w", p, err)
		}
		startedTags = append(startedTags, derived.Tag)
	}
	return nil
}

func (m *Manager) IsRunning(tag string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.listeners[tag]
	return exists
}

var Global *Manager

func init() {
	Global = New()
}
