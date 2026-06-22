package tunnel

import (
	"fmt"
	"sync"
	"sync/atomic"
)

func (m *Manager) GetTransport() string {
	return m.config.Transport
}

func (m *Manager) SetTransport(transport string) {
	m.config.Transport = transport
}

func (m *Manager) SetSpoofIPs(ips []string) {
	m.connCfg.SetSpoofIPs(ips)
}

func (m *Manager) SetRateLimit(kbps int) {
	m.connCfg.SetRateLimitKB(kbps)
}

func (m *Manager) GetRateLimit() int {
	return m.connCfg.RateLimitKB()
}

func (m *Manager) SetTLSFragmentSize(size int) {
	m.connCfg.SetTLSFragmentSize(size)
	if m.config != nil {
		if size < 0 {
			size = 0
		}
		m.config.TLSFragmentSize = size
	}
}

func (m *Manager) GetTLSFragmentSize() int {
	return m.connCfg.TLSFragmentSize()
}

func (m *Manager) SetForceObfuscation(enabled bool) {
	m.connCfg.SetForceObfuscation(enabled)
}

func (m *Manager) IsForceObfuscation() bool {
	return m.connCfg.IsForceObfuscation()
}

func (m *Manager) SetBehavioralProfile(profile string) error {
	if m.obfuscator == nil {
		return fmt.Errorf("obfuscator not initialized")
	}
	if profile == "" {
		return nil
	}
	return m.obfuscator.SetProfile(profile)
}

type connConfig struct {
	rateLimitKB             atomic.Int32
	tlsFragmentSize         atomic.Int32
	transportSecureOverride atomic.Int32
	forceObfuscation        atomic.Int32

	spoofMu  sync.RWMutex
	spoofIPs []string
	spoofIdx uint64
}

func (c *connConfig) RateLimitKB() int { return int(c.rateLimitKB.Load()) }

func (c *connConfig) SetRateLimitKB(kbps int) { c.rateLimitKB.Store(int32(kbps)) }

func (c *connConfig) TLSFragmentSize() int { return int(c.tlsFragmentSize.Load()) }

func (c *connConfig) SetTLSFragmentSize(size int) {
	if size < 0 {
		size = 0
	}
	c.tlsFragmentSize.Store(int32(size))
}

func (c *connConfig) TransportSecureOverride() int32 { return c.transportSecureOverride.Load() }

func (c *connConfig) ForceObfuscation() int32 { return c.forceObfuscation.Load() }

func (c *connConfig) SetForceObfuscation(enabled bool) {
	if enabled {
		c.transportSecureOverride.Store(0)
		c.forceObfuscation.Store(1)
	} else {
		c.transportSecureOverride.Store(1)
		c.forceObfuscation.Store(0)
	}
}

func (c *connConfig) IsForceObfuscation() bool { return c.transportSecureOverride.Load() == 0 }

func (c *connConfig) SpoofIPs() []string {
	c.spoofMu.RLock()
	defer c.spoofMu.RUnlock()
	return c.spoofIPs
}

func (c *connConfig) SetSpoofIPs(ips []string) {
	c.spoofMu.Lock()
	c.spoofIPs = ips
	c.spoofMu.Unlock()
}
