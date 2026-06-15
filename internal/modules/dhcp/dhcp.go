package dhcp

import (
	"fmt"
	"net"
	"sync"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/log"
)

const (
	ModuleName    = "dhcp.manager"
	ModuleVersion = "1.0.0"
)

type IPPool struct {
	mu sync.Mutex

	network   *net.IPNet
	networkIP net.IP
	broadcast net.IP

	usedIPs     map[string]bool
	reservedIPs map[string]bool

	nextIP uint32

	firstIP uint32
	lastIP  uint32
}

type Config struct {
	Enabled       bool          `json:"enabled" yaml:"enabled"`
	SubnetCIDR    string        `json:"subnet_cidr" yaml:"subnet_cidr"`
	LeaseTime     time.Duration `json:"lease_time" yaml:"lease_time"`
	DNSServers    []string      `json:"dns_servers" yaml:"dns_servers"`
	Gateway       string        `json:"gateway" yaml:"gateway"`
	DomainSuffix  string        `json:"domain_suffix" yaml:"domain_suffix"`
	PushRoutes    []string      `json:"push_routes" yaml:"push_routes"`
	FullTunneling bool          `json:"full_tunneling" yaml:"full_tunneling"`
}

type Lease struct {
	IP          net.IP                 `json:"ip"`
	ClientID    string                 `json:"client_id"`
	SessionID   uint32                 `json:"session_id,omitempty"`
	Hostname    string                 `json:"hostname,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	LastRenewed time.Time              `json:"last_renewed"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (l *Lease) IsExpired() bool {
	return time.Now().After(l.ExpiresAt)
}
func (l *Lease) TimeRemaining() time.Duration {
	remaining := time.Until(l.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

type ClientParams struct {
	AssignedIP   net.IP   `json:"assigned_ip"`
	SubnetMask   net.IP   `json:"subnet_mask"`
	Gateway      net.IP   `json:"gateway"`
	DNSServers   []net.IP `json:"dns_servers"`
	DomainSuffix string   `json:"domain_suffix,omitempty"`
	Routes       []Route  `json:"routes,omitempty"`
	LeaseTime    int64    `json:"lease_time_seconds"`
}

type Route struct {
	Network string `json:"network"`
	Gateway string `json:"gateway,omitempty"`
}

type Manager struct {
	*base.Module
	config *Config

	pool *IPPool

	leasesMu sync.RWMutex
	leases   map[string]*Lease

	clientToIP map[string]string

	gateway    net.IP
	dnsServers []net.IP
	subnetMask net.IP

	log *logger.Logger
}

func (m *Manager) ReleaseByClient(clientID string) error {
	m.leasesMu.Lock()
	defer m.leasesMu.Unlock()

	ipStr, ok := m.clientToIP[clientID]
	if !ok {
		return fmt.Errorf("no lease found for client %s", clientID)
	}

	lease := m.leases[ipStr]
	if lease != nil {
		m.pool.Release(lease.IP)
	}

	delete(m.leases, ipStr)
	delete(m.clientToIP, clientID)

	return nil
}

func (m *Manager) GetAllLeases() []*Lease {
	m.leasesMu.RLock()
	defer m.leasesMu.RUnlock()

	result := make([]*Lease, 0, len(m.leases))
	for _, lease := range m.leases {
		copy := *lease
		result = append(result, &copy)
	}
	return result
}

func (m *Manager) GetStats() map[string]interface{} {
	m.leasesMu.RLock()
	defer m.leasesMu.RUnlock()

	return map[string]interface{}{
		"enabled":        m.config.Enabled,
		"subnet":         m.config.SubnetCIDR,
		"total_ips":      m.pool.TotalCount(),
		"available_ips":  m.pool.AvailableCount(),
		"used_ips":       m.pool.UsedCount(),
		"active_leases":  len(m.leases),
		"lease_time":     m.config.LeaseTime.String(),
		"dns_servers":    m.config.DNSServers,
		"full_tunneling": m.config.FullTunneling,
	}
}

func (p *IPPool) Release(ip net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ipStr := ip.String()

	if !p.usedIPs[ipStr] {
		return fmt.Errorf("IP %s is not in use", ipStr)
	}

	delete(p.usedIPs, ipStr)
	return nil
}

func (p *IPPool) AvailableCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	total := int(p.lastIP - p.firstIP + 1)
	used := len(p.usedIPs)
	reserved := len(p.reservedIPs)

	available := total - used - reserved
	if available < 0 {
		available = 0
	}
	return available
}

func (p *IPPool) UsedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.usedIPs)
}

func (p *IPPool) TotalCount() int {
	return int(p.lastIP - p.firstIP + 1)
}
