package asn_bypass

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/logger"

	utls "github.com/refraction-networking/utls"
)

var log = logger.Module("asn_bypass")

const (
	ModuleName    = "transport.asn_bypass"
	ModuleVersion = "1.0.0"
)

type TransportConfig struct {
	ServerAddr string

	Strategy Strategy

	FrontDomain string
	RealSNI     string

	TLSFingerprint string
	EnableECH      bool

	ResidentialProxies []string
	ProxyRotation      bool

	ConnectionTimeout time.Duration
	KeepaliveInterval time.Duration
	MaxRetries        int

	EnableJA3Randomization  bool
	EnableTLSFragmentation bool
	TLSFragmentSize        int
	ConnectionBurstLimit   int
	BurstCooldown          time.Duration
}

func DefaultTransportConfig() *TransportConfig {
	return &TransportConfig{
		Strategy:                StrategyTLSMasquerade,
		TLSFingerprint:          "chrome",
		ConnectionTimeout:       30 * time.Second,
		KeepaliveInterval:       30 * time.Second,
		MaxRetries:              3,
		EnableJA3Randomization:  true,
		EnableTLSFragmentation: true,
		TLSFragmentSize:        40,
		ConnectionBurstLimit:    5,
		BurstCooldown:           2 * time.Second,
	}
}

type Transport struct {
	*base.Module
	config *TransportConfig
	dialer *Dialer

	conn      net.Conn
	connMu    sync.RWMutex
	connected uint32

	bytesUp    uint64
	bytesDown  uint64
	connTime   time.Time
	lastActive time.Time

	onDisconnect func(error)
}

func NewTransport(cfg *TransportConfig) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultTransportConfig()
	}

	dialerCfg := &Config{
		Strategy:               cfg.Strategy,
		FrontDomain:            cfg.FrontDomain,
		TLSFingerprint:         cfg.TLSFingerprint,
		TLSMinVersion:          tls.VersionTLS13,
		TLSMaxVersion:          tls.VersionTLS13,
		EnableECH:              cfg.EnableECH,
		EnableJA3Randomization:  cfg.EnableJA3Randomization,
		EnableTLSFragmentation: cfg.EnableTLSFragmentation,
		TLSFragmentSize:        cfg.TLSFragmentSize,
		ConnectionBurstLimit:    cfg.ConnectionBurstLimit,
		ConnectionCooldown:      cfg.BurstCooldown,
		ResidentialProxies:     cfg.ResidentialProxies,
		ProxyRotation:          cfg.ProxyRotation,
		FailoverTimeout:        cfg.ConnectionTimeout,
		FallbackStrategies:     []Strategy{StrategyTLSMasquerade, StrategyDomainFronting},
	}

	t := &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		dialer: NewDialer(dialerCfg),
	}

	return t, nil
}

func (t *Transport) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := t.Module.Init(ctx, cfg); err != nil {
		return err
	}
	return nil
}

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	t.SetHealthy(true, "ASN bypass transport ready")
	t.PublishEvent(events.EventTypeModuleStarted, nil)
	log.Info("ASN bypass transport started with strategy: %d, fingerprint: %s",
		t.config.Strategy, t.config.TLSFingerprint)

	return nil
}

func (t *Transport) Stop() error {
	t.Disconnect()
	t.PublishEvent(events.EventTypeModuleStopped, nil)
	return t.Module.Stop()
}

func (t *Transport) Connect(ctx context.Context) error {
	if t.IsConnected() {
		return nil
	}

	log.Info("Connecting to %s with ASN bypass (strategy: %d)", t.config.ServerAddr, t.config.Strategy)

	var lastErr error
	for attempt := 0; attempt < t.config.MaxRetries; attempt++ {
		if attempt > 0 {
			log.Info("Retry attempt %d/%d", attempt+1, t.config.MaxRetries)
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		conn, err := t.dialer.DialContext(ctx, "tcp", t.config.ServerAddr)
		if err != nil {
			lastErr = err
			log.Warn("Connection attempt %d failed: %v", attempt+1, err)
			continue
		}

		t.connMu.Lock()
		t.conn = conn
		t.connTime = time.Now()
		t.lastActive = time.Now()
		atomic.StoreUint32(&t.connected, 1)
		t.connMu.Unlock()

		t.SetHealthy(true, "connected")
		t.PublishEvent("transport.connected", map[string]interface{}{
			"server":   t.config.ServerAddr,
			"strategy": t.config.Strategy,
		})

		log.Info("Connected to %s successfully", t.config.ServerAddr)
		return nil
	}

	return fmt.Errorf("failed to connect after %d attempts: %w", t.config.MaxRetries, lastErr)
}

func (t *Transport) Disconnect() {
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	atomic.StoreUint32(&t.connected, 0)
	t.SetHealthy(true, "disconnected")
	t.PublishEvent("transport.disconnected", nil)
}

func (t *Transport) IsConnected() bool {
	return atomic.LoadUint32(&t.connected) == 1
}

func (t *Transport) Write(data []byte) (int, error) {
	t.connMu.RLock()
	conn := t.conn
	t.connMu.RUnlock()

	if conn == nil {
		return 0, fmt.Errorf("not connected")
	}

	n, err := conn.Write(data)
	if err != nil {
		if t.onDisconnect != nil {
			t.onDisconnect(err)
		}
		return n, err
	}

	atomic.AddUint64(&t.bytesUp, uint64(n))
	t.lastActive = time.Now()
	t.UpdateActivity()

	return n, nil
}

func (t *Transport) Read(buf []byte) (int, error) {
	t.connMu.RLock()
	conn := t.conn
	t.connMu.RUnlock()

	if conn == nil {
		return 0, fmt.Errorf("not connected")
	}

	n, err := conn.Read(buf)
	if err != nil {
		if t.onDisconnect != nil && err != io.EOF {
			t.onDisconnect(err)
		}
		return n, err
	}

	atomic.AddUint64(&t.bytesDown, uint64(n))
	t.lastActive = time.Now()
	t.UpdateActivity()

	return n, nil
}

func (t *Transport) SetStrategy(s Strategy) {
	t.dialer.SetStrategy(s)
	t.config.Strategy = s
	log.Info("Changed ASN bypass strategy to: %d", s)
}

func (t *Transport) SetFingerprint(fp string) {
	t.dialer.SetFingerprint(fp)
	t.config.TLSFingerprint = fp
	log.Info("Changed TLS fingerprint to: %s", fp)
}

func (t *Transport) OnDisconnect(callback func(error)) {
	t.onDisconnect = callback
}

func (t *Transport) GetConnection() net.Conn {
	t.connMu.RLock()
	defer t.connMu.RUnlock()
	return t.conn
}

func (t *Transport) SetReadDeadline(deadline time.Time) error {
	t.connMu.RLock()
	conn := t.conn
	t.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}
	return conn.SetReadDeadline(deadline)
}

func (t *Transport) SetWriteDeadline(deadline time.Time) error {
	t.connMu.RLock()
	conn := t.conn
	t.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}
	return conn.SetWriteDeadline(deadline)
}

func (t *Transport) Stats() map[string]interface{} {
	dialerStats := t.dialer.Stats()
	return map[string]interface{}{
		"connected":   t.IsConnected(),
		"bytes_up":    atomic.LoadUint64(&t.bytesUp),
		"bytes_down":  atomic.LoadUint64(&t.bytesDown),
		"uptime":      time.Since(t.connTime).String(),
		"last_active": t.lastActive,
		"strategy":    t.config.Strategy,
		"fingerprint": t.config.TLSFingerprint,
		"dialer":      dialerStats,
	}
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	status := t.Module.HealthCheck()

	status.Details["connected"] = t.IsConnected()
	status.Details["strategy"] = t.config.Strategy
	status.Details["fingerprint"] = t.config.TLSFingerprint
	status.Details["bytes_up"] = atomic.LoadUint64(&t.bytesUp)
	status.Details["bytes_down"] = atomic.LoadUint64(&t.bytesDown)

	if !t.connTime.IsZero() {
		status.Details["uptime"] = time.Since(t.connTime).String()
	}

	return status
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	var config *TransportConfig
	if c, ok := cfg.(*TransportConfig); ok {
		config = c
	} else {
		config = DefaultTransportConfig()
	}
	return NewTransport(config)
}


type ECHConfig struct {
	PublicKey   []byte
	ECHConfigs  []byte
	LastUpdated time.Time
}

func FetchECHConfig(ctx context.Context, domain string) (*ECHConfig, error) {
	log.Info("Fetching ECH config for %s (not yet implemented)", domain)
	return nil, fmt.Errorf("ECH config fetch not implemented")
}

func ApplyECH(conn *utls.UConn, config *ECHConfig) error {
	if config == nil || len(config.ECHConfigs) == 0 {
		return fmt.Errorf("no ECH config available")
	}

	return nil
}
