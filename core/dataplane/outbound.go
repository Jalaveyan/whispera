package dataplane

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"
	"whispera/common/log"
	"whispera/core/config"
	"whispera/core/crypto"
	"whispera/core/handshake"
	"whispera/core/session"
	"whispera/core/tunnel"
)

type OutboundManager struct {
	outbounds    map[string]*tunnel.Manager
	outboundCfgs map[string]config.OutboundConfig
	mu           sync.RWMutex
	log          *logger.Logger
	stealthMode  string
}

func NewOutboundManager() *OutboundManager {
	return &OutboundManager{
		outbounds:    make(map[string]*tunnel.Manager),
		outboundCfgs: make(map[string]config.OutboundConfig),
		log:          logger.Module("outbound"),
	}
}

type cascadeConn struct {
	net.Conn
	closeFns []func()
}

func (c *cascadeConn) Close() error {
	err := c.Conn.Close()
	for i := len(c.closeFns) - 1; i >= 0; i-- {
		c.closeFns[i]()
	}
	return err
}

func (om *OutboundManager) SetStealthMode(mode string) {
	om.mu.Lock()
	om.stealthMode = mode
	om.mu.Unlock()
}

func (om *OutboundManager) AddOutbound(cfg config.OutboundConfig) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if _, exists := om.outbounds[cfg.Tag]; exists {
		return fmt.Errorf("outbound %s already exists", cfg.Tag)
	}

	om.outboundCfgs[cfg.Tag] = cfg

	russiaMode := om.stealthMode == "russia"

	tCfg := &tunnel.Config{
		ServerAddr:        cfg.Address,
		KeepaliveInterval: 15 * time.Second,
		ReconnectInterval: 5 * time.Second,
		EnableRotation:    false,
	}

	if russiaMode {
		tCfg.Transport = "asn_bypass"
	}

	if secret, ok := cfg.Settings["whispera_secret"].(string); ok && secret != "" {
		if decoded, err := decodePSK(secret); err == nil && len(decoded) == 32 {
			tCfg.EnableWhispera = true
			tCfg.WhisperaAddr = cfg.Address
			tCfg.WhisperaSecret = decoded
			if sni, ok := cfg.Settings["whispera_sni"].(string); ok && sni != "" {
				tCfg.WhisperaSNI = sni
			}
			if qa, ok := cfg.Settings["whispera_quic_addr"].(string); ok && qa != "" {
				tCfg.WhisperaQUICAddr = qa
			}
		}
	}

	if len(cfg.Chain) > 0 {
		hops := cfg.Chain
		targetAddr := cfg.Address
		tCfg.CustomDialFn = func(ctx context.Context) (net.Conn, error) {
			return om.dialCascade(ctx, hops, targetAddr)
		}
	}

	cryptoMod, err := crypto.New(nil)
	if err != nil {
		return fmt.Errorf("outbound %s: crypto init: %w", cfg.Tag, err)
	}
	if err := cryptoMod.Init(context.Background(), nil); err != nil {
		return fmt.Errorf("outbound %s: crypto init: %w", cfg.Tag, err)
	}
	if err := cryptoMod.Start(); err != nil {
		return fmt.Errorf("outbound %s: crypto start: %w", cfg.Tag, err)
	}

	sessMod, err := session.New(&session.Config{MaxSessions: 10})
	if err != nil {
		return fmt.Errorf("outbound %s: session init: %w", cfg.Tag, err)
	}
	if err := sessMod.Init(context.Background(), nil); err != nil {
		return fmt.Errorf("outbound %s: session init: %w", cfg.Tag, err)
	}
	if err := sessMod.Start(); err != nil {
		return fmt.Errorf("outbound %s: session start: %w", cfg.Tag, err)
	}

	hsMod, err := handshake.New(&handshake.Config{RateLimit: 100})
	if err != nil {
		return fmt.Errorf("outbound %s: handshake init: %w", cfg.Tag, err)
	}
	hsMod.SetDependencies(cryptoMod, sessMod)
	if err := hsMod.Init(context.Background(), nil); err != nil {
		return fmt.Errorf("outbound %s: handshake init: %w", cfg.Tag, err)
	}
	if err := hsMod.Start(); err != nil {
		return fmt.Errorf("outbound %s: handshake start: %w", cfg.Tag, err)
	}

	tManager, err := tunnel.New(tCfg)
	if err != nil {
		return err
	}

	tManager.SetDependencies(nil, hsMod, nil, cryptoMod)

	if err := tManager.Init(context.Background(), tCfg); err != nil {
		return err
	}
	if err := tManager.Start(); err != nil {
		return err
	}

	om.outbounds[cfg.Tag] = tManager

	go func() { _ = tManager.Connect(context.Background()) }()

	return nil
}

func (om *OutboundManager) dialCascade(ctx context.Context, hops []string, finalAddr string) (net.Conn, error) {
	if len(hops) == 0 {
		return nil, fmt.Errorf("cascade: empty hop chain")
	}

	om.mu.RLock()
	firstMgr := om.outbounds[hops[0]]
	om.mu.RUnlock()
	if firstMgr == nil {
		return nil, fmt.Errorf("cascade: hop %q not found", hops[0])
	}

	if len(hops) == 1 {
		return firstMgr.DialStream(ctx, "tcp", finalAddr)
	}

	var closeFns []func()
	currentMgr := firstMgr

	for i := 1; i < len(hops); i++ {
		om.mu.RLock()
		nextCfg, cfgOK := om.outboundCfgs[hops[i]]
		om.mu.RUnlock()
		if !cfgOK {
			om.cleanupFns(closeFns)
			return nil, fmt.Errorf("cascade: hop %q config not found", hops[i])
		}

		rawConn, err := currentMgr.DialStream(ctx, "tcp", nextCfg.Address)
		if err != nil {
			om.cleanupFns(closeFns)
			return nil, fmt.Errorf("cascade: %q→%q: %w", hops[i-1], hops[i], err)
		}

		innerMgr, err := om.newHopTunnel(ctx, nextCfg, rawConn)
		if err != nil {
			rawConn.Close()
			om.cleanupFns(closeFns)
			return nil, fmt.Errorf("cascade: tunnel to %q: %w", hops[i], err)
		}

		rc, im := rawConn, innerMgr
		closeFns = append(closeFns, func() { im.Stop(); rc.Close() })
		currentMgr = innerMgr
	}

	conn, err := currentMgr.DialStream(ctx, "tcp", finalAddr)
	if err != nil {
		om.cleanupFns(closeFns)
		return nil, fmt.Errorf("cascade: final dial %q: %w", finalAddr, err)
	}
	if len(closeFns) == 0 {
		return conn, nil
	}
	return &cascadeConn{Conn: conn, closeFns: closeFns}, nil
}

func (om *OutboundManager) cleanupFns(fns []func()) {
	for i := len(fns) - 1; i >= 0; i-- {
		fns[i]()
	}
}

func (om *OutboundManager) newHopTunnel(ctx context.Context, cfg config.OutboundConfig, transport net.Conn) (*tunnel.Manager, error) {
	tCfg := tunnel.DefaultConfig()
	tCfg.ServerAddr = cfg.Address
	tCfg.EnableRotation = false
	tCfg.MaxReconnectAttempts = 1
	tCfg.KeepaliveInterval = 30 * time.Second
	tCfg.CustomDialFn = func(_ context.Context) (net.Conn, error) {
		return transport, nil
	}

	if secret, ok := cfg.Settings["whispera_secret"].(string); ok && secret != "" {
		if decoded, err := decodePSK(secret); err == nil && len(decoded) == 32 {
			tCfg.EnableWhispera = true
			tCfg.WhisperaAddr = cfg.Address
			tCfg.WhisperaSecret = decoded
			if sni, ok := cfg.Settings["whispera_sni"].(string); ok && sni != "" {
				tCfg.WhisperaSNI = sni
			}
			if qa, ok := cfg.Settings["whispera_quic_addr"].(string); ok && qa != "" {
				tCfg.WhisperaQUICAddr = qa
			}
		}
	}

	cryptoMod, err := crypto.New(nil)
	if err != nil {
		return nil, err
	}
	_ = cryptoMod.Init(context.Background(), nil)
	_ = cryptoMod.Start()

	sessMod, err := session.New(&session.Config{MaxSessions: 2})
	if err != nil {
		return nil, err
	}
	_ = sessMod.Init(context.Background(), nil)
	_ = sessMod.Start()

	hsMod, err := handshake.New(&handshake.Config{RateLimit: 10})
	if err != nil {
		return nil, err
	}
	hsMod.SetDependencies(cryptoMod, sessMod)
	_ = hsMod.Init(context.Background(), nil)
	_ = hsMod.Start()

	mgr, err := tunnel.New(tCfg)
	if err != nil {
		return nil, err
	}
	mgr.SetDependencies(nil, hsMod, nil, cryptoMod)
	_ = mgr.Init(context.Background(), tCfg)
	_ = mgr.Start()

	if err := mgr.Connect(ctx); err != nil {
		mgr.Stop()
		return nil, err
	}
	return mgr, nil
}

func (om *OutboundManager) RemoveOutbound(tag string) {
	om.mu.Lock()
	defer om.mu.Unlock()

	if t, exists := om.outbounds[tag]; exists {
		t.Stop()
		delete(om.outbounds, tag)
		delete(om.outboundCfgs, tag)
	}
}

func (om *OutboundManager) Dial(ctx context.Context, tag string, network, addr string) (net.Conn, error) {
	om.mu.RLock()
	t, exists := om.outbounds[tag]
	om.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("outbound not found: %s", tag)
	}

	return t.DialStream(ctx, network, addr)
}

func (om *OutboundManager) ForwardPacket(packet []byte, tag string) error {
	om.mu.RLock()
	t, exists := om.outbounds[tag]
	om.mu.RUnlock()

	if !exists {
		return fmt.Errorf("outbound not found: %s", tag)
	}

	const FrameTypeRawPacket = 0x09

	frame := make([]byte, 8+len(packet))
	frame[2] = FrameTypeRawPacket
	frame[3] = 0x00

	frame[0] = 0x00
	frame[1] = 0x00

	frame[4] = byte(len(packet) >> 24)
	frame[5] = byte(len(packet) >> 16)
	frame[6] = byte(len(packet) >> 8)
	frame[7] = byte(len(packet))

	copy(frame[8:], packet)

	return t.Send(frame)
}

func (om *OutboundManager) UpdateOutbounds(configs []config.OutboundConfig) {
	if err := validateChainGraph(configs); err != nil {
		return
	}

	current := make(map[string]bool)
	for _, c := range configs {
		current[c.Tag] = true
		om.mu.RLock()
		_, exists := om.outbounds[c.Tag]
		om.mu.RUnlock()

		if !exists {
			if err := om.AddOutbound(c); err != nil {
				om.log.Error("Failed to add outbound %s: %v", c.Tag, err)
			}
		}
	}

	om.mu.Lock()
	for tag := range om.outbounds {
		if !current[tag] {
			om.outbounds[tag].Stop()
			delete(om.outbounds, tag)
			delete(om.outboundCfgs, tag)
		}
	}
	om.mu.Unlock()
}

func validateChainGraph(configs []config.OutboundConfig) error {
	known := make(map[string]*config.OutboundConfig, len(configs))
	for i := range configs {
		known[configs[i].Tag] = &configs[i]
	}

	var visit func(tag string, stack map[string]bool) error
	visit = func(tag string, stack map[string]bool) error {
		out, ok := known[tag]
		if !ok {
			return nil
		}
		if stack[tag] {
			return fmt.Errorf("outbound chain cycle detected at %q", tag)
		}
		stack[tag] = true
		defer delete(stack, tag)
		for _, hop := range out.Chain {
			if err := visit(hop, stack); err != nil {
				return err
			}
		}
		return nil
	}

	for tag := range known {
		if err := visit(tag, make(map[string]bool)); err != nil {
			return err
		}
	}
	return nil
}

func decodePSK(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return hex.DecodeString(s)
}
