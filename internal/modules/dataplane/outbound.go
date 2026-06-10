package dataplane

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"whispera/internal/logger"
	"whispera/internal/modules/bridgepool"
	"whispera/internal/modules/config"
	"whispera/internal/modules/crypto"
	"whispera/internal/modules/handshake"
	"whispera/internal/modules/obfuscator"
	"whispera/internal/modules/session"
	"whispera/internal/modules/tunnel"
)

type OutboundManager struct {
	outbounds    map[string]*tunnel.Manager
	outboundCfgs map[string]config.OutboundConfig
	mu           sync.RWMutex
	log          *logger.Logger
	bridgeReg    *bridgepool.Registry
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

func (om *OutboundManager) SetBridgeRegistry(reg *bridgepool.Registry) {
	om.bridgeReg = reg
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
		tCfg.Transport = "vkwebrtc,yatelemost,okwebrtc,vkbot,cdnworker,russian,asn_bypass"
	}

	if secret, ok := cfg.Settings["chameleon_secret"].(string); ok && secret != "" {
		if decoded, err := decodePSK(secret); err == nil && len(decoded) == 32 {
			tCfg.EnableChameleon = true
			tCfg.ChameleonAddr = cfg.Address
			tCfg.ChameleonSecret = decoded
			if sni, ok := cfg.Settings["chameleon_sni"].(string); ok && sni != "" {
				tCfg.ChameleonSNI = sni
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

	threatLevel := 5
	if russiaMode {
		threatLevel = 8
	}
	obfsMod, err := obfuscator.New(&obfuscator.Config{
		DefaultProfile: "default",
		ThreatLevel:    threatLevel,
		EnableML:       true,
		EnableFTE:      true,
	})
	if err != nil {
		return fmt.Errorf("outbound %s: obfuscator init: %w", cfg.Tag, err)
	}
	if err := obfsMod.Init(context.Background(), nil); err != nil {
		return fmt.Errorf("outbound %s: obfuscator init: %w", cfg.Tag, err)
	}
	if err := obfsMod.Start(); err != nil {
		return fmt.Errorf("outbound %s: obfuscator start: %w", cfg.Tag, err)
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
	tManager.SetObfuscator(obfsMod)

	if err := tManager.Init(context.Background(), tCfg); err != nil {
		return err
	}
	if err := tManager.Start(); err != nil {
		return err
	}

	om.outbounds[cfg.Tag] = tManager
	om.log.Info("Started outbound tunnel: %s (%s)", cfg.Tag, cfg.Address)

	go func() { _ = tManager.Connect(context.Background()) }()

	return nil
}

func (om *OutboundManager) dialCascade(ctx context.Context, hops []string, finalAddr string) (net.Conn, error) {
	om.mu.RLock()
	firstMgr, ok := om.outbounds[hops[0]]
	om.mu.RUnlock()
	if !ok {
		return om.dialBridgeHop(ctx, hops[0], finalAddr)
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

func (om *OutboundManager) dialBridgeHop(ctx context.Context, hopTag, finalAddr string) (net.Conn, error) {
	bridgeID := hopTag
	if len(bridgeID) > 7 && bridgeID[:7] == "bridge:" {
		bridgeID = bridgeID[7:]
	}
	if om.bridgeReg != nil {
		if br, err := om.bridgeReg.GetBridge(bridgeID); err == nil && br.IsAlive {
			return (&net.Dialer{}).DialContext(ctx, "tcp", br.Address)
		}
	}
	return nil, fmt.Errorf("cascade: hop %q not found as outbound or bridge", hopTag)
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

	if secret, ok := cfg.Settings["chameleon_secret"].(string); ok && secret != "" {
		if decoded, err := decodePSK(secret); err == nil && len(decoded) == 32 {
			tCfg.EnableChameleon = true
			tCfg.ChameleonAddr = cfg.Address
			tCfg.ChameleonSecret = decoded
			if sni, ok := cfg.Settings["chameleon_sni"].(string); ok && sni != "" {
				tCfg.ChameleonSNI = sni
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
		om.log.Info("Removed outbound: %s", tag)
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
		om.log.Error("Outbound chain graph rejected: %v", err)
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
			om.log.Info("Removed stale outbound: %s", tag)
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
			if len(hop) > 7 && hop[:7] == "bridge:" {
				continue
			}
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
