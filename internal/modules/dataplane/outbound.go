package dataplane

import (
	"context"
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
	outbounds   map[string]*tunnel.Manager
	mu          sync.RWMutex
	log         *logger.Logger
	bridgeReg   *bridgepool.Registry
	stealthMode string
}

func NewOutboundManager() *OutboundManager {
	return &OutboundManager{
		outbounds: make(map[string]*tunnel.Manager),
		log:       logger.Module("outbound"),
	}
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

	if pubKey, ok := cfg.Settings["server_pub_key"].(string); ok && pubKey != "" {
		tCfg.EnablePhantom = true
		tCfg.PhantomServerPubKey = pubKey
		tCfg.PhantomSNI = "google.com"
		if sni, ok := cfg.Settings["sni"].(string); ok {
			tCfg.PhantomSNI = sni
		}
	}

	if len(cfg.Chain) > 0 {
		firstHop := cfg.Chain[0]
		targetAddr := cfg.Address
		tCfg.CustomDialFn = func(ctx context.Context) (net.Conn, error) {
			om.mu.RLock()
			hopTunnel, exists := om.outbounds[firstHop]
			om.mu.RUnlock()
			if exists {
				return hopTunnel.DialStream(ctx, "tcp", targetAddr)
			}

			bridgeID := firstHop
			if len(bridgeID) > 7 && bridgeID[:7] == "bridge:" {
				bridgeID = bridgeID[7:]
			}
			if om.bridgeReg != nil {
				if br, err := om.bridgeReg.GetBridge(bridgeID); err == nil && br.IsAlive {
					return (&net.Dialer{}).DialContext(ctx, "tcp", br.Address)
				}
			}

			return nil, fmt.Errorf("chain hop %q not found as outbound or bridge", firstHop)
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

func (om *OutboundManager) RemoveOutbound(tag string) {
	om.mu.Lock()
	defer om.mu.Unlock()

	if t, exists := om.outbounds[tag]; exists {
		t.Stop()
		delete(om.outbounds, tag)
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
