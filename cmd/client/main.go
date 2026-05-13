package main

import (
	"context"
	"encoding/base64"
	"flag"
	"io"
	stdlog "log"
	mrand "math/rand"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	_ "go.uber.org/automaxprocs"

	"whispera/internal/auth"
	"whispera/internal/client/bridge"
	"whispera/internal/core/lifecycle"
	"whispera/internal/logger"
	mlpkg "whispera/internal/obfuscation/ml"

	"whispera/internal/modules/config"
	"whispera/internal/modules/crypto"
	"whispera/internal/modules/dnsmodule"
	"whispera/internal/modules/handshake"
	"whispera/internal/modules/killswitch"
	"whispera/internal/modules/mitm"
	"whispera/internal/modules/obfuscator"
	"whispera/internal/modules/proxyagent"
	"whispera/internal/modules/session"
	"whispera/internal/modules/socks5"
	"whispera/internal/modules/tunnel"
	"whispera/internal/split_tunnel"
)

var log = logger.Module("client")

var Version = "2.0.0"

var (
	configPath       = flag.String("config", "", "Path to configuration file")
	serverAddr       = flag.String("server", "212.192.246.108:8443", "Server address (host:port)")
	socksAddr        = flag.String("socks", "127.0.0.1:10800", "SOCKS5 listen address for hev-socks5-tunnel")
	connKey          = flag.String("key", "", "Connection key (whispera://...)")
	transport        = flag.String("transport", "tcp", "Transport mode: auto|tcp|udp")
	obfsLevel        = flag.Int("obfs-level", 5, "Obfuscation threat level (0-10)")
	asnBypass        = flag.Bool("asn-bypass", false, "Enable ASN bypass for VPN/datacenter IP evasion")
	tlsFingerprint   = flag.String("tls-fingerprint", "chrome", "TLS fingerprint for ASN bypass: chrome, firefox, safari, ios, android")
	enableKillSwitch = flag.Bool("kill-switch", false, "Enable kill switch to prevent traffic leaks")
	allowLAN         = flag.Bool("allow-lan", true, "Allow LAN traffic when kill switch is enabled")
	phantomKey       = flag.String("phantom-key", "", "Phantom Server Public Key (hex) for REALITY authentication")
	userKey          = flag.String("user-key", "", "User private key (base64) for ML-mode auth — sets PSK without a full connection key")
	noInternalTun    = flag.Bool("no-tun", true, "Disable internal TUN (use external like Mihomo)")
	russianService   = flag.String("russian-service", "", "Enable Russian Service masquerading (e.g. vk_video)")
	vkToken          = flag.String("vk-token", "", "VK User Access Token for WebRTC Tunneling")
	serverList       = flag.String("servers", "", "Comma-separated server addresses for latency-based routing")
	rekeyInterval    = flag.Duration("rekey", 10*time.Minute, "Session rekeying interval (0 = disabled)")
	mlServerURL      = flag.String("ml-server", "", "ML server URL (e.g. https://127.0.0.1:8000)")
	mlTokenFlag      = flag.String("ml-token", "", "ML API auth token")
	controlPort      = flag.String("control-port", "10801", "Control server port (default 10801)")
	dnsUpstream      = flag.String("dns", "", "DNS upstream: host:port for UDP (8.8.8.8:53), https://... for DoH (https://1.1.1.1/dns-query). Empty = 1.1.1.1:53. 'system' = ISP resolver")
	enableMITM       = flag.Bool("mitm", false, "Enable local TLS inspection proxy (MITM)")
	mitmAddr         = flag.String("mitm-addr", "127.0.0.1:10899", "MITM proxy listen address")
	spoofIPs         = flag.String("spoof-ips", "", "Comma-separated source IPs for IP spoofing (requires multiple local IPs)")
	adminTokenFlag   = flag.String("admin-token", "", "Admin token required for privileged control endpoints (e.g. /spoof). Empty = no auth")
	tlsFragSize      = flag.Int("tls-fragment", 0, "TLS ClientHello fragment size in bytes (0=default 40, range 16-200). Smaller = harder for DPI but more RTT")
	logFilePath      = flag.String("log-file", "", "Write logs to file (default: in-memory only, no disk storage)")
	forceSNIFlag     = flag.String("sni", "", "Force custom SNI in TLS ClientHello for all connections (e.g. www.google.com). Overrides phantom/asn-bypass SNI")
	regionFlag       = flag.String("region", "", "Preferred server region: auto|ru|eu|us|cn (overrides config)")
	subURL           = flag.String("sub-url", "", "Subscription URL for automatic key refresh (checked every 24h)")
	subInterval      = flag.Duration("sub-interval", 24*time.Hour, "Subscription refresh interval")
)

// pickServerAddress returns the best server address for the given transport,
// respecting transport-specific overrides in ClientConfig.
func pickServerAddress(cfg *config.ClientConfig, transport string) string {
	switch transport {
	case "tcp", "tls":
		if cfg.ServerTCP != "" {
			return cfg.ServerTCP
		}
	case "ws", "websocket":
		if cfg.ServerWS != "" {
			return cfg.ServerWS
		}
		if cfg.ServerTCP != "" {
			return cfg.ServerTCP
		}
	}
	if cfg.Server != "" {
		return cfg.Server
	}
	return cfg.ServerTCP
}

func mlDefaultDataDir() string {
	if exe, err := os.Executable(); err == nil {
		exeDir := strings.TrimSuffix(exe, "/"+strings.Split(exe, "/")[len(strings.Split(exe, "/"))-1])
		if fi, err := os.Stat(exeDir + "/data/api_token"); err == nil && !fi.IsDir() {
			return exeDir + "/data"
		}
	}
	switch {
	case strings.EqualFold(os.Getenv("OS"), "Windows_NT") || os.PathSeparator == '\\':
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return appdata + `\Whispera`
		}
	default:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return xdg + "/whispera"
		}
		if home, err := os.UserHomeDir(); err == nil {
			return home + "/.config/whispera"
		}
	}
	return "data"
}

func resolveMLToken(cfg *config.ClientConfig) string {
	if cfg.MLServerURL == "" {
		return ""
	}
	if cfg.MLToken != "" {
		return cfg.MLToken
	}

	candidates := []string{}
	if cfg.MLTokenFile != "" {
		candidates = append(candidates, cfg.MLTokenFile)
	}
	candidates = append(candidates, mlDefaultDataDir()+string(os.PathSeparator)+"api_token")

	for _, p := range candidates {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(f)
		f.Close()
		if err == nil {
			if tok := strings.TrimSpace(string(b)); tok != "" {
				stdlog.Printf("ML API token loaded from %s", p)
				return tok
			}
		}
	}
	stdlog.Printf("WARNING: MLServerURL set but no API token found — requests may be rejected (401)")
	return ""
}

func main() {
	// Keep GC aggressive enough to avoid large heap on memory-constrained devices
	// (mobile). 100 = GC when live heap doubles (Go default). 200 trades RAM for
	// CPU — fine on desktop, bad on mobile where 150–200 MB heaps drain battery.
	debug.SetGCPercent(100)
	// Return OS memory promptly after GC instead of holding it speculatively.
	debug.SetMemoryLimit(200 << 20) // soft cap: 200 MB

	flag.Parse()

	if *mlServerURL != "" {
		mlpkg.SetMLServerURL(*mlServerURL, *mlTokenFlag)
	}

	// Detect systemd: JOURNAL_STREAM or INVOCATION_ID means we are a unit.
	// In that case write to stdout so journald captures us; skip /dev/null redirect.
	underSystemd := os.Getenv("JOURNAL_STREAM") != "" || os.Getenv("INVOCATION_ID") != ""

	var logWriter io.Writer
	if *logFilePath != "" {
		// Explicit file requested — write there.
		logFile, err := os.OpenFile(*logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			rb := newRingLogBuffer(2000)
			globalLogBuf = rb
			logWriter = rb
		} else {
			logWriter = logFile
		}
	} else if underSystemd {
		// Under systemd: let journald capture our stdout. No timestamps —
		// journald adds them. Redirect stderr too so panics are captured.
		logWriter = os.Stdout
	} else {
		// Foreground / non-systemd: silence stdout/stderr, use ring buffer.
		if null, errNull := os.OpenFile(os.DevNull, os.O_WRONLY, 0666); errNull == nil {
			os.Stdout = null
			os.Stderr = null
		}
		rb := newRingLogBuffer(2000)
		globalLogBuf = rb
		logWriter = rb
	}
	stdlog.SetOutput(logWriter)
	logger.SetOutput(logWriter)
	log = logger.Module("client")
	stdlog.Printf("Whispera Client v%s starting...", Version)

	var cfg *config.ClientConfig

	if *connKey != "" {
		key, err := config.ParseConnectionKey(*connKey)
		if err != nil {
			stdlog.Fatalf("Failed to parse connection key: %v", err)
		}
		cfg = key.ToClientConfig()
		stdlog.Printf("Loaded config from key: %s", key.Name)
		stdlog.Printf("Server: %s (transport: %s, obfuscation: %s)", key.GetPrimaryServer(), key.Transport, key.ObfsPreset)
	} else if *configPath != "" {
		var loadErr error
		cfg, loadErr = config.LoadClient(*configPath)
		if loadErr != nil {
			stdlog.Fatalf("Failed to load config: %v", loadErr)
		}
	} else {
		cfg = &config.ClientConfig{
			Server: *serverAddr,
		}
	}

	if *connKey == "" && *serverAddr != "" {
		cfg.Server = *serverAddr
	}

	if *mlServerURL != "" {
		cfg.MLServerURL = *mlServerURL
	}
	if *mlTokenFlag != "" {
		cfg.MLToken = *mlTokenFlag
	}

	if *userKey != "" {
		if cfg.Phantom == nil {
			cfg.Phantom = &config.ClientPhantomConfig{}
		}
		cfg.Phantom.Enabled = true
		cfg.Phantom.PSK = *userKey
		stdlog.Printf("ML mode: user-key PSK set, phantom auth enabled")
	}

	if cfg.Server == "" && cfg.ServerTCP == "" {
		stdlog.Fatalf("No server address specified. Use -server, -key, or -config")
	}

	stdlog.Printf("Starting Whispera Client v%s", Version)
	stdlog.Printf("Server: %s", cfg.Server)
	if cfg.ServerTCP != "" {
		stdlog.Printf("TCP Fallback: %s", cfg.ServerTCP)
	}
	if cfg.ObfsPreset != "" {
		stdlog.Printf("Obfuscation: %s", cfg.ObfsPreset)
	}

	lc := lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 30 * time.Second,
		GracefulStop:    true,
	})

	ctx := lc.Context()

	cryptoMod, _ := crypto.New(nil)
	lc.Register(cryptoMod)

	obfsProfile := cfg.ObfsPreset
	if obfsProfile == "" {
		obfsProfile = "default"
	}
	obfsMod, _ := obfuscator.New(&obfuscator.Config{
		DefaultProfile:           obfsProfile,
		ThreatLevel:              *obfsLevel,
		EnableML:                 true,
		EnableFTE:                true,
		EnableJitter:             true,
		EnableResidentialMimicry: true,
		ConnectionBurstLimit:     8,
		JitterMinMs:              30,
		JitterMaxMs:              200,
	})
	lc.Register(obfsMod)

	sessMod, _ := session.New(&session.Config{MaxSessions: 10})
	lc.Register(sessMod)

	hsMod, _ := handshake.New(&handshake.Config{
		RateLimit: 100,
		RateBurst: 50,
		Timeout:   10 * time.Second,
	})
	hsMod.SetDependencies(cryptoMod, sessMod)
	if deviceID, devErr := auth.LoadOrCreateDeviceID(); devErr == nil {
		hsMod.SetDeviceID(deviceID)
		stdlog.Printf("Device ID: %x", deviceID[:8])
	} else {
		stdlog.Printf("WARNING: Could not load/create device ID: %v", devErr)
	}
	lc.Register(hsMod)

	dnsUpstreamAddr := "1.1.1.1:53"
	if *dnsUpstream != "" {
		if strings.EqualFold(*dnsUpstream, "system") {
			dnsUpstreamAddr = ""
		} else {
			dnsUpstreamAddr = *dnsUpstream
		}
	}
	// bypassDNS is a resolver that always dials Yandex DNS (77.88.8.8) directly,
	// never through the VPN tunnel. Yandex DNS is geo-aware for RU services and
	// returns correct regional IPs. We use it for two purposes:
	//   1. DNS module bypass path — so VPN tunnel DNS changes don't affect
	//      Russian domains that must resolve locally.
	//   2. Pre-resolve startup — capture IPs of bypass domains so that apps
	//      that pre-resolve and send a bare IP to SOCKS5 are still routed direct.
	bypassDNS := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			// Try primary (Yandex), fallback to secondary on error is handled by
			// the Go resolver automatically when the UDP exchange times out.
			return d.DialContext(ctx, "udp", "77.88.8.8:53")
		},
	}

	// Build split-tunnel manager first — needed by both SOCKS5 bypass and DNS.
	// Russian whitelist is always pre-loaded so that services like YaDisk /
	// Gosuslugi resolve via system DNS and connect directly, keeping their
	// regional IPs regardless of the configured VPN upstream.
	stm := split_tunnel.NewSplitTunnelManager()
	stm.AddRussianWhitelist()
	stm.CreateDefaultRules()
	if cfg.SplitTunnel {
		stm.SetEnabled(true)
		if cfg.SplitTunnelMode != "" {
			stm.SetMode(cfg.SplitTunnelMode)
		}
		if cfg.SplitTunnelRules != "" {
			if err := stm.LoadConfig(cfg.SplitTunnelRules); err != nil {
				stdlog.Printf("WARNING: split tunnel config load failed: %v", err)
			}
		}
	} else {
		// Even without full split-tunnel enabled, still bypass Russian whitelist
		// at DNS level so the VPN doesn't break access to Russian services.
		stm.SetEnabled(true)
	}

	// Pre-resolve Russian bypass domains into /32 IP rules so that native apps
	// which resolve DNS themselves (and hand a bare IP to SOCKS5) are still
	// routed directly. Runs in the background so startup is not blocked.
	go func() {
		resolveCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		n := stm.PreResolveAndCacheIPs(resolveCtx, bypassDNS)
		stdlog.Printf("[split-tunnel] pre-resolved %d Russian bypass IPs", n)
	}()

	socksMod, _ := socks5.New(&socks5.Config{
		ListenAddr:    *socksAddr,
		Debug:         true,
		VPNServerAddr: cfg.Server,
		MTU:           cfg.MTU,
		// Route Russian services directly so they resolve to Russian IPs.
		BypassFunc: stm.ShouldBypass,
		// Drop BitTorrent connections — they reveal the real IP via DHT/PEX
		// and unnecessarily consume VPN bandwidth.
		BlockTorrents: true,
	})
	generateSocksAuth()
	socksMod.SetAuthHandler(socksUser, socksPass)
	stdlog.Printf("SOCKS5 auth enabled (user=%s)", socksUser)
	lc.Register(socksMod)

	dnsMod, _ := dnsmodule.New(&dnsmodule.Config{
		Upstream:       dnsUpstreamAddr,
		CacheEnabled:   true,
		BypassFunc:     stm.ShouldBypassByHostname,
		BypassResolver: bypassDNS, // fixed Russian DNS, never goes through VPN tunnel
	})
	lc.Register(dnsMod)

	// Determine active transport (key overrides flag).
	resolvedTransport := cfg.Transport
	if resolvedTransport == "" {
		resolvedTransport = *transport
	}

	// Pick the best server address for the resolved transport.
	serverAddress := pickServerAddress(cfg, resolvedTransport)
	if serverAddress == "" {
		serverAddress = cfg.Server
	}
	// Ensure port is present; default to 8443.
	if serverAddress != "" {
		if _, _, err := net.SplitHostPort(serverAddress); err != nil {
			serverAddress = net.JoinHostPort(serverAddress, "8443")
		}
	}

	var globalBridgeSel *bridge.Selector
	if cfg.BridgeDiscoveryURL != "" {
		globalBridgeSel = bridge.NewSelectorWithURL(cfg.BridgeDiscoveryURL)
		fetchCtx, fetchCancel := context.WithTimeout(ctx, 10*time.Second)
		if err := globalBridgeSel.FetchBridges(fetchCtx); err != nil {
			stdlog.Printf("Bridge discovery failed (%v) — connecting directly to %s", err, serverAddress)
		} else {
			globalBridgeSel.TestAllBridges(fetchCtx)
			if best := globalBridgeSel.SelectBest(); best != nil {
				stdlog.Printf("Bridge selected: %s (%s, %dms)", best.ID, best.Address, best.Latency)
				serverAddress = best.Address
			} else {
				stdlog.Printf("No reachable bridges — connecting directly to %s", serverAddress)
			}
		}
		fetchCancel()
		globalBridgeSel.StartRefresh(ctx)
	}
	asnBypassEnabled := *asnBypass
	asnBypassFingerprint := *tlsFingerprint
	if cfg.ASNBypass != nil && cfg.ASNBypass.Enabled {
		asnBypassEnabled = true
		if cfg.ASNBypass.TLSFingerprint != "" {
			asnBypassFingerprint = cfg.ASNBypass.TLSFingerprint
		}
	}

	phantomEnabled := false
	phantomSNI := "cloudflare.com"
	phantomShortId := ""
	phantomServerPubKey := "jDwJpsAOm/dizeRNOMyUkoiHzslRkEmSQ/SKvigNtQw="
	var phantomPSK []byte
	chatFSMEnabled := false
	var chatFSMInterval time.Duration

	if cfg.Phantom != nil && cfg.Phantom.Enabled {
		phantomEnabled = true
		if cfg.Phantom.SNI != "" {
			phantomSNI = cfg.Phantom.SNI
		}
		phantomShortId = cfg.Phantom.ShortId
		if cfg.Phantom.ServerPublicKey != "" {
			phantomServerPubKey = cfg.Phantom.ServerPublicKey
		}
		if cfg.Phantom.PSK != "" {
			if pskBytes, err := base64.StdEncoding.DecodeString(cfg.Phantom.PSK); err == nil && len(pskBytes) == 32 {
				phantomPSK = pskBytes
			}
		}
		chatFSMEnabled = cfg.Phantom.EnableChatFSM
		if cfg.Phantom.ChatFSMCoverInterval > 0 {
			chatFSMInterval = time.Duration(cfg.Phantom.ChatFSMCoverInterval) * time.Second
		}
	} else if asnBypassEnabled {
		phantomEnabled = true
		stdlog.Printf("Auto-enabling Phantom protocol for enhanced DPI evasion")
	}

	if *phantomKey != "" {
		phantomServerPubKey = *phantomKey
		if !phantomEnabled {
			phantomEnabled = true
			stdlog.Printf("Force-enabling Phantom protocol due to -phantom-key flag")
		}
	}

	if *russianService != "" {
		cfg.RussianService = *russianService
		stdlog.Printf("Override: Russian Service masquerading enabled: %s", cfg.RussianService)
	}

	// ForceSNI: CLI flag takes priority, then config file.
	activeForceSNI := *forceSNIFlag
	if activeForceSNI == "" {
		activeForceSNI = cfg.ForceSNI
	}
	if activeForceSNI != "" {
		phantomSNI = activeForceSNI
		globalForceSNI.Store(activeForceSNI)
		stdlog.Printf("SNI override active: all connections will use SNI=%q", activeForceSNI)
	}

	// Region selection: CLI > config file > "auto"
	activeRegion := *regionFlag
	if activeRegion == "" {
		activeRegion = cfg.PreferredRegion
	}
	if activeRegion == "" {
		activeRegion = "auto"
	}
	globalRegion.Store(activeRegion)
	if len(cfg.Regions) > 0 {
		cfgRegions = cfg.Regions
	}
	if activeRegion != "auto" {
		stdlog.Printf("Region: %s", activeRegion)
	}

	fallbackTCP := cfg.ServerTCP
	if fallbackTCP == "" {
		fallbackTCP = cfg.Server
	}

	var srvList []string
	if *serverList != "" {
		for _, s := range strings.Split(*serverList, ",") {
			if s = strings.TrimSpace(s); s != "" {
				srvList = append(srvList, s)
			}
		}
	}
	for _, alt := range cfg.ServerAlts {
		if alt = strings.TrimSpace(alt); alt != "" {
			srvList = append(srvList, alt)
		}
	}

	activeTransport := cfg.Transport
	if activeTransport == "" {
		activeTransport = *transport
	}

	var transports []string
	for _, t := range strings.Split(activeTransport, ",") {
		if t = strings.TrimSpace(t); t != "" {
			transports = append(transports, t)
		}
	}
	if len(transports) == 0 {
		transports = []string{"tcp"}
	}
	mrand.Shuffle(len(transports), func(i, j int) {
		transports[i], transports[j] = transports[j], transports[i]
	})

	newTunnelMod := func(tr string) *tunnel.Manager {
		m, _ := tunnel.New(&tunnel.Config{
			ServerAddr:              serverAddress,
			ServerAddrTCP:           fallbackTCP,
			Transport:               tr,
			TransportWhitelist:      cfg.TransportWhitelist,
			TransportBlacklist:      cfg.TransportBlacklist,
			KeepaliveInterval:       30 * time.Second,
			QualityMissedKeepalives: 3,
			EnableASNBypass:         asnBypassEnabled,
			TLSFingerprint:      asnBypassFingerprint,
			EnableJA3Randomize:  true,
			EnablePhantom:       phantomEnabled,
			PhantomSNI:          phantomSNI,
			PhantomShortId:      phantomShortId,
			PhantomServerPubKey: phantomServerPubKey,
			PhantomPSK:          phantomPSK,
			EnableChatFSM:        chatFSMEnabled,
			ChatFSMCoverInterval: chatFSMInterval,
			RussianService:      cfg.RussianService,
			VKToken:             *vkToken,
			ServerList:          srvList,
			RekeyInterval:       *rekeyInterval,
			TransportConfig:     cfg.TransportConfig,
			MLServerURL:         cfg.MLServerURL,
			MLToken:             resolveMLToken(cfg),
			ForceSNI:            getGlobalSNI(),
			Regions:             cfgRegions,
			PreferredRegion:     getGlobalRegion(),
		})
		return m
	}

	var spoofList []string

	buildBaseCfg := func(e *TransportEntry) *tunnel.Config {
		e.mu.Lock()
		tr := e.Transport
		force := e.ForceObfuscation
		profile := e.BehavioralProfile
		customSNI := e.SNI
		noSNI := e.NoSNI
		bridgeAddr := e.Bridge
		rateLimitKB := e.RateLimitKB
		e.mu.Unlock()

		if customSNI == "" {
			customSNI = getGlobalSNI()
		}

		tc := cfg.TransportConfig
		if customSNI != "" && !noSNI {
			tc = make(map[string]interface{})
			for k, v := range cfg.TransportConfig {
				tc[k] = v
			}
			tc["sni"] = customSNI
		}

		return &tunnel.Config{
			ServerAddr:              serverAddress,
			ServerAddrTCP:           fallbackTCP,
			Transport:               tr,
			KeepaliveInterval:       30 * time.Second,
			QualityMissedKeepalives: 3,
			EnableASNBypass:         asnBypassEnabled,
			TLSFingerprint:      asnBypassFingerprint,
			EnableJA3Randomize:  true,
			EnablePhantom:       phantomEnabled,
			PhantomSNI:          phantomSNI,
			PhantomShortId:      phantomShortId,
			PhantomServerPubKey: phantomServerPubKey,
			PhantomPSK:          phantomPSK,
			EnableChatFSM:        chatFSMEnabled,
			ChatFSMCoverInterval: chatFSMInterval,
			RussianService:      cfg.RussianService,
			VKToken:             *vkToken,
			ServerList:          srvList,
			RekeyInterval:       *rekeyInterval,
			TransportConfig:     tc,
			MLServerURL:         cfg.MLServerURL,
			MLToken:             resolveMLToken(cfg),
			ForceObfuscation:    force,
			BehavioralProfile:   profile,
			CustomSNI:           customSNI,
			ForceSNI:            getGlobalSNI(),
			NoSNI:               noSNI,
			Regions:             cfgRegions,
			PreferredRegion:     getGlobalRegion(),
			BridgeAddr:          bridgeAddr,
			RateLimitKB:         rateLimitKB,
			EnableIPSpoof:       len(spoofList) > 0,
			SpoofSourceIPs:      spoofList,
			TLSFragmentSize:     *tlsFragSize,
		}
	}

	restartEntry := func(e *TransportEntry, tunnelCfg *tunnel.Config) {
		e.mu.Lock()
		if e.cancel != nil {
			e.cancel()
		}
		e.Status = connStatusConnecting
		e.Error = ""
		e.mu.Unlock()

		newMgr, err := tunnel.New(tunnelCfg)
		if err != nil {
			stdlog.Printf("restartEntry %s build failed: %v", e.ID, err)
			e.mu.Lock()
			e.Status = connStatusFailed
			e.Error = err.Error()
			e.mu.Unlock()
			return
		}
		newMgr.SetDependencies(nil, hsMod, nil, cryptoMod)
		newMgr.SetObfuscator(obfsMod)
		if tunnelCfg.BehavioralProfile != "" {
			if err := newMgr.SetBehavioralProfile(tunnelCfg.BehavioralProfile); err != nil {
				stdlog.Printf("restartEntry %s: set profile %q: %v", e.ID, tunnelCfg.BehavioralProfile, err)
			}
		}

		newCtx, newCancel := context.WithCancel(ctx)
		e.mu.Lock()
		e.mgr = newMgr
		e.cancel = newCancel
		e.mu.Unlock()

		connStart := time.Now()
		if err := newMgr.Connect(newCtx); err != nil {
			stdlog.Printf("restartEntry %s connect failed: %v", e.ID, err)
			e.mu.Lock()
			e.Status = connStatusFailed
			e.Error = err.Error()
			tr := e.Transport
			e.mu.Unlock()
			if globalAgent != nil {
				globalAgent.ReportResult(proxyagent.ProbeResult{
					Transport: tr,
					Server:    tunnelCfg.ServerAddr,
					Latency:   time.Since(connStart),
					Success:   false,
					Error:     err.Error(),
					Timestamp: time.Now(),
				})
			}
		} else {
			e.mu.Lock()
			e.Status = connStatusConnected
			e.ConnectedAt = time.Now()
			e.mu.Unlock()
			stdlog.Printf("restartEntry %s connected (encap=%v)", e.ID, tunnelCfg.CustomDialFn != nil)
			if globalAgent != nil {
				globalAgent.ReportResult(proxyagent.ProbeResult{
					Transport: tunnelCfg.Transport,
					Server:    tunnelCfg.ServerAddr,
					Latency:   time.Since(connStart),
					Success:   true,
					Timestamp: time.Now(),
				})
			}
		}
	}

	wireEncapsulate := func(e *TransportEntry) {
		e.onEncapsulate = func(outerID string) {
			baseCfg := buildBaseCfg(e)
			var finalCfg *tunnel.Config
			if outerID == "" {
				finalCfg = baseCfg
			} else {
				outer, ok := pool.Get(outerID)
				if !ok {
					stdlog.Printf("encapsulate %s: outer %s not found", e.ID, outerID)
					return
				}
				outer.mu.Lock()
				outerMgr := outer.mgr
				outer.mu.Unlock()
				if outerMgr == nil || !outerMgr.IsConnected() {
					stdlog.Printf("encapsulate %s: outer %s manager not connected", e.ID, outerID)
					return
				}
				finalCfg = tunnel.EncapsulatedConfig(baseCfg, outerMgr)
			}
			restartEntry(e, finalCfg)
		}
	}

	if asnBypassEnabled {
		stdlog.Printf("ASN bypass enabled (fingerprint: %s)", asnBypassFingerprint)
	}
	if phantomEnabled {
		stdlog.Printf("Phantom protocol enabled (SNI: %s)", phantomSNI)
	}

	tunnelMod := newTunnelMod(transports[0])
	tunnelMod.SetDependencies(nil, hsMod, nil, cryptoMod)
	lc.Register(tunnelMod)
	tunnelMod.SetObfuscator(obfsMod)

	multiRouter := socks5.NewMultiRouter(tunnelMod)
	globalMultiRouter = multiRouter
	socksMod.SetTunnel(multiRouter)

	primaryEntry := &TransportEntry{
		ID:               pool.NextID(),
		Transport:        transports[0],
		Server:           serverAddress,
		Enabled:          true,
		Obfuscated:       true,
		ForceObfuscation: true,
		Status:           connStatusConnecting,
		mgr:              tunnelMod,
	}
	pool.Add(primaryEntry)
	wireEncapsulate(primaryEntry)

	extraTunnels := make([]*tunnel.Manager, 0, len(transports)-1)
	for i := 1; i < len(transports); i++ {
		tr := transports[i]
		m := newTunnelMod(tr)
		m.SetDependencies(nil, hsMod, nil, cryptoMod)
		lc.Register(m)
		m.SetObfuscator(obfsMod)

		_, connCancel := context.WithCancel(ctx)
		entry := &TransportEntry{
			ID:               pool.NextID(),
			Transport:        tr,
			Server:           serverAddress,
			Enabled:          true,
			Obfuscated:       true,
			ForceObfuscation: true,
			Status:           connStatusStandby,
			mgr:              m,
			cancel:           connCancel,
		}
		pool.Add(entry)
		wireEncapsulate(entry)
		extraTunnels = append(extraTunnels, m)
	}

	agentCfg := proxyagent.DefaultAgentConfig()
	agentCfg.ExploreRate = 0.1
	agentCfg.FailThreshold = 5
	for _, tr := range transports {
		agentCfg.Candidates = append(agentCfg.Candidates, proxyagent.TransportCandidate{
			Name:     tr,
			Server:   serverAddress,
			Enabled:  true,
			Priority: 1.0,
		})
	}
	knownTransports := map[string]bool{}
	for _, tr := range transports {
		knownTransports[tr] = true
	}
	for _, extra := range []string{"tcp", "udp", "websocket", "grpc", "xhttp", "quic"} {
		if !knownTransports[extra] {
			agentCfg.Candidates = append(agentCfg.Candidates, proxyagent.TransportCandidate{
				Name:     extra,
				Server:   serverAddress,
				Enabled:  false,
				Priority: 0.5,
			})
		}
	}
	globalAgent = proxyagent.NewProxyAgent(agentCfg)
	globalAgent.Start()
	defer globalAgent.Stop()

	controlAddr = "127.0.0.1:" + *controlPort
	adminToken = *adminTokenFlag
	globalDNS = dnsMod

	if *spoofIPs != "" {
		for _, ip := range strings.Split(*spoofIPs, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				spoofList = append(spoofList, ip)
			}
		}
	}
	if len(spoofList) > 0 {
		tunnelMod.SetSpoofIPs(spoofList)
		stdlog.Printf("IP spoofing enabled: %v", spoofList)
	}

	if *enableMITM {
		mitmProxy, err := mitm.New(&mitm.Config{
			ListenAddr: *mitmAddr,
			TunnelDial: tunnelMod.DialStream,
			MetaHook: func(meta mitm.TrafficMeta) {
				if meta.Host != "" {
					tunnelMod.AddRussianSNI(meta.Host)
				}
			},
		})
		if err != nil {
			stdlog.Printf("MITM init failed: %v", err)
		} else {
			if err := mitmProxy.Start(); err != nil {
				stdlog.Printf("MITM start failed: %v", err)
			} else {
				globalMITM = mitmProxy
				stdlog.Printf("MITM proxy started on %s", *mitmAddr)
			}
		}
	}

	reconnectEntry = func(e *TransportEntry) {
		restartEntry(e, buildBaseCfg(e))
	}

	newMultiBridgeTunnel = func(bridgeCtx context.Context, bridgeID, bridgeAddr string, rules []string) {
		m, err := tunnel.New(&tunnel.Config{
			ServerAddr:              bridgeAddr,
			ServerAddrTCP:           bridgeAddr,
			Transport:               transports[0],
			KeepaliveInterval:       30 * time.Second,
			QualityMissedKeepalives: 3,
			EnableASNBypass:         asnBypassEnabled,
			TLSFingerprint:      asnBypassFingerprint,
			EnableJA3Randomize:  true,
			EnablePhantom:       phantomEnabled,
			PhantomSNI:          phantomSNI,
			PhantomShortId:      phantomShortId,
			PhantomServerPubKey: phantomServerPubKey,
			PhantomPSK:          phantomPSK,
			EnableChatFSM:        chatFSMEnabled,
			ChatFSMCoverInterval: chatFSMInterval,
			RussianService:      cfg.RussianService,
			VKToken:             *vkToken,
			RekeyInterval:       *rekeyInterval,
			TransportConfig:     cfg.TransportConfig,
			MLServerURL:         cfg.MLServerURL,
			MLToken:             resolveMLToken(cfg),
			ForceSNI:            getGlobalSNI(),
			Regions:             cfgRegions,
			PreferredRegion:     getGlobalRegion(),
		})
		if err != nil {
			stdlog.Printf("[multi-bridge] build tunnel %s failed: %v", bridgeID, err)
			return
		}
		m.SetDependencies(nil, hsMod, nil, cryptoMod)
		m.SetObfuscator(obfsMod)
		lc.Register(m)

		entry := &TransportEntry{
			ID:               pool.NextID(),
			Transport:        transports[0],
			Server:           bridgeAddr,
			Enabled:          true,
			Obfuscated:       true,
			ForceObfuscation: true,
			Status:           connStatusConnecting,
			mgr:              m,
		}
		pool.Add(entry)

		connCtx, connCancel := context.WithCancel(bridgeCtx)
		entry.mu.Lock()
		entry.cancel = connCancel
		entry.mu.Unlock()

		if err := m.Connect(connCtx); err != nil {
			stdlog.Printf("[multi-bridge] connect %s (%s) failed: %v", bridgeID, bridgeAddr, err)
			entry.mu.Lock()
			entry.Status = connStatusFailed
			entry.Error = err.Error()
			entry.mu.Unlock()
			connCancel()
			return
		}
		entry.mu.Lock()
		entry.Status = connStatusConnected
		entry.ConnectedAt = time.Now()
		entry.mu.Unlock()
		stdlog.Printf("[multi-bridge] bridge %s connected (%s), rules: %v", bridgeID, bridgeAddr, rules)
		if err := multiRouter.AttachBridgeTunnel(bridgeID, m); err != nil {
			stdlog.Printf("[multi-bridge] bridge %s attach error: %v", bridgeID, err)
		}
	}

	// Resolve subscription URL: explicit flag overrides key's sub_url field.
	effectiveSubURL := *subURL
	if effectiveSubURL == "" && cfg != nil {
		effectiveSubURL = cfg.SubscriptionURL
	}
	if effectiveSubURL == "" && *connKey != "" {
		if ck, err := config.ParseConnectionKey(*connKey); err == nil {
			effectiveSubURL = ck.SubscriptionURL
		}
	}

	var globalSubMgr *config.SubscriptionManager
	if effectiveSubURL != "" {
		stdlog.Printf("Subscription URL: %s (refresh every %s)", effectiveSubURL, *subInterval)
		globalSubMgr = config.NewSubscriptionManager(effectiveSubURL, *subInterval, func(keys []*config.ConnectionKey) {
			if len(keys) == 0 {
				return
			}
			best := keys[0]
			stdlog.Printf("Subscription updated: %d keys available, using %q (server=%s)", len(keys), best.Name, best.Server)
			// Update the primary tunnel's server address if it changed.
			if best.Server != "" && best.Server != serverAddress {
				serverAddress = best.Server
				stdlog.Printf("Subscription: server address updated to %s", serverAddress)
			}
		})
		globalSubMgr.Start()
		defer globalSubMgr.Stop()
		globalSubscriptionMgr = globalSubMgr
	}

	startControlServer(ctx)

	if err := lc.Start(); err != nil {
		stdlog.Fatalf("Failed to start: %v", err)
	}

	stdlog.Printf("Connecting to VPN server: %s via %s", serverAddress, transports[0])

	var ks *killswitch.KillSwitch
	if *enableKillSwitch {
		var err error
		ks, err = killswitch.New(&killswitch.Config{
			Enabled:  true,
			AllowLAN: *allowLAN,
			AllowDNS: true,
		})
		if err != nil {
			stdlog.Printf("WARNING: Failed to create kill switch: %v", err)
		}
	}

	if err := tunnelMod.Connect(ctx); err != nil {
		stdlog.Printf("WARNING: Failed to connect to VPN server via %s: %s", transports[0], tunnel.ClassifyConnError(err))
		primaryEntry.mu.Lock()
		primaryEntry.Status = connStatusFailed
		primaryEntry.Error = err.Error()
		primaryEntry.mu.Unlock()

		for i, m := range extraTunnels {
			if pool.AnyConnected() {
				socksMod.SetTunnel(m)
				stdlog.Printf("Switched to transport %s", transports[i+1])
				break
			}
		}
		if !pool.AnyConnected() {
			stdlog.Printf("Running in local proxy mode (traffic NOT encrypted)")
		}
	} else {
		primaryEntry.mu.Lock()
		primaryEntry.Status = connStatusConnected
		primaryEntry.ConnectedAt = time.Now()
		primaryEntry.mu.Unlock()
		stdlog.Printf("Connected to VPN server via %s", transports[0])

		dnsMod.SetDialContext(tunnelMod.DialStream)
		stdlog.Printf("DNS now routed through tunnel")

		if *noInternalTun {
			stdlog.Printf("External TUN mode: Mihomo will handle TUN/routing")
			stdlog.Printf("SOCKS5 proxy ready for Mihomo at %s", *socksAddr)
			if host, _, err := net.SplitHostPort(serverAddress); err == nil {
				vpnServerIP := net.ParseIP(host)
				vpnPort := 8443
				if p, err := net.DefaultResolver.LookupPort(context.Background(), "tcp", "8443"); err == nil {
					vpnPort = p
				}

				if ks != nil && vpnServerIP != nil {
					ks.SetVPNServer(vpnServerIP, vpnPort)
					if err := ks.Enable(); err != nil {
						stdlog.Printf("WARNING: Failed to enable kill switch: %v", err)
					} else {
						stdlog.Printf("Kill Switch ENABLED - traffic blocked except to %s", host)
					}
				}
			}
		} else {
			if host, _, err := net.SplitHostPort(serverAddress); err == nil {
				os.Setenv("WHISPERA_VPN_SERVER", host)
				stdlog.Printf("VPN server IP for routing: %s", host)
			}
			stdlog.Printf("WARNING: Internal HevTunnel support removed. Use --no-tun=true (default) with Mihomo.")
		}
	}

	stdlog.Printf("SOCKS5 proxy listening on %s", *socksAddr)
	log.Println("Obfuscation: FTE + Marionette + ML enabled")

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		var primaryReconnecting int32
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Always check the current manager from the entry, not the
				// initial tunnelMod — restartEntry replaces e.mgr on reconnect.
				primaryEntry.mu.Lock()
				currentMgr := primaryEntry.mgr
				wasConnected := primaryEntry.Status == connStatusConnected
				primaryEntry.mu.Unlock()

				if currentMgr != nil && currentMgr.IsConnected() {
					continue
				}

				isRST := wasConnected && (currentMgr == nil || !currentMgr.IsConnected())
				if isRST {
					primaryEntry.mu.Lock()
					primaryEntry.Status = connStatusRST
					primaryEntry.Error = "connection reset by peer"
					primaryEntry.mu.Unlock()
					stdlog.Printf("Transport watchdog: primary %s got RST", transports[0])
				}

				activated := false
				entries := pool.List()
				for _, e := range entries {
					e.mu.Lock()
					status := e.Status
					mgr := e.mgr
					e.mu.Unlock()

					if status == connStatusConnected && mgr != nil && mgr.IsConnected() && mgr != currentMgr {
						socksMod.SetTunnel(mgr)
						stdlog.Printf("Transport watchdog: switched SOCKS to %s", e.Transport)
						activated = true
						break
					}
				}

				if !activated {
					for _, e := range entries {
						e.mu.Lock()
						status := e.Status
						mgr := e.mgr
						tr := e.Transport
						e.mu.Unlock()

						if status == connStatusStandby && mgr != nil {
							stdlog.Printf("Transport watchdog: activating standby transport %s", tr)
							go func(entry *TransportEntry) {
								entry.mu.Lock()
								entry.Status = connStatusConnecting
								entry.mu.Unlock()
								restartEntry(entry, buildBaseCfg(entry))
								entry.mu.Lock()
								if entry.Status == connStatusConnected && entry.mgr != nil && entry.mgr.IsConnected() {
									socksMod.SetTunnel(entry.mgr)
									stdlog.Printf("Transport watchdog: standby %s now active", entry.Transport)
								}
								entry.mu.Unlock()
							}(e)
							break
						}
					}
				}

				primaryEntry.mu.Lock()
				enabled := primaryEntry.Enabled
				primaryEntry.mu.Unlock()
				if enabled && atomic.CompareAndSwapInt32(&primaryReconnecting, 0, 1) {
					go func() {
						defer atomic.StoreInt32(&primaryReconnecting, 0)
						time.Sleep(2 * time.Second)
						stdlog.Printf("Transport watchdog: reconnecting primary %s...", transports[0])

						targetCfg := buildBaseCfg(primaryEntry)
						if globalBridgeSel != nil && globalBridgeSel.HasBridges() {
							queryCtx, qcancel := context.WithTimeout(ctx, 5*time.Second)
							if master := globalBridgeSel.GetClusterMaster(queryCtx); master != nil && master.MasterAddress != "" {
								targetCfg.ServerAddr = master.MasterAddress
								targetCfg.ServerAddrTCP = master.MasterAddress
							}
							qcancel()
						}

						restartEntry(primaryEntry, targetCfg)
						primaryEntry.mu.Lock()
						if primaryEntry.Status == connStatusConnected && primaryEntry.mgr != nil {
							socksMod.SetTunnel(primaryEntry.mgr)
							stdlog.Printf("Transport watchdog: primary reconnected, SOCKS restored")
						}
						primaryEntry.mu.Unlock()
					}()
				}
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				eng := mlpkg.GetNativeEngine()
				snIs := eng.GetSNIPool()
				allMgrs := []*tunnel.Manager{tunnelMod}
				for _, e := range pool.List() {
					e.mu.Lock()
					m := e.mgr
					e.mu.Unlock()
					if m != nil && m != tunnelMod {
						allMgrs = append(allMgrs, m)
					}
				}
				for _, sni := range snIs {
					for _, m := range allMgrs {
						m.AddRussianSNI(sni)
					}
				}
				if len(snIs) > 0 {
					stdlog.Printf("SNI sync: fed %d Russian SNIs into %d tunnel managers", len(snIs), len(allMgrs))
				}

				dpiType, conf := eng.GetCurrentDPILevel()
				if conf > 0.5 {
					var profile string
					switch {
					case dpiType >= 6:
						profile = "high_threat"
					case dpiType >= 3:
						profile = "telegram"
					default:
						profile = "default"
					}
					for _, m := range allMgrs {
						if m.IsConnected() {
							if err := m.SetBehavioralProfile(profile); err == nil && dpiType >= 3 {
								stdlog.Printf("[ML] DPI type=%d conf=%.2f → obfuscation profile switched to %q", dpiType, conf, profile)
							}
						}
					}
				}
			}
		}
	}()

	// Memory watchdog: force GC if heap grows past 150 MB to stay within the
	// 200 MB soft cap and avoid OOM on memory-constrained mobile devices.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		const heapThreshold = 150 << 20 // 150 MB
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > heapThreshold {
					runtime.GC()
					debug.FreeOSMemory()
					stdlog.Printf("[mem] heap=%dMB — forced GC (threshold %dMB)",
						ms.HeapAlloc>>20, heapThreshold>>20)
				}
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down...")
		lc.Stop()
	}()

	log.Println("Client running. Press Ctrl+C to stop.")
	<-ctx.Done()
}
