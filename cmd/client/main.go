package main

import (
	"context"
	"encoding/base64"
	"flag"
	"io"
	stdlog "log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"whispera/internal/auth"
	"whispera/internal/client/bridge"
	"whispera/internal/core/lifecycle"
	"whispera/internal/logger"

	"whispera/internal/modules/config"
	"whispera/internal/modules/crypto"
	"whispera/internal/modules/dnsmodule"
	"whispera/internal/modules/handshake"
	"whispera/internal/modules/killswitch"
	"whispera/internal/modules/obfuscator"
	"whispera/internal/modules/session"
	"whispera/internal/modules/socks5"
	"whispera/internal/modules/tunnel"
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
)

// mlDefaultDataDir возвращает каталог данных Whispera по тем же правилам, что и ml_api_server.py.
// Windows → %APPDATA%\Whispera
// Linux   → ~/.config/whispera  (или $XDG_CONFIG_HOME/whispera)
// macOS   → ~/Library/Application Support/Whispera
// При запуске рядом с ml_api_server.exe (production) — папка data/ рядом с бинарём.
func mlDefaultDataDir() string {
	// Production: если рядом с нашим бинарём лежит data/api_token — используем его.
	if exe, err := os.Executable(); err == nil {
		exeDir := strings.TrimSuffix(exe, "/"+strings.Split(exe, "/")[len(strings.Split(exe, "/"))-1])
		if fi, err := os.Stat(exeDir + "/data/api_token"); err == nil && !fi.IsDir() {
			return exeDir + "/data"
		}
	}
	// Платформенный каталог конфига — совпадает с _default_data_dir() в ml_api_server.py.
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

// resolveMLToken возвращает API-токен для ml_api_server.
// Приоритет: cfg.MLToken (из connection key / config) → cfg.MLTokenFile → автопоиск по тем же
// путям, что использует ml_api_server.py при сохранении токена.
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
	// Тот же путь, что пишет ml_api_server.py: <data_dir>/api_token
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
	debug.SetGCPercent(200)

	flag.Parse()
	logFile, err := os.OpenFile("whispera-client.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		if null, errNull := os.OpenFile(os.DevNull, os.O_WRONLY, 0666); errNull == nil {
			os.Stdout = null
			os.Stderr = null
		}

		stdlog.SetOutput(logFile)
		logger.SetOutput(logFile)
		log = logger.Module("client")
	} else {
		if null, errNull := os.OpenFile(os.DevNull, os.O_WRONLY, 0666); errNull == nil {
			os.Stdout = null
			os.Stderr = null
		}
	}
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
		cfg, err = config.LoadClient(*configPath)
		if err != nil {
			stdlog.Fatalf("Failed to load config: %v", err)
		}
	} else {
		cfg = &config.ClientConfig{
			Server: *serverAddr,
		}
	}

	if *connKey == "" && *serverAddr != "" {
		cfg.Server = *serverAddr
	}

	// ML server URL/token from CLI flags (override key-parsed values)
	if *mlServerURL != "" {
		cfg.MLServerURL = *mlServerURL
	}
	if *mlTokenFlag != "" {
		cfg.MLToken = *mlTokenFlag
	}

	// ML mode: -user-key sets phantom PSK without requiring a full connection key
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

	socksMod, _ := socks5.New(&socks5.Config{
		ListenAddr:    *socksAddr,
		Debug:         true,
		VPNServerAddr: cfg.Server,
		MTU:           cfg.MTU,
	})
	lc.Register(socksMod)

	dnsMod, _ := dnsmodule.New(&dnsmodule.Config{
		Upstream:     "1.1.1.1:53",
		CacheEnabled: true,
	})
	lc.Register(dnsMod)

	serverAddress := cfg.Server
	if *transport == "tcp" && cfg.ServerTCP != "" {
		serverAddress = cfg.ServerTCP
	}

	// Bridge discovery: if the connection key embeds a discovery URL, fetch the
	// bridge list, pick the fastest reachable one, and use it as the server address.
	if cfg.BridgeDiscoveryURL != "" {
		bridgeSel := bridge.NewSelectorWithURL(cfg.BridgeDiscoveryURL)
		fetchCtx, fetchCancel := context.WithTimeout(ctx, 10*time.Second)
		if err := bridgeSel.FetchBridges(fetchCtx); err != nil {
			stdlog.Printf("Bridge discovery failed (%v) — connecting directly to %s", err, serverAddress)
		} else {
			bridgeSel.TestAllBridges(fetchCtx)
			if best := bridgeSel.SelectBest(); best != nil {
				stdlog.Printf("Bridge selected: %s (%s, %dms)", best.ID, best.Address, best.Latency)
				serverAddress = best.Address
			} else {
				stdlog.Printf("No reachable bridges — connecting directly to %s", serverAddress)
			}
		}
		fetchCancel()
		// Start background refresh so newly registered bridges are discovered automatically
		bridgeSel.StartRefresh(ctx)
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

	// Use transport from key if present, else fall back to -transport flag
	activeTransport := cfg.Transport
	if activeTransport == "" {
		activeTransport = *transport
	}

	tunnelMod, _ := tunnel.New(&tunnel.Config{
		ServerAddr:          serverAddress,
		ServerAddrTCP:       fallbackTCP,
		Transport:           activeTransport,
		KeepaliveInterval:   30 * time.Second,
		EnableASNBypass:     asnBypassEnabled,
		TLSFingerprint:      asnBypassFingerprint,
		EnableJA3Randomize:  true,
		EnablePhantom:       phantomEnabled,
		PhantomSNI:          phantomSNI,
		PhantomShortId:      phantomShortId,
		PhantomServerPubKey: phantomServerPubKey,
		PhantomPSK:          phantomPSK,
		RussianService:      cfg.RussianService,
		VKToken:             *vkToken,
		ServerList:          srvList,
		RekeyInterval:       *rekeyInterval,
		TransportConfig:     cfg.TransportConfig,
		MLServerURL:         cfg.MLServerURL,
		MLToken:             resolveMLToken(cfg),
	})

	if asnBypassEnabled {
		stdlog.Printf("ASN bypass enabled (fingerprint: %s)", asnBypassFingerprint)
	}
	if phantomEnabled {
		stdlog.Printf("Phantom protocol enabled (SNI: %s)", phantomSNI)
	}

	tunnelMod.SetDependencies(nil, hsMod, nil, cryptoMod)
	lc.Register(tunnelMod)

	tunnelMod.SetObfuscator(obfsMod)

	socksMod.SetTunnel(tunnelMod)

	if err := lc.Start(); err != nil {
		stdlog.Fatalf("Failed to start: %v", err)
	}

	stdlog.Printf("Connecting to VPN server: %s", serverAddress)

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
		stdlog.Printf("WARNING: Failed to connect to VPN server: %v", err)
		stdlog.Printf("Running in local proxy mode (traffic NOT encrypted)")
		stdlog.Printf("HevTunnel NOT started to prevent routing loop")
	} else {
		stdlog.Printf("Connected to VPN server successfully")

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
