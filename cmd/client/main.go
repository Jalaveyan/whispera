// Package main is the entry point for the Whispera modular client
package main

import (
	"flag"
	"io"
	stdlog "log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"whispera/internal/core/lifecycle"
	"whispera/internal/logger"

	// Modules
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

// log is the module logger
var log = logger.Module("client")

var Version = "2.0.0"

var (
	configPath       = flag.String("config", "", "Path to configuration file")
	serverAddr       = flag.String("server", "212.192.246.108:8443", "Server address (host:port)")
	socksAddr        = flag.String("socks", "127.0.0.1:10800", "SOCKS5 listen address for hev-socks5-tunnel")
	connKey          = flag.String("key", "", "Connection key (whispera://...)")
	transport        = flag.String("transport", "udp", "Transport mode: auto|tcp|udp")
	obfsLevel        = flag.Int("obfs-level", 5, "Obfuscation threat level (0-10)")
	asnBypass        = flag.Bool("asn-bypass", false, "Enable ASN bypass for VPN/datacenter IP evasion")
	tlsFingerprint   = flag.String("tls-fingerprint", "chrome", "TLS fingerprint for ASN bypass: chrome, firefox, safari, ios, android")
	enableKillSwitch = flag.Bool("kill-switch", false, "Enable kill switch to prevent traffic leaks")
	allowLAN         = flag.Bool("allow-lan", true, "Allow LAN traffic when kill switch is enabled")
	phantomKey       = flag.String("phantom-key", "", "Phantom Server Public Key (hex) for REALITY authentication")
	noInternalTun    = flag.Bool("no-tun", true, "Disable internal TUN (use external like Mihomo)")
)

func main() {
	flag.Parse()

	// Setup file loggingc:\Users\art\AppData\Local\Packages\MicrosoftWindows.Client.Core_cw5n1h2txyewy\TempState\ScreenClip\{1238D042-C415-40B7-BD41-94AB3E3105CA}.png
	logFile, err := os.OpenFile("whispera-client.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		// Write to both file and stdout
		multiWriter := io.MultiWriter(os.Stdout, logFile)
		stdlog.SetOutput(multiWriter)
		defer logFile.Close()
	}
	stdlog.Printf("Whispera Client v%s starting...", Version)

	// Load config from various sources
	var cfg *config.ClientConfig

	// Priority: connection key > config file > command line flags
	if *connKey != "" {
		// Parse connection key
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

	// Override with command line flags ONLY if no connection key was provided
	// (because -server has a default value that would always override the key)
	if *connKey == "" && *serverAddr != "" {
		cfg.Server = *serverAddr
	}

	// Validate server address
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

	// Lifecycle manager
	lc := lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 30 * time.Second,
		GracefulStop:    true,
	})

	ctx := lc.Context()

	// Create and register modules
	cryptoMod, _ := crypto.New(nil)
	lc.Register(cryptoMod)

	// Obfuscator with full stack: FTE + Marionette + ML
	obfsProfile := cfg.ObfsPreset
	if obfsProfile == "" {
		obfsProfile = "default"
	}
	obfsMod, _ := obfuscator.New(&obfuscator.Config{
		DefaultProfile: obfsProfile,
		ThreatLevel:    *obfsLevel,
		// DPI evasion (protocol masking)
		EnableML:  true, // ML-based pattern detection
		EnableFTE: true, // Format-Transforming Encryption
		// Anti-reputation evasion (edge-node filtering bypass)
		EnableJitter:             true, // Human-like timing randomization
		EnableResidentialMimicry: true, // Mimic residential connection patterns
		ConnectionBurstLimit:     8,    // Limit connection bursts
		JitterMinMs:              30,   // 30-200ms human-like delays
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
	lc.Register(hsMod)

	// SOCKS5 Server for HevTunnel (replaces internal TUN)
	socksMod, _ := socks5.New(&socks5.Config{
		ListenAddr:    *socksAddr,
		Debug:         true,
		VPNServerAddr: cfg.Server, // Pass VPN server address for routing
		MTU:           cfg.MTU,
	})
	lc.Register(socksMod)

	dnsMod, _ := dnsmodule.New(&dnsmodule.Config{
		Upstream:     "1.1.1.1:53",
		CacheEnabled: true,
	})
	lc.Register(dnsMod)

	// Determine primary server based on transport preference
	serverAddress := cfg.Server
	if *transport == "tcp" && cfg.ServerTCP != "" {
		serverAddress = cfg.ServerTCP
	}

	// Configure ASN bypass (for VPN/datacenter IP evasion)
	asnBypassEnabled := *asnBypass
	asnBypassFingerprint := *tlsFingerprint
	if cfg.ASNBypass != nil && cfg.ASNBypass.Enabled {
		asnBypassEnabled = true
		if cfg.ASNBypass.TLSFingerprint != "" {
			asnBypassFingerprint = cfg.ASNBypass.TLSFingerprint
		}
	}

	// Configure Phantom protocol (SNI masquerading for DPI evasion)
	phantomEnabled := false
	phantomSNI := "cloudflare.com" // Default SNI
	phantomShortId := ""
	// Default Public Key corresponding to the static Private Key in server config
	phantomServerPubKey := "8c3c09a6c00e9bf762cc44d38c94912887cec1951904992243f48abe20fa3506"

	if cfg.Phantom != nil && cfg.Phantom.Enabled {
		phantomEnabled = true
		if cfg.Phantom.SNI != "" {
			phantomSNI = cfg.Phantom.SNI
		}
		phantomShortId = cfg.Phantom.ShortId
		phantomServerPubKey = cfg.Phantom.ServerPublicKey
	} else if asnBypassEnabled {
		// Auto-enable Phantom when ASN bypass is enabled for better DPI evasion
		phantomEnabled = true
		stdlog.Printf("Auto-enabling Phantom protocol for enhanced DPI evasion")
	}

	// Override with flag if provided
	if *phantomKey != "" {
		phantomServerPubKey = *phantomKey
		if !phantomEnabled {
			phantomEnabled = true
			stdlog.Printf("Force-enabling Phantom protocol due to -phantom-key flag")
		}
	}

	// Calculate fallback TCP address
	fallbackTCP := cfg.ServerTCP
	if fallbackTCP == "" {
		fallbackTCP = cfg.Server // Assume same address supports TCP
	}

	tunnelMod, _ := tunnel.New(&tunnel.Config{
		ServerAddr:        serverAddress,
		ServerAddrTCP:     fallbackTCP,
		KeepaliveInterval: 30 * time.Second,
		// ASN Bypass settings
		EnableASNBypass:    asnBypassEnabled,
		TLSFingerprint:     asnBypassFingerprint,
		EnableJA3Randomize: true,
		// Phantom Protocol settings
		EnablePhantom:       phantomEnabled,
		PhantomSNI:          phantomSNI,
		PhantomShortId:      phantomShortId,
		PhantomServerPubKey: phantomServerPubKey,
	})

	if asnBypassEnabled {
		stdlog.Printf("ASN bypass enabled (fingerprint: %s)", asnBypassFingerprint)
	}
	if phantomEnabled {
		stdlog.Printf("Phantom protocol enabled (SNI: %s)", phantomSNI)
	}

	// Inject dependencies: Transport(nil/SOCKS), Handshake, DataPlane(nil), Crypto
	tunnelMod.SetDependencies(nil, hsMod, nil, cryptoMod)
	lc.Register(tunnelMod)

	// Wire obfuscation to tunnel for encrypted traffic masking
	tunnelMod.SetObfuscator(obfsMod)

	// Wire tunnel to SOCKS5 for encrypted relay
	socksMod.SetTunnel(tunnelMod)

	// Start
	if err := lc.Start(); err != nil {
		stdlog.Fatalf("Failed to start: %v", err)
	}

	// Connect tunnel to VPN server
	stdlog.Printf("Connecting to VPN server: %s", serverAddress)

	// Create Kill Switch manager (but don't activate yet)
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

		// Skip internal TUN management if using external TUN (e.g., Mihomo)
		if *noInternalTun {
			stdlog.Printf("External TUN mode: Mihomo will handle TUN/routing")
			stdlog.Printf("SOCKS5 proxy ready for Mihomo at %s", *socksAddr)
		} else {
			// Set VPN server IP for route configuration
			// This ensures the VPN server traffic doesn't go through TUN (avoiding loop)
			var vpnServerIP net.IP
			var vpnPort int = 8443
			if host, portStr, err := net.SplitHostPort(serverAddress); err == nil {
				os.Setenv("WHISPERA_VPN_SERVER", host)
				stdlog.Printf("VPN server IP for routing: %s", host)
				vpnServerIP = net.ParseIP(host)
				if p, _ := net.LookupPort("udp", portStr); p > 0 {
					vpnPort = p
				}
			}

			// Start HevTunnel now that tunnel is connected
			// All traffic will now go through the encrypted tunnel
			if err := socksMod.StartHevTunnel(); err != nil {
				stdlog.Printf("WARNING: Failed to start HevTunnel: %v", err)
			} else {
				stdlog.Printf("HevTunnel started - all traffic routed through VPN")

				// Activate Kill Switch AFTER HevTunnel is running
				// This ensures VPN traffic is allowed before blocking other traffic
				if ks != nil && vpnServerIP != nil {
					ks.SetVPNServer(vpnServerIP, vpnPort)
					if err := ks.Enable(); err != nil {
						stdlog.Printf("WARNING: Failed to enable kill switch: %v", err)
					} else {
						stdlog.Printf("Kill Switch ENABLED - traffic will NOT leak if VPN drops")
					}
				}
			}
		}
	}

	stdlog.Printf("SOCKS5 proxy listening on %s", *socksAddr)
	log.Println("Obfuscation: FTE + Marionette + ML enabled")

	// Handle signals
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
