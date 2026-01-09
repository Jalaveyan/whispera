// Package main is the entry point for the Whispera modular client
package main

import (
	"flag"
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
	"whispera/internal/modules/obfuscator"
	"whispera/internal/modules/session"
	"whispera/internal/modules/socks5"
	"whispera/internal/modules/tunnel"
)

// log is the module logger
var log = logger.Module("client")

var Version = "2.0.0"

var (
	configPath = flag.String("config", "", "Path to configuration file")
	serverAddr = flag.String("server", "144.124.225.252:8443", "Server address (host:port)")
	socksAddr  = flag.String("socks", "127.0.0.1:10800", "SOCKS5 listen address for hev-socks5-tunnel")
	connKey    = flag.String("key", "", "Connection key (whispera://...)")
	transport  = flag.String("transport", "auto", "Transport mode: auto|tcp|udp")
	obfsLevel  = flag.Int("obfs-level", 5, "Obfuscation threat level (0-10)")
)

func main() {
	flag.Parse()

	// Load config from various sources
	var cfg *config.ClientConfig
	var err error

	// Priority: connection key > config file > command line flags
	if *connKey != "" {
		// Parse connection key
		key, err := config.ParseConnectionKey(*connKey)
		if err != nil {
			log.Fatalf("Failed to parse connection key: %v", err)
		}
		cfg = key.ToClientConfig()
		log.Printf("Loaded config from key: %s", key.Name)
		log.Printf("Server: %s (transport: %s, obfuscation: %s)", key.GetPrimaryServer(), key.Transport, key.ObfsPreset)
	} else if *configPath != "" {
		cfg, err = config.LoadClient(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
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
		log.Fatalf("No server address specified. Use -server, -key, or -config")
	}

	log.Printf("Starting Whispera Client v%s", Version)
	log.Printf("Server: %s", cfg.Server)
	if cfg.ServerTCP != "" {
		log.Printf("TCP Fallback: %s", cfg.ServerTCP)
	}
	if cfg.ObfsPreset != "" {
		log.Printf("Obfuscation: %s", cfg.ObfsPreset)
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
		ListenAddr: *socksAddr,
		Debug:      true,
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

	tunnelMod, _ := tunnel.New(&tunnel.Config{
		ServerAddr:        serverAddress,
		KeepaliveInterval: 30 * time.Second,
	})
	// Inject dependencies: Transport(nil/SOCKS), Handshake, DataPlane(nil), Crypto
	tunnelMod.SetDependencies(nil, hsMod, nil, cryptoMod)
	lc.Register(tunnelMod)

	// Wire obfuscation to tunnel for encrypted traffic masking
	tunnelMod.SetObfuscator(obfsMod)

	// Wire tunnel to SOCKS5 for encrypted relay
	socksMod.SetTunnel(tunnelMod)

	// Start
	if err := lc.Start(); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	// Connect tunnel to VPN server
	log.Printf("Connecting to VPN server: %s", serverAddress)
	if err := tunnelMod.Connect(ctx); err != nil {
		log.Printf("WARNING: Failed to connect to VPN server: %v", err)
		log.Printf("Running in local proxy mode (traffic NOT encrypted)")
		log.Printf("HevTunnel NOT started to prevent routing loop")
	} else {
		log.Printf("Connected to VPN server successfully")

		// Set VPN server IP for route configuration
		// This ensures the VPN server traffic doesn't go through TUN (avoiding loop)
		if host, _, err := net.SplitHostPort(serverAddress); err == nil {
			os.Setenv("WHISPERA_VPN_SERVER", host)
			log.Printf("VPN server IP for routing: %s", host)
		}

		// Start HevTunnel now that tunnel is connected
		// All traffic will now go through the encrypted tunnel
		if err := socksMod.StartHevTunnel(); err != nil {
			log.Printf("WARNING: Failed to start HevTunnel: %v", err)
		} else {
			log.Printf("HevTunnel started - all traffic routed through VPN")
		}
	}

	log.Printf("SOCKS5 proxy listening on %s", *socksAddr)
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
