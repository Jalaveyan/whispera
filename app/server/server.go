package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	rtdebug "runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"whispera/app/commands"
	"whispera/app/db"
	"whispera/common/log"
	"whispera/common/runtime/base"
	"whispera/common/runtime/events"
	"whispera/common/runtime/interfaces"
	"whispera/common/runtime/lifecycle"
	"whispera/common/stats"
	"whispera/common/update"
	"whispera/core/apiserver"
	"whispera/core/config"
	"whispera/core/crypto"
	"whispera/core/dataplane"
	"whispera/core/handshake"
	"whispera/core/keylimits"
	server "whispera/core/manager"
	"whispera/core/mlserver"
	"whispera/core/probedetector"
	protocol2 "whispera/core/protocol"
	relay2 "whispera/core/relay"
	"whispera/core/router"
	"whispera/core/session"
	"whispera/core/transport/grpc"
	"whispera/core/transport/tcp"
	"whispera/core/transport/udp"
	"whispera/core/transport/yadisk"
	"whispera/neural"
	"whispera/neural/evasion"

	_ "go.uber.org/automaxprocs"
	"golang.org/x/crypto/curve25519"
)

var log = logger.Module("server")

const (
	whisperaCertPath     = "/etc/whispera/whispera.crt"
	whisperaKeyPath      = "/etc/whispera/whispera.key"
	whisperaDecoyCertDir = "/etc/whispera/decoy_certs"
)

var (
	Version   = "2.1.6"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

type prependConn struct {
	net.Conn
	prepend []byte
}

func (c *prependConn) Read(b []byte) (int, error) {
	if len(c.prepend) > 0 {
		n := copy(b, c.prepend)
		c.prepend = c.prepend[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

var globalProbeDetector *probedetector.Detector

func defaultRouteIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "00000000" {
			return f[0]
		}
	}
	return ""
}

var (
	configFile     = flag.String("config", "", "Path to configuration file")
	listenAddr     = flag.String("listen", "", "UDP/TCP listen address (default from config)")
	apiAddr        = flag.String("api", ":8080", "API server listen address")
	debug          = flag.Bool("debug", false, "Enable debug logging")
	printVersion   = flag.Bool("version", false, "Print version and exit")
	validateConfig = flag.Bool("validate-config", false, "Validate configuration and exit")
	pprofAddr      = flag.String("pprof", "localhost:6060", "Pprof server listen address")
)

var globalKeyLimits = keylimits.New(keylimits.Limits{
	MaxActiveSessions: 10,
	GlobalCap:         10000,
	SoftIPCap:         50,
	BurstPerMinute:    0,
	SessionTTL:        30 * time.Minute,
})

var (
	globalHandshake    *handshake.Handler
	globalDataPlane    *dataplane.Processor
	globalSessionMgr   *session.Manager
	globalUDPTransport *udp.Transport
	globalRelay        *relay2.Server
	globalObfuscator   interfaces.ObfuscationProcessor

	globalServerConfig *config.ServerConfig
	globalRouter       *router.Engine
	globalCorrelation  *evasion.CorrelationDefense
	globalUpdater      *update.Updater

	activeListeners = make(map[string]net.Listener)
	listenersMutex  sync.RWMutex

	portH2CChans   = make(map[string]chan net.Conn)
	portH2CChansMu sync.Mutex
)

var udpIPRate struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	lastClean time.Time
}

func init() {
	udpIPRate.seen = make(map[string]time.Time)
	udpIPRate.lastClean = time.Now()
}

func udpIPRateAllow(addr net.Addr) bool {
	ip := addr.String()
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}

	udpIPRate.mu.Lock()
	defer udpIPRate.mu.Unlock()

	now := time.Now()
	if now.Sub(udpIPRate.lastClean) > time.Minute {
		for k, v := range udpIPRate.seen {
			if now.Sub(v) > 5*time.Second {
				delete(udpIPRate.seen, k)
			}
		}
		udpIPRate.lastClean = now
	}

	if last, ok := udpIPRate.seen[ip]; ok && now.Sub(last) < 200*time.Millisecond {
		return false
	}
	udpIPRate.seen[ip] = now
	return true
}

func StartInbound(inbound config.InboundConfig, serverConfig *config.ServerConfig) error {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()
	if _, exists := activeListeners[inbound.Tag]; exists {
		return fmt.Errorf("inbound %s already running", inbound.Tag)
	}

	listenAddr := fmt.Sprintf("%s:%d", inbound.Listen, inbound.Port)

	if serverConfig.Whispera.Enabled {
		if _, chmPort, err := net.SplitHostPort(serverConfig.Whispera.ListenAddr); err == nil && chmPort != "" && strconv.Itoa(inbound.Port) == chmPort {
			return nil
		}
	}

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}

	activeListeners[inbound.Tag] = listener

	go func() {
		defer func() {
			listenersMutex.Lock()
			delete(activeListeners, inbound.Tag)
			listenersMutex.Unlock()
		}()

		for {
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				continue
			}

			var peek [3]byte
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _ := io.ReadFull(conn, peek[:])
			conn.SetReadDeadline(time.Time{})

			pConn := &prependConn{Conn: conn, prepend: peek[:n]}

			portH2CChansMu.Lock()
			h2cCh, hasH2C := portH2CChans[listenAddr]
			portH2CChansMu.Unlock()

			if hasH2C && n == 3 && peek[0] == 'P' && peek[1] == 'R' && peek[2] == 'I' {
				select {
				case h2cCh <- pConn:
				default:
					pConn.Close()
				}
				continue
			}

			release, ok := acquireConnSlot(conn.RemoteAddr())
			if !ok {
				pConn.Close()
				continue
			}
			go func() {
				defer release()
				handleTCPConnection(pConn, globalHandshake)
			}()
		}
	}()

	return nil
}

func StopInbound(tag string) error {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()

	listener, exists := activeListeners[tag]
	if !exists {
		return fmt.Errorf("inbound %s not running", tag)
	}

	if err := listener.Close(); err != nil {
		return fmt.Errorf("failed to close listener %s: %w", tag, err)
	}

	delete(activeListeners, tag)
	return nil
}

func StartReverseInbound(inbound config.InboundConfig, stopCh <-chan struct{}) {
	remoteAddr := inbound.RemoteAddr

	if remoteAddr == "" {
		return
	}

	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		conn, err := (&net.Dialer{Timeout: 1 * time.Second}).DialContext(context.Background(), "tcp", remoteAddr)

		if err != nil {
			select {
			case <-stopCh:
				return
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}

		backoff = 2 * time.Second

		if globalRelay != nil {
			if globalHandshake != nil {
				handleTCPConnection(conn, globalHandshake)
			} else {
				globalRelay.ServeTunnel(stats.WrapConn(conn, conn.RemoteAddr().String()), false)
			}
		} else {
			conn.Close()
		}
	}
}

func acceptBackoff(d *time.Duration) {
	time.Sleep(*d)
	if *d < time.Second {
		*d *= 2
	}
}

func main() {
	if len(os.Args) > 1 {
		switch strings.TrimSpace(os.Args[1]) {
		case "x25519":
			commands.RunX25519Cmd()
		case "pubkey":
			commands.RunPubkeyCmd()
		case "create-admin":
			commands.RunCreateAdminCmd()
		case "create-key":
			commands.RunCreateKeyCmd()
		case "gen-decoy-cert":
			commands.RunGenDecoyCertCmd()
		case "generate-sub":
			commands.RunGenerateSubCmd()
		case "view-keys":
			commands.RunViewKeysCmd()
		case "hash-password":
			commands.RunHashPasswordCmd()
		case "update-checksum":
			commands.RunUpdateChecksumCmd()
		}
	}

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[PANIC] Whispera Server: %v\n", r)
			os.Exit(2)
		}
	}()

	flag.Parse()

	if *configFile == "" {
		*configFile = "config.yaml"
	}

	runtime.SetBlockProfileRate(10000)
	runtime.SetMutexProfileFraction(100)

	go func() {
		if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
		}
	}()

	if *debug {
		log.SetLevel(logger.LevelDebug)
	}

	if *printVersion {
		os.Exit(0)
	}

	manager := lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 30_000_000_000,
		GracefulStop:    true,
	})

	memWatchdog := base.NewMemoryWatchdog(512, 1024, 30*time.Second)
	memWatchdog.Start()
	manager.OnShutdown(func() { memWatchdog.Stop() })

	moduleCtx, moduleCancel := context.WithCancel(context.Background())
	manager.OnShutdown(moduleCancel)

	if err := createModules(manager, moduleCtx); err != nil {
		log.Fatalf("Failed to create modules: %v", err)
	}

	if globalServerConfig != nil && globalServerConfig.NATS.Enabled && globalServerConfig.NATS.URL != "" {
		prefix := globalServerConfig.NATS.Prefix
		if prefix == "" {
			prefix = "whispera"
		}
		if natsBus, err := events.NewNATSEventBus(globalServerConfig.NATS.URL, prefix); err == nil {
			manager.Registry().SetEventBus(natsBus)
		}
	}

	if *validateConfig {
		os.Exit(0)
	}
	manager.OnStop(func() error {
		if eng := neural.GetNativeEngine(); eng != nil {
			eng.Close()
		}
		return nil
	})

	if err := manager.Run(); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

func createModules(manager *lifecycle.Manager, ctx context.Context) error {
	configProvider, err := config.New(*configFile)
	if err != nil {
		return err
	}
	if err := manager.Register(configProvider); err != nil {
		return err
	}

	var serverConfig *config.ServerConfig
	if *configFile != "" {
		_ = configProvider.Load(*configFile)
		serverConfig = configProvider.GetConfig()
	} else {
		serverConfig = config.DefaultServerConfig()
	}
	globalServerConfig = serverConfig

	if !*debug && serverConfig.Logging.Level != "" {
		log.SetLevel(logger.ParseLevel(serverConfig.Logging.Level))
	}

	if serverConfig.API.AuthToken == "" && *configFile != "" {
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err == nil {
			newToken := base64.StdEncoding.EncodeToString(tokenBytes)
			if err := configProvider.Update(func(c *config.ServerConfig) {
				c.API.AuthToken = newToken
			}); err == nil {
				serverConfig = configProvider.GetConfig()
				globalServerConfig = serverConfig
			}
		}
	}

	if serverConfig.API.AdminUsername == "admin" && serverConfig.API.AdminPassword == "admin" {
		fmt.Println("The default login and username are not secure and need to be changed:")
	}

	if serverConfig.Database.PostgresURL != "" {
		dbCfg := db.DefaultConfig()
		dbCfg.URL = serverConfig.Database.PostgresURL
		if serverConfig.Database.MaxConns > 0 {
			dbCfg.MaxConns = int32(serverConfig.Database.MaxConns)
		}
		if serverConfig.Database.MinConns > 0 {
			dbCfg.MinConns = int32(serverConfig.Database.MinConns)
		}

		database, err := db.New(dbCfg)
		if err != nil {
			return err
		}
		db.SetGlobal(database)
	}
	server.Global.SetCallbacks(
		func(inbound config.InboundConfig) error {
			if inbound.Mode == "reverse" {
				go StartReverseInbound(inbound, ctx.Done())
				return nil
			}
			return StartInbound(inbound, serverConfig)
		},
		func(tag string) error {
			return StopInbound(tag)
		},
	)

	if *listenAddr != "" {
		serverConfig.Transport.UDP.ListenAddr = *listenAddr
		serverConfig.Server.ListenAddr = *listenAddr
	}
	if *apiAddr != "" {
		serverConfig.API.ListenAddr = *apiAddr
	}

	if err := initCore(manager, serverConfig); err != nil {
		return err
	}
	if err := initTransports(manager, serverConfig, ctx, configProvider); err != nil {
		return err
	}

	return initOptional(manager, serverConfig, ctx)
}

func initCore(m *lifecycle.Manager, sc *config.ServerConfig) error {
	cryptoProvider, err := crypto.New(&crypto.Config{
		DefaultCipher: crypto.CipherChaCha20Poly1305,
		EnableKeyPool: true,
		KeyPoolSize:   100,
	})
	if err != nil {
		return err
	}
	if err := m.Register(cryptoProvider); err != nil {
		return err
	}

	sessionMgr, err := session.New(&session.Config{
		MaxSessions:     sc.Session.MaxSessions,
		SessionTimeout:  sc.Session.SessionTimeout.D(),
		CleanupInterval: sc.Session.CleanupInterval.D(),
	})
	if err != nil {
		return err
	}
	globalSessionMgr = sessionMgr
	if err := m.Register(sessionMgr); err != nil {
		return err
	}

	routerEngine, err := router.New(&router.Config{
		MaxRules:    1000,
		EnableCache: true,
		CacheSize:   10000,
	})
	if err != nil {
		return err
	}
	globalRouter = routerEngine
	if err := m.Register(routerEngine); err != nil {
		return err
	}

	if geo := sc.Routing.Geo; geo.Enabled {
		dir := "/var/lib/whispera/geo"
		if geo.GeoIPFile != "" {
			_ = routerEngine.LoadGeoIPFile(geo.GeoIPFile)
		} else if geo.GeoSiteFile != "" {
			_ = routerEngine.LoadGeoSiteFile(geo.GeoSiteFile)
		} else {
			_ = routerEngine.LoadGeoData(dir)
		}
	}

	handshakeHandler, err := handshake.New(&handshake.Config{
		RateLimit:        100,
		RateBurst:        50,
		Timeout:          sc.Session.SessionTimeout.D(),
		MaxPending:       1000,
		EnableAntiReplay: true,
	})
	if err != nil {
		return err
	}
	handshakeHandler.SetDependencies(cryptoProvider, sessionMgr)

	if sc.Server.PrivateKey != "" {
		var privateKey []byte
		privateKey, err = base64.StdEncoding.DecodeString(sc.Server.PrivateKey)
		if err != nil {
			log.Fatalf("Invalid private key in config: %v (only Base64)", err)
		}
		if len(privateKey) != 32 {
			log.Fatalf("Private key only 32 bytes (Base64)")
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			log.Fatalf("Failed to derive public key: %v", err)
		}
		handshakeHandler.SetStaticKeys(publicKey, privateKey)
	}
	globalHandshake = handshakeHandler
	if err := m.Register(handshakeHandler); err != nil {
		return err
	}

	dataPlaneProcessor, err := dataplane.New(&dataplane.Config{
		MTU:                 sc.Server.MTU,
		WorkerCount:         sc.Server.Workers,
		BufferSize:          4096,
		EnableNAT:           true,
		EnableFragmentation: true,
	})
	if err != nil {
		return err
	}
	globalDataPlane = dataPlaneProcessor
	if err := m.Register(dataPlaneProcessor); err != nil {
		return err
	}

	return nil
}

func initTransports(m *lifecycle.Manager, sc *config.ServerConfig, ctx context.Context, cfgProvider *config.Provider) error {
	udpTransport, err := udp.New(&udp.Config{
		ListenAddr:    sc.Transport.UDP.ListenAddr,
		MaxPacketSize: sc.Transport.UDP.MaxPacketSize,
		WorkerCount:   sc.Transport.UDP.Workers,
		BufferSize:    sc.Transport.UDP.BufferSize,
	})
	if err != nil {
		return err
	}
	udpTransport.OnPacket(handlePacket)
	globalUDPTransport = udpTransport
	if err := m.Register(udpTransport); err != nil {
		return err
	}

	relayServer, err := relay2.New(&relay2.Config{
		MaxStreams:     sc.Relay.MaxStreams,
		EnableTCP:      sc.Relay.EnableTCP,
		EnableUDP:      sc.Relay.EnableUDP,
		Debug:          sc.Relay.Debug || *debug,
		UpstreamProxy:  sc.Relay.UpstreamProxy,
		PaddingMaxSize: sc.Obfuscation.Padding.MaxSize,
	})
	if err != nil {
		return err
	}

	relayServer.SetTransport(func(data []byte, addr net.Addr) error {
		payload := data
		if globalObfuscator != nil {
			obfuscated, _, err := globalObfuscator.Process(data, interfaces.DirectionOutbound)
			if err != nil {
				return fmt.Errorf("failed to obfuscate relay frame: %w", err)
			}
			payload = obfuscated
			if *debug {
				fmt.Printf("[Relay] Obfuscated response %d -> %d bytes for %v\n", len(data), len(payload), addr)
			}
		}
		if globalUDPTransport != nil {
			_, err := globalUDPTransport.WriteTo(payload, addr)
			return err
		}
		return nil
	})

	relayServer.SetRawPacketHandler(func(data []byte) error {
		if globalDataPlane != nil {
			return globalDataPlane.InjectPacket(data)
		}
		return fmt.Errorf("dataplane not available")
	})

	globalRelay = relayServer
	relayServer.SetRouter(globalRouter)

	if om := globalDataPlane.GetOutboundManager(); om != nil {
		relayServer.SetOutboundDial(om.Dial)
		om.UpdateOutbounds(sc.Outbounds)
		outboundsCh := cfgProvider.Watch("outbounds")
		go func() {
			for val := range outboundsCh {
				if outbounds, ok := val.([]config.OutboundConfig); ok {
					om.UpdateOutbounds(outbounds)
				}
			}
		}()
	}

	if err := m.Register(relayServer); err != nil {
		return err
	}

	if len(sc.Inbounds) > 0 {
		for _, inbound := range sc.Inbounds {
			if inbound.Mode == "reverse" {
				ib := inbound
				go StartReverseInbound(ib, ctx.Done())
				continue
			}
			if inbound.Port == 0 {
				continue
			}
			if err := StartInbound(inbound, sc); err != nil {
			}
		}
	} else {
		if sc.Transport.TCP.Enabled {
			tcpTransport, err := tcp.New(&tcp.Config{
				ListenAddr:   sc.Transport.TCP.ListenAddr,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				KeepAlive:    30 * time.Second,
				MaxConns:     10000,
				BufferSize:   32 * 1024,
			})
			if err != nil {
				return err
			}
			if err := m.Register(tcpTransport); err != nil {
				return err
			}
			go func() {
				time.Sleep(1 * time.Second)
				backoffTCP := 1 * time.Millisecond
				for {
					conn, err := tcpTransport.Accept()
					if err != nil {
						acceptBackoff(&backoffTCP)
						continue
					}
					backoffTCP = 1 * time.Millisecond
					release, ok := acquireConnSlot(conn.RemoteAddr())
					if !ok {
						conn.Close()
						continue
					}
					go func() {
						defer release()
						handleTCPConnection(conn, globalHandshake)
					}()
				}
			}()
		}
	}

	return nil
}

func initOptional(m *lifecycle.Manager, sc *config.ServerConfig, ctx context.Context) error {
	reactor := newThreatReactor(sc)

	if sc.API.Enabled {
		if err := initAPIServer(m, sc); err != nil {
			return err
		}
	}

	if sc.Whispera.Enabled && sc.Whispera.Domain == "" {
		ensureWhisperaServerCert(sc)
	}

	if sc.Whispera.Enabled && (sc.Whispera.TLSCert != "" || sc.Whispera.Domain != "") {
		initWhispera(m, sc, ctx, reactor)
	}

	if err := initGRPC(m, sc); err != nil {
		return err
	}

	if err := initYaDisk(m, sc); err != nil {
		return err
	}

	if sc.Correlation.Enabled {
		initCorrelationDefense(m, sc)
	}

	mlServer, err := initMLServer(m, sc)
	if err != nil {
		return err
	}
	reactor.SetAdversarial(mlServer.Adversarial())
	neural.GetNativeEngine().SetOnTSPUDetected(reactor.OnTSPUDetected)

	if sc.Update.Enabled && sc.Update.ManifestURL != "" {
		initUpdater(m, sc)
	}

	return nil
}

func initAPIServer(m *lifecycle.Manager, sc *config.ServerConfig) error {
	apiServer, err := apiserver.New(&apiserver.Config{
		Enabled:           true,
		ListenAddr:        sc.API.ListenAddr,
		AuthToken:         sc.API.AuthToken,
		WebRoot:           sc.API.WebRoot,
		EnableCORS:        true,
		AdminUsername:     sc.API.AdminUsername,
		AdminPassword:     sc.API.AdminPassword,
		AdminPasswordHash: sc.API.AdminPasswordHash,
		LoginRateLimit:    sc.API.LoginRateLimit,
	})
	if err != nil {
		return err
	}

	apiServer.SetRegistry(m.Registry())
	apiServer.SetKeyLimits(globalKeyLimits)

	if err := m.Register(apiServer); err != nil {
		return err
	}

	apiServer.Handle("/api/ml/weights", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		snap := neural.GetGlobalSnapshot()
		if snap == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"error":"weights not ready yet"}`)
			return
		}
		data, err := json.Marshal(snap)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	globalProbeDetector = probedetector.New(probedetector.DefaultConfig())
	globalProbeDetector.Start()
	apiServer.SetProbeDetector(globalProbeDetector)
	return nil
}

func ensureWhisperaServerCert(sc *config.ServerConfig) {
	if sc.Whispera.TLSCert != "" {
		return
	}

	certPath := whisperaCertPath
	keyPath := whisperaKeyPath
	if _, err := os.Stat(certPath); err == nil {
		if !certHasStaleSigAlg(certPath) {
			sc.Whispera.TLSCert = certPath
			sc.Whispera.TLSKey = keyPath
			return
		}
		log.Warn("whispera: server cert at %s uses a signature algorithm most clients reject (e.g. Ed25519) — regenerating as ECDSA", certPath)
	}

	os.MkdirAll(filepath.Dir(certPath), 0755)
	if err := generateSelfSignedCert(certPath, keyPath); err != nil {
		log.Warn("whispera: auto cert generation failed: %v", err)
		return
	}

	log.Info("whispera: generated self-signed server cert at %s", certPath)
	sc.Whispera.TLSCert = certPath
	sc.Whispera.TLSKey = keyPath
}

func certHasStaleSigAlg(certPath string) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return cert.PublicKeyAlgorithm != x509.ECDSA
}

func generateSelfSignedCert(certPath, keyPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	notBefore := time.Now().Add(-24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	return pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
}

func initWhispera(m *lifecycle.Manager, sc *config.ServerConfig, ctx context.Context, reactor *threatReactor) {
	ganIface := sc.Whispera.GANIface
	if ganIface == "" {
		ganIface = defaultRouteIface()
	}
	ganPort := sc.Whispera.GANPort
	if ganPort == 0 {
		if _, p, err := net.SplitHostPort(sc.Whispera.ListenAddr); err == nil {
			ganPort, _ = strconv.Atoi(p)
		}
	}
	if ganPort == 0 {
		ganPort = 443
	}
	ganMaxPadding := sc.Whispera.GANMaxPadding
	if ganMaxPadding == 0 {
		ganMaxPadding = 4096
	}
	ganModelDir := os.Getenv("WHISPERA_ML_MODEL_DIR")
	if ganModelDir == "" {
		ganModelDir = "./ml_models"
	}
	ganSavePath := filepath.Join(ganModelDir, "gan_state.json")
	if err := os.MkdirAll(ganModelDir, 0755); err != nil {
		log.Error("GAN: failed to create model dir %s: %v", ganModelDir, err)
	}
	ganRunner := neural.NewGANRunner(ganIface, ganPort, ganSavePath)
	if err := ganRunner.Start(); err != nil {
		log.Error("GAN: failed to start traffic-shaping runner: %v", err)
	} else {
		m.OnStop(func() error {
			ganRunner.Stop()
			return nil
		})
	}

	cCfg := &protocol2.ServerConfig{
		IsNeuralDisabled: apiserver.IsNeuralDisabled,
		GANDecide: func(iatMean, sizeMean, upRatio float64) protocol2.GANAction {
			a := ganRunner.GAN().Decide(neural.FlowFeatures{
				IATMean:  iatMean,
				SizeMean: sizeMean,
				UpRatio:  upRatio,
			})
			lambda := neural.GANLambda(reactor.EffectiveThreatLevel())
			return protocol2.GANAction{
				SleepMs:   a.SleepMs * lambda,
				PaddingN:  int(a.PaddingFrac * float64(ganMaxPadding) * lambda),
				SegShrink: a.SegShrink * lambda,
			}
		},
		ListenAddr:   sc.Whispera.ListenAddr,
		TLSCert:      sc.Whispera.TLSCert,
		TLSKey:       sc.Whispera.TLSKey,
		Domain:       sc.Whispera.Domain,
		DecoyCertDir: whisperaDecoyCertDir,
		ACMEDir:      sc.Whispera.ACMEDir,
		DecoyOrigin:  sc.Whispera.DecoyOrigin,
		GetUsers: func() []protocol2.UserEntry {
			registered := apiserver.GetRegisteredUsers()
			entries := make([]protocol2.UserEntry, 0, len(registered))
			for _, u := range registered {
				psk, err := base64.StdEncoding.DecodeString(u.PrivateKey)
				if err != nil || len(psk) != 32 {
					continue
				}
				entries = append(entries, protocol2.UserEntry{UserID: u.UserID, PSK: psk})
			}
			return entries
		},
		OnConn: func(conn net.Conn, userID string) {
			log.Info("whispera: tunnel connected userID=%s remote=%s", userID, conn.RemoteAddr())
			neural.FlowRegistry.RegisterConn(conn.LocalAddr(), conn.RemoteAddr(), neural.FlowTunnel)
			tracked := stats.WrapConn(conn, userID)
			go func() {
				globalRelay.ServeTunnelRaw(tracked, false)
				neural.FlowRegistry.DeleteConn(conn.LocalAddr(), conn.RemoteAddr())
				log.Info("whispera: tunnel closed userID=%s remote=%s", userID, conn.RemoteAddr())
			}()
		},
	}
	cCfg.QUICListenAddr = sc.Whispera.QUICListenAddr
	if len(sc.Whispera.ExtraPorts) > 0 {
		listenHost, _, _ := net.SplitHostPort(sc.Whispera.ListenAddr)
		for _, p := range sc.Whispera.ExtraPorts {
			if p <= 0 || p > 65535 {
				continue
			}
			cCfg.ExtraListenAddrs = append(cCfg.ExtraListenAddrs, net.JoinHostPort(listenHost, strconv.Itoa(p)))
		}
	}
	if len(sc.Whispera.QUICExtraPorts) > 0 && sc.Whispera.QUICListenAddr != "" {
		quicHost, _, _ := net.SplitHostPort(sc.Whispera.QUICListenAddr)
		for _, p := range sc.Whispera.QUICExtraPorts {
			if p <= 0 || p > 65535 {
				continue
			}
			cCfg.ExtraQUICListenAddrs = append(cCfg.ExtraQUICListenAddrs, net.JoinHostPort(quicHost, strconv.Itoa(p)))
		}
	}
	go func() { _ = protocol2.ListenAndServe(ctx, cCfg) }()
}

func initCorrelationDefense(m *lifecycle.Manager, sc *config.ServerConfig) {
	corrCfg := &evasion.CorrelationConfig{
		Enabled:         true,
		PaddingEnabled:  sc.Correlation.PaddingEnabled,
		MixEnabled:      sc.Correlation.JitterEnabled,
		ConstantRatePPS: sc.Correlation.RateBytesPerSec,
	}
	if sc.Correlation.MaxJitterMs > 0 {
		corrCfg.DelayJitter = time.Duration(sc.Correlation.MaxJitterMs) * time.Millisecond
	} else {
		corrCfg.DelayJitter = 50 * time.Millisecond
	}
	if corrCfg.ConstantRatePPS <= 0 {
		corrCfg.ConstantRatePPS = 100
	}
	globalCorrelation = evasion.NewCorrelationDefense(corrCfg)
	m.OnShutdown(func() { globalCorrelation.Stop() })
}

func initMLServer(m *lifecycle.Manager, sc *config.ServerConfig) (*mlserver.MLServer, error) {
	mlListenAddr := ":8000"
	if sc.ML.ListenAddr != "" {
		mlListenAddr = sc.ML.ListenAddr
	}
	mlServer, err := mlserver.New(&mlserver.Config{
		ListenAddr: mlListenAddr,
		Token:      sc.API.AuthToken,
		DataDir:    "./ml_data",
	})
	if err != nil {
		return nil, err
	}
	if err := m.Register(mlServer); err != nil {
		return nil, err
	}
	os.Setenv("WHISPERA_ML_SERVER", "http://"+mlListenAddr)
	return mlServer, nil
}

func initUpdater(m *lifecycle.Manager, sc *config.ServerConfig) {
	updateConfig := &update.Config{
		ManifestURL:    sc.Update.ManifestURL,
		CurrentVersion: Version,
		CheckInterval:  sc.Update.CheckInterval.D(),
	}
	if sc.Update.PublicKey != "" {
		if pk, err := hex.DecodeString(sc.Update.PublicKey); err == nil && len(pk) == ed25519.PublicKeySize {
			updateConfig.PublicKey = ed25519.PublicKey(pk)
		} else {
			log.Warn("update: public_key is set but invalid (must be %d-byte hex) — signature verification disabled", ed25519.PublicKeySize)
		}
	}
	if updateConfig.CheckInterval <= 0 {
		updateConfig.CheckInterval = 1 * time.Hour
	}
	binaryPath, _ := os.Executable()
	updateConfig.BinaryPath = binaryPath
	globalUpdater = update.NewUpdater(updateConfig)
	globalUpdater.Start()
	m.OnShutdown(func() { globalUpdater.Stop() })
}

func tryHandshakePacket(data []byte, addr net.Addr) bool {
	if len(data) < 32 || len(data) > 96 || globalHandshake == nil {
		return false
	}
	if !udpIPRateAllow(addr) {
		return true
	}

	sess, err := globalHandshake.HandleHandshake(context.Background(), data, addr)
	if err != nil || sess == nil {
		return false
	}

	if response := globalHandshake.BuildResponse(sess); response != nil && globalUDPTransport != nil {
		globalUDPTransport.WriteTo(response, addr)
	}
	return true
}

func handlePacket(data []byte, addr net.Addr) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("PANIC in handlePacket: %v\n%s", r, rtdebug.Stack())
		}
	}()

	if tryHandshakePacket(data, addr) {
		return
	}

	if globalSessionMgr == nil {
		return
	}

	sess, ok := globalSessionMgr.GetSessionByAddr(addr)
	if !ok || sess == nil {
		return
	}

	payload := data

	if globalObfuscator != nil {
		deobfuscated, _, err := globalObfuscator.Process(data, interfaces.DirectionInbound)

		if err == nil && len(deobfuscated) > 0 {
			payload = deobfuscated
		}
	}

	if globalCorrelation != nil {
		payload = globalCorrelation.ProcessInbound(payload)

		if len(payload) == 0 {
			return
		}

		if len(payload) >= 1 && payload[0] == 0xFF {
			return
		}
	}

	if len(payload) >= 8 && globalRelay != nil {
		frameType := payload[2]

		if frameType >= 0x01 && frameType <= 0x08 {
			dataLen := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])

			if int(dataLen) <= len(payload)-8 {
				writer := &UDPResponseWriter{
					transport:  globalUDPTransport,
					addr:       addr,
					obfuscator: globalObfuscator,
					debug:      *debug,
				}

				var userID string
				if val := sess.GetMetadata("user_id"); val != nil {
					userID = val.(string)
					writer.UserID = userID
					stats.AddRx(userID, int64(len(payload)))
				}

				if err := globalRelay.ProcessFrame(payload, sess, writer); err != nil {
					return
				}
			}
		}
	}

	if globalDataPlane != nil {
		packet := &interfaces.Packet{
			SessionID: sess.ID(),
			Payload:   payload,
			SrcAddr:   addr,
		}

		if err := globalDataPlane.ProcessInbound(context.Background(), packet, sess); err != nil {
			return
		}
	}
}

func handleTCPConnection(conn net.Conn, hsHandler *handshake.Handler) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Error("PANIC in handleTCPConnection: %v\n%s", r, rtdebug.Stack())
		}
	}()

	addr := conn.RemoteAddr()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	var firstByte [1]byte

	if _, err := io.ReadFull(conn, firstByte[:]); err != nil {
		return
	}

	if hsHandler != nil && firstByte[0] == byte(handshake.HandshakeTypeInit) {
		rest := make([]byte, 63)

		if _, err := io.ReadFull(conn, rest); err != nil {
			return
		}

		padLen := int(rest[62])

		buf := append(firstByte[:], rest...)

		if padLen > 0 && padLen <= 32 {
			extra := make([]byte, padLen)

			if _, err := io.ReadFull(conn, extra); err == nil {
				buf = append(buf, extra...)
			}
		}

		conn.SetReadDeadline(time.Time{})

		sess, err := hsHandler.HandleHandshake(context.Background(), buf, addr)
		if err != nil {
			return
		}

		if response := hsHandler.BuildResponse(sess); response != nil {
			if _, err := conn.Write(response); err != nil {
				return
			}
		}

		if globalRelay != nil {
			globalRelay.ServeTunnel(stats.WrapConn(conn, addr.String()), false)
		}
	} else {
		logger.Trace().Infow("raw_tcp_no_handshake",
			"remote", addr.String(),
			"first_byte", fmt.Sprintf("0x%02x", firstByte[0]),
		)
	}
}

func verifyAltTransportAuth(conn net.Conn) bool {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	var sidLenByte [1]byte
	if _, err := io.ReadFull(conn, sidLenByte[:]); err != nil {
		return false
	}
	sidLen := int(sidLenByte[0])
	if sidLen == 0 || sidLen > 64 {
		return false
	}
	sessionID := make([]byte, sidLen)
	if _, err := io.ReadFull(conn, sessionID); err != nil {
		return false
	}

	var tokLenBuf [2]byte
	if _, err := io.ReadFull(conn, tokLenBuf[:]); err != nil {
		return false
	}
	tokLen := int(binary.BigEndian.Uint16(tokLenBuf[:]))
	if tokLen == 0 || tokLen > 256 {
		return false
	}
	tokenBytes := make([]byte, tokLen)
	if _, err := io.ReadFull(conn, tokenBytes); err != nil {
		return false
	}
	token := string(tokenBytes)

	for _, u := range apiserver.GetRegisteredUsers() {
		psk, err := base64.StdEncoding.DecodeString(u.PrivateKey)
		if err != nil || len(psk) != 32 {
			continue
		}
		if protocol2.VerifyAuthToken(psk, token, sessionID) {
			return true
		}
	}
	return false
}

func handleAltTransportConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("PANIC in handleAltTransportConn: %v\n%s", r, rtdebug.Stack())
		}
	}()

	if !verifyAltTransportAuth(conn) {
		conn.Close()
		return
	}
	if globalRelay == nil {
		conn.Close()
		return
	}
	globalRelay.ServeTunnelRaw(stats.WrapConn(conn, conn.RemoteAddr().String()), false)
}

func initGRPC(m *lifecycle.Manager, sc *config.ServerConfig) error {
	if !sc.GRPC.Enabled || sc.GRPC.ListenAddr == "" {
		return nil
	}
	var grpcExtraAddrs []string
	if len(sc.GRPC.ExtraPorts) > 0 {
		grpcHost, _, _ := net.SplitHostPort(sc.GRPC.ListenAddr)
		for _, p := range sc.GRPC.ExtraPorts {
			if p <= 0 || p > 65535 {
				continue
			}
			grpcExtraAddrs = append(grpcExtraAddrs, net.JoinHostPort(grpcHost, strconv.Itoa(p)))
		}
	}
	t, err := grpc.New(&grpc.Config{
		ListenAddr:       sc.GRPC.ListenAddr,
		ExtraListenAddrs: grpcExtraAddrs,
		ServerName:       sc.GRPC.ServerName,
		UseTLS:           sc.GRPC.TLSCert != "",
		CertFile:         sc.GRPC.TLSCert,
		KeyFile:          sc.GRPC.TLSKey,
	})
	if err != nil {
		return err
	}
	if err := m.Register(t); err != nil {
		return err
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("PANIC in grpc accept loop: %v\n%s", r, rtdebug.Stack())
			}
		}()
		time.Sleep(1 * time.Second)
		backoffGRPC := 1 * time.Millisecond
		for {
			conn, err := t.Accept()
			if err != nil {
				acceptBackoff(&backoffGRPC)
				continue
			}
			backoffGRPC = 1 * time.Millisecond
			release, ok := acquireConnSlot(conn.RemoteAddr())
			if !ok {
				conn.Close()
				continue
			}
			go func() {
				defer release()
				handleAltTransportConn(conn)
			}()
		}
	}()
	return nil
}

func initYaDisk(m *lifecycle.Manager, sc *config.ServerConfig) error {
	if !sc.YaDisk.Enabled || sc.YaDisk.OAuthToken == "" {
		return nil
	}
	t, err := yadisk.New(&yadisk.Config{
		OAuthToken: sc.YaDisk.OAuthToken,
		SessionID:  sc.YaDisk.SessionID,
		ServerMode: true,
	})
	if err != nil {
		return err
	}
	if err := m.Register(t); err != nil {
		return err
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("PANIC in yadisk accept loop: %v\n%s", r, rtdebug.Stack())
			}
		}()
		time.Sleep(1 * time.Second)
		backoffYaDisk := 1 * time.Millisecond
		for {
			conn, err := t.Accept()
			if err != nil {
				acceptBackoff(&backoffYaDisk)
				continue
			}
			backoffYaDisk = 1 * time.Millisecond
			release, ok := acquireConnSlot(conn.RemoteAddr())
			if !ok {
				conn.Close()
				continue
			}
			go func() {
				defer release()
				handleAltTransportConn(conn)
			}()
		}
	}()
	return nil
}

type UDPResponseWriter struct {
	transport  *udp.Transport
	addr       net.Addr
	obfuscator interfaces.ObfuscationProcessor
	debug      bool
	UserID     string
}

func (w *UDPResponseWriter) Write(data []byte) error {
	payload := data

	if w.obfuscator != nil {
		obfuscated, _, err := w.obfuscator.Process(data, interfaces.DirectionOutbound)
		if err != nil {
			return fmt.Errorf("obfuscation failed: %w", err)
		}

		payload = obfuscated
	}

	if w.transport == nil {
		return fmt.Errorf("UDP not available")
	}

	n, err := w.transport.WriteTo(payload, w.addr)

	if err == nil && n > 0 && w.UserID != "" {
		stats.AddTx(w.UserID, int64(n))
	}

	return err
}

func (w *UDPResponseWriter) RemoteAddr() net.Addr { return w.addr }
