package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	_ "net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"

	_ "go.uber.org/automaxprocs"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/proxy"

	"whispera/internal/cache"
	"whispera/internal/core/base"
	"whispera/internal/core/events"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/lifecycle"
	"whispera/internal/db"
	"whispera/internal/logger"
	bridgeagent "whispera/internal/modules/bridge"
	"whispera/internal/obfuscation/core/evasion"
	"whispera/internal/server/dynamic"
	"whispera/internal/stats"
	"whispera/internal/update"

	"whispera/internal/modules/apiserver"
	"whispera/internal/modules/bot"
	"whispera/internal/modules/bridgepool"
	modconfig "whispera/internal/modules/config"
	"whispera/internal/modules/crypto"
	"whispera/internal/modules/dataplane"
	"whispera/internal/modules/handshake"
	"whispera/internal/modules/metricscollector"
	"whispera/internal/modules/obfuscator"
	"whispera/internal/modules/keylimits"
	"whispera/internal/modules/phantom"
	"whispera/internal/modules/probedetector"
	"whispera/internal/modules/relay"
	"whispera/pkg/wiraid"
	"whispera/internal/modules/router"
	"whispera/internal/modules/session"
	_ "whispera/internal/modules/transport/domainfront"
	_ "whispera/internal/modules/transport/grpc"
	h2c_transport "whispera/internal/modules/transport/h2c"
	_ "whispera/internal/modules/transport/httpupgrade"
	_ "whispera/internal/modules/transport/meek"
	obfs4_transport "whispera/internal/modules/transport/obfs4"
	_ "whispera/internal/modules/transport/okwebrtc"
	shadowsocks_transport "whispera/internal/modules/transport/shadowsocks"
	shadowtls_transport "whispera/internal/modules/transport/shadowtls"
	_ "whispera/internal/modules/transport/snowflake"
	_ "whispera/internal/modules/transport/splithttp"
	"whispera/internal/modules/transport/tcp"
	_ "whispera/internal/modules/transport/tgbot"
	_ "whispera/internal/modules/transport/torsocks"
	_ "whispera/internal/modules/transport/tuic"
	"whispera/internal/modules/transport/udp"
	_ "whispera/internal/modules/transport/vkbot"
	_ "whispera/internal/modules/transport/vkwebrtc"
	ws_transport "whispera/internal/modules/transport/websocket"
	"whispera/internal/modules/mlserver"
	_ "whispera/internal/modules/transport/yacloud"
	"whispera/internal/obfuscation/marionette"
	mlpkg "whispera/internal/obfuscation/ml"
	_ "whispera/internal/modules/transport/yadisk"
	_ "whispera/internal/modules/transport/yatelemost"
)

var log = logger.Module("server")

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

// chanListener delivers pre-accepted connections to h2c when sharing a TCP port.
type chanListener struct {
	ch   chan net.Conn
	addr net.Addr
	once sync.Once
	done chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.ch:
		if !ok {
			return nil, fmt.Errorf("listener closed")
		}
		return conn, nil
	case <-l.done:
		return nil, fmt.Errorf("listener closed")
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }

// findListenerByAddr returns the active listener bound to addr.
// Must be called with listenersMutex held.
func findListenerByAddr(addr string) net.Listener {
	for _, l := range activeListeners {
		if l.Addr().String() == addr {
			return l
		}
	}
	return nil
}

var globalProbeDetector *probedetector.Detector

var (
	configFile     = flag.String("config", "", "Path to configuration file")
	listenAddr     = flag.String("listen", "", "UDP/TCP listen address (default from config)")
	apiAddr        = flag.String("api", ":8080", "API server listen address")
	metricsAddr    = flag.String("metrics", ":9091", "Metrics server listen address")
	debug          = flag.Bool("debug", false, "Enable debug logging")
	printVersion   = flag.Bool("version", false, "Print version and exit")
	validateConfig = flag.Bool("validate-config", false, "Validate configuration and exit")
	pprofAddr      = flag.String("pprof", "localhost:6060", "Pprof server listen address")
	p2pAddr        = flag.String("p2p-addr", "", "P2P relay listen address (e.g. :8445), empty = disabled")
	p2pSecret      = flag.String("p2p-secret", "", "P2P relay HMAC secret; auto-generated if empty")
	clusterAddr    = flag.String("cluster-addr", ":8082", "Bridge cluster HTTP listen address (served by bridge agent)")
	selfAddr       = flag.String("self-addr", "", "Public address of this bridge node (host:port), used in cluster election")
)

var globalP2PRelay *relay.P2PRelay
var globalBridgePool *bridgepool.Registry
var globalWiraidEngine *wiraid.Engine
var globalKeyLimits = keylimits.New(keylimits.Limits{
	MaxActiveSessions: 200,
	SoftIPCap:         50,
	BurstPerMinute:    120,
	SessionTTL:        2 * time.Minute,
})

var (
	globalHandshake      *handshake.Handler
	globalDataPlane      *dataplane.Processor
	globalSessionMgr     *session.Manager
	globalUDPTransport   *udp.Transport
	globalRelay          *relay.Server
	globalObfuscator     interfaces.Obfuscator
	globalCryptoProvider interfaces.CryptoProvider
	globalServerConfig   *modconfig.ServerConfig
	globalBridgeAgent    *bridgeagent.Agent
	globalBridge         *relay.Bridge
	globalCorrelation    *evasion.CorrelationDefense
	globalUpdater        *update.Updater

	activeListeners = make(map[string]net.Listener)
	listenersMutex  sync.RWMutex

	phantomHandlers   = make(map[string]*phantom.Handler)
	phantomHandlersMu sync.RWMutex

	// portH2CChans maps listenAddr → channel used to hand off H2C connections
	// detected by the TCP mux (first 3 bytes == "PRI").
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

func createHandshakeHandler(privateKeyStr string, serverConfig *modconfig.ServerConfig) *handshake.Handler {
	if privateKeyStr == "" {
		return nil
	}

	h, err := handshake.New(&handshake.Config{
		RateLimit:        100,
		RateBurst:        50,
		Timeout:          serverConfig.Session.SessionTimeout.D(),
		MaxPending:       1000,
		EnableAntiReplay: true,
	})
	if err != nil {
		log.Printf("⚠ Failed to create handshake handler: %v", err)
		return nil
	}

	h.SetDependencies(globalCryptoProvider, globalSessionMgr)

	privKey, err := base64.StdEncoding.DecodeString(privateKeyStr)

	if err != nil || len(privKey) != 32 {
		log.Printf("⚠ Invalid private key: %v (must be 32 bytes Base64)", err)
		return nil
	}

	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		log.Printf("⚠ Failed to derive public key: %v", err)
		return nil
	}

	h.SetStaticKeys(pubKey, privKey)
	return h
}

func StartInbound(inbound modconfig.InboundConfig, serverConfig *modconfig.ServerConfig) error {
	listenersMutex.Lock()
	defer listenersMutex.Unlock()
	if _, exists := activeListeners[inbound.Tag]; exists {
		return fmt.Errorf("inbound %s already running", inbound.Tag)
	}

	listenAddr := fmt.Sprintf("%s:%d", inbound.Listen, inbound.Port)
	network := inbound.StreamSettings.Network

	log.Printf("🚀 [Dynamic] Starting inbound %s (%s) on %s", inbound.Tag, network, listenAddr)

	if network == "udp" {
		log.Printf("ℹ [Dynamic] Inbound %s (udp): served by global UDP transport, skipping", inbound.Tag)
		return nil
	}

	selfManaged := network == "ws" || network == "h2c" || network == "shadowsocks" ||
		network == "obfs4" || network == "shadowtls"

	var listener net.Listener
	if !selfManaged {
		var err error
		listener, err = (&net.ListenConfig{}).Listen(context.Background(), "tcp", listenAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
		}
	}

	var hsHandler *handshake.Handler
	var phantomHandler *phantom.Handler

	isPhantom := inbound.StreamSettings.Security == "phantom" || inbound.StreamSettings.Security == "reality"

	if network == "ws" {
		path := inbound.StreamSettings.WS.Path
		if path == "" {
			path = "/ws"
		}
		_ = path
	}

	if isPhantom {
		pPrivKey := inbound.StreamSettings.Phantom.PrivateKey
		if pPrivKey == "" {
			pPrivKey = serverConfig.Server.PrivateKey
		}
		inboundServerNames := inbound.StreamSettings.Phantom.ServerNames
		if len(inboundServerNames) == 0 {
			inboundServerNames = serverConfig.Phantom.ServerNames
		}
		inboundShortIds := inbound.StreamSettings.Phantom.ShortIds
		if len(inboundShortIds) == 0 {
			inboundShortIds = serverConfig.Phantom.ShortIds
		}
		inboundMaxTimeDiff := inbound.StreamSettings.Phantom.MaxTimeDiff
		if inboundMaxTimeDiff == 0 {
			inboundMaxTimeDiff = serverConfig.Phantom.MaxTimeDiff
		}

		pCfg := &phantom.Config{
			Enabled:            true,
			ListenAddr:         listenAddr,
			Dest:               inbound.StreamSettings.Phantom.Dest,
			PrivateKey:         pPrivKey,
			ServerNames:        inboundServerNames,
			ShortIds:           inboundShortIds,
			MaxTimeDiff:        inboundMaxTimeDiff,
			Fingerprint:        serverConfig.Phantom.Fingerprint,
			EnableObfuscation:  false,
			ObfuscationProfile: "",
			EnableChatFSM:      serverConfig.Phantom.EnableChatFSM,
			ChatFSMCoverInterval: time.Duration(serverConfig.Phantom.ChatFSMCoverInterval) * time.Second,
			GetUsers: func() []phantom.UserEntry {
				registered := apiserver.GetRegisteredUsers()
				entries := make([]phantom.UserEntry, 0, len(registered))
				for _, u := range registered {
					privBytes, err := base64.StdEncoding.DecodeString(u.PrivateKey)
					if err != nil || len(privBytes) != 32 {
						continue
					}
					pub, err := curve25519.X25519(privBytes, curve25519.Basepoint)
					if err != nil || len(pub) != 32 {
						continue
					}
					var pubKey [32]byte
					copy(pubKey[:], pub)
					entries = append(entries, phantom.UserEntry{UserID: u.UserID, PublicKey: pubKey})
				}
				return entries
			},
			AdmitSession: func(clientID, sessionID, remoteIP string) (func(), string) {
				reason, msg := globalKeyLimits.Admit(clientID, sessionID, remoteIP)
				if reason == keylimits.ReasonActiveCap {
					// Evict the 10 oldest stuck connections and retry once.
					globalKeyLimits.EvictOldest(10)
					reason, msg = globalKeyLimits.Admit(clientID, sessionID, remoteIP)
				}
				if reason != keylimits.ReasonNone {
					return nil, msg
				}
				return func() { globalKeyLimits.Release(clientID, sessionID) }, ""
			},
			OnConnReady: func(clientID, sessionID string, conn net.Conn) {
				globalKeyLimits.RegisterCloser(clientID, sessionID, func() { conn.Close() })
			},
			OnAuthenticated: func(conn net.Conn, clientID string) {
				log.Printf("[Dynamic-Phantom] Authenticated: %s on inbound %s", clientID, inbound.Tag)
				stats.RegisterConn(clientID, conn)
				defer stats.DeregisterConn(clientID, conn)
				if globalRelay != nil {
					var session interfaces.Session
					if globalSessionMgr != nil {
						params := interfaces.SessionParams{
							ClientAddr: conn.RemoteAddr(),
							UserID:     clientID,
							Metadata: map[string]interface{}{
								"user_id":       clientID,
								"inbound_tag":   inbound.Tag,
								"protocol":      "phantom",
								"authenticated": true,
								"created_at":    time.Now(),
							},
						}

						sess, err := globalSessionMgr.CreateSession(params)
						if err != nil {
							log.Printf("⚠ Failed to create session for phantom client %s: %v", clientID, err)
						} else {
							session = sess
							log.Printf("  + Session created: %d (User: %s)", session.ID(), clientID)
							defer session.Close()
						}
					}
					globalRelay.ServeTunnel(conn, true)
				} else {
					conn.Close()
				}
			},
		}

		if pCfg.Dest == "" {
			pCfg.Dest = serverConfig.Phantom.Dest
		}

		var err error
		phantomHandler, err = phantom.New(pCfg)
		if err != nil {
			if listener != nil {
				listener.Close()
			}
			return fmt.Errorf("failed to create phantom handler: %w", err)
		}
		if globalProbeDetector != nil {
			phantomHandler.SetProbeDetector(globalProbeDetector)
			phantomHandler.SetConnGuard(globalProbeDetector.Guard)
		}
		phantomHandlersMu.Lock()
		phantomHandlers[inbound.Tag] = phantomHandler
		phantomHandlersMu.Unlock()
		log.Printf("  ✨ [Dynamic] Enabled Phantom/Reality on inbound %s", inbound.Tag)
	} else {
		privKey := ""
		if inbound.StreamSettings.Phantom.PrivateKey != "" {
			privKey = inbound.StreamSettings.Phantom.PrivateKey
		} else if serverConfig.Server.PrivateKey != "" {
			privKey = serverConfig.Server.PrivateKey
		}

		if privKey != "" {
			hsHandler = createHandshakeHandler(privKey, serverConfig)
			if hsHandler == nil {
				if listener != nil {
					listener.Close()
				}
				return fmt.Errorf("failed to create handshake handler for %s", inbound.Tag)
			}
		}
	}

	paramStr := func(key, fallback string) string {
		if v, ok := inbound.StreamSettings.Params[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
		return fallback
	}

	if network == "ws" {
		path := inbound.StreamSettings.WS.Path
		if path == "" {
			path = paramStr("path", "/ws")
		}
		wsCfg := ws_transport.DefaultConfig()
		wsCfg.ListenAddr = listenAddr
		wsCfg.Path = path
		wsTrans, err := ws_transport.New(wsCfg)
		if err != nil {
			if listener != nil {
				listener.Close()
			}
			return fmt.Errorf("failed to create websocket transport: %w", err)
		}
		if listener != nil {
			listener.Close()
		}
		if err := wsTrans.Listen(listenAddr); err != nil {
			return fmt.Errorf("failed to listen ws on %s: %w", listenAddr, err)
		}
		log.Printf("✅ [Dynamic] Inbound %s listening on %s (WebSocket path=%s)", inbound.Tag, listenAddr, path)
		go func() {
			defer func() {
				wsTrans.Close()
				log.Printf("⏹ [Dynamic] Stopped inbound %s (WebSocket)", inbound.Tag)
			}()
			for {
				conn, err := wsTrans.Accept()
				if err != nil {
					log.Printf("⚠ [Dynamic] WS Accept error on %s: %v", inbound.Tag, err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if globalRelay != nil {
					go globalRelay.ServeTunnel(conn, false)
				} else {
					conn.Close()
				}
			}
		}()
		return nil
	}

	if network == "shadowsocks" {
		password := paramStr("password", "")
		if password == "" {
			if listener != nil {
				listener.Close()
			}
			return fmt.Errorf("shadowsocks inbound %s: 'password' required in params", inbound.Tag)
		}
		method := shadowsocks_transport.Method(paramStr("method", "aes-256-gcm"))
		ssCfg := &shadowsocks_transport.Config{
			Password: password,
			Method:   method,
		}
		ssTrans, err := shadowsocks_transport.New(ssCfg)
		if err != nil {
			if listener != nil {
				listener.Close()
			}
			return fmt.Errorf("failed to create shadowsocks transport: %w", err)
		}
		if listener != nil {
			listener.Close()
		}
		if err := ssTrans.Listen(listenAddr); err != nil {
			return fmt.Errorf("failed to listen shadowsocks on %s: %w", listenAddr, err)
		}
		log.Printf("✅ [Dynamic] Inbound %s listening on %s (Shadowsocks method=%s)", inbound.Tag, listenAddr, method)
		go func() {
			defer func() {
				ssTrans.Close()
				log.Printf("⏹ [Dynamic] Stopped inbound %s (Shadowsocks)", inbound.Tag)
			}()
			for {
				conn, err := ssTrans.Accept()
				if err != nil {
					log.Printf("⚠ [Dynamic] Shadowsocks Accept error on %s: %v", inbound.Tag, err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if globalRelay != nil {
					go globalRelay.ServeTunnel(conn, false)
				} else {
					conn.Close()
				}
			}
		}()
		return nil
	}

	if network == "obfs4" {
		obfsCfg := &obfs4_transport.Config{
			ListenAddr: listenAddr,
			NodeID:     paramStr("node_id", ""),
			PublicKey:  paramStr("public_key", ""),
			PrivateKey: paramStr("private_key", ""),
		}
		obfsTrans, err := obfs4_transport.New(obfsCfg)
		if err != nil {
			if listener != nil {
				listener.Close()
			}
			return fmt.Errorf("failed to create obfs4 transport: %w", err)
		}
		if listener != nil {
			listener.Close()
		}
		if err := obfsTrans.Listen(listenAddr); err != nil {
			return fmt.Errorf("failed to listen obfs4 on %s: %w", listenAddr, err)
		}
		log.Printf("✅ [Dynamic] Inbound %s listening on %s (obfs4)", inbound.Tag, listenAddr)
		go func() {
			defer func() {
				obfsTrans.Close()
				log.Printf("⏹ [Dynamic] Stopped inbound %s (obfs4)", inbound.Tag)
			}()
			for {
				conn, err := obfsTrans.Accept()
				if err != nil {
					log.Printf("⚠ [Dynamic] obfs4 Accept error on %s: %v", inbound.Tag, err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if globalRelay != nil {
					go globalRelay.ServeTunnel(conn, false)
				} else {
					conn.Close()
				}
			}
		}()
		return nil
	}

	if network == "h2c" {
		h2cConfig := &h2c_transport.Config{
			ListenAddr:           listenAddr,
			Path:                 "/",
			MaxConcurrentStreams: 1000,
		}

		h2cTrans, err := h2c_transport.New(h2cConfig)
		if err != nil {
			if listener != nil {
				listener.Close()
			}
			return fmt.Errorf("failed to create h2c transport: %w", err)
		}

		if sharedL := findListenerByAddr(listenAddr); sharedL != nil {
			// Port already owned by a TCP inbound — share it via protocol mux.
			if listener != nil {
				listener.Close()
			}
			ch := make(chan net.Conn, 64)
			portH2CChansMu.Lock()
			portH2CChans[listenAddr] = ch
			portH2CChansMu.Unlock()
			cL := &chanListener{ch: ch, addr: sharedL.Addr(), done: make(chan struct{})}
			if err := h2cTrans.ServeOn(cL); err != nil {
				return fmt.Errorf("failed to serve h2c on shared port %s: %w", listenAddr, err)
			}
			log.Printf("✅ [Dynamic] Inbound %s muxed on %s (H2C+TCP shared port)", inbound.Tag, listenAddr)
		} else {
			if listener != nil {
				listener.Close()
			}
			if err := h2cTrans.Listen(listenAddr); err != nil {
				return fmt.Errorf("failed to listen h2c on %s: %w", listenAddr, err)
			}
			log.Printf("✅ [Dynamic] Inbound %s listening on %s (H2C)", inbound.Tag, listenAddr)
		}

		go func() {
			defer func() {
				portH2CChansMu.Lock()
				delete(portH2CChans, listenAddr)
				portH2CChansMu.Unlock()
				h2cTrans.Close()
				log.Printf("⏹ [Dynamic] Stopped inbound %s (H2C)", inbound.Tag)
			}()

			for {
				conn, err := h2cTrans.Accept()
				if err != nil {
					log.Printf("⚠ [Dynamic] H2C Accept error on %s: %v", inbound.Tag, err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if globalRelay != nil {
					go globalRelay.ServeTunnel(conn, false)
				} else {
					conn.Close()
				}
			}
		}()
		return nil
	}

	if network == "shadowtls" {
		password := paramStr("password", "")
		if password == "" {
			log.Printf("ℹ [Dynamic] ShadowTLS inbound %s: no password configured, skipping", inbound.Tag)
			return nil
		}
		shadowHost := paramStr("shadow_server", "www.apple.com:443")
		sni := paramStr("sni", "")
		stCfg := &shadowtls_transport.Config{
			Password:     password,
			ShadowServer: shadowHost,
			SNI:          sni,
			ServerMode:   true,
			Version:      3,
		}
		stTrans, err := shadowtls_transport.New(stCfg)
		if err != nil {
			return fmt.Errorf("failed to create shadowtls transport: %w", err)
		}
		if err := stTrans.Listen(listenAddr); err != nil {
			return fmt.Errorf("failed to listen shadowtls on %s: %w", listenAddr, err)
		}
		log.Printf("✅ [Dynamic] Inbound %s listening on %s (ShadowTLS)", inbound.Tag, listenAddr)
		go func() {
			defer func() {
				stTrans.Close()
				log.Printf("⏹ [Dynamic] Stopped inbound %s (ShadowTLS)", inbound.Tag)
			}()
			for {
				conn, err := stTrans.Accept()
				if err != nil {
					log.Printf("⚠ [Dynamic] ShadowTLS Accept error on %s: %v", inbound.Tag, err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if globalRelay != nil {
					go globalRelay.ServeTunnel(conn, false)
				} else {
					conn.Close()
				}
			}
		}()
		return nil
	}

	activeListeners[inbound.Tag] = listener

	go func() {
		defer func() {
			listenersMutex.Lock()
			delete(activeListeners, inbound.Tag)
			listenersMutex.Unlock()
			phantomHandlersMu.Lock()
			delete(phantomHandlers, inbound.Tag)
			phantomHandlersMu.Unlock()
			log.Printf("⏹ [Dynamic] Stopped inbound %s", inbound.Tag)
		}()

		log.Printf("✅ [Dynamic] Inbound %s listening on %s", inbound.Tag, listenAddr)

		for {
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				log.Printf("⚠ [Dynamic] Accept error on %s: %v", inbound.Tag, err)
				continue
			}

			// Peek first 3 bytes to detect H2C preface ("PRI").
			var peek [3]byte
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
			n, _ := io.ReadFull(conn, peek[:])
			conn.SetReadDeadline(time.Time{}) //nolint:errcheck

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

			if phantomHandler != nil {
				go phantomHandler.HandleConnection(pConn)
			} else {
				go handleTCPConnection(pConn, hsHandler)
			}
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

	log.Printf("🛑 [Dynamic] Stopping inbound %s...", tag)

	if err := listener.Close(); err != nil {
		return fmt.Errorf("failed to close listener %s: %w", tag, err)
	}

	delete(activeListeners, tag)
	return nil
}

func StartReverseInbound(inbound modconfig.InboundConfig, serverConfig *modconfig.ServerConfig, stopCh <-chan struct{}) {
	remoteAddr := inbound.RemoteAddr
	if remoteAddr == "" {
		log.Printf("⚠ [Reverse] Inbound %s: remote_addr is empty, skipping", inbound.Tag)
		return
	}

	var hsHandler *handshake.Handler
	if serverConfig.Server.PrivateKey != "" {
		hsHandler = createHandshakeHandler(serverConfig.Server.PrivateKey, serverConfig)
	}

	log.Printf("🔄 [Reverse] Inbound %s: will dial %s repeatedly", inbound.Tag, remoteAddr)

	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		select {
		case <-stopCh:
			log.Printf("⏹ [Reverse] Inbound %s stopped", inbound.Tag)
			return
		default:
		}

		conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.Background(), "tcp", remoteAddr)
		if err != nil {
			log.Printf("⚠ [Reverse] %s: dial failed: %v (retry in %v)", inbound.Tag, err, backoff)
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
		log.Printf("✅ [Reverse] %s: connected to %s", inbound.Tag, remoteAddr)

		if globalRelay != nil {
			if hsHandler != nil {
				handleTCPConnection(conn, hsHandler)
			} else {
				globalRelay.ServeTunnel(conn, false)
			}
		} else {
			conn.Close()
		}

		log.Printf("🔁 [Reverse] %s: connection closed, reconnecting...", inbound.Tag)
	}
}

func main() {
	if len(os.Args) > 1 {
		cmd := strings.TrimSpace(os.Args[1])
		switch cmd {
		case "x25519":
			priv, pub, err := phantom.GenerateKeyPair()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Private Key: %s\n", base64.StdEncoding.EncodeToString(priv))
			fmt.Printf("Public Key:  %s\n", base64.StdEncoding.EncodeToString(pub))
			os.Exit(0)
		case "pubkey":
			if len(os.Args) < 3 {
				fmt.Fprintln(os.Stderr, "Usage: whispera pubkey <private_key>")
				os.Exit(1)
			}
			privKeyStr := strings.TrimSpace(os.Args[2])
			var priv []byte
			var err error

			priv, err = base64.StdEncoding.DecodeString(privKeyStr)

			if err != nil || len(priv) != 32 {
				fmt.Fprintf(os.Stderr, "Error: invalid private key (must be 32 bytes Base64)\n")
				os.Exit(1)
			}
			pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
			fmt.Println(base64.StdEncoding.EncodeToString(pub))
			os.Exit(0)
		case "create-admin":
			createAdminCmd := flag.NewFlagSet("create-admin", flag.ExitOnError)
			email := createAdminCmd.String("email", "", "Admin email")
			password := createAdminCmd.String("password", "", "Admin password")
			dbURL := createAdminCmd.String("db", "", "PostgreSQL URL")

			createAdminCmd.Parse(os.Args[2:])

			if *email == "" || *password == "" || *dbURL == "" {
				fmt.Fprintln(os.Stderr, "Usage: whispera create-admin -email <email> -password <pass> -db <postgres_url>")
				os.Exit(1)
			}

			cfg := db.DefaultConfig()
			cfg.URL = *dbURL
			database, err := db.New(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to connect to DB: %v\n", err)
				os.Exit(1)
			}
			defer database.Close()

			ctx := context.Background()
			user, err := database.GetUserByEmail(ctx, *email)
			if err != nil {
				user, err = database.CreateUser(ctx, *email, *password, 0, nil, "http2", "browser", "vk", "", "")
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to create user: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("User %s created\n", *email)
			} else {
				if err := database.UpdateUser(ctx, user.ID, *email, *password); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to update password: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("User %s password updated\n", *email)
			}

			if err := database.SetAdmin(ctx, user.ID, true); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to set admin: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("User %s is now an admin\n", *email)
			os.Exit(0)
		case "wiraid":
			runWiraidCLI(os.Args[2:])
			os.Exit(0)
		case "update-checksum":
			cfgPath := "/etc/whispera/config.yaml"
			if len(os.Args) >= 3 {
				cfgPath = os.Args[2]
			}
			p, err := modconfig.New(cfgPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			if err := p.UpdateChecksum(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to update checksum: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Checksum updated successfully")
			os.Exit(0)
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

	go func() {
		log.Printf("pprof listening on http://%s/debug/pprof/", *pprofAddr)
		if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
			log.Printf("Failed to start pprof server: %v", err)
		}
	}()

	if *debug {
		logger.SetLevel(logger.LevelDebug)
	}

	if *printVersion {
		log.Printf("Whispera Server v%s (built %s, commit %s)", Version, BuildTime, GitCommit)
		os.Exit(0)
	}

	log.Printf("╔══════════════════════════════════════════════════════════════╗")
	log.Printf("║           Whispera Modular Server v%s                    ║", Version)
	log.Printf("╚══════════════════════════════════════════════════════════════╝")

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
		natsBus, err := events.NewNATSEventBus(globalServerConfig.NATS.URL, prefix)
		if err != nil {
			log.Printf("⚠ NATS EventBus failed: %v (using in-memory)", err)
		} else {
			manager.Registry().SetEventBus(natsBus)
			log.Printf("✅ NATS EventBus connected: %s (prefix: %s)", globalServerConfig.NATS.URL, prefix)
		}
	}

	if globalServerConfig != nil && globalServerConfig.Bridge.AutoRegister && globalServerConfig.UpstreamServer != "" {
		go func() {
			time.Sleep(2 * time.Second)
			registerBridgeWithMainServer()
		}()
	}

	setupEventHandlers(manager)

	if *validateConfig {
		log.Println("✓ Configuration validated successfully")
		os.Exit(0)
	}
	manager.OnStop(func() error {
		if eng := mlpkg.GetNativeEngine(); eng != nil {
			eng.Close()
		}
		return nil
	})

	if err := manager.Run(); err != nil {
		log.Fatalf("Application error: %v", err)
	}

	log.Println("Server shutdown complete")
}

func createModules(manager *lifecycle.Manager, ctx context.Context) error {
	configProvider, err := modconfig.New(*configFile)
	if err != nil {
		return err
	}
	if err := manager.Register(configProvider); err != nil {
		return err
	}

	var serverConfig *modconfig.ServerConfig
	if *configFile != "" {
		if err := configProvider.Load(*configFile); err != nil {
			log.Printf("⚠ Warning: Failed to load config file: %v, using defaults", err)
		}
		serverConfig = configProvider.GetConfig()
	} else {
		serverConfig = modconfig.DefaultServerConfig()
	}
	globalServerConfig = serverConfig

	if serverConfig.API.AuthToken == "" && *configFile != "" {
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err == nil {
			newToken := base64.StdEncoding.EncodeToString(tokenBytes)
			if err := configProvider.Update(func(c *modconfig.ServerConfig) {
				c.API.AuthToken = newToken
			}); err == nil {
				serverConfig = configProvider.GetConfig()
				globalServerConfig = serverConfig
				log.Printf("[API] Generated and persisted new auth token to config")
			}
		}
	}

	if serverConfig.API.AdminUsername == "admin" && serverConfig.API.AdminPassword == "admin" {
		fmt.Println("")
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║  ⚠️  WARNING: DEFAULT ADMIN CREDENTIALS DETECTED!           ║")
		fmt.Println("║  Username: admin / Password: admin                          ║")
		fmt.Println("║                                                             ║")
		fmt.Println("║  Change admin_username and admin_password in config.yaml     ║")
		fmt.Println("║  before deploying to production!                            ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		fmt.Println("")
	}

	cacheInstance := cache.New(serverConfig.Cache.RedisURL)
	cache.SetGlobal(cacheInstance)
	if serverConfig.Cache.RedisURL != "" {
		log.Printf("✅ Redis cache initialized: %s", serverConfig.Cache.RedisURL)
	} else {
		log.Printf("✅ In-memory cache initialized (no Redis URL)")
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
			log.Printf("⚠ PostgreSQL not available: %v (user management disabled)", err)
		} else {
			db.SetGlobal(database)
			log.Printf("✅ PostgreSQL connected (user management enabled)")
		}
	} else {
		log.Printf("ℹ PostgreSQL not configured (user management disabled)")
	}

	dynamic.Global.SetCallbacks(
		func(inbound modconfig.InboundConfig) error {
			if inbound.Mode == "reverse" {
				go StartReverseInbound(inbound, serverConfig, ctx.Done())
				return nil
			}
			return StartInbound(inbound, serverConfig)
		},
		func(tag string) error {
			return StopInbound(tag)
		},
	)
	log.Printf("✅ Dynamic inbound manager initialized")

	if *listenAddr != "" {
		serverConfig.Transport.UDP.ListenAddr = *listenAddr
		serverConfig.Server.ListenAddr = *listenAddr
	}
	if *apiAddr != "" {
		serverConfig.API.ListenAddr = *apiAddr
	}
	if *metricsAddr != "" {
		serverConfig.Metrics.ListenAddr = *metricsAddr
	}

	if serverConfig.RelayMode == "bridge" {
		log.Printf("╔══════════════════════════════════════════════════════════════╗")
		log.Printf("║                  BRIDGE MODE ENABLED                         ║")
		log.Printf("╚══════════════════════════════════════════════════════════════╝")
		log.Printf("  Upstream: %s", serverConfig.UpstreamServer)

		phantomCfg := &phantom.Config{
			Enabled:            true,
			ServerNames:        serverConfig.Phantom.ServerNames,
			PrivateKey:         serverConfig.Phantom.PrivateKey,
			MaxTimeDiff:        serverConfig.Phantom.MaxTimeDiff,
			UseRussianService:  serverConfig.Phantom.UseRussianService,
			RussianServiceName: serverConfig.Phantom.RussianService,
		}

		bridgeCfg := &relay.BridgeConfig{
			ListenAddr:     serverConfig.Server.ListenAddr,
			UpstreamServer: serverConfig.UpstreamServer,
			PhantomConfig:  phantomCfg,
		}

		bridge, err := relay.NewBridge(bridgeCfg)
		if err != nil {
			return fmt.Errorf("failed to create bridge: %w", err)
		}

		bridge.OnFailover(func(active bool) {
			if active {
				log.Printf("[Failover] Upstream %s unreachable — bridge is now operating as master", serverConfig.UpstreamServer)
			} else {
				log.Printf("[Failover] Upstream %s recovered — returning to relay mode", serverConfig.UpstreamServer)
			}
		})
		globalBridge = bridge

		if err := bridge.Start(serverConfig.Server.ListenAddr); err != nil {
			return fmt.Errorf("failed to start bridge: %w", err)
		}

		log.Printf("✅ Bridge started on %s -> %s", serverConfig.Server.ListenAddr, serverConfig.UpstreamServer)

		agentCfg := bridgeagent.DefaultAgentConfig()
		agentCfg.BridgeID = serverConfig.Bridge.Region + "-" + serverConfig.Server.ListenAddr
		agentCfg.UpstreamServer = serverConfig.UpstreamServer
		agentCfg.RegistrationToken = serverConfig.Bridge.RegistrationToken
		agentCfg.ClusterListenAddr = *clusterAddr
		if *selfAddr != "" {
			agentCfg.SelfAddress = *selfAddr
		} else {
			agentCfg.SelfAddress = serverConfig.Server.ListenAddr
		}
		globalBridgeAgent = bridgeagent.NewAgent(agentCfg)
		globalBridgeAgent.OnConfigUpdate(func(cfg map[string]interface{}) {
			log.Printf("[BridgeAgent] Config update received: %v", cfg)
		})
		globalBridgeAgent.OnAlert(func(alertType, message string) {
			log.Printf("[BridgeAgent] Alert %s: %s", alertType, message)
		})
		globalBridgeAgent.Start()
		log.Printf("✅ Bridge Agent started (id=%s)", agentCfg.BridgeID)

		select {}
	}

	cryptoProvider, err := crypto.New(&crypto.Config{
		DefaultCipher: crypto.CipherChaCha20Poly1305,
		EnableKeyPool: true,
		KeyPoolSize:   100,
	})
	if err != nil {
		return err
	}
	globalCryptoProvider = cryptoProvider
	if err := manager.Register(cryptoProvider); err != nil {
		return err
	}

	sessionMgr, err := session.New(&session.Config{
		MaxSessions:     serverConfig.Session.MaxSessions,
		SessionTimeout:  serverConfig.Session.SessionTimeout.D(),
		CleanupInterval: serverConfig.Session.CleanupInterval.D(),
	})
	if err != nil {
		return err
	}
	globalSessionMgr = sessionMgr
	if err := manager.Register(sessionMgr); err != nil {
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
	if err := manager.Register(routerEngine); err != nil {
		return err
	}

	obfuscatorEngine, err := obfuscator.New(&obfuscator.Config{
		DefaultProfile: serverConfig.Obfuscation.Profile,
		ThreatLevel:    serverConfig.Obfuscation.ThreatLevel,
		EnableML:       true,
		EnableFTE:      true,
	})
	if err != nil {
		return err
	}
	globalObfuscator = obfuscatorEngine
	if err := manager.Register(obfuscatorEngine); err != nil {
		return err
	}

	handshakeHandler, err := handshake.New(&handshake.Config{
		RateLimit:        100,
		RateBurst:        50,
		Timeout:          serverConfig.Session.SessionTimeout.D(),
		MaxPending:       1000,
		EnableAntiReplay: true,
	})
	if err != nil {
		return err
	}
	handshakeHandler.SetDependencies(cryptoProvider, sessionMgr)

	if serverConfig.Server.PrivateKey != "" {
		var privKey []byte
		var err error

		privKey, err = base64.StdEncoding.DecodeString(serverConfig.Server.PrivateKey)

		if err != nil {
			log.Fatalf("Invalid private key in config: %v (must be Base64)", err)
		}
		if len(privKey) != 32 {
			log.Fatalf("Private key must be 32 bytes (Base64)")
		}

		pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
		if err != nil {
			log.Fatalf("Failed to derive public key: %v", err)
		}

		handshakeHandler.SetStaticKeys(pubKey, privKey)
	}

	globalHandshake = handshakeHandler
	if err := manager.Register(handshakeHandler); err != nil {
		return err
	}

	dataPlaneProcessor, err := dataplane.New(&dataplane.Config{
		MTU:                 serverConfig.Server.MTU,
		WorkerCount:         serverConfig.Server.Workers,
		BufferSize:          4096,
		EnableNAT:           true,
		EnableFragmentation: true,
	})
	if err != nil {
		return err
	}
	dataPlaneProcessor.SetDependencies(routerEngine, obfuscatorEngine, sessionMgr)
	globalDataPlane = dataPlaneProcessor
	if err := manager.Register(dataPlaneProcessor); err != nil {
		return err
	}

	udpTransport, err := udp.New(&udp.Config{
		ListenAddr:    serverConfig.Transport.UDP.ListenAddr,
		MaxPacketSize: serverConfig.Transport.UDP.MaxPacketSize,
		WorkerCount:   serverConfig.Transport.UDP.Workers,
		BufferSize:    serverConfig.Transport.UDP.BufferSize,
	})
	if err != nil {
		return err
	}
	udpTransport.OnPacket(handlePacket)
	globalUDPTransport = udpTransport
	if err := manager.Register(udpTransport); err != nil {
		return err
	}
	relayServer, err := relay.New(&relay.Config{
		MaxStreams:    serverConfig.Relay.MaxStreams,
		EnableTCP:     serverConfig.Relay.EnableTCP,
		EnableUDP:     serverConfig.Relay.EnableUDP,
		Debug:         serverConfig.Relay.Debug || *debug,
		UpstreamProxy: serverConfig.Relay.UpstreamProxy,
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
	relayServer.SetRouter(routerEngine)
	if om := dataPlaneProcessor.GetOutboundManager(); om != nil {
		relayServer.SetOutboundDial(om.Dial)
		if serverConfig != nil {
			om.UpdateOutbounds(serverConfig.Outbounds)
		}
		outboundsCh := configProvider.Watch("outbounds")
		go func() {
			for val := range outboundsCh {
				if outbounds, ok := val.([]modconfig.OutboundConfig); ok {
					om.UpdateOutbounds(outbounds)
				}
			}
		}()
	}
	if err := manager.Register(relayServer); err != nil {
		return err
	}
	log.Printf("  ✓ Relay server enabled (TCP+UDP+L3)")

	if *p2pAddr != "" {
		secret := []byte(*p2pSecret)
		if len(secret) == 0 {
			secret = make([]byte, 32)
			rand.Read(secret)
			log.Printf("  [P2P] Auto-generated secret: %x", secret)
		}
		p2pCfg := relay.DefaultP2PRelayConfig()
		p2pCfg.ListenAddr = *p2pAddr
		p2pCfg.Secret = secret
		p2pRelay := relay.NewP2PRelay(p2pCfg)
		if err := p2pRelay.Start(); err != nil {
			log.Printf("  ⚠ P2P relay failed to start on %s: %v", *p2pAddr, err)
		} else {
			globalP2PRelay = p2pRelay
			log.Printf("  ✓ P2P relay started on %s", *p2pAddr)
		}
	}

	if len(serverConfig.Inbounds) > 0 {
		log.Printf("[Server] Starting %d inbounds...", len(serverConfig.Inbounds))
		for _, inbound := range serverConfig.Inbounds {
			if inbound.Mode == "reverse" {
				ib := inbound
				go StartReverseInbound(ib, serverConfig, ctx.Done())
				continue
			}
			if inbound.Port == 0 {
				continue
			}
			if err := StartInbound(inbound, serverConfig); err != nil {
				log.Printf("⚠ Failed to start inbound %s: %v", inbound.Tag, err)
			}
		}
	} else {
		if serverConfig.Transport.TCP.Enabled {
			tcpTransport, err := tcp.New(&tcp.Config{
				ListenAddr:   serverConfig.Transport.TCP.ListenAddr,
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				KeepAlive:    30 * time.Second,
				MaxConns:     10000,
				BufferSize:   32 * 1024,
			})
			if err != nil {
				return err
			}
			if err := manager.Register(tcpTransport); err != nil {
				return err
			}

			go func() {
				time.Sleep(1 * time.Second)
				log.Printf("[TCP] Starting legacy accept loop on %s", serverConfig.Transport.TCP.ListenAddr)
				for {
					conn, err := tcpTransport.Accept()
					if err != nil {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					go handleTCPConnection(conn, globalHandshake)
				}
			}()
		}
	}

	if serverConfig.Metrics.Enabled {
		metricsCollector, err := metricscollector.New(&metricscollector.Config{
			Enabled:    true,
			ListenAddr: serverConfig.Metrics.ListenAddr,
			Path:       serverConfig.Metrics.Path,
		})
		if err != nil {
			return err
		}
		if err := manager.Register(metricsCollector); err != nil {
			return err
		}
	}

	if serverConfig.API.Enabled {
		apiServer, err := apiserver.New(&apiserver.Config{
			Enabled:        true,
			ListenAddr:     serverConfig.API.ListenAddr,
			AuthToken:      serverConfig.API.AuthToken,
			WebRoot:        serverConfig.API.WebRoot,
			EnableCORS:     true,
			AdminUsername:  serverConfig.API.AdminUsername,
			AdminPassword:  serverConfig.API.AdminPassword,
			LoginRateLimit: serverConfig.API.LoginRateLimit,
		})
		if err != nil {
			return err
		}
		apiServer.SetRegistry(manager.Registry())
		apiServer.SetKeyLimits(globalKeyLimits)
		globalBridgePool = apiServer.BridgePool()
		if err := manager.Register(apiServer); err != nil {
			return err
		}

		apiServer.Handle("/api/bridge/failover", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if globalBridge == nil {
				json.NewEncoder(w).Encode(map[string]interface{}{"mode": "master", "failover": false})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"mode":             "bridge",
				"upstream_alive":   globalBridge.IsUpstreamAlive(),
				"failover_active":  globalBridge.IsFailoverActive(),
				"active_conns":     globalBridge.GetActiveConnections(),
			})
		})

		apiServer.Handle("/api/marionette/status", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"live_connections": marionette.LiveCount(),
				"known_profiles":   marionette.KnownProfiles(),
			})
		})

		apiServer.Handle("/api/marionette/profile", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			var body struct {
				Profile string `json:"profile"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Profile == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "profile required"})
				return
			}
			p := marionette.ProfileByName(body.Profile)
			if p == nil {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "unknown profile", "known": marionette.KnownProfiles()})
				return
			}
			n := marionette.BroadcastSetProfile(p)
			_ = json.NewEncoder(w).Encode(map[string]any{"updated": n, "profile": body.Profile})
		})

		apiServer.Handle("/api/marionette/cover", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			var body struct {
				Enabled    *bool `json:"enabled,omitempty"`
				IntervalMs *int  `json:"interval_ms,omitempty"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid body"})
				return
			}
			resp := map[string]any{}
			if body.Enabled != nil {
				resp["cover_toggled"] = marionette.BroadcastSetCoverEnabled(*body.Enabled)
				resp["enabled"] = *body.Enabled
			}
			if body.IntervalMs != nil && *body.IntervalMs >= 0 {
				d := time.Duration(*body.IntervalMs) * time.Millisecond
				resp["interval_updated"] = marionette.BroadcastSetCoverInterval(d)
				resp["interval_ms"] = *body.IntervalMs
			}
			_ = json.NewEncoder(w).Encode(resp)
		})

		apiServer.Handle("/api/p2p/stats", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if globalP2PRelay == nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintf(w, `{"error":"p2p relay not running"}`)
				return
			}
			stats := globalP2PRelay.Stats()
			data, _ := json.Marshal(stats)
			w.Write(data)
		})

		apiServer.Handle("/api/ml/weights", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			snap := mlpkg.GetGlobalSnapshot()
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

		wiraidBaseDir := os.Getenv("WHISPERA_WIRAID_DIR")
		if wiraidBaseDir == "" {
			wiraidBaseDir = "/var/lib/whispera/wiraid"
		}
		if os.Getenv("WHISPERA_PUBLIC_HOST") == "" && serverConfig.Server.PublicURL != "" {
			if u, err := url.Parse(serverConfig.Server.PublicURL); err == nil && u.Hostname() != "" {
				os.Setenv("WHISPERA_PUBLIC_HOST", u.Hostname())
				log.Printf("[wiraid] public host from config: %s", u.Hostname())
			}
		}
		if eng, err := wiraid.NewEngine(wiraidBaseDir); err != nil {
			log.Printf("[wiraid] init failed: %v", err)
		} else {
			globalWiraidEngine = eng
			eng.RegisterRoutes(apiServer.Handle)
			log.Printf("[wiraid] engine ready (base=%s, modules=%d)", wiraidBaseDir, len(eng.Registry.List()))
			go eng.StartEnabled()
			if globalRelay != nil {
				globalRelay.SetProxyDialer(&wiraidProxyDialer{eng: eng})
				log.Printf("[wiraid] per-module proxy routing active")
			}
		}

		globalProbeDetector = probedetector.New(probedetector.DefaultConfig())
		globalProbeDetector.Start()
		apiServer.SetProbeDetector(globalProbeDetector)

		phantomHandlersMu.RLock()
		for _, ph := range phantomHandlers {
			ph.SetProbeDetector(globalProbeDetector)
			ph.SetConnGuard(globalProbeDetector.Guard)
		}
		phantomHandlersMu.RUnlock()
		log.Printf("[Server] ProbeDetector propagated to %d phantom handler(s)", len(phantomHandlers))
	}

	if serverConfig.Bot.Enabled {
		if db.IsEnabled() {
			fmt.Println("[DEBUG] Whispera Server: starting Telegram bot module")
			botModule, err := bot.New(&serverConfig.Bot, db.Global())
			if err != nil {
				log.Printf("⚠ Warning: Failed to create Telegram Bot: %v", err)
			} else {
				if globalWiraidEngine != nil {
						botModule.SetWiraidEngine(globalWiraidEngine)
					}
					if globalBridgePool != nil {
						botModule.SetBridgePool(globalBridgePool)
					}
					if err := manager.Register(botModule); err != nil {
					return err
				}
				log.Printf("  ✓ Telegram Bot enabled (Admin ID: %d)", serverConfig.Bot.AdminID)
			}
		} else {
			log.Printf("ℹ Telegram Bot disabled (requires database)")
		}
	}

	if serverConfig.Correlation.Enabled {
		corrCfg := &evasion.CorrelationConfig{
			Enabled:         true,
			PaddingEnabled:  serverConfig.Correlation.PaddingEnabled,
			MixEnabled:      serverConfig.Correlation.JitterEnabled,
			ConstantRatePPS: serverConfig.Correlation.RateBytesPerSec,
		}
		if serverConfig.Correlation.MaxJitterMs > 0 {
			corrCfg.DelayJitter = time.Duration(serverConfig.Correlation.MaxJitterMs) * time.Millisecond
		} else {
			corrCfg.DelayJitter = 50 * time.Millisecond
		}
		if corrCfg.ConstantRatePPS <= 0 {
			corrCfg.ConstantRatePPS = 100
		}
		globalCorrelation = evasion.NewCorrelationDefense(corrCfg)
		manager.OnShutdown(func() { globalCorrelation.Stop() })
		log.Printf("✅ Correlation defense enabled (padding=%v, jitter=%v, cover=%v)",
			serverConfig.Correlation.PaddingEnabled, serverConfig.Correlation.JitterEnabled, serverConfig.Correlation.CoverTraffic)
	}

	{
		listenAddr := ":8000"
		if serverConfig.ML.ListenAddr != "" {
			listenAddr = serverConfig.ML.ListenAddr
		}
		mlCfg := &mlserver.Config{
			ListenAddr: listenAddr,
			Token:      serverConfig.API.AuthToken,
			DataDir:    "./ml_data",
		}
		mlSrv, err := mlserver.New(mlCfg)
		if err != nil {
			log.Printf("⚠ ML server init failed: %v", err)
		} else {
			if err := manager.Register(mlSrv); err != nil {
				return err
			}
			localML := "http://127.0.0.1" + listenAddr
			if !strings.HasPrefix(listenAddr, ":") {
				localML = "http://" + listenAddr
			}
			os.Setenv("WHISPERA_ML_SERVER", localML)
			log.Printf("✅ ML server (native Gorgonia engine) on %s", listenAddr)
		}
	}

	if serverConfig.Update.Enabled && serverConfig.Update.ManifestURL != "" {
		updCfg := &update.Config{
			ManifestURL:    serverConfig.Update.ManifestURL,
			CurrentVersion: Version,
			CheckInterval:  serverConfig.Update.CheckInterval.D(),
		}
		if updCfg.CheckInterval <= 0 {
			updCfg.CheckInterval = 1 * time.Hour
		}
		binaryPath, _ := os.Executable()
		updCfg.BinaryPath = binaryPath
		globalUpdater = update.NewUpdater(updCfg)
		globalUpdater.OnUpdateAvailable(func(v update.VersionInfo) {
			log.Printf("🔄 Update available: %s (current: %s)", v.Version, Version)
		})
		globalUpdater.OnUpdateApplied(func(oldV, newV string) {
			log.Printf("✅ Updated: %s → %s", oldV, newV)
		})
		globalUpdater.OnUpdateFailed(func(v string, err error) {
			log.Printf("⚠ Update to %s failed: %v", v, err)
		})
		globalUpdater.Start()
		manager.OnShutdown(func() { globalUpdater.Stop() })
		log.Printf("✅ Auto-updater enabled (manifest: %s, interval: %v)", serverConfig.Update.ManifestURL, updCfg.CheckInterval)
	}

	log.Printf("✓ Registered %d modules", len(manager.Registry().GetAll()))
	return nil
}

func handlePacket(data []byte, addr net.Addr) {
	if *debug {
		log.Printf("[Packet] Received %d bytes from %v", len(data), addr)
	}
	ctx := context.Background()

	if len(data) >= 32 && len(data) <= 96 && globalHandshake != nil {
		if !udpIPRateAllow(addr) {
			return
		}
		sess, err := globalHandshake.HandleHandshake(ctx, data, addr)
		if err == nil && sess != nil {
			if *debug {
				log.Printf("[Packet] Handshake completed for %v, session: %d", addr, sess.ID())
			}
			if response := globalHandshake.BuildResponse(sess); response != nil {
				if globalUDPTransport != nil {
					if _, err := globalUDPTransport.WriteTo(response, addr); err != nil {
						if *debug {
							log.Printf("[Packet] Failed to send handshake response: %v", err)
						}
					} else if *debug {
						log.Printf("[Packet] Sent handshake response (%d bytes) to %v", len(response), addr)
					}
				}
			}
			return
		}
	}

	if globalSessionMgr == nil {
		return
	}

	sess, ok := globalSessionMgr.GetSessionByAddr(addr)
	if !ok {
		if *debug {
			log.Printf("[Packet] No session for %v (Total sessions: %d), dropping packet",
				addr, globalSessionMgr.Count())
		}
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
					if *debug {
						log.Printf("[Packet] Relay error: %v", err)
					}
				}
				return
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
			if *debug {
				log.Printf("[Packet] Data plane error: %v", err)
			}
		}
	}
}

func handleTCPConnection(conn net.Conn, hsHandler *handshake.Handler) {
	defer conn.Close()

	addr := conn.RemoteAddr()
	if *debug {
		log.Printf("[TCP] New connection from %v", addr)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var firstByte [1]byte
	if _, err := io.ReadFull(conn, firstByte[:]); err != nil {
		if *debug {
			log.Printf("[TCP] Failed to read first byte from %v: %v", addr, err)
		}
		return
	}
	conn.SetReadDeadline(time.Time{})

	if hsHandler != nil && firstByte[0] == byte(handshake.HandshakeTypeInit) {
		rest := make([]byte, 63)
		if _, err := io.ReadFull(conn, rest); err != nil {
			if *debug {
				log.Printf("[TCP] Failed to read handshake body from %v: %v", addr, err)
			}
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

		sess, err := hsHandler.HandleHandshake(context.Background(), buf, addr)
		if err != nil {
			if *debug {
				log.Printf("[TCP] Handshake failed from %v: %v", addr, err)
			}
			return
		}
		if *debug {
			log.Printf("[TCP] Handshake completed for %v", addr)
		}
		if response := hsHandler.BuildResponse(sess); response != nil {
			if _, err := conn.Write(response); err != nil {
				return
			}
		}
		if globalRelay != nil {
			globalRelay.ServeTunnel(conn, false)
		}
	} else {
		if *debug {
			log.Printf("[TCP] No handshake from %v (first byte=0x%02x), routing directly to smux", addr, firstByte[0])
		}
		if globalRelay != nil {
			globalRelay.ServeTunnel(&prependConn{Conn: conn, prepend: []byte{firstByte[0]}}, false)
		}
	}
}

type UDPResponseWriter struct {
	transport  *udp.Transport
	addr       net.Addr
	obfuscator interfaces.Obfuscator
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
		return fmt.Errorf("UDP transport not available")
	}
	n, err := w.transport.WriteTo(payload, w.addr)
	if err == nil && n > 0 && w.UserID != "" {
		stats.AddTx(w.UserID, int64(n))
	}
	return err
}

func (w *UDPResponseWriter) RemoteAddr() net.Addr { return w.addr }

type TCPResponseWriter struct {
	conn       net.Conn
	obfuscator interfaces.Obfuscator
	debug      bool
	UserID     string
}

func (w *TCPResponseWriter) Write(data []byte) error {
	payload := data
	if w.obfuscator != nil {
		obfuscated, _, err := w.obfuscator.Process(data, interfaces.DirectionOutbound)
		if err != nil {
			return fmt.Errorf("obfuscation failed: %w", err)
		}
		payload = obfuscated
	}
	n, err := w.conn.Write(payload)
	if err == nil && n > 0 && w.UserID != "" {
		stats.AddTx(w.UserID, int64(n))
	}
	return err
}

func (w *TCPResponseWriter) RemoteAddr() net.Addr { return w.conn.RemoteAddr() }

func setupEventHandlers(manager *lifecycle.Manager) {
	eventBus := manager.Events()

	moduleStarted := eventBus.Subscribe("module.started")
	go func() {
		for event := range moduleStarted {
			log.Printf("  ✓ Module started: %s", event.Source)
		}
	}()

	moduleStopped := eventBus.Subscribe("module.stopped")
	go func() {
		for event := range moduleStopped {
			log.Printf("  ○ Module stopped: %s", event.Source)
		}
	}()

	if *debug {
		sessionEvents := eventBus.Subscribe("session.*")
		go func() {
			for event := range sessionEvents {
				log.Printf("[Session] %s: %v", event.Type, event.Data)
			}
		}()
	}

	handshakeEvents := eventBus.Subscribe("handshake.*")
	go func() {
		count := 0
		for range handshakeEvents {
			count++
			if count%100 == 0 {
				log.Printf("[Stats] Processed %d handshakes", count)
			}
		}
	}()

	manager.OnStart(func() error {
		log.Println("Initializing server components...")
		return nil
	})

	manager.OnReload(func() error {
		log.Println("Reloading configuration...")
		return nil
	})

	manager.OnShutdown(func() {
		log.Println("Cleanup complete")
	})
}

func registerBridgeWithMainServer() {
	cfg := globalServerConfig
	if cfg == nil {
		return
	}

	log.Printf("Registering bridge with main server: %s", cfg.UpstreamServer)

	publicIP := getPublicIP()
	if publicIP == "" {
		log.Printf("⚠ Bridge registration failed: could not determine public IP")
		return
	}

	port := "443"
	if len(cfg.Inbounds) > 0 {
		port = fmt.Sprintf("%d", cfg.Inbounds[0].Port)
	} else if cfg.Server.ListenAddr != "" {
		if _, p, err := net.SplitHostPort(cfg.Server.ListenAddr); err == nil {
			port = p
		}
	}

	address := fmt.Sprintf("%s:%s", publicIP, port)

	reqBody := map[string]string{
		"address":    address,
		"provider":   cfg.Bridge.Provider,
		"region":     cfg.Bridge.Region,
		"public_key": cfg.Server.PrivateKey,
		"type":       cfg.Bridge.Type,
		"token":      cfg.Bridge.RegistrationToken,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		log.Printf("⚠ Bridge registration failed: %v", err)
		return
	}

	client := &http.Client{Timeout: 30 * time.Second}
	url := fmt.Sprintf("https://%s/api/bridge-register", cfg.UpstreamServer)
	req1, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(data))
	req1.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req1)
	if err != nil {
		url = fmt.Sprintf("http://%s/api/bridge-register", cfg.UpstreamServer)
		req2, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(data))
		req2.Header.Set("Content-Type", "application/json")
		resp, err = client.Do(req2)
	}

	if err != nil {
		log.Printf("⚠ Bridge registration failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("⚠ Bridge registration failed: HTTP %d", resp.StatusCode)
		return
	}

	log.Printf("✓ Bridge registered with main server: %s", address)
}

func getPublicIP() string {
	client := &http.Client{Timeout: 5 * time.Second}
	services := []string{
		"https://ifconfig.me",
		"https://icanhazip.com",
		"https://api.ipify.org",
	}

	for _, svc := range services {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, svc, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		ip := strings.TrimSpace(string(buf[:n]))

		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// wiraidProxyDialer implements proxy.Dialer, routing connections through
// WirAid module SOCKS5 proxies when the destination matches a module's rules.
type wiraidProxyDialer struct {
	eng *wiraid.Engine
}

func (d *wiraidProxyDialer) Dial(network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err == nil {
		var port64 uint64
		fmt.Sscanf(portStr, "%d", &port64)
		if socksAddr, ok := d.eng.MatchRoute(host, uint16(port64)); ok {
			socks, err2 := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
			if err2 == nil {
				return socks.Dial(network, addr)
			}
		}
	}
	return proxy.Direct.Dial(network, addr)
}
