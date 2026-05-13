package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"whispera/internal/adblock"
	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("mitm")

type TrafficMeta struct {
	Host      string
	Method    string
	URL       string
	UserAgent string
	Status    int
	IsTLS     bool
	SNI       string
	Timestamp time.Time
}

type MetaHook func(meta TrafficMeta)

// RequestHook is called before each forwarded request. Return false to block.
type RequestHook func(meta TrafficMeta) bool

type Config struct {
	ListenAddr  string
	TunnelDial  func(ctx context.Context, network, addr string) (net.Conn, error)
	MetaHook    MetaHook
	RequestHook RequestHook
}

type Proxy struct {
	*base.Module
	cfg    *Config
	caMu   sync.RWMutex
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	certMu sync.Map
}

func New(cfg *Config) (*Proxy, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:10899"
	}
	p := &Proxy{
		Module: base.NewModule("mitm.proxy", "1.0.0", nil),
		cfg:    cfg,
	}
	if err := p.generateCA(); err != nil {
		return nil, fmt.Errorf("mitm ca: %w", err)
	}
	return p, nil
}

func (p *Proxy) generateCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Whispera Local CA", Organization: []string{"Whispera"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	p.caMu.Lock()
	p.caCert = cert
	p.caKey = key
	p.caMu.Unlock()
	return nil
}

func (p *Proxy) CACertPEM() []byte {
	p.caMu.RLock()
	cert := p.caCert
	p.caMu.RUnlock()
	if cert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func (p *Proxy) signHostCert(host string) (*tls.Certificate, error) {
	if cached, ok := p.certMu.Load(host); ok {
		return cached.(*tls.Certificate), nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	p.caMu.RLock()
	caCert := p.caCert
	caKey := p.caKey
	p.caMu.RUnlock()

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return nil, err
	}
	p.certMu.Store(host, &tlsCert)
	return &tlsCert, nil
}

func (p *Proxy) Start() error {
	if err := p.Module.Start(); err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", p.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("mitm listen %s: %w", p.cfg.ListenAddr, err)
	}
	log.Info("MITM proxy listening on %s", p.cfg.ListenAddr)
	go p.serve(ln)
	return nil
}

func (p *Proxy) serve(ln net.Listener) {
	defer ln.Close()
	for p.IsRunning() {
		conn, err := ln.Accept()
		if err != nil {
			if p.IsRunning() {
				log.Error("mitm accept: %v", err)
			}
			return
		}
		go p.handleConn(conn)
	}
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if adblock.Global.IsBlockedHTTPS(host) {
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	if req.Method == http.MethodConnect {
		p.handleCONNECT(conn, req.Host)
		return
	}

	p.handleHTTP(conn, br, req)
}

func (p *Proxy) handleCONNECT(conn net.Conn, hostport string) {
	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		port = "443"
	}
	if port == "" {
		port = "443"
	}

	tlsCert, err := p.signHostCert(host)
	if err != nil {
		log.Error("mitm sign cert %s: %v", host, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			sni := chi.ServerName
			if sni != "" && sni != host {
				cert, err := p.signHostCert(sni)
				if err != nil {
					return nil, err
				}
				return &tls.Config{Certificates: []tls.Certificate{*cert}}, nil
			}
			return nil, nil
		},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}
	defer tlsConn.Close()

	sni := tlsConn.ConnectionState().ServerName
	if sni == "" {
		sni = host
	}

	var upstream net.Conn
	if p.cfg.TunnelDial != nil {
		upstream, err = p.cfg.TunnelDial(ctx, "tcp", hostport)
	} else {
		upstream, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	if err != nil {
		log.Error("mitm upstream dial %s: %v", hostport, err)
		return
	}
	defer upstream.Close()

	upstreamTLS := tls.Client(upstream, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	})
	if err := upstreamTLS.HandshakeContext(ctx); err != nil {
		upstreamTLS.Close()
		log.Error("mitm upstream tls %s: %v", host, err)
		return
	}
	defer upstreamTLS.Close()

	// Parse HTTP requests inside TLS for per-request inspection/blocking.
	p.proxyHTTPStream(tlsConn, bufio.NewReader(tlsConn), upstreamTLS, host, sni, true)
}

// proxyHTTPStream proxies a sequence of HTTP requests/responses between client and upstream.
// clientConn is used for write deadlines and writing responses.
// clientBR may contain pre-buffered bytes (e.g. first request already partially read).
func (p *Proxy) proxyHTTPStream(clientConn net.Conn, clientBR *bufio.Reader, upstream net.Conn, host, sni string, isTLS bool) {
	upstreamBR := bufio.NewReader(upstream)

	for {
		clientConn.SetReadDeadline(time.Now().Add(90 * time.Second))
		req, err := http.ReadRequest(clientBR)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})

		urlStr := req.URL.String()
		if !strings.HasPrefix(urlStr, "http") {
			scheme := "http"
			if isTLS {
				scheme = "https"
			}
			urlStr = scheme + "://" + host + urlStr
		}

		meta := TrafficMeta{
			Host:      host,
			Method:    req.Method,
			URL:       urlStr,
			UserAgent: req.Header.Get("User-Agent"),
			IsTLS:     isTLS,
			SNI:       sni,
			Timestamp: time.Now(),
		}

		if p.cfg.RequestHook != nil && !p.cfg.RequestHook(meta) {
			req.Body.Close()
			clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nContent-Type: text/plain\r\n\r\nBlocked.\n"))
			return
		}

		req.Header.Del("Proxy-Connection")
		req.Header.Del("Proxy-Authenticate")
		req.Header.Del("Proxy-Authorization")
		req.RequestURI = req.URL.RequestURI()

		upstream.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err := req.Write(upstream); err != nil {
			req.Body.Close()
			return
		}
		upstream.SetWriteDeadline(time.Time{})
		req.Body.Close()

		upstream.SetReadDeadline(time.Now().Add(60 * time.Second))
		resp, err := http.ReadResponse(upstreamBR, req)
		if err != nil {
			return
		}
		upstream.SetReadDeadline(time.Time{})

		meta.Status = resp.StatusCode
		if p.cfg.MetaHook != nil {
			p.cfg.MetaHook(meta)
		}

		clientConn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if err := resp.Write(clientConn); err != nil {
			resp.Body.Close()
			return
		}
		clientConn.SetWriteDeadline(time.Time{})
		resp.Body.Close()

		if req.Close || resp.Close || req.Header.Get("Connection") == "close" {
			return
		}
	}
}

func (p *Proxy) handleHTTP(conn net.Conn, br *bufio.Reader, firstReq *http.Request) {
	host := firstReq.Host
	if host == "" {
		host = firstReq.URL.Host
	}

	plainHost := host
	if !strings.Contains(plainHost, ":") {
		plainHost = plainHost + ":80"
	}
	h, port, err := net.SplitHostPort(plainHost)
	if err != nil {
		h = plainHost
		port = "80"
	}

	// Port 443 → TLS; everything else (80, 8080, custom) → plain HTTP.
	isTLS := port == "443"
	targetHost := net.JoinHostPort(h, port)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var rawConn net.Conn
	if p.cfg.TunnelDial != nil {
		rawConn, err = p.cfg.TunnelDial(ctx, "tcp", targetHost)
	} else {
		rawConn, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", targetHost)
	}
	if err != nil {
		log.Error("mitm http dial %s: %v", targetHost, err)
		return
	}
	defer rawConn.Close()

	var upstream net.Conn
	if isTLS {
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         h,
			InsecureSkipVerify: false,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tlsConn.Close()
			log.Error("mitm http→https tls %s: %v", h, err)
			return
		}
		upstream = tlsConn
	} else {
		upstream = rawConn
	}
	defer upstream.Close()

	// Re-serialize the first request and prepend it to the remaining buffered
	// bytes so proxyHTTPStream processes it as part of the normal request loop.
	var prefixBuf bytes.Buffer
	firstReq.Write(&prefixBuf)
	combinedBR := bufio.NewReader(io.MultiReader(&prefixBuf, br))

	p.proxyHTTPStream(conn, combinedBR, upstream, h, h, isTLS)
}

func (p *Proxy) Stop() error {
	return p.Module.Stop()
}

func (p *Proxy) ListenAddr() string {
	return p.cfg.ListenAddr
}
