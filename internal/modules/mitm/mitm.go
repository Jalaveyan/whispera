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

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("mitm")

type TrafficMeta struct {
	Host      string
	UserAgent string
	IsTLS     bool
	SNI       string
	Timestamp time.Time
}

type MetaHook func(meta TrafficMeta)

type Config struct {
	ListenAddr string
	TunnelDial func(ctx context.Context, network, addr string) (net.Conn, error)
	MetaHook   MetaHook
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

	if req.Method == http.MethodConnect {
		p.handleCONNECT(conn, br, req.Host)
		return
	}

	p.handleHTTP(conn, br, req)
}

func (p *Proxy) handleCONNECT(conn net.Conn, _ *bufio.Reader, hostport string) {
	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	host, _, _ := net.SplitHostPort(hostport)

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

	var upstream net.Conn
	if p.cfg.TunnelDial != nil {
		upstream, err = p.cfg.TunnelDial(ctx, "tcp", hostport)
	} else {
		upstream, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", hostport)
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

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		io.Copy(pw, tlsConn)
	}()

	meta := TrafficMeta{
		Host:      host,
		IsTLS:     true,
		SNI:       sni,
		Timestamp: time.Now(),
	}

	go p.teeAndForward(pr, upstreamTLS, &meta)
	io.Copy(tlsConn, upstreamTLS)

	if p.cfg.MetaHook != nil && meta.Host != "" {
		p.cfg.MetaHook(meta)
	}
}

func (p *Proxy) teeAndForward(r io.Reader, w io.Writer, meta *TrafficMeta) {
	buf := make([]byte, 4096)
	first := true
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if first {
				first = false
				ua := extractUserAgent(buf[:n])
				if ua != "" {
					meta.UserAgent = ua
				}
			}
			w.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func (p *Proxy) handleHTTP(conn net.Conn, br *bufio.Reader, req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
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
	useHTTPS := port == "80" || port == "8080" || port == ""
	var httpsHost string
	if useHTTPS {
		httpsHost = h + ":443"
	} else {
		httpsHost = plainHost
	}

	meta := TrafficMeta{
		Host:      h,
		UserAgent: req.Header.Get("User-Agent"),
		IsTLS:     useHTTPS,
		Timestamp: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var rawConn net.Conn
	if p.cfg.TunnelDial != nil {
		rawConn, err = p.cfg.TunnelDial(ctx, "tcp", httpsHost)
	} else {
		rawConn, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", httpsHost)
	}
	if err != nil {
		log.Error("mitm http dial %s: %v", httpsHost, err)
		return
	}

	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")

	if p.cfg.MetaHook != nil {
		p.cfg.MetaHook(meta)
	}

	if useHTTPS {
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         h,
			InsecureSkipVerify: false,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tlsConn.Close()
			rawConn.Close()
			log.Error("mitm http→https tls handshake %s: %v", h, err)
			return
		}
		defer tlsConn.Close()
		req.URL.Scheme = "https"
		if err := req.Write(tlsConn); err != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(tlsConn, conn)
		}()
		io.Copy(conn, tlsConn)
		<-done
	} else {
		defer rawConn.Close()
		if err := req.Write(rawConn); err != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			io.Copy(rawConn, conn)
		}()
		io.Copy(conn, rawConn)
		<-done
	}
}

func extractUserAgent(data []byte) string {
	idx := bytes.Index(data, []byte("User-Agent: "))
	if idx < 0 {
		return ""
	}
	rest := data[idx+12:]
	end := bytes.IndexByte(rest, '\r')
	if end < 0 {
		end = bytes.IndexByte(rest, '\n')
	}
	if end < 0 {
		return ""
	}
	return string(rest[:end])
}

func (p *Proxy) Stop() error {
	return p.Module.Stop()
}

func (p *Proxy) ListenAddr() string {
	return p.cfg.ListenAddr
}
