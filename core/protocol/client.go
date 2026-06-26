package protocol

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"time"

	quicgo "github.com/quic-go/quic-go"
	http3 "github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func newH2Transport(dial func(context.Context, string, string, *tls.Config) (net.Conn, error)) *http2.Transport {
	stub := &http.Transport{
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerStream:     h2StreamWindow,
			MaxReceiveBufferPerConnection: h2ConnWindow,
		},
	}
	h2t, err := http2.ConfigureTransports(stub)
	if err != nil || h2t == nil {
		h2t = &http2.Transport{}
	}
	h2t.ConnPool = nil
	h2t.MaxReadFrameSize = 1 << 20
	h2t.ReadIdleTimeout = 30 * time.Second
	h2t.PingTimeout = 15 * time.Second
	h2t.MaxDecoderHeaderTableSize = 65536
	h2t.MaxHeaderListSize = 262144
	h2t.DisableCompression = true
	h2t.DialTLSContext = dial
	return h2t
}

func Client(ctx context.Context, cfg *ClientConfig) (net.Conn, error) {
	sessionID := make([]byte, 16)
	if _, err := crand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("whispera: session id: %w", err)
	}
	anchor := time.Now().UTC().Truncate(time.Second)

	keys := DeriveKeys(cfg.SharedSecret)
	sched := NewWindowScheduler(keys.Behavior, sessionID, anchor)

	windowIdx := sched.CurrentIndex()
	bp := DeriveBehaviorParams(keys.Behavior, windowIdx, sessionID)
	path := GeneratePath(bp.PathSeed, windowIdx)
	token := AuthToken(keys.Auth, anchor.Unix()/authWindowSeconds, sessionID)

	sni := pickSNI(cfg)
	origin := "https://" + sni

	helloID, helloSpec := pickFingerprint()

	dialFn := func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		var rawConn net.Conn
		var err error
		if cfg.TCPDialer != nil {
			rawConn, err = cfg.TCPDialer(ctx, network, addr)
		} else {
			d := &net.Dialer{Timeout: 10 * time.Second}
			rawConn, err = d.DialContext(ctx, network, addr)
		}
		if err != nil {
			return nil, err
		}
		if tcpConn, ok := rawConn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(time.Duration(30+mrand.Intn(61)) * time.Second)
			tcpConn.SetNoDelay(true)
		}
		uCfg := &utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		}
		if cfg.ServerCertPin != "" {
			uCfg.VerifyPeerCertificate = pinVerifier(cfg.ServerCertPin)
		}
		if sc, ok := cfg.SessionCache.(utls.ClientSessionCache); ok {
			uCfg.ClientSessionCache = sc
		}
		var uConn *utls.UConn
		if helloSpec != nil {
			uConn = utls.UClient(rawConn, uCfg, utls.HelloCustom)
			if err := uConn.ApplyPreset(helloSpec); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("whispera: apply fingerprint: %w", err)
			}
		} else {
			uConn = utls.UClient(rawConn, uCfg, helloID)
			if err := uConn.BuildHandshakeState(); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("whispera: build hello: %w", err)
			}
		}
		if camoKey := deriveCamoKey(cfg.SharedSecret); camoKey != nil {
			if hello := uConn.HandshakeState.Hello; hello != nil && len(hello.Random) == 32 {
				if keyShare := extractX25519KeyShare(hello.KeyShares); len(keyShare) > 0 {
					marker := buildCamoMarker(camoKey, keyShare)
					copy(hello.Random, marker[:])
				}
			}
		}
		if err := uConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("whispera: utls handshake: %w", err)
		}
		return uConn, nil
	}

	h2Transport := newH2Transport(dialFn)
	decoyTransport := newH2Transport(dialFn)

	pr, pw := io.Pipe()
	bpw := newBufferedPipeWriter(pw)

	tunnelAddr := cfg.ServerAddr
	if cfg.EnableQUIC && cfg.QUICAddr != "" {
		tunnelAddr = cfg.QUICAddr
	}
	url := fmt.Sprintf("https://%s%s", tunnelAddr, path)

	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())

	req, err := http.NewRequestWithContext(tunnelCtx, http.MethodPost, url, pr)
	if err != nil {
		tunnelCancel()
		pr.Close()
		bpw.Close()
		return nil, fmt.Errorf("whispera: build request: %w", err)
	}
	req.Host = sni
	req.Header.Set("Content-Type", contentType)
	req.Header.Set(headerToken, "Bearer "+token)
	applyBrowserHeaders(req, origin)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: encodeSession(sessionID, anchor)})

	network := "tcp"
	local := staticAddr{network, tunnelAddr}
	remote := staticAddr{network, tunnelAddr}

	pc := newPipelinedConn(pr, bpw, tunnelCancel, local, remote)

	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	var tunnelTransport http.RoundTripper
	if cfg.EnableQUIC {
		tlsCfgQUIC := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		}
		if cfg.ServerCertPin != "" {
			tlsCfgQUIC.VerifyPeerCertificate = pinVerifier(cfg.ServerCertPin)
		}
		tunnelTransport = &http3.Transport{
			TLSClientConfig:    tlsCfgQUIC,
			QUICConfig:         chromeLikeQUICConfig(),
			DisableCompression: true,
			Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, qCfg *quicgo.Config) (*quicgo.Conn, error) {
				udpAddr, err := net.ResolveUDPAddr("udp", addr)
				if err != nil {
					return nil, err
				}
				pconn, err := net.ListenUDP("udp", nil)
				if err != nil {
					return nil, err
				}
				if camoKey := deriveCamoKey(cfg.SharedSecret); camoKey != nil {
					if probe, perr := buildQUICCamoProbe(camoKey, sni); perr == nil {
						_, _ = pconn.WriteToUDP(probe, udpAddr)
					}
				}
				qconn, derr := quicgo.Dial(ctx, pconn, udpAddr, tlsConf, qCfg)
				if derr == nil && cfg.OnQUICConn != nil {
					cfg.OnQUICConn(qconn)
				}
				return qconn, derr
			},
		}
	} else {
		tunnelTransport = h2Transport
	}

	client := &http.Client{Transport: tunnelTransport, CheckRedirect: noRedirect}
	decoyClient := &http.Client{Transport: decoyTransport, CheckRedirect: noRedirect}

	fc := NewFrameConn(pc)

	go runDecoy(tunnelCtx, decoyClient, cfg.ServerAddr, sni, origin, bp, fc)

	connected := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			pc.deliver(nil)
			connected <- err
			return
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			pc.deliver(nil)
			connected <- fmt.Errorf("whispera: server returned status %d", resp.StatusCode)
			return
		}
		if !pc.deliver(resp.Body) {
			resp.Body.Close()
		}
		connected <- nil
	}()

	select {
	case err := <-connected:
		if err != nil {
			tunnelCancel()
			pc.Close()
			return nil, fmt.Errorf("whispera: tunnel POST not established: %w", err)
		}
	case <-ctx.Done():
		tunnelCancel()
		pc.Close()
		return nil, ctx.Err()
	}

	return fc, nil
}
