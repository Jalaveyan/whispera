package protocol

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

func FetchServerFingerprints(ctx context.Context, cfg *ClientConfig) (int, error) {
	sessionID := make([]byte, 16)
	if _, err := rand.Read(sessionID); err != nil {
		return 0, fmt.Errorf("whispera: fp sync session id: %w", err)
	}
	anchor := time.Now().UTC().Truncate(time.Second)
	keys := DeriveKeys(cfg.SharedSecret)
	token := AuthToken(keys.Auth, anchor.Unix()/authWindowSeconds, sessionID)
	sni := pickSNI(cfg)

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
		uCfg := &utls.Config{ServerName: sni, InsecureSkipVerify: true}
		if cfg.ServerCertPin != "" {
			uCfg.VerifyPeerCertificate = pinVerifier(cfg.ServerCertPin)
		}
		var uConn *utls.UConn
		if helloSpec != nil {
			uConn = utls.UClient(rawConn, uCfg, utls.HelloCustom)
			if err := uConn.ApplyPreset(helloSpec); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("whispera: fp sync fingerprint: %w", err)
			}
		} else {
			uConn = utls.UClient(rawConn, uCfg, helloID)
		}
		if err := uConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("whispera: fp sync handshake: %w", err)
		}
		return uConn, nil
	}

	client := &http.Client{Transport: newH2Transport(dialFn), Timeout: 15 * time.Second}

	url := fmt.Sprintf("https://%s/video/sync", cfg.ServerAddr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Host = sni
	req.Header.Set(headerToken, "Bearer "+token)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: encodeSession(sessionID, anchor)})

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("whispera: fp sync request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("whispera: fp sync server returned status %d", resp.StatusCode)
	}

	var body struct {
		Fingerprints []string `json:"fingerprints"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("whispera: fp sync decode: %w", err)
	}

	n := 0
	for _, enc := range body.Fingerprints {
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			continue
		}
		if HarvestRawClientHello(raw) == nil {
			n++
		}
	}
	return n, nil
}
