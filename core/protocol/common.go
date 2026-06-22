package protocol

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"time"

	quicgo "github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"

	"whispera/common/log"
)

type UserEntry struct {
	UserID string
	PSK    []byte
}

var traceLog = logger.Trace()

func NewSessionCache(capacity int) any {
	return utls.NewLRUClientSessionCache(capacity)
}

var decoyGraph = [4][]string{
	{"/api/v1/config", "/cdn/app/index.js", "/assets/main.css"},
	{"/static/vendor.js", "/static/app.js", "/assets/theme.css", "/cdn/fonts/roboto.woff2"},
	{"/static/icons/192.png", "/favicon.ico", "/manifest.json", "/robots.txt"},
	{"/api/v1/health", "/api/v1/status"},
}

const (
	sessionCookie       = "_s"
	headerToken         = "Authorization"
	contentType         = "application/octet-stream"
	contentTypeDownload = "video/mp4"

	h2StreamWindow = 64 << 20
	h2ConnWindow   = 256 << 20
)

func chromeLikeQUICConfig() *quicgo.Config {
	return &quicgo.Config{
		Versions:                       []quicgo.Version{quicgo.Version1},
		MaxIdleTimeout:                 30 * time.Second,
		HandshakeIdleTimeout:           10 * time.Second,
		InitialStreamReceiveWindow:     6 * 1024 * 1024,
		MaxStreamReceiveWindow:         6 * 1024 * 1024,
		InitialConnectionReceiveWindow: 15 * 1024 * 1024,
		MaxConnectionReceiveWindow:     15 * 1024 * 1024,
		KeepAlivePeriod:                15 * time.Second,
		MaxIncomingStreams:             300,
		MaxIncomingUniStreams:          100,
		Allow0RTT:                      true,
	}
}

func encodeSession(sessionID []byte, anchor time.Time) string {
	buf := make([]byte, 24)
	copy(buf, sessionID)
	binary.BigEndian.PutUint64(buf[16:], uint64(anchor.Unix()))
	return base64.RawURLEncoding.EncodeToString(buf)
}

func decodeSession(s string) (sessionID []byte, anchor time.Time, err error) {
	buf, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(buf) != 24 {
		return nil, time.Time{}, fmt.Errorf("whispera: bad session header")
	}
	sessionID = buf[:16]
	anchor = time.Unix(int64(binary.BigEndian.Uint64(buf[16:])), 0)
	return
}

var defaultSNIPool = []string{
	"yandex.ru", "ya.ru", "mail.ru", "vk.com", "ok.ru",
	"rutube.ru", "dzen.ru", "avito.ru", "ozon.ru", "wildberries.ru",
}

func validSNI(s string) bool {
	return s != "" && net.ParseIP(s) == nil
}

func pickSNI(cfg *ClientConfig) string {
	pool := make([]string, 0, len(cfg.ServerNames)+1)
	for _, s := range cfg.ServerNames {
		if validSNI(s) {
			pool = append(pool, s)
		}
	}
	if len(pool) == 0 && validSNI(cfg.ServerName) {
		pool = append(pool, cfg.ServerName)
	}
	if len(pool) == 0 {
		pool = defaultSNIPool
	}
	return pool[mrand.Intn(len(pool))]
}

func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func pinVerifier(pin string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("whispera: no server certificate to pin")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("whispera: parse server cert: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(SPKIPin(cert)), []byte(pin)) != 1 {
			return fmt.Errorf("whispera: server cert pin mismatch")
		}
		return nil
	}
}
