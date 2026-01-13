package tls

import (
	"context"
	"net"

	utls "github.com/refraction-networking/utls"
)

// UTLSConfig configuration for uTLS
type UTLSConfig struct {
	Fingerprint string // "chrome", "firefox", "safari", "random", "360", "qq"
	MinVersion  uint16
	MaxVersion  uint16
}

var fingerprintMap = map[string]*utls.ClientHelloID{
	"chrome":  &utls.HelloChrome_Auto,
	"firefox": &utls.HelloFirefox_Auto,
	"safari":  &utls.HelloSafari_Auto,
	"ios":     &utls.HelloIOS_Auto,
	"android": &utls.HelloAndroid_11_OkHttp,
	"edge":    &utls.HelloEdge_Auto,
	"360":     &utls.Hello360_Auto,
	"qq":      &utls.HelloQQ_Auto,
	"random":  &utls.HelloRandomized,
}

// Dial connects to the address using uTLS with the specified fingerprint
func (c *UTLSConfig) Dial(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	fingerprint, ok := fingerprintMap[c.Fingerprint]
	if !ok {
		fingerprint = &utls.HelloChrome_Auto // Default to Chrome Auto for stability
	}

	uconn := utls.UClient(conn, &utls.Config{
		ServerName: extractHost(addr),
		MinVersion: c.MinVersion,
		MaxVersion: c.MaxVersion,
	}, *fingerprint)

	if err := uconn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	return uconn, nil
}

// WrapConn wraps an existing connection with uTLS
func (c *UTLSConfig) WrapConn(conn net.Conn, addr string) (net.Conn, error) {
	fingerprint, ok := fingerprintMap[c.Fingerprint]
	if !ok {
		fingerprint = &utls.HelloChrome_Auto // Default to Chrome Auto for stability
	}

	uconn := utls.UClient(conn, &utls.Config{
		ServerName: extractHost(addr),
		MinVersion: c.MinVersion,
		MaxVersion: c.MaxVersion,
	}, *fingerprint)

	if err := uconn.Handshake(); err != nil {
		return nil, err
	}

	return uconn, nil
}

func extractHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // assume it's just host
	}
	return host
}
