package sni_bypass

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

type Config struct {
	ServerName  string
	Fingerprint string
	FragmentSize int
	FragmentDelay time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		Fingerprint:   "chrome",
		FragmentSize:  41,
		FragmentDelay: 50 * time.Millisecond,
	}
}

var fingerprintMap = map[string]*utls.ClientHelloID{
	"chrome":  &utls.HelloChrome_Auto,
	"firefox": &utls.HelloFirefox_Auto,
	"safari":  &utls.HelloSafari_Auto,
	"random":  &utls.HelloRandomized,
}

func DialFragmented(addr string, cfg *Config) (net.Conn, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	fp, ok := fingerprintMap[cfg.Fingerprint]
	if !ok {
		fp = &utls.HelloChrome_Auto
	}

	serverName := cfg.ServerName
	if serverName == "" {
		serverName = extractHost(addr)
	}

	uConn := utls.UClient(tcpConn, &utls.Config{
		ServerName: serverName,
		MinVersion: utls.VersionTLS12,
		MaxVersion: utls.VersionTLS13,
	}, *fp)

	if err := uConn.BuildHandshakeState(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("build handshake: %w", err)
	}

	helloBytes := uConn.HandshakeState.Hello.Raw
	if len(helloBytes) == 0 {
		tcpConn.Close()
		return nil, fmt.Errorf("empty ClientHello")
	}

	records := fragmentClientHello(helloBytes, cfg.FragmentSize)

	for i, rec := range records {
		if _, err := tcpConn.Write(rec); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("write fragment %d: %w", i, err)
		}
		if i < len(records)-1 && cfg.FragmentDelay > 0 {
			jitter := time.Duration(randInt(0, int(cfg.FragmentDelay.Milliseconds()/2))) * time.Millisecond
			time.Sleep(cfg.FragmentDelay + jitter)
		}
	}

	uConn.SetUnderlyingConn(&alreadySentConn{Conn: tcpConn})

	if err := uConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return uConn, nil
}

func fragmentClientHello(hello []byte, fragSize int) [][]byte {
	if fragSize <= 0 {
		fragSize = 41
	}

	var records [][]byte

	for offset := 0; offset < len(hello); {
		end := offset + fragSize
		if end > len(hello) {
			end = len(hello)
		}
		chunk := hello[offset:end]

		record := make([]byte, 5+len(chunk))
		record[0] = 0x16
		record[1] = 0x03
		record[2] = 0x01
		record[3] = byte(len(chunk) >> 8)
		record[4] = byte(len(chunk))
		copy(record[5:], chunk)

		records = append(records, record)
		offset = end
	}

	return records
}

type alreadySentConn struct {
	net.Conn
	firstRead bool
}

func (c *alreadySentConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *alreadySentConn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}

func DialWithPadding(addr string, cfg *Config) (net.Conn, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	serverName := cfg.ServerName
	if serverName == "" {
		serverName = extractHost(addr)
	}

	spec, err := buildPaddedClientHelloSpec(serverName)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}

	uConn := utls.UClient(tcpConn, &utls.Config{
		ServerName: serverName,
		MinVersion: utls.VersionTLS12,
		MaxVersion: utls.VersionTLS13,
	}, utls.HelloCustom)

	if err := uConn.ApplyPreset(spec); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("apply spec: %w", err)
	}

	if err := uConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return uConn, nil
}

func buildPaddedClientHelloSpec(serverName string) (*utls.ClientHelloSpec, error) {
	sniLen := len(serverName)
	targetSize := 16384 + 64
	currentEstimate := 200 + sniLen
	paddingNeeded := targetSize - currentEstimate
	if paddingNeeded < 0 {
		paddingNeeded = 0
	}
	if paddingNeeded > 65535 {
		paddingNeeded = 65535
	}

	spec := &utls.ClientHelloSpec{
		TLSVersMax: utls.VersionTLS13,
		TLSVersMin: utls.VersionTLS12,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.GREASE_PLACEHOLDER,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.GREASEEncryptedClientHelloExtension{},
			&utls.SNIExtension{ServerName: serverName},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.CurveID(utls.GREASE_PLACEHOLDER),
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.UtlsPaddingExtension{PaddingLen: paddingNeeded, WillPad: true},
		},
	}
	return spec, nil
}

func extractHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func randInt(min, max int) int {
	if max <= min {
		return min
	}
	b := make([]byte, 1)
	io.ReadFull(rand.Reader, b)
	return min + int(b[0])%(max-min)
}
