package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

type PinStore struct {
	mu   sync.RWMutex
	pins map[string]string
	path string
}

func NewPinStore(path string) *PinStore {
	ps := &PinStore{
		pins: make(map[string]string),
		path: path,
	}
	ps.load()
	return ps
}

func (ps *PinStore) AddPin(bridgeID, certHash string) {
	ps.mu.Lock()
	ps.pins[bridgeID] = certHash
	ps.mu.Unlock()
	ps.save()
}

func (ps *PinStore) RemovePin(bridgeID string) {
	ps.mu.Lock()
	delete(ps.pins, bridgeID)
	ps.mu.Unlock()
	ps.save()
}

func (ps *PinStore) VerifyPin(bridgeID string, certDER []byte) bool {
	ps.mu.RLock()
	expected, exists := ps.pins[bridgeID]
	ps.mu.RUnlock()
	if !exists {
		return true
	}
	hash := sha256.Sum256(certDER)
	actual := hex.EncodeToString(hash[:])
	return actual == expected
}

func (ps *PinStore) GetPin(bridgeID string) string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.pins[bridgeID]
}

func CertHash(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return hex.EncodeToString(hash[:])
}

func (ps *PinStore) load() {
	data, err := os.ReadFile(ps.path)
	if err != nil {
		return
	}
	lines := splitLines(data)
	for _, line := range lines {
		parts := splitTab(line)
		if len(parts) == 2 {
			ps.pins[parts[0]] = parts[1]
		}
	}
}

func (ps *PinStore) save() {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	var buf []byte
	for id, hash := range ps.pins {
		buf = append(buf, []byte(id+"\t"+hash+"\n")...)
	}
	os.WriteFile(ps.path, buf, 0600)
}

func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			line := string(data[start:i])
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			if line != "" {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(data) {
		line := string(data[start:])
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func splitTab(s string) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\t' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

func GenerateSelfSignedCA(org string, validYears int) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{org}, CommonName: org + " CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(validYears) * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func IssueBridgeCert(caCertPEM, caKeyPEM []byte, bridgeID string, validDays int) (certPEM, keyPEM []byte, err error) {
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, fmt.Errorf("invalid CA cert")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("invalid CA key")
	}
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Whispera Bridge"}, CommonName: bridgeID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func NewMTLSServerConfig(caCertPEM, serverCertPEM, serverKeyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("invalid CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func NewMTLSClientConfig(caCertPEM, clientCertPEM, clientKeyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("invalid CA cert")
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
	}, nil
}
