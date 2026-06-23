package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

type ClonedCertInfo struct {
	Subject   string
	DNSNames  []string
	NotBefore time.Time
	NotAfter  time.Time
}

func fetchRealCert(domain string) (*x509.Certificate, error) {
	host := domain
	if h, _, err := net.SplitHostPort(domain); err == nil {
		host = h
	}
	addr := net.JoinHostPort(host, "443")

	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate presented by %s", addr)
	}
	return certs[0], nil
}

func cloneCertTemplate(real *x509.Certificate) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	notBefore := time.Now().Add(-24 * time.Hour)
	validity := real.NotAfter.Sub(real.NotBefore)
	if validity <= 0 {
		validity = 90 * 24 * time.Hour
	}
	notAfter := notBefore.Add(validity)

	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               real.Subject,
		DNSNames:              real.DNSNames,
		IPAddresses:           real.IPAddresses,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, nil
}

func CloneCertToFiles(domain, outCert, outKey string) (*ClonedCertInfo, error) {
	real, err := fetchRealCert(domain)
	if err != nil {
		return nil, fmt.Errorf("fetch real certificate from %s: %w", domain, err)
	}

	template, err := cloneCertTemplate(real)
	if err != nil {
		return nil, fmt.Errorf("build certificate template: %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certOut, err := os.OpenFile(outCert, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", outCert, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyOut, err := os.OpenFile(outKey, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", outKey, err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return &ClonedCertInfo{
		Subject:   template.Subject.String(),
		DNSNames:  template.DNSNames,
		NotBefore: template.NotBefore,
		NotAfter:  template.NotAfter,
	}, nil
}

var sniFileSafe = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

func SNICertPaths(decoyCertDir, sni string) (certPath, keyPath string, ok bool) {
	if decoyCertDir == "" || sni == "" || !sniFileSafe.MatchString(sni) {
		return "", "", false
	}
	return filepath.Join(decoyCertDir, sni+".crt"), filepath.Join(decoyCertDir, sni+".key"), true
}

var (
	sniCertCacheMu sync.RWMutex
	sniCertCache   = map[string]*tls.Certificate{}
)

func loadSNICert(decoyCertDir, sni string) (*tls.Certificate, bool) {
	certPath, keyPath, ok := SNICertPaths(decoyCertDir, sni)
	if !ok {
		return nil, false
	}

	sniCertCacheMu.RLock()
	c, found := sniCertCache[sni]
	sniCertCacheMu.RUnlock()
	if found {
		return c, true
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, false
	}

	sniCertCacheMu.Lock()
	sniCertCache[sni] = &cert
	sniCertCacheMu.Unlock()
	return &cert, true
}
