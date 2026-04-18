package wiraid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type GenCtx struct {
	ModuleDir string
	Host      string
	Binary    string
	execCache map[string]string
}

func (c *GenCtx) runExec(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("exec_cmd is empty")
	}
	rendered := make([]string, len(argv))
	for i, a := range argv {
		a = strings.ReplaceAll(a, "{binary}", c.Binary)
		a = strings.ReplaceAll(a, "{module_dir}", c.ModuleDir)
		rendered[i] = a
	}
	key := strings.Join(rendered, "\x00")
	if c.execCache == nil {
		c.execCache = map[string]string{}
	}
	if out, ok := c.execCache[key]; ok {
		return out, nil
	}
	cmd := exec.CommandContext(context.Background(), rendered[0], rendered[1:]...)
	cmd.Dir = c.ModuleDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("exec %v: %w (%s)", rendered, err, strings.TrimSpace(string(out)))
	}
	s := string(out)
	c.execCache[key] = s
	return s, nil
}

func generateSelfSignedCert(moduleDir, host string) (certPath string, err error) {
	if host == "" {
		host = "localhost"
	}
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		return "", err
	}
	certFile := filepath.Join(moduleDir, "tls.crt")
	keyFile := filepath.Join(moduleDir, "tls.key")
	if _, e1 := os.Stat(certFile); e1 == nil {
		if _, e2 := os.Stat(keyFile); e2 == nil {
			return certFile, nil
		}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", err
	}
	cf, err := os.OpenFile(certFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kf, err := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()
	return certFile, nil
}

func GenerateParamCtx(schema ParamSchema, ctx *GenCtx) (string, error) {
	switch schema.Generator {
	case "self_signed_cert":
		return generateSelfSignedCert(ctx.ModuleDir, ctx.Host)
	case "exec":
		out, err := ctx.runExec(schema.ExecCmd)
		if err != nil {
			return "", err
		}
		if schema.ExecRegex == "" {
			return strings.TrimSpace(out), nil
		}
		re, err := regexp.Compile(schema.ExecRegex)
		if err != nil {
			return "", fmt.Errorf("exec_regex compile: %w", err)
		}
		m := re.FindStringSubmatch(out)
		group := schema.ExecGroup
		if group <= 0 {
			group = 1
		}
		if len(m) <= group {
			return "", fmt.Errorf("exec_regex %q did not match stdout", schema.ExecRegex)
		}
		return strings.TrimSpace(m[group]), nil
	}
	return GenerateParam(schema)
}

func GenerateParam(schema ParamSchema) (string, error) {
	switch schema.Generator {
	case "":
		if schema.Default != "" {
			return schema.Default, nil
		}
		return "", nil
	case "random_hex":
		n := schema.Length
		if n <= 0 {
			n = 16
		}
		buf := make([]byte, n)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		return hex.EncodeToString(buf), nil
	case "random_alnum":
		n := schema.Length
		if n <= 0 {
			n = 16
		}
		const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		buf := make([]byte, n)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for i, b := range buf {
			buf[i] = alphabet[int(b)%len(alphabet)]
		}
		return string(buf), nil
	case "env":
		if schema.Env == "" {
			return "", fmt.Errorf("env generator needs 'env' field")
		}
		return os.Getenv(schema.Env), nil
	case "fixed":
		return schema.Value, nil
	default:
		return "", fmt.Errorf("unknown generator: %s", schema.Generator)
	}
}

func FillMissingParams(m *InstalledModule) (bool, error) {
	if m.Params == nil {
		m.Params = make(map[string]string)
	}
	gctx := &GenCtx{
		ModuleDir: m.Dir,
		Host:      os.Getenv("WHISPERA_PUBLIC_HOST"),
		Binary:    m.Binary,
	}
	changed := false
	for key, schema := range m.Manifest.ParamsSchema {
		if _, ok := m.Params[key]; ok {
			continue
		}
		if schema.Generator == "" && schema.Default == "" {
			continue
		}
		v, err := GenerateParamCtx(schema, gctx)
		if err != nil {
			if schema.Generator == "exec" {
				fmt.Fprintf(os.Stderr, "[wiraid] warn: param %q exec generator failed: %v (will retry on next enable)\n", key, err)
				continue
			}
			return changed, fmt.Errorf("param %q: %w", key, err)
		}
		if v == "" {
			continue
		}
		m.Params[key] = v
		changed = true
	}
	return changed, nil
}
