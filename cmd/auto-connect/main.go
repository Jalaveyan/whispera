package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"whispera/internal/modules/config"
)

var (
	connectionKey = flag.String("key", "", "Connection key (whispera://...)")
	configFile    = flag.String("config", "", "Config file path")
	socksPort     = flag.Int("socks-port", 1080, "SOCKS5 proxy port")
	tunMode       = flag.Bool("tun", false, "Enable TUN mode (requires admin)")
	daemon        = flag.Bool("daemon", false, "Run as background daemon")
	checkIP       = flag.Bool("check-ip", true, "Check IP after connection")
	verbose       = flag.Bool("verbose", false, "Verbose logging")
)

func main() {
	flag.Parse()

	log.SetPrefix("[Whispera] ")
	log.SetFlags(log.Ltime)

	key := findConnectionKey()
	if key == "" {
		log.Fatal("No connection key found. Use -key flag or create ~/.whispera/key.txt")
	}

	ck, err := config.ParseConnectionKey(key)
	if err != nil {
		log.Fatalf("Invalid connection key: %v", err)
	}

	log.Printf("Server: %s", ck.Server)
	log.Printf("Profile: %s", ck.ObfsProfile)
	log.Printf("Transport: %s", ck.Transport)
	if ck.PhantomEnabled {
		log.Printf("Phantom: enabled (SNI: %s)", ck.PhantomSNI)
	}
	if ck.EnableASNBypass {
		log.Printf("ASN Bypass: enabled (TLS: %s)", ck.TLSFingerprint)
	}

	cfgPath := generateConfig(ck)

	if *daemon {
		runDaemon(cfgPath, key)
		return
	}

	startClient(cfgPath, key)
}

func findConnectionKey() string {
	if *connectionKey != "" {
		return *connectionKey
	}

	if key := os.Getenv("WHISPERA_KEY"); key != "" {
		return key
	}
	if *configFile != "" {
		data, err := ioutil.ReadFile(*configFile)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}

	home, _ := os.UserHomeDir()
	keyPaths := []string{
		filepath.Join(home, ".whispera", "key.txt"),
		filepath.Join(home, ".whispera", "connection.key"),
		"./key.txt",
		"./whispera.key",
	}

	for _, path := range keyPaths {
		data, err := ioutil.ReadFile(path)
		if err == nil {
			key := strings.TrimSpace(string(data))
			if strings.HasPrefix(key, "whispera://") {
				log.Printf("Loaded key from: %s", path)
				return key
			}
		}
	}

	return ""
}

func generateConfig(ck *config.ConnectionKey) string {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".whispera")
	os.MkdirAll(configDir, 0700)

	cfgPath := filepath.Join(configDir, "client_config.yaml")

	profile := ck.ObfsProfile
	if profile == "" {
		profile = "vk" 
	}

	phantomSNI := ck.PhantomSNI
	if phantomSNI == "" {
		phantomSNI = "cloudflare.com"
	}

	tlsFP := ck.TLSFingerprint
	if tlsFP == "" {
		tlsFP = "chrome"
	}

	cfg := fmt.Sprintf(`# Whispera Client Configuration (auto-generated)
# Generated: %s

server: "%s"
psk: "%s"
server_pub: "%s"

# SOCKS5 Proxy
socks:
  enabled: true
  address: "127.0.0.1"
  port: %d

# Obfuscation
obfuscation:
  enabled: true
  profile: "%s"

# Phantom Protocol
phantom:
  enabled: %v
  sni: "%s"
  short_id: "%s"

# ASN Bypass
asn_bypass:
  enabled: %v
  tls_fingerprint: "%s"
  domain_front: "%s"

# Connection
connection:
  timeout: 30s
  keep_alive: 25s
  retry_interval: 5s
  max_retries: -1

# Auto-reconnect
auto_reconnect: true
`, time.Now().Format(time.RFC3339),
		ck.Server,
		ck.PSK,
		ck.ServerPub,
		*socksPort,
		profile,
		ck.PhantomEnabled,
		phantomSNI,
		ck.PhantomShortID,
		ck.EnableASNBypass,
		tlsFP,
		ck.DomainFrontHost,
	)

	ioutil.WriteFile(cfgPath, []byte(cfg), 0600)
	log.Printf("Config written to: %s", cfgPath)

	return cfgPath
}

func startClient(cfgPath, key string) {
	log.Println("Starting Whispera client...")

	clientPath := findClientBinary()
	if clientPath == "" {
		log.Fatal("Client binary not found")
	}

	args := []string{"-config", cfgPath, "-key", key}
	if *verbose {
		args = append(args, "-verbose")
	}

	cmd := exec.CommandContext(context.Background(), clientPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		if cmd.Process != nil {
			cmd.Process.Signal(syscall.SIGTERM)
		}
	}()

	err := cmd.Start()
	if err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}

	log.Printf("Client started (PID: %d)", cmd.Process.Pid)

	waitForSOCKS()

	if *tunMode {
		startTUN()
	}

	if *checkIP {
		go checkExternalIP()
	}

	cmd.Wait()
}

func findClientBinary() string {
	names := []string{"whispera-client", "whispera-go-client"}
	if runtime.GOOS == "windows" {
		names = []string{"whispera-client.exe", "whispera-go-client.exe"}
	}

	for _, name := range names {
		if _, err := os.Stat(name); err == nil {
			return "./" + name
		}
	}

	for _, name := range names {
		path, err := exec.LookPath(name)
		if err == nil {
			return path
		}
	}

	home, _ := os.UserHomeDir()
	locations := []string{
		filepath.Join(home, ".whispera", "bin"),
		"/usr/local/bin",
		"/opt/whispera/bin",
	}

	for _, loc := range locations {
		for _, name := range names {
			path := filepath.Join(loc, name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	return ""
}

func waitForSOCKS() {
	addr := fmt.Sprintf("127.0.0.1:%d", *socksPort)
	log.Printf("Waiting for SOCKS5 proxy on %s...", addr)

	for i := 0; i < 30; i++ {
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", addr)
		if err == nil {
			conn.Close()
			log.Println("✓ SOCKS5 proxy is ready")
			return
		}
		time.Sleep(time.Second)
	}

	log.Println("⚠ SOCKS5 proxy not responding (continuing anyway)")
}

func startTUN() {
	log.Println("Starting TUN mode...")

	tunPath := findTUNBinary()
	if tunPath == "" {
		log.Println("⚠ TUN binary not found, skipping TUN mode")
		return
	}

	home, _ := os.UserHomeDir()
	tunConfig := filepath.Join(home, ".whispera", "tun.yml")

	cfg := fmt.Sprintf(`misc:
  log-level: info

socks5:
  address: 127.0.0.1
  port: %d
  udp: true

tunnel:
  mtu: 1500
`, *socksPort)

	ioutil.WriteFile(tunConfig, []byte(cfg), 0600)

	cmd := exec.CommandContext(context.Background(), tunPath, tunConfig)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		log.Printf("⚠ Failed to start TUN: %v", err)
		return
	}

	log.Printf("✓ TUN started (PID: %d)", cmd.Process.Pid)
}

func findTUNBinary() string {
	names := []string{"hev-socks5-tunnel"}
	if runtime.GOOS == "windows" {
		names = []string{"hev-socks5-tunnel.exe"}
	}

	for _, name := range names {
		if _, err := os.Stat(name); err == nil {
			return "./" + name
		}
	}

	for _, name := range names {
		path, err := exec.LookPath(name)
		if err == nil {
			return path
		}
	}

	return ""
}

func checkExternalIP() {
	time.Sleep(3 * time.Second)

	proxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", *socksPort)
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		log.Printf("IP check failed (proxy URL): %v", err)
		return
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://2ip.ru/api/self", nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("IP check failed: %v", err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		IP string `json:"ip"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	log.Printf("✓ External IP: %s", result.IP)
}

func runDaemon(cfgPath, key string) {
	log.Println("Running as daemon...")

	for {
		startClient(cfgPath, key)
		log.Println("Client exited, restarting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}
