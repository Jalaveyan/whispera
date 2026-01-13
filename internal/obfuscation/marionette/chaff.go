package marionette

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ChaffGenerator generates fake traffic (chaff) to disguise the real connection
type ChaffGenerator struct {
	Enabled     bool
	Targets     []string
	Interval    time.Duration
	Variance    time.Duration
	Concurrency int
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewChaffGenerator creates a new ChaffGenerator instance
func NewChaffGenerator() *ChaffGenerator {
	return &ChaffGenerator{
		Enabled: true,
		Targets: []string{
			"www.google.com:443",
			"www.microsoft.com:443",
			"www.apple.com:443",
			"www.cloudflare.com:443",
			"aws.amazon.com:443",
			"www.instagram.com:443",
		},
		Interval:    3 * time.Second, // Create noise every few seconds
		Variance:    2 * time.Second,
		Concurrency: 1, // Keep it light to avoid bandwidth drain
	}
}

// Start begins the chaff generation process
func (cg *ChaffGenerator) Start() {
	if !cg.Enabled {
		return
	}
	cg.ctx, cg.cancel = context.WithCancel(context.Background())

	// Start concurrent generators
	for i := 0; i < cg.Concurrency; i++ {
		go cg.loop()
	}
}

// Stop halts the chaff generation
func (cg *ChaffGenerator) Stop() {
	if cg.cancel != nil {
		cg.cancel()
	}
}

func (cg *ChaffGenerator) loop() {
	ticker := time.NewTicker(cg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-cg.ctx.Done():
			return
		case <-ticker.C:
			// Add randomization to the interval
			longRand, _ := rand.Int(rand.Reader, big.NewInt(int64(cg.Variance)))
			time.Sleep(time.Duration(longRand.Int64()))

			cg.spawnChaff()
		}
	}
}

func (cg *ChaffGenerator) spawnChaff() {
	// Pick random target
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(cg.Targets))))
	target := cg.Targets[idx.Int64()]

	// 1. Establish TCP connection
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// 2. Perform TLS Handshake (mimicking a browser)
	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         splitHost(target),
		InsecureSkipVerify: true, // We don't care about the cert for chaff
	}, utls.HelloChrome_Auto)

	// Set deadline for handshake
	uConn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := uConn.Handshake(); err != nil {
		return
	}

	// 3. Send some random application data (HTTP-like) or just close
	// sending data makes it look more like a real short session
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\nConnection: close\r\n\r\n", splitHost(target))
	uConn.Write([]byte(req))

	// Short read to simulate waiting for response
	buf := make([]byte, 1024)
	uConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	uConn.Read(buf)

	// Connection closes via defer
}

func splitHost(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
