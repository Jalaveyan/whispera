package marionette

import (
	"context"
	"fmt"
	"math/rand"
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
			// Global
			"www.google.com:443",
			"www.microsoft.com:443",
			"www.twitch.tv:443",

			// Russian
			"vk.com:443",
			"dzen.ru:443",
			"www.ozon.ru:443",
			"www.wildberries.ru:443",
			"rutube.ru:443",
			"yandex.ru:443",
			"mail.ru:443",
			"disk.yandex.ru:443",
			"ok.ru:443",
			"www.gosuslugi.ru:443",
		},
		Interval:    5 * time.Second, // Slower interval to be less annoying
		Variance:    3 * time.Second,
		Concurrency: 2, // Slightly more concurrent to mask better
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
			// Add randomization to the interval
			// Use Int63n for a positive random duration
			jitter := rand.Int63n(int64(cg.Variance))
			time.Sleep(time.Duration(jitter))

			cg.spawnChaff()
		}
	}
}

func (cg *ChaffGenerator) spawnChaff() {
	// Pick random target
	// Pick random target
	idx := rand.Intn(len(cg.Targets))
	target := cg.Targets[idx]

	// 1. Establish TCP connection
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// 2. Perform TLS Handshake (mimicking various browsers)
	// Randomize the fingerprint to avoid static signature detection
	var helloID utls.ClientHelloID
	r := rand.Intn(3)
	switch r {
	case 0:
		helloID = utls.HelloChrome_Auto
	case 1:
		helloID = utls.HelloFirefox_Auto
	case 2:
		helloID = utls.HelloIOS_Auto
	}

	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         splitHost(target),
		InsecureSkipVerify: true, // We don't care about the cert for chaff
	}, helloID)

	// Set deadline for handshake
	uConn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := uConn.Handshake(); err != nil {
		return
	}

	// 3. Send realistic Application Data (HTTP GET)
	// Using standard browser headers to elicit a real 200/301 response
	headers := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n"+
			"Accept-Language: en-US,en;q=0.9,ru;q=0.8\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		splitHost(target))

	uConn.Write([]byte(headers))

	// 4. "Mirror" the response (Read until EOF or timeout)
	// This ensures we actually receive the server's answer
	buf := make([]byte, 4096)
	uConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read response to simulate real download
	for {
		_, err := uConn.Read(buf)
		if err != nil {
			break
		}
		// In a real scenario, we might discard `n` bytes
		// Just creating traffic flow here
	}

	// Connection closes via defer
}

func splitHost(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
