package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"whispera/core/mlserver"

	_ "go.uber.org/automaxprocs"
)

var Version = "2.0.0"

func main() {
	listenAddr := flag.String("listen", ":8000", "listen address")
	tokenFile := flag.String("token-file", "", "path to API token file")
	token := flag.String("token", "", "API auth token (overrides token-file)")
	dataDir := flag.String("data-dir", "./ml_data", "data directory for datasets")
	modelDir := flag.String("model-dir", "./ml_models", "model directory")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file")
	tlsKey := flag.String("tls-key", "", "TLS key file")
	flag.Parse()

	authToken := *token
	if authToken == "" && *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err == nil {
			authToken = string(data)
		}
	}
	if authToken == "" {
		if home, err := os.UserConfigDir(); err == nil {
			data, err := os.ReadFile(home + "/Whispera/api_token")
			if err == nil {
				authToken = string(data)
			}
		}
	}

	cfg := &mlserver.Config{
		ListenAddr: *listenAddr,
		Token:      authToken,
		DataDir:    *dataDir,
		ModelDir:   *modelDir,
		TLSCert:    *tlsCert,
		TLSKey:     *tlsKey,
	}

	server, err := mlserver.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init failed: %v\n", err)
		os.Exit(1)
	}

	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start failed: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()

	server.Stop()
}
