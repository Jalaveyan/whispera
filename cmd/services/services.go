package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "go.uber.org/automaxprocs"

	"whispera/internal/core/interfaces"
	"whispera/internal/core/lifecycle"
	"whispera/internal/modules/crypto"
	"whispera/internal/modules/session"
)

var Version = "2.0.0"

type jsonSessionOpenResponse struct {
	SessionID  string `json:"session_id"`
	AEADKey    string `json:"aead_key"`
	Seed       string `json:"seed"`
	InitialSeq uint32 `json:"initial_seq"`
	ExpiresAt  string `json:"expires_at"`
}

type jsonSessionRefreshResponse struct {
	Renewed    bool   `json:"renewed"`
	ExpiresAt  string `json:"expires_at"`
	NewAEADKey string `json:"new_aead_key,omitempty"`
	NewSeq     uint32 `json:"new_seq"`
}

type jsonSessionCloseResponse struct {
	Closed bool `json:"closed"`
}

type sessionOpenRequest struct {
	ClientID  string `json:"client_id"`
	ClientKey string `json:"client_key"`
}

type sessionRefreshRequest struct {
	SessionID string `json:"session_id"`
}

type sessionCloseRequest struct {
	SessionID string `json:"session_id"`
}

func main() {
	var (
		listenAddr   = flag.String("listen", ":9090", "HTTP listen address")
		sessionTTL   = flag.Duration("session-ttl", time.Hour, "session lifetime duration")
		timeout      = flag.Duration("session-timeout", 2*time.Hour, "session manager inactivity timeout")
		printVersion = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *printVersion {
		log.Printf("Whispera v%s", Version)
		os.Exit(0)
	}

	manager := lifecycle.NewManager(lifecycle.Config{
		ShutdownTimeout: 10_000_000_000,
		GracefulStop:    true,
	})

	cryptoProvider, err := crypto.New(&crypto.Config{
		DefaultCipher: crypto.CipherChaCha20Poly1305,
		EnableKeyPool: true,
		KeyPoolSize:   50,
	})

	if err != nil {
		log.Fatalf("Failed to create crypto provider: %v", err)
	}
	manager.Register(cryptoProvider)

	sessionMgr, err := session.New(&session.Config{
		MaxSessions:     10000,
		SessionTimeout:  *timeout,
		CleanupInterval: time.Minute,
	})
	if err != nil {
		log.Fatalf("Failed to create session manager: %v", err)
	}
	manager.Register(sessionMgr)

	if err := manager.Start(); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	logger := log.New(os.Stdout, "[authsvc] ", log.LstdFlags|log.Lmicroseconds)

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/v1/sessions:open", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "POST required")
			return
		}

		var req sessionOpenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, http.StatusBadRequest, fmt.Sprintf("invalid json: %v", err))
			return
		}

		seed := make([]byte, 32)
		cryptoProvider.DeriveKey([]byte(req.ClientID+req.ClientKey), seed, 32)

		aeadKey := make([]byte, 32)
		cryptoProvider.DeriveKey(seed, aeadKey, 32)

		sess, err := sessionMgr.CreateSession(interfaces.SessionParams{
			ClientAddr: nil,
			Seed:       seed,
			Metadata: map[string]interface{}{
				"client_id": req.ClientID,
				"ttl":       *sessionTTL,
			},
		})
		if err != nil {
			logger.Printf("open session error: %v", err)
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}

		expiresAt := time.Now().Add(*sessionTTL)

		writeJSON(w, http.StatusOK, jsonSessionOpenResponse{
			SessionID:  fmt.Sprintf("%d", sess.ID()),
			AEADKey:    base64.StdEncoding.EncodeToString(aeadKey),
			Seed:       base64.StdEncoding.EncodeToString(seed),
			InitialSeq: 0,
			ExpiresAt:  expiresAt.UTC().Format(time.RFC3339Nano),
		})
	})

	mux.HandleFunc("/v1/sessions:refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "POST required")
			return
		}

		var req sessionRefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, http.StatusBadRequest, fmt.Sprintf("invalid json: %v", err))
			return
		}

		var sessionID uint32
		fmt.Sscanf(req.SessionID, "%d", &sessionID)

		sess, ok := sessionMgr.GetSession(sessionID)
		if !ok {
			httpError(w, http.StatusNotFound, "session not found")
			return
		}

		sess.UpdateActivity()
		expiresAt := time.Now().Add(*sessionTTL)

		writeJSON(w, http.StatusOK, jsonSessionRefreshResponse{
			Renewed:   true,
			ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano),
			NewSeq:    0,
		})
	})

	mux.HandleFunc("/v1/sessions:close", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpError(w, http.StatusMethodNotAllowed, "POST required")
			return
		}

		var req sessionCloseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, http.StatusBadRequest, fmt.Sprintf("invalid json: %v", err))
			return
		}

		var sessionID uint32
		fmt.Sscanf(req.SessionID, "%d", &sessionID)

		sessionMgr.RemoveSession(sessionID)

		writeJSON(w, http.StatusOK, jsonSessionCloseResponse{
			Closed: true,
		})
	})

	logger.Printf("listening on %s", *listenAddr)
	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		logger.Fatalf("server exited: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write json error: %v", err)
	}
}

func httpError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}
