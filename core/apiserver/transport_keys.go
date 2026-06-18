package apiserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

type TransportCredentials struct {
	Transport    string                 `json:"transport"`
	Credentials  map[string]interface{} `json:"credentials"`
	ClientConfig map[string]interface{} `json:"client_config"`
}

func generateTransportCredentials(transport string) (*TransportCredentials, error) {
	creds := &TransportCredentials{
		Transport:    transport,
		Credentials:  make(map[string]interface{}),
		ClientConfig: make(map[string]interface{}),
	}

	switch transport {
	case "udp", "tcp", "grpc", "quic":
		kp, err := generateX25519Keys()
		if err != nil {
			return nil, err
		}
		creds.Credentials["private_key"] = kp.PrivateKey
		creds.Credentials["public_key"] = kp.PublicKey
		creds.ClientConfig["public_key"] = kp.PublicKey

	case "vkbot":
		creds.Credentials["note"] = "requires VK Bot token — provide vk_token and group_id"
		creds.ClientConfig["note"] = "requires VK Bot token"

	case "yacloud", "yadisk":
		creds.Credentials["note"] = "requires Yandex OAuth token — provide ya_token"
		creds.ClientConfig["note"] = "requires Yandex OAuth token"

	default:
		return nil, fmt.Errorf("unknown transport type: %s", transport)
	}

	return creds, nil
}

func (s *Server) handleGenerateTransportKeys(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		Transport string `json:"transport"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Transport == "" {
		s.jsonError(w, http.StatusBadRequest, "transport field required")
		return
	}

	creds, err := generateTransportCredentials(req.Transport)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.jsonOK(w, map[string]interface{}{
		"success": true,
		"result":  creds,
	})
}

func (s *Server) handleGenerateMultiTransportKeys(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		Transports []string `json:"transports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Transports) == 0 {
		s.jsonError(w, http.StatusBadRequest, "transports array required")
		return
	}

	results := make(map[string]*TransportCredentials)
	for _, t := range req.Transports {
		creds, err := generateTransportCredentials(t)
		if err != nil {
			s.jsonError(w, http.StatusBadRequest, fmt.Sprintf("transport %s: %s", t, err.Error()))
			return
		}
		results[t] = creds
	}

	s.jsonOK(w, map[string]interface{}{
		"success": true,
		"results": results,
	})
}

func randomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
