package apiserver

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/crypto/curve25519"
)

type TransportCredentials struct {
	Transport   string                 `json:"transport"`
	Credentials map[string]interface{} `json:"credentials"`
	ClientConfig map[string]interface{} `json:"client_config"`
}

func generateTransportCredentials(transport string) (*TransportCredentials, error) {
	creds := &TransportCredentials{
		Transport:    transport,
		Credentials:  make(map[string]interface{}),
		ClientConfig: make(map[string]interface{}),
	}

	switch transport {
	case "udp", "tcp", "websocket", "h2c", "xhttp", "httpupgrade", "splithttp", "grpc", "quic":
		kp, err := generateX25519Keys()
		if err != nil {
			return nil, err
		}
		creds.Credentials["private_key"] = kp.PrivateKey
		creds.Credentials["public_key"] = kp.PublicKey
		creds.ClientConfig["public_key"] = kp.PublicKey

	case "shadowsocks":
		pw, err := randomBase64(32)
		if err != nil {
			return nil, err
		}
		creds.Credentials["password"] = pw
		creds.Credentials["method"] = "chacha20-ietf-poly1305"
		creds.ClientConfig["password"] = pw
		creds.ClientConfig["method"] = "chacha20-ietf-poly1305"

	case "obfs4":
		nodeID, err := randomHex(20)
		if err != nil {
			return nil, err
		}
		privKey, pubKey, err := generateX25519Hex()
		if err != nil {
			return nil, err
		}
		iatMode := 0
		creds.Credentials["node_id"] = nodeID
		creds.Credentials["private_key"] = privKey
		creds.Credentials["public_key"] = pubKey
		creds.Credentials["iat_mode"] = iatMode
		certBytes := make([]byte, 0, 52)
		nid, _ := hex.DecodeString(nodeID)
		pk, _ := hex.DecodeString(pubKey)
		certBytes = append(certBytes, nid...)
		certBytes = append(certBytes, pk...)
		creds.Credentials["cert"] = base64.StdEncoding.EncodeToString(certBytes)
		creds.ClientConfig["cert"] = base64.StdEncoding.EncodeToString(certBytes)
		creds.ClientConfig["iat_mode"] = iatMode

	case "shadowtls":
		pw, err := randomBase64(32)
		if err != nil {
			return nil, err
		}
		creds.Credentials["password"] = pw
		creds.Credentials["sni"] = "www.apple.com"
		creds.Credentials["version"] = 3
		creds.ClientConfig["password"] = pw
		creds.ClientConfig["sni"] = "www.apple.com"

	case "tuic":
		uuid, err := generateUUID()
		if err != nil {
			return nil, err
		}
		pw, err := randomBase64(24)
		if err != nil {
			return nil, err
		}
		creds.Credentials["uuid"] = uuid
		creds.Credentials["password"] = pw
		creds.Credentials["congestion_control"] = "bbr"
		creds.ClientConfig["uuid"] = uuid
		creds.ClientConfig["password"] = pw

	case "snowflake", "torsocks", "domainfront":
		creds.Credentials["note"] = "uses public infrastructure, no server-side credentials"
		creds.ClientConfig["note"] = "no credentials required"

	case "meek":
		creds.Credentials["front_domain"] = "ajax.aspnetcdn.com"
		creds.Credentials["url"] = "https://meek.azureedge.net/"
		creds.ClientConfig["front_domain"] = "ajax.aspnetcdn.com"
		creds.ClientConfig["url"] = "https://meek.azureedge.net/"

	case "vkwebrtc", "okwebrtc", "yatelemost":
		creds.Credentials["note"] = "requires VK/OK API token — provide vk_token and vk_group_id"
		creds.ClientConfig["note"] = "requires VK/OK API token"

	case "tgbot":
		creds.Credentials["note"] = "requires Telegram Bot token — provide bot_token and chat_id"
		creds.ClientConfig["note"] = "requires Telegram Bot token"

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

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateX25519Hex() (privHex, pubHex string, err error) {
	priv := make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return
	}
	privHex = hex.EncodeToString(priv)
	pubHex = hex.EncodeToString(pub)
	return
}

func generateUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
