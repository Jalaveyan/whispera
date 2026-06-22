package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"
)

var (
	pathPrefixes = []string{
		"/api/v1/", "/api/v2/", "/cdn/", "/static/", "/assets/",
		"/media/", "/content/", "/data/", "/resources/", "/files/",
	}
	pathExts = []string{"", "", "", ".json", ".js", ".css", ".woff2", ".bin"}
)

const authWindowSeconds = 30

const authWindowTolerance = 1

const clockDriftProbeWindows = 10

func GeneratePath(seed uint64, seq int) string {
	mix := int64(seed>>1) ^ int64(seq)*0x517cc1b727220a95
	rng := rand.New(rand.NewSource(mix))

	prefix := pathPrefixes[rng.Intn(len(pathPrefixes))]
	ext := pathExts[rng.Intn(len(pathExts))]

	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	n := 8 + rng.Intn(12)
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rng.Intn(len(chars))]
	}

	return fmt.Sprintf("%s%s%s", prefix, string(b), ext)
}

func AuthToken(authKey []byte, window int64, sessionID []byte) string {
	mac := hmac.New(sha256.New, authKey)
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	mac.Write(sessionID)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func ClientAuthToken(authKey, sessionID []byte) string {
	return AuthToken(authKey, time.Now().Unix()/authWindowSeconds, sessionID)
}

func VerifyAuthToken(authKey []byte, token string, sessionID []byte) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return false
	}
	w := time.Now().Unix() / authWindowSeconds
	for candidate := w - authWindowTolerance; candidate <= w+authWindowTolerance; candidate++ {
		if macMatches(authKey, candidate, sessionID, raw) {
			return true
		}
	}
	return false
}

func macMatches(authKey []byte, window int64, sessionID, want []byte) bool {
	mac := hmac.New(sha256.New, authKey)
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	mac.Write(sessionID)
	return hmac.Equal(mac.Sum(nil), want)
}

func ProbeClockDrift(authKey []byte, token string, sessionID []byte) (driftWindows int64, found bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return 0, false
	}
	w := time.Now().Unix() / authWindowSeconds
	for offset := int64(authWindowTolerance + 1); offset <= clockDriftProbeWindows; offset++ {
		if macMatches(authKey, w+offset, sessionID, raw) {
			return offset, true
		}
		if macMatches(authKey, w-offset, sessionID, raw) {
			return -offset, true
		}
	}
	return 0, false
}
