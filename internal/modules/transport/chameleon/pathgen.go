package chameleon

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

// GeneratePath produces a realistic-looking URL path from a seed and sequence number.
// Same (seed, seq) always returns the same path.
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

// AuthToken produces a time-windowed HMAC token for the initial HTTP request.
// token = base64url(HMAC-SHA256(authKey, window_bytes || sessionID))
func AuthToken(authKey []byte, window int64, sessionID []byte) string {
	mac := hmac.New(sha256.New, authKey)
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	mac.Write(sessionID)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyAuthToken checks the token for the given window ±1 (clock skew tolerance).
func VerifyAuthToken(authKey []byte, token string, sessionID []byte) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return false
	}
	w := time.Now().Unix() / 30
	for _, candidate := range []int64{w, w - 1, w + 1} {
		mac := hmac.New(sha256.New, authKey)
		var wb [8]byte
		binary.BigEndian.PutUint64(wb[:], uint64(candidate))
		mac.Write(wb[:])
		mac.Write(sessionID)
		if hmac.Equal(mac.Sum(nil), raw) {
			return true
		}
	}
	return false
}
