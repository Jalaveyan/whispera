package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func deviceIDPath() string {
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = os.TempDir()
		}
		return filepath.Join(appData, "whispera", "device.id")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".whispera", "device.id")
	}
	return filepath.Join(home, ".whispera", "device.id")
}

func LoadOrCreateDeviceID() ([16]byte, error) {
	var id [16]byte
	path := deviceIDPath()

	data, err := os.ReadFile(path)
	if err == nil {
		s := strings.TrimSpace(string(data))
		b, decErr := hex.DecodeString(s)
		if decErr == nil && len(b) == 16 {
			copy(id[:], b)
			return id, nil
		}
	}

	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("failed to generate device ID: %w", err)
	}

	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80

	if mkErr := os.MkdirAll(filepath.Dir(path), 0700); mkErr == nil {
		_ = os.WriteFile(path, []byte(hex.EncodeToString(id[:])+"\n"), 0600)
	}

	return id, nil
}
