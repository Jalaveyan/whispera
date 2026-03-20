package apiserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const (
	backupDataDir    = "/etc/whispera"
	adblockDataFile  = "/etc/whispera/adblock.json"
	bridgesDataFile  = "/etc/whispera/bridges.json"
)

func readRawJSON(path string) json.RawMessage {
	data, err := os.ReadFile(path)
	if err != nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(data)
}

func (s *Server) handleGetBackup(w http.ResponseWriter, r *http.Request) {
	backup := map[string]interface{}{
		"version":   "1",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"users":         readRawJSON(userDataFile),
		"subscriptions": readRawJSON(subDataFile),
		"bridges":       readRawJSON(bridgesDataFile),
		"adblock":       readRawJSON(adblockDataFile),
	}

	if s.registry != nil {
		if mod, ok := s.registry.Get("config.provider"); ok {
			type cfgProvider interface {
				GetConfigPath() string
			}
			if p, ok := mod.(cfgProvider); ok {
				if data, err := os.ReadFile(p.GetConfigPath()); err == nil {
					backup["config_yaml"] = string(data)
				}
			}
		}
	}

	s.jsonOK(w, backup)
}

const maxBackupBodySize = 10 << 20

func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupBodySize)
	var payload map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid backup file")
		return
	}

	if err := os.MkdirAll(backupDataDir, 0755); err != nil {
		s.jsonError(w, http.StatusInternalServerError, "failed to access data dir")
		return
	}

	restored := []string{}
	failed := []string{}

	files := map[string]string{
		"users":         userDataFile,
		"subscriptions": subDataFile,
		"bridges":       bridgesDataFile,
		"adblock":       adblockDataFile,
	}

	for key, path := range files {
		raw, ok := payload[key]
		if !ok || string(raw) == "null" {
			continue
		}
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			log.Printf("[API] Backup restore: failed to write %s: %v", path, err)
			failed = append(failed, key)
		} else {
			restored = append(restored, key)
		}
	}

	loadUsers()
	loadSubscriptions()

	msg := fmt.Sprintf("Restored: %v", restored)
	if len(failed) > 0 {
		msg += fmt.Sprintf("; Failed: %v", failed)
	}

	s.jsonOK(w, map[string]interface{}{
		"success":  len(failed) == 0,
		"message":  msg,
		"restored": restored,
		"failed":   failed,
	})
}
