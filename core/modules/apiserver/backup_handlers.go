package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	backupDataDir    = "/etc/whispera"
	adblockDataFile  = "/etc/whispera/adblock.json"
	backupStorageDir = "/etc/whispera/backups"
	maxBackupRetain  = 7
)

func readRawJSON(path string) json.RawMessage {
	data, err := os.ReadFile(path)
	if err != nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(data)
}

func (s *Server) handleGetBackup(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	backup := map[string]interface{}{
		"version":       "1",
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"users":         readRawJSON(userDataFile),
		"subscriptions": readRawJSON(subDataFile),
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
	if !s.requireAdmin(w, r) {
		return
	}
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
		"adblock":       adblockDataFile,
	}

	for key, path := range files {
		raw, ok := payload[key]
		if !ok || string(raw) == "null" {
			continue
		}
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
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

func dumpPostgres(postgresURL string) ([]byte, error) {
	if postgresURL == "" {
		return nil, nil
	}
	cmd := exec.CommandContext(context.Background(), "pg_dump", "--no-owner", "--no-acl", "--format=custom", postgresURL)
	return cmd.Output()
}

func (s *Server) handleGetBackupFull(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	backup := map[string]interface{}{
		"version":       "2",
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"users":         readRawJSON(userDataFile),
		"subscriptions": readRawJSON(subDataFile),
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

	pgURL := s.getPostgresURL()
	if pgURL != "" {
		if data, err := dumpPostgres(pgURL); err != nil {
			backup["database_error"] = err.Error()
		} else if data != nil {
			backup["database_dump_size"] = len(data)
		}
	}

	s.jsonOK(w, backup)
}

func (s *Server) getPostgresURL() string {
	if s.registry == nil {
		return ""
	}
	mod, ok := s.registry.Get("config.provider")
	if !ok {
		return ""
	}
	type dbCfg interface {
		GetDatabaseURL() string
	}
	if p, ok := mod.(dbCfg); ok {
		return p.GetDatabaseURL()
	}
	return ""
}

var (
	scheduledBackupOnce sync.Once
	scheduledBackupStop chan struct{}
)

func (s *Server) StartScheduledBackups(intervalHours int) {
	if intervalHours <= 0 {
		intervalHours = 24
	}
	scheduledBackupOnce.Do(func() {
		scheduledBackupStop = make(chan struct{})
		go s.backupLoop(time.Duration(intervalHours) * time.Hour)
	})
}

func (s *Server) StopScheduledBackups() {
	if scheduledBackupStop != nil {
		close(scheduledBackupStop)
	}
}

func (s *Server) backupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.createBackupSnapshot()

	for {
		select {
		case <-scheduledBackupStop:
			return
		case <-ticker.C:
			s.createBackupSnapshot()
		}
	}
}

func (s *Server) createBackupSnapshot() {
	os.MkdirAll(backupStorageDir, 0700)

	ts := time.Now().UTC().Format("20060102-150405")
	filename := filepath.Join(backupStorageDir, fmt.Sprintf("backup-%s.json", ts))

	backup := map[string]interface{}{
		"version":       "2",
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"users":         readRawJSON(userDataFile),
		"subscriptions": readRawJSON(subDataFile),
		"adblock":       readRawJSON(adblockDataFile),
	}

	pgURL := s.getPostgresURL()
	if pgURL != "" {
		dumpFile := filepath.Join(backupStorageDir, fmt.Sprintf("pgdump-%s.dump", ts))
		cmd := exec.CommandContext(context.Background(), "pg_dump", "--no-owner", "--no-acl", "--format=custom", "-f", dumpFile, pgURL)
		if err := cmd.Run(); err != nil {
		} else {
			backup["database_dump"] = dumpFile
		}
	}

	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return
	}

	s.rotateBackups()
}

func (s *Server) rotateBackups() {
	entries, err := os.ReadDir(backupStorageDir)
	if err != nil {
		return
	}

	var jsonFiles []string
	var dumpFiles []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "backup-") && strings.HasSuffix(name, ".json") {
			jsonFiles = append(jsonFiles, name)
		}
		if strings.HasPrefix(name, "pgdump-") && strings.HasSuffix(name, ".dump") {
			dumpFiles = append(dumpFiles, name)
		}
	}

	sort.Strings(jsonFiles)
	sort.Strings(dumpFiles)

	for len(jsonFiles) > maxBackupRetain {
		os.Remove(filepath.Join(backupStorageDir, jsonFiles[0]))
		jsonFiles = jsonFiles[1:]
	}
	for len(dumpFiles) > maxBackupRetain {
		os.Remove(filepath.Join(backupStorageDir, dumpFiles[0]))
		dumpFiles = dumpFiles[1:]
	}
}

func (s *Server) handleBackupList(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	entries, err := os.ReadDir(backupStorageDir)
	if err != nil {
		s.jsonOK(w, map[string]interface{}{"backups": []string{}})
		return
	}

	var backups []map[string]interface{}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "backup-") {
			continue
		}
		info, _ := e.Info()
		b := map[string]interface{}{
			"name": e.Name(),
		}
		if info != nil {
			b["size"] = info.Size()
			b["modified"] = info.ModTime().UTC().Format(time.RFC3339)
		}
		backups = append(backups, b)
	}

	s.jsonOK(w, map[string]interface{}{"backups": backups})
}
