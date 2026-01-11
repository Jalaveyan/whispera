// Package dynamicconfig implements dynamic configuration reloading
// Allows hot-reloading of configuration without restart
package dynamicconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"whispera/internal/core/base"
	"whispera/internal/logger"
)

var log = logger.Module("dynamicconfig")

const (
	ModuleName    = "config.dynamic"
	ModuleVersion = "1.0.0"
)

// ChangeType represents the type of configuration change
type ChangeType string

const (
	ChangeAdded    ChangeType = "added"
	ChangeModified ChangeType = "modified"
	ChangeRemoved  ChangeType = "removed"
)

// Change represents a configuration change
type Change struct {
	Type     ChangeType
	Path     string // Dot-separated path like "server.listen_addr"
	OldValue interface{}
	NewValue interface{}
}

// Callback is called when configuration changes
type Callback func(changes []Change) error

// Config holds dynamic config manager configuration
type Config struct {
	// Configuration file path
	FilePath string

	// Watch settings
	WatchEnabled  bool
	WatchInterval time.Duration

	// Validation
	ValidateOnLoad   bool
	ValidateOnChange bool

	// Callbacks
	OnChange []Callback

	// Atomic loading
	AtomicLoad bool // Create temp file and rename

	// Backup
	BackupEnabled bool
	BackupDir     string
	MaxBackups    int
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		WatchEnabled:     true,
		WatchInterval:    5 * time.Second,
		ValidateOnLoad:   true,
		ValidateOnChange: true,
		AtomicLoad:       true,
		BackupEnabled:    true,
		BackupDir:        "./config_backups",
		MaxBackups:       10,
	}
}

// Manager manages dynamic configuration
type Manager struct {
	*base.Module
	config *Config

	mu          sync.RWMutex
	current     map[string]interface{}
	currentHash [32]byte
	validators  []func(map[string]interface{}) error
	callbacks   []Callback

	stopCh chan struct{}
	wg     sync.WaitGroup

	// Stats
	reloadCount   uint64
	reloadErrors  uint64
	lastReload    time.Time
	lastReloadErr string
}

// New creates a new dynamic config manager
func New(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	m := &Manager{
		Module:    base.NewModule(ModuleName, ModuleVersion, nil),
		config:    cfg,
		current:   make(map[string]interface{}),
		callbacks: cfg.OnChange,
		stopCh:    make(chan struct{}),
	}

	return m, nil
}

// Load loads configuration from file
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.loadLocked()
}

// loadLocked loads configuration (must hold lock)
func (m *Manager) loadLocked() error {
	data, err := os.ReadFile(m.config.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	// Calculate hash
	newHash := sha256.Sum256(data)
	if newHash == m.currentHash {
		return nil // No changes
	}

	// Parse configuration
	var newConfig map[string]interface{}
	ext := filepath.Ext(m.config.FilePath)

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &newConfig); err != nil {
			return fmt.Errorf("failed to parse YAML: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &newConfig); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config format: %s", ext)
	}

	// Validate
	if m.config.ValidateOnLoad {
		for _, validator := range m.validators {
			if err := validator(newConfig); err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}
		}
	}

	// Calculate changes
	changes := m.diffConfig(m.current, newConfig)

	// Backup old config
	if m.config.BackupEnabled && len(m.current) > 0 {
		m.backupConfig()
	}

	// Apply changes
	oldConfig := m.current
	m.current = newConfig
	m.currentHash = newHash
	m.lastReload = time.Now()
	atomic.AddUint64(&m.reloadCount, 1)

	// Notify callbacks
	if len(changes) > 0 {
		go m.notifyCallbacks(changes, oldConfig)
	}

	log.Info("Configuration reloaded (%d changes)", len(changes))
	return nil
}

// diffConfig calculates the difference between two configs
func (m *Manager) diffConfig(old, new map[string]interface{}) []Change {
	var changes []Change

	// Check for modified and removed
	m.diffConfigRecursive("", old, new, &changes)

	return changes
}

// diffConfigRecursive recursively calculates config diff
func (m *Manager) diffConfigRecursive(prefix string, old, new map[string]interface{}, changes *[]Change) {
	for key, oldVal := range old {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		newVal, exists := new[key]
		if !exists {
			*changes = append(*changes, Change{
				Type:     ChangeRemoved,
				Path:     path,
				OldValue: oldVal,
			})
			continue
		}

		// Check if values are equal
		if !reflect.DeepEqual(oldVal, newVal) {
			// Check if both are maps (nested config)
			oldMap, oldIsMap := oldVal.(map[string]interface{})
			newMap, newIsMap := newVal.(map[string]interface{})

			if oldIsMap && newIsMap {
				m.diffConfigRecursive(path, oldMap, newMap, changes)
			} else {
				*changes = append(*changes, Change{
					Type:     ChangeModified,
					Path:     path,
					OldValue: oldVal,
					NewValue: newVal,
				})
			}
		}
	}

	// Check for added
	for key, newVal := range new {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		if _, exists := old[key]; !exists {
			*changes = append(*changes, Change{
				Type:     ChangeAdded,
				Path:     path,
				NewValue: newVal,
			})
		}
	}
}

// notifyCallbacks notifies all callbacks of changes
func (m *Manager) notifyCallbacks(changes []Change, _ map[string]interface{}) {
	for _, callback := range m.callbacks {
		if err := callback(changes); err != nil {
			log.Warn("Callback error: %v", err)
		}
	}
}

// backupConfig creates a backup of current config
func (m *Manager) backupConfig() {
	if err := os.MkdirAll(m.config.BackupDir, 0755); err != nil {
		log.Warn("Failed to create backup dir: %v", err)
		return
	}

	// Create backup filename with timestamp
	filename := fmt.Sprintf("config_%s.yaml", time.Now().Format("20060102_150405"))
	path := filepath.Join(m.config.BackupDir, filename)

	// Marshal current config
	data, err := yaml.Marshal(m.current)
	if err != nil {
		log.Warn("Failed to marshal config for backup: %v", err)
		return
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Warn("Failed to write backup: %v", err)
		return
	}

	// Cleanup old backups
	m.cleanupBackups()
}

// cleanupBackups removes old backups
func (m *Manager) cleanupBackups() {
	entries, err := os.ReadDir(m.config.BackupDir)
	if err != nil {
		return
	}

	// Sort by name (which includes timestamp)
	if len(entries) <= m.config.MaxBackups {
		return
	}

	// Remove oldest backups
	toRemove := len(entries) - m.config.MaxBackups
	for i := 0; i < toRemove; i++ {
		path := filepath.Join(m.config.BackupDir, entries[i].Name())
		os.Remove(path)
	}
}

// Get gets a configuration value by path
func (m *Manager) Get(path string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.getPathLocked(m.current, path)
}

// getPathLocked gets a value by dot-separated path
func (m *Manager) getPathLocked(config map[string]interface{}, path string) (interface{}, bool) {
	parts := splitPath(path)
	current := interface{}(config)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			val, ok := v[part]
			if !ok {
				return nil, false
			}
			current = val
		default:
			return nil, false
		}
	}

	return current, true
}

// GetString gets a string configuration value
func (m *Manager) GetString(path string, defaultVal string) string {
	val, ok := m.Get(path)
	if !ok {
		return defaultVal
	}
	if s, ok := val.(string); ok {
		return s
	}
	return defaultVal
}

// GetInt gets an int configuration value
func (m *Manager) GetInt(path string, defaultVal int) int {
	val, ok := m.Get(path)
	if !ok {
		return defaultVal
	}
	switch v := val.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case int64:
		return int(v)
	}
	return defaultVal
}

// GetBool gets a bool configuration value
func (m *Manager) GetBool(path string, defaultVal bool) bool {
	val, ok := m.Get(path)
	if !ok {
		return defaultVal
	}
	if b, ok := val.(bool); ok {
		return b
	}
	return defaultVal
}

// GetDuration gets a duration configuration value
func (m *Manager) GetDuration(path string, defaultVal time.Duration) time.Duration {
	val, ok := m.Get(path)
	if !ok {
		return defaultVal
	}
	switch v := val.(type) {
	case string:
		d, err := time.ParseDuration(v)
		if err != nil {
			return defaultVal
		}
		return d
	case time.Duration:
		return v
	}
	return defaultVal
}

// Set sets a configuration value at runtime
func (m *Manager) Set(path string, value interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate new value
	if m.config.ValidateOnChange {
		tempConfig := deepCopyMap(m.current)
		setPath(tempConfig, path, value)
		for _, validator := range m.validators {
			if err := validator(tempConfig); err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}
		}
	}

	oldValue, _ := m.getPathLocked(m.current, path)
	setPath(m.current, path, value)

	// Notify callbacks
	changes := []Change{{
		Type:     ChangeModified,
		Path:     path,
		OldValue: oldValue,
		NewValue: value,
	}}
	go m.notifyCallbacks(changes, nil)

	return nil
}

// Save saves current configuration to file
func (m *Manager) Save() error {
	m.mu.RLock()
	config := deepCopyMap(m.current)
	m.mu.RUnlock()

	var data []byte
	var err error
	ext := filepath.Ext(m.config.FilePath)

	switch ext {
	case ".yaml", ".yml":
		data, err = yaml.Marshal(config)
	case ".json":
		data, err = json.MarshalIndent(config, "", "  ")
	default:
		return fmt.Errorf("unsupported config format: %s", ext)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if m.config.AtomicLoad {
		// Write to temp file and rename
		tempPath := m.config.FilePath + ".tmp"
		if err := os.WriteFile(tempPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write temp file: %w", err)
		}
		if err := os.Rename(tempPath, m.config.FilePath); err != nil {
			os.Remove(tempPath)
			return fmt.Errorf("failed to rename temp file: %w", err)
		}
	} else {
		if err := os.WriteFile(m.config.FilePath, data, 0644); err != nil {
			return fmt.Errorf("failed to write config: %w", err)
		}
	}

	return nil
}

// AddValidator adds a configuration validator
func (m *Manager) AddValidator(validator func(map[string]interface{}) error) {
	m.mu.Lock()
	m.validators = append(m.validators, validator)
	m.mu.Unlock()
}

// AddCallback adds a change callback
func (m *Manager) AddCallback(callback Callback) {
	m.mu.Lock()
	m.callbacks = append(m.callbacks, callback)
	m.mu.Unlock()
}

// watchLoop watches for configuration file changes
func (m *Manager) watchLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.WatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			if err := m.Load(); err != nil {
				atomic.AddUint64(&m.reloadErrors, 1)
				m.mu.Lock()
				m.lastReloadErr = err.Error()
				m.mu.Unlock()
				log.Warn("Failed to reload config: %v", err)
			}
		}
	}
}

// Helper functions

func splitPath(path string) []string {
	var parts []string
	current := ""
	for _, c := range path {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func setPath(config map[string]interface{}, path string, value interface{}) {
	parts := splitPath(path)
	current := config

	for i, part := range parts {
		if i == len(parts)-1 {
			current[part] = value
			return
		}

		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else {
			newMap := make(map[string]interface{})
			current[part] = newMap
			current = newMap
		}
	}
}

func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		if nested, ok := v.(map[string]interface{}); ok {
			result[k] = deepCopyMap(nested)
		} else {
			result[k] = v
		}
	}
	return result
}

// Interface implementation

func (m *Manager) Init(ctx context.Context) error {
	return m.Load()
}

func (m *Manager) Start(ctx context.Context) error {
	if m.config.WatchEnabled {
		m.wg.Add(1)
		go m.watchLoop()
	}
	return nil
}

func (m *Manager) Stop(ctx context.Context) error {
	close(m.stopCh)
	m.wg.Wait()
	return nil
}

func (m *Manager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"reload_count":    atomic.LoadUint64(&m.reloadCount),
		"reload_errors":   atomic.LoadUint64(&m.reloadErrors),
		"last_reload":     m.lastReload,
		"last_reload_err": m.lastReloadErr,
		"keys_count":      len(m.current),
	}
}
