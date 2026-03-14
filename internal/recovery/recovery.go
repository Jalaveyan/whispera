package recovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type BackupTarget struct {
	Name string
	Path string
}

type Snapshot struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Targets   []string  `json:"targets"`
	Size      int64     `json:"size"`
}

type Manager struct {
	mu         sync.Mutex
	backupDir  string
	targets    []BackupTarget
	maxBackups int
	interval   time.Duration
	stopCh     chan struct{}
}

func NewManager(backupDir string, maxBackups int, interval time.Duration) *Manager {
	if maxBackups <= 0 {
		maxBackups = 10
	}
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &Manager{
		backupDir:  backupDir,
		maxBackups: maxBackups,
		interval:   interval,
		stopCh:     make(chan struct{}),
	}
}

func (m *Manager) AddTarget(name, path string) {
	m.targets = append(m.targets, BackupTarget{Name: name, Path: path})
}

func (m *Manager) Start() {
	os.MkdirAll(m.backupDir, 0755)
	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.CreateBackup()
			}
		}
	}()
}

func (m *Manager) Stop() {
	close(m.stopCh)
}

func (m *Manager) CreateBackup() (*Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	snap := &Snapshot{
		ID:        fmt.Sprintf("snap-%d", time.Now().Unix()),
		Timestamp: time.Now(),
	}

	snapDir := filepath.Join(m.backupDir, snap.ID)
	if err := os.MkdirAll(snapDir, 0755); err != nil {
		return nil, fmt.Errorf("create snapshot dir: %w", err)
	}

	var totalSize int64
	for _, target := range m.targets {
		dst := filepath.Join(snapDir, target.Name)
		size, err := copyFileOrDir(target.Path, dst)
		if err != nil {
			continue
		}
		snap.Targets = append(snap.Targets, target.Name)
		totalSize += size
	}
	snap.Size = totalSize

	metaPath := filepath.Join(snapDir, "meta.json")
	metaData, _ := json.MarshalIndent(snap, "", "  ")
	os.WriteFile(metaPath, metaData, 0600)

	m.pruneOldBackups()

	return snap, nil
}

func (m *Manager) Restore(snapshotID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	snapDir := filepath.Join(m.backupDir, snapshotID)
	metaPath := filepath.Join(snapDir, "meta.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("snapshot not found: %w", err)
	}

	var snap Snapshot
	if err := json.Unmarshal(metaData, &snap); err != nil {
		return fmt.Errorf("invalid snapshot: %w", err)
	}

	for _, target := range m.targets {
		src := filepath.Join(snapDir, target.Name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if _, err := copyFileOrDir(src, target.Path); err != nil {
			return fmt.Errorf("restore %s: %w", target.Name, err)
		}
	}

	return nil
}

func (m *Manager) ListSnapshots() ([]Snapshot, error) {
	entries, err := os.ReadDir(m.backupDir)
	if err != nil {
		return nil, err
	}

	var snapshots []Snapshot
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(m.backupDir, entry.Name(), "meta.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var snap Snapshot
		if json.Unmarshal(data, &snap) == nil {
			snapshots = append(snapshots, snap)
		}
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Timestamp.After(snapshots[j].Timestamp)
	})
	return snapshots, nil
}

func (m *Manager) pruneOldBackups() {
	snapshots, err := m.ListSnapshots()
	if err != nil {
		return
	}
	for i := m.maxBackups; i < len(snapshots); i++ {
		dir := filepath.Join(m.backupDir, snapshots[i].ID)
		os.RemoveAll(dir)
	}
}

func copyFileOrDir(src, dst string) (int64, error) {
	info, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if info.IsDir() {
		return copyDir(src, dst)
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	os.MkdirAll(filepath.Dir(dst), 0755)
	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	n, err := io.Copy(out, in)
	return n, err
}

func copyDir(src, dst string) (int64, error) {
	os.MkdirAll(dst, 0755)
	entries, err := os.ReadDir(src)
	if err != nil {
		return 0, err
	}

	var total int64
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		n, err := copyFileOrDir(srcPath, dstPath)
		if err != nil {
			continue
		}
		total += n
	}
	return total, nil
}

type HealthChecker struct {
	mu       sync.Mutex
	checks   map[string]func(context.Context) error
	interval time.Duration
	stopCh   chan struct{}
	onFail   func(name string, err error)
}

func NewHealthChecker(interval time.Duration) *HealthChecker {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &HealthChecker{
		checks:   make(map[string]func(context.Context) error),
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (hc *HealthChecker) AddCheck(name string, check func(context.Context) error) {
	hc.mu.Lock()
	hc.checks[name] = check
	hc.mu.Unlock()
}

func (hc *HealthChecker) OnFailure(fn func(string, error)) {
	hc.onFail = fn
}

func (hc *HealthChecker) Start() {
	go func() {
		ticker := time.NewTicker(hc.interval)
		defer ticker.Stop()
		for {
			select {
			case <-hc.stopCh:
				return
			case <-ticker.C:
				hc.runChecks()
			}
		}
	}()
}

func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
}

func (hc *HealthChecker) runChecks() {
	hc.mu.Lock()
	checks := make(map[string]func(context.Context) error, len(hc.checks))
	for k, v := range hc.checks {
		checks[k] = v
	}
	hc.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for name, check := range checks {
		if err := check(ctx); err != nil {
			if hc.onFail != nil {
				hc.onFail(name, err)
			}
		}
	}
}
