package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type VersionInfo struct {
	Version   string `json:"version"`
	Channel   string `json:"channel"`
	Checksum  string `json:"checksum_sha256"`
	Signature string `json:"signature_ed25519"`
	URL       string `json:"url"`
	Size      int64  `json:"size"`
	ReleaseAt string `json:"released_at"`
	Changelog string `json:"changelog,omitempty"`
}

type Manifest struct {
	Latest   VersionInfo            `json:"latest"`
	Versions map[string]VersionInfo `json:"versions"`
}

type Config struct {
	ManifestURL    string
	PublicKey      ed25519.PublicKey
	CurrentVersion string
	BinaryPath     string
	BackupDir      string
	CheckInterval  time.Duration
}

type Updater struct {
	config *Config
	client *http.Client
	mu     sync.Mutex
	stopCh chan struct{}

	onUpdateAvailable func(VersionInfo)
	onUpdateApplied   func(string, string)
	onUpdateFailed    func(string, error)
}

func NewUpdater(cfg *Config) *Updater {
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 1 * time.Hour
	}
	if cfg.BackupDir == "" {
		cfg.BackupDir = "/etc/whispera/backups"
	}
	return &Updater{
		config: cfg,
		client: &http.Client{Timeout: 60 * time.Second},
		stopCh: make(chan struct{}),
	}
}

func (u *Updater) Start() {
	go func() {
		ticker := time.NewTicker(u.config.CheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-u.stopCh:
				return
			case <-ticker.C:
				u.CheckAndApply()
			}
		}
	}()
}

func (u *Updater) Stop() {
	close(u.stopCh)
}

func (u *Updater) CheckForUpdate() (*VersionInfo, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.config.ManifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("manifest HTTP %d", resp.StatusCode)
	}

	var manifest Manifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	if manifest.Latest.Version == u.config.CurrentVersion {
		return nil, nil
	}

	return &manifest.Latest, nil
}

func (u *Updater) CheckAndApply() {
	info, err := u.CheckForUpdate()
	if err != nil {
		if u.onUpdateFailed != nil {
			u.onUpdateFailed("", err)
		}
		return
	}
	if info == nil {
		return
	}

	if u.onUpdateAvailable != nil {
		u.onUpdateAvailable(*info)
	}

	if err := u.Apply(*info); err != nil {
		if u.onUpdateFailed != nil {
			u.onUpdateFailed(info.Version, err)
		}
	}
}

func (u *Updater) Apply(info VersionInfo) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	tmpFile, err := u.download(info.URL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer os.Remove(tmpFile)

	if err := u.verifyChecksum(tmpFile, info.Checksum); err != nil {
		return fmt.Errorf("checksum: %w", err)
	}

	if u.config.PublicKey != nil && info.Signature != "" {
		if err := u.verifySignature(tmpFile, info.Signature); err != nil {
			return fmt.Errorf("signature: %w", err)
		}
	}

	if err := u.backup(); err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	if err := u.atomicReplace(tmpFile); err != nil {
		u.rollback()
		return fmt.Errorf("replace: %w", err)
	}

	if u.onUpdateApplied != nil {
		u.onUpdateApplied(u.config.CurrentVersion, info.Version)
	}
	u.config.CurrentVersion = info.Version

	return nil
}

func (u *Updater) download(url string) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "whispera-update-*")
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}
	tmpFile.Close()
	return tmpFile.Name(), nil
}

func (u *Updater) verifyChecksum(file, expectedHex string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expectedHex {
		return fmt.Errorf("checksum mismatch: got %s, expected %s", actual, expectedHex)
	}
	return nil
}

func (u *Updater) verifySignature(file, sigHex string) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	digest := h.Sum(nil)

	if !ed25519.Verify(u.config.PublicKey, digest, sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (u *Updater) backup() error {
	os.MkdirAll(u.config.BackupDir, 0755)
	src := u.config.BinaryPath
	dst := filepath.Join(u.config.BackupDir, fmt.Sprintf("whispera-%s.bak", u.config.CurrentVersion))

	srcFile, err := os.Open(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func (u *Updater) atomicReplace(tmpFile string) error {
	info, err := os.Stat(u.config.BinaryPath)
	if err == nil {
		os.Chmod(tmpFile, info.Mode())
	} else {
		os.Chmod(tmpFile, 0755)
	}

	return os.Rename(tmpFile, u.config.BinaryPath)
}

func (u *Updater) rollback() error {
	pattern := filepath.Join(u.config.BackupDir, "whispera-*.bak")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return fmt.Errorf("no backup found")
	}

	latest := matches[len(matches)-1]
	return os.Rename(latest, u.config.BinaryPath)
}
