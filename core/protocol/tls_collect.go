package protocol

import (
	"os"
	"path/filepath"
	"sync"

	utls "github.com/refraction-networking/utls"
)

var harvestOnce sync.Once

var (
	harvestDirMu       sync.RWMutex
	harvestDirOverride string
)

// SetHarvestDir points fingerprint persistence/loading at a writable directory
// (the client's data dir). Falls back to WHISPERA_FP_DIR when unset.
func SetHarvestDir(dir string) {
	harvestDirMu.Lock()
	harvestDirOverride = dir
	harvestDirMu.Unlock()
}

func harvestDirPath() string {
	harvestDirMu.RLock()
	d := harvestDirOverride
	harvestDirMu.RUnlock()
	if d != "" {
		return d
	}
	return os.Getenv("WHISPERA_FP_DIR")
}

func HarvestRawClientHello(record []byte) error {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	spec, err := fp.FingerprintClientHello(record)
	if err != nil {
		return err
	}
	addHarvestedFingerprint(spec, record)
	return nil
}

// persistFingerprint writes a new unique ClientHello to disk so harvested
// fingerprints are not lost on restart. Atomic (temp + rename); a no-op when no
// harvest dir is configured or the file already exists.
func persistFingerprint(key string, raw []byte) {
	dir := harvestDirPath()
	if dir == "" || len(raw) == 0 {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	path := filepath.Join(dir, key+".bin")
	if _, err := os.Stat(path); err == nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func LoadHarvestDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".bin" {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		if HarvestRawClientHello(data) == nil {
			n++
		}
	}
	return n, nil
}

func initHarvest() {
	dir := harvestDirPath()
	if dir == "" {
		return
	}
	_, _ = LoadHarvestDir(dir)
}
