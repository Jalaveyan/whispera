package protocol

import (
	"os"
	"path/filepath"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func resetHarvestState(t *testing.T) {
	t.Helper()
	harvestMu.Lock()
	s, r, k, seen := harvestSpecs, harvestRaw, harvestKinds, harvestSeen
	harvestSpecs, harvestRaw, harvestKinds, harvestSeen = nil, nil, nil, map[string]bool{}
	harvestMu.Unlock()
	t.Cleanup(func() {
		harvestMu.Lock()
		harvestSpecs, harvestRaw, harvestKinds, harvestSeen = s, r, k, seen
		harvestMu.Unlock()
	})
}

func chromeRecord(t *testing.T) []byte {
	t.Helper()
	raw := rawClientHello(t, utls.HelloChrome_133)
	rec := make([]byte, 5+len(raw))
	rec[0], rec[1], rec[2] = 0x16, 0x03, 0x01
	rec[3], rec[4] = byte(len(raw)>>8), byte(len(raw))
	copy(rec[5:], raw)
	return rec
}

func countBins(t *testing.T, dir string) int {
	t.Helper()
	files, _ := os.ReadDir(dir)
	n := 0
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".bin" {
			n++
		}
	}
	return n
}

func TestHarvestDedupAndPersist(t *testing.T) {
	resetHarvestState(t)
	dir := t.TempDir()
	SetHarvestDir(dir)
	t.Cleanup(func() { SetHarvestDir("") })

	// Two captures of the same browser (GREASE differs each time) must collapse
	// to one stored fingerprint and one file on disk.
	if err := HarvestRawClientHello(chromeRecord(t)); err != nil {
		t.Fatalf("harvest 1: %v", err)
	}
	if err := HarvestRawClientHello(chromeRecord(t)); err != nil {
		t.Fatalf("harvest 2: %v", err)
	}

	harvestMu.RLock()
	n := len(harvestSpecs)
	harvestMu.RUnlock()
	if n != 1 {
		t.Fatalf("in-memory specs = %d, want 1 after dedup", n)
	}
	if got := countBins(t, dir); got != 1 {
		t.Fatalf("persisted .bin files = %d, want 1", got)
	}

	// A fresh process should reload the fingerprint from disk.
	resetHarvestState(t)
	if got, err := LoadHarvestDir(dir); err != nil || got != 1 {
		t.Fatalf("LoadHarvestDir = (%d, %v), want (1, nil)", got, err)
	}
}
