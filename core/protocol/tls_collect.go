package protocol

import (
	"os"
	"path/filepath"
	"sync"

	utls "github.com/refraction-networking/utls"
)

var harvestOnce sync.Once

func HarvestRawClientHello(record []byte) error {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	spec, err := fp.FingerprintClientHello(record)
	if err != nil {
		return err
	}
	addHarvestedFingerprint(spec, record)
	return nil
}

func LoadHarvestDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
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
	dir := os.Getenv("WHISPERA_FP_DIR")
	if dir == "" {
		return
	}
	if n, err := LoadHarvestDir(dir); err == nil && n > 0 {
	}
}
