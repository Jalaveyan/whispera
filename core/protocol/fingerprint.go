package protocol

import (
	mrand "math/rand"
	"sync"

	utls "github.com/refraction-networking/utls"
)

var fingerprintPool = []utls.ClientHelloID{
	utls.HelloChrome_133,
	utls.HelloChrome_131,
	utls.HelloChrome_120_PQ,
	utls.HelloFirefox_148,
	utls.HelloFirefox_120,
	utls.HelloEdge_106,
	utls.HelloSafari_26_3,
	utls.HelloSafari_16_0,
	utls.HelloIOS_14,
	utls.HelloAndroid_11_OkHttp,
}

var (
	harvestMu    sync.RWMutex
	harvestSpecs []*utls.ClientHelloSpec
	harvestRaw   [][]byte

	detectedBrowserID utls.ClientHelloID
)

const maxHarvest = 32

func addHarvestedFingerprint(spec *utls.ClientHelloSpec, raw []byte) {
	if spec == nil {
		return
	}
	harvestMu.Lock()
	if len(harvestSpecs) < maxHarvest {
		harvestSpecs = append(harvestSpecs, spec)
		harvestRaw = append(harvestRaw, raw)
	}
	harvestMu.Unlock()
}

func AddHarvestedFingerprint(spec *utls.ClientHelloSpec) {
	addHarvestedFingerprint(spec, nil)
}

func HarvestedRawRecords() [][]byte {
	harvestMu.RLock()
	defer harvestMu.RUnlock()
	out := make([][]byte, 0, len(harvestRaw))
	for _, rec := range harvestRaw {
		if rec != nil {
			out = append(out, append([]byte(nil), rec...))
		}
	}
	return out
}

func HarvestedFingerprintCount() int {
	harvestMu.RLock()
	defer harvestMu.RUnlock()
	return len(harvestSpecs)
}

func HarvestedFingerprintCapacity() int {
	return maxHarvest
}

func pickFingerprint() (utls.ClientHelloID, *utls.ClientHelloSpec) {
	harvestOnce.Do(initHarvest)

	harvestMu.RLock()
	defer harvestMu.RUnlock()

	if len(harvestSpecs) > 0 {
		return utls.HelloCustom, harvestSpecs[mrand.Intn(len(harvestSpecs))]
	}

	if detectedBrowserID.Client != "" {
		return detectedBrowserID, nil
	}

	return fingerprintPool[mrand.Intn(len(fingerprintPool))], nil
}
