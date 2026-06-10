package chameleon

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

	detectOnce        sync.Once
	detectedBrowserID utls.ClientHelloID
)

const maxHarvest = 32

func AddHarvestedFingerprint(spec *utls.ClientHelloSpec) {
	if spec == nil {
		return
	}
	harvestMu.Lock()
	if len(harvestSpecs) < maxHarvest {
		harvestSpecs = append(harvestSpecs, spec)
	}
	harvestMu.Unlock()
}

func pickFingerprint() (utls.ClientHelloID, *utls.ClientHelloSpec) {
	harvestOnce.Do(initHarvest)
	detectOnce.Do(func() {
		detectedBrowserID = detectDefaultBrowserID()
	})

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
