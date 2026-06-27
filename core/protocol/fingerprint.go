package protocol

import (
	"encoding/binary"
	"hash/fnv"
	mrand "math/rand"
	"sort"
	"strconv"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// Browser fingerprints only: each must have a matching UA dialect in
// newBrowserProfile. App fingerprints (e.g. OkHttp) are excluded because
// they don't send browser HTTP headers, so pairing them with our browser
// headers would itself be a mismatch.
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
}

var (
	harvestMu    sync.RWMutex
	harvestSpecs []*utls.ClientHelloSpec
	harvestRaw   [][]byte
	harvestKinds []browserKind   // browser family of each harvested spec, for UA pairing
	harvestSeen  = map[string]bool{} // dedup keys, so the same browser isn't stored 32×
)

var detectedBrowserID utls.ClientHelloID

const maxHarvest = 32

func addHarvestedFingerprint(spec *utls.ClientHelloSpec, raw []byte) {
	if spec == nil {
		return
	}
	key, keyed := harvestKey(raw)

	harvestMu.Lock()
	if keyed && harvestSeen[key] {
		harvestMu.Unlock()
		return
	}
	added := false
	if len(harvestSpecs) < maxHarvest {
		harvestSpecs = append(harvestSpecs, spec)
		harvestRaw = append(harvestRaw, raw)
		harvestKinds = append(harvestKinds, classifyClientHello(raw))
		if keyed {
			harvestSeen[key] = true
		}
		added = true
	}
	harvestMu.Unlock()

	// Persist outside the lock; a new unique fingerprint survives restarts.
	if added && keyed {
		persistFingerprint(key, raw)
	}
}

// harvestKey is a GREASE-normalized, order-independent digest of the extension
// set, so repeated hellos from one browser map to a single entry. Both GREASE
// values and extension order vary per handshake (Chrome shuffles extensions),
// so we mask GREASE and sort before hashing.
func harvestKey(raw []byte) (string, bool) {
	exts, ok := clientHelloExtTypes(raw)
	if !ok {
		return "", false
	}
	norm := make([]uint16, len(exts))
	for i, t := range exts {
		if isGREASE(t) {
			t = 0x0a0a
		}
		norm[i] = t
	}
	sort.Slice(norm, func(i, j int) bool { return norm[i] < norm[j] })

	h := fnv.New64a()
	var b [2]byte
	for _, t := range norm {
		binary.BigEndian.PutUint16(b[:], t)
		_, _ = h.Write(b[:])
	}
	return strconv.FormatUint(h.Sum64(), 16), true
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

// pickFingerprint returns the TLS ClientHelloID and (for harvested specs) the
// raw spec to mimic, plus uaID: a representative ID whose UA dialect matches the
// fingerprint so the HTTP layer stays coherent. For harvested specs (HelloCustom
// carries no browser family) uaID comes from classifying the captured ClientHello.
func pickFingerprint() (id utls.ClientHelloID, spec *utls.ClientHelloSpec, uaID utls.ClientHelloID) {
	harvestOnce.Do(initHarvest)

	harvestMu.RLock()
	defer harvestMu.RUnlock()

	if len(harvestSpecs) > 0 {
		i := mrand.Intn(len(harvestSpecs))
		return utls.HelloCustom, harvestSpecs[i], repIDForKind(harvestKinds[i])
	}

	if detectedBrowserID.Client != "" {
		return detectedBrowserID, nil, detectedBrowserID
	}

	picked := fingerprintPool[mrand.Intn(len(fingerprintPool))]
	return picked, nil, picked
}

// repIDForKind maps a browser family back to a representative ClientHelloID so
// uaForFingerprint/kindForFingerprint produce a matching UA and header dialect.
func repIDForKind(k browserKind) utls.ClientHelloID {
	switch k {
	case kindFirefox:
		return utls.HelloFirefox_148
	case kindSafari:
		return utls.HelloSafari_16_0
	default:
		return utls.HelloChrome_133
	}
}

// TLS extension type IDs used to tell browser families apart.
const (
	extRecordSizeLimit = 0x001c // Firefox sends it; Chrome/Safari don't
	extALPSOld         = 0x4469 // application_settings 17513 (older Chrome/Edge)
	extALPSNew         = 0x44cd // application_settings 17613 (Chrome 124+): Chromium-only
)

// classifyClientHello infers the browser family from the extension set of a
// captured ClientHello, so a harvested fingerprint gets a matching User-Agent
// instead of always defaulting to Chrome.
func classifyClientHello(raw []byte) browserKind {
	exts, ok := clientHelloExtTypes(raw)
	if !ok {
		return kindChromium
	}
	hasGREASE := false
	for _, t := range exts {
		switch {
		case t == extRecordSizeLimit:
			return kindFirefox
		case t == extALPSOld, t == extALPSNew:
			return kindChromium
		case isGREASE(t):
			hasGREASE = true
		}
	}
	if hasGREASE {
		return kindSafari // GREASE but no ALPS ⇒ Apple
	}
	return kindChromium
}

// isGREASE reports whether a TLS value is a GREASE placeholder (RFC 8701):
// both bytes equal with low nibble 0xA. Firefox never sends GREASE.
func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && v&0x0f0f == 0x0a0a
}

// clientHelloExtTypes parses a raw ClientHello (with or without the TLS record
// header) and returns the list of extension type IDs. Fully bounds-checked.
func clientHelloExtTypes(raw []byte) ([]uint16, bool) {
	b := raw
	if len(b) >= 5 && b[0] == 0x16 { // strip TLS record header
		b = b[5:]
	}
	if len(b) < 4 || b[0] != 0x01 { // handshake type: ClientHello
		return nil, false
	}
	b = b[4:] // skip handshake type + 3-byte length

	if len(b) < 34 { // client_version(2) + random(32)
		return nil, false
	}
	b = b[34:]

	if len(b) < 1 || len(b) < 1+int(b[0]) { // session_id
		return nil, false
	}
	b = b[1+int(b[0]):]

	if len(b) < 2 { // cipher_suites
		return nil, false
	}
	csLen := int(b[0])<<8 | int(b[1])
	if len(b) < 2+csLen {
		return nil, false
	}
	b = b[2+csLen:]

	if len(b) < 1 || len(b) < 1+int(b[0]) { // compression_methods
		return nil, false
	}
	b = b[1+int(b[0]):]

	if len(b) < 2 { // extensions length
		return nil, false
	}
	extTotal := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < extTotal {
		extTotal = len(b)
	}
	b = b[:extTotal]

	var types []uint16
	for len(b) >= 4 {
		t := uint16(b[0])<<8 | uint16(b[1])
		l := int(b[2])<<8 | int(b[3])
		types = append(types, t)
		if len(b) < 4+l {
			break
		}
		b = b[4+l:]
	}
	return types, true
}
