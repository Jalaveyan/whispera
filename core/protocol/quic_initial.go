package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

var quicV1InitialSalt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

const (
	quicFrameTypePadding = 0x00
	quicFrameTypeCrypto  = 0x06
	quicMinInitialPacket = 1200
)

func hkdfExpandLabelQUIC(secret, context []byte, label string, length int) []byte {
	b := make([]byte, 3, 3+6+len(label)+1+len(context))
	binary.BigEndian.PutUint16(b, uint16(length))
	b[2] = uint8(6 + len(label))
	b = append(b, []byte("tls13 ")...)
	b = append(b, []byte(label)...)
	b = b[:3+6+len(label)+1]
	b[3+6+len(label)] = uint8(len(context))
	b = append(b, context...)

	out := make([]byte, length)
	if _, err := hkdf.Expand(sha256.New, secret, b).Read(out); err != nil {
		return nil
	}
	return out
}

func quicInitialSecrets(dcid []byte) (clientSecret, serverSecret []byte) {
	initialSecret := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	clientSecret = hkdfExpandLabelQUIC(initialSecret, nil, "client in", sha256.Size)
	serverSecret = hkdfExpandLabelQUIC(initialSecret, nil, "server in", sha256.Size)
	return
}

func quicKeyIVHP(secret []byte) (key, iv, hp []byte) {
	key = hkdfExpandLabelQUIC(secret, nil, "quic key", 16)
	iv = hkdfExpandLabelQUIC(secret, nil, "quic iv", 12)
	hp = hkdfExpandLabelQUIC(secret, nil, "quic hp", 16)
	return
}

func quicAEADNonce(iv []byte, pn uint64) []byte {
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	var pnb [8]byte
	binary.BigEndian.PutUint64(pnb[:], pn)
	off := len(nonce) - 8
	for i := 0; i < 8; i++ {
		nonce[off+i] ^= pnb[i]
	}
	return nonce
}

func quicSeal(key, iv []byte, pn uint64, plaintext, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := quicAEADNonce(iv, pn)
	return gcm.Seal(nil, nonce, plaintext, ad), nil
}

func quicOpen(key, iv []byte, pn uint64, ciphertext, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := quicAEADNonce(iv, pn)
	return gcm.Open(nil, nonce, ciphertext, ad)
}

func quicHeaderProtectionMask(hpKey, sample []byte) ([]byte, error) {
	if len(sample) != 16 {
		return nil, errors.New("whispera: invalid quic hp sample size")
	}
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)
	return mask, nil
}

func quicVarintAppend(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v <= 1073741823:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

func quicVarintParse(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("whispera: empty varint")
	}
	l := 1 << (b[0] >> 6)
	if len(b) < l {
		return 0, 0, errors.New("whispera: truncated varint")
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, l, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		return nil
	}
	return b
}

// buildMarkedClientHello constructs a realistic TLS 1.3 ClientHello (via uTLS)
// whose Random field carries the camo HMAC marker bound to its own key share.
func buildMarkedClientHello(camoKey []byte, sni string) (chBytes, keyShare, random []byte, err error) {
	uconn := utls.UClient(nil, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloGolang)
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, nil, nil, err
	}
	hello := uconn.HandshakeState.Hello
	if hello == nil || len(hello.Random) != 32 {
		return nil, nil, nil, errors.New("whispera: quic probe: no client hello random")
	}
	ks := extractX25519KeyShare(hello.KeyShares)
	if len(ks) == 0 {
		return nil, nil, nil, errors.New("whispera: quic probe: no x25519 key share")
	}
	// Drop any larger (e.g. post-quantum hybrid) key shares the preset may
	// have added — this probe is a one-shot throwaway artifact, not a real
	// handshake, and keeping only X25519 keeps it well under one UDP datagram.
	for _, share := range hello.KeyShares {
		if share.Group == utls.X25519 {
			hello.KeyShares = []utls.KeyShare{share}
			break
		}
	}
	marker := buildCamoMarker(camoKey, ks)
	copy(hello.Random, marker[:])
	hello.Raw = nil
	raw, err := hello.Marshal()
	if err != nil {
		return nil, nil, nil, err
	}
	return raw, ks, hello.Random, nil
}

func quicCryptoFrame(data []byte) []byte {
	f := []byte{quicFrameTypeCrypto}
	f = quicVarintAppend(f, 0)
	f = quicVarintAppend(f, uint64(len(data)))
	f = append(f, data...)
	return f
}

// buildQUICCamoProbe builds a one-shot, throwaway, RFC 9001-shaped QUIC v1
// Initial packet whose embedded ClientHello.Random carries the camo marker.
// It is never meant to complete a real handshake — its only purpose is to
// authenticate the source (ip,port) to the server's camouflage gate before
// the real quic-go dial proceeds from the same local UDP port.
func buildQUICCamoProbe(camoKey []byte, sni string) ([]byte, error) {
	dcid := randomBytes(8)
	scid := randomBytes(8)
	if dcid == nil || scid == nil {
		return nil, errors.New("whispera: quic probe: rand failure")
	}

	chBytes, _, _, err := buildMarkedClientHello(camoKey, sni)
	if err != nil {
		return nil, err
	}

	payload := quicCryptoFrame(chBytes)

	clientSecret, _ := quicInitialSecrets(dcid)
	key, iv, hp := quicKeyIVHP(clientSecret)

	const pn = uint64(0)
	pnLen := 1

	header := []byte{0xc0 | byte(pnLen-1)}
	header = append(header, 0x00, 0x00, 0x00, 0x01) // version 1
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0x00) // empty token length

	const aeadOverhead = 16
	padTo := quicMinInitialPacket
	unpaddedTotal := len(header) + quicVarintLen(uint64(pnLen+len(payload)+aeadOverhead)) + pnLen + len(payload) + aeadOverhead
	if padTo < unpaddedTotal {
		padTo = unpaddedTotal
	}
	padLen := padTo - unpaddedTotal
	if padLen > 0 {
		payload = append(payload, make([]byte, padLen)...)
	}

	lenField := uint64(pnLen + len(payload) + aeadOverhead)
	header = quicVarintAppend(header, lenField)
	pnOffset := len(header)
	header = append(header, byte(pn))

	ad := make([]byte, len(header))
	copy(ad, header)

	sealed, err := quicSeal(key, iv, pn, payload, ad)
	if err != nil {
		return nil, err
	}

	packet := append(header, sealed...)

	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(packet) {
		return nil, errors.New("whispera: quic probe: packet too short to sample")
	}
	mask, err := quicHeaderProtectionMask(hp, packet[sampleOffset:sampleOffset+16])
	if err != nil {
		return nil, err
	}
	packet[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}

	return packet, nil
}

func quicVarintLen(v uint64) int {
	switch {
	case v <= 63:
		return 1
	case v <= 16383:
		return 2
	case v <= 1073741823:
		return 4
	default:
		return 8
	}
}

type parsedQUICInitial struct {
	dcid     []byte
	sni      string
	random   []byte
	keyShare []byte
}

// parseQUICInitialClientHello decrypts a client-sent QUIC v1 Initial packet
// (Initial-level keys are derived solely from the public salt and the
// packet's own destination connection ID, by design — no secret is needed)
// and extracts the embedded TLS ClientHello fields needed for camo-marker
// verification.
func parseQUICInitialClientHello(packet []byte) (*parsedQUICInitial, error) {
	if len(packet) < 7 || packet[0]&0x80 == 0 || packet[0]&0x40 == 0 {
		return nil, errors.New("whispera: not a quic long header packet")
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	if version != 1 {
		return nil, errors.New("whispera: unsupported quic version")
	}
	if (packet[0] >> 4 & 0x3) != 0x0 {
		return nil, errors.New("whispera: not a quic initial packet")
	}

	pos := 5
	if pos >= len(packet) {
		return nil, errors.New("whispera: truncated quic header")
	}
	dcidLen := int(packet[pos])
	pos++
	if pos+dcidLen+1 > len(packet) {
		return nil, errors.New("whispera: truncated quic dcid")
	}
	dcid := append([]byte{}, packet[pos:pos+dcidLen]...)
	pos += dcidLen
	scidLen := int(packet[pos])
	pos++
	if pos+scidLen > len(packet) {
		return nil, errors.New("whispera: truncated quic scid")
	}
	pos += scidLen

	tokenLen, n, err := quicVarintParse(packet[pos:])
	if err != nil {
		return nil, err
	}
	pos += n
	if pos+int(tokenLen) > len(packet) {
		return nil, errors.New("whispera: truncated quic token")
	}
	pos += int(tokenLen)

	lenField, n, err := quicVarintParse(packet[pos:])
	if err != nil {
		return nil, err
	}
	pos += n
	if pos+int(lenField) > len(packet) {
		return nil, errors.New("whispera: truncated quic packet")
	}

	pnOffset := pos

	clientSecret, _ := quicInitialSecrets(dcid)
	key, iv, hp := quicKeyIVHP(clientSecret)

	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(packet) {
		return nil, errors.New("whispera: quic initial too short to sample")
	}
	mask, err := quicHeaderProtectionMask(hp, packet[sampleOffset:sampleOffset+16])
	if err != nil {
		return nil, err
	}

	firstByte := packet[0] ^ (mask[0] & 0x0f)
	pnLen := int(firstByte&0x03) + 1

	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = packet[pnOffset+i] ^ mask[1+i]
	}
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = pn<<8 | uint64(pnBytes[i])
	}

	adEnd := pnOffset + pnLen
	ad := make([]byte, adEnd)
	copy(ad, packet[:adEnd])
	ad[0] = firstByte
	copy(ad[pnOffset:adEnd], pnBytes)

	if int(lenField) < pnLen {
		return nil, errors.New("whispera: quic initial length field too small")
	}
	ciphertext := packet[adEnd : pnOffset+int(lenField)]

	plaintext, err := quicOpen(key, iv, pn, ciphertext, ad)
	if err != nil {
		return nil, err
	}

	chBytes, ok := extractCryptoFrameData(plaintext)
	if !ok {
		return nil, errors.New("whispera: no crypto frame in quic initial")
	}
	msg := utls.UnmarshalClientHello(chBytes)
	if msg == nil {
		return nil, errors.New("whispera: failed to parse client hello from quic initial")
	}
	return &parsedQUICInitial{
		dcid:     dcid,
		sni:      msg.ServerName,
		random:   msg.Random,
		keyShare: extractX25519KeyShare(msg.KeyShares),
	}, nil
}

func extractCryptoFrameData(payload []byte) ([]byte, bool) {
	var crypto []byte
	for len(payload) > 0 {
		switch payload[0] {
		case quicFrameTypePadding:
			payload = payload[1:]
			continue
		case quicFrameTypeCrypto:
			payload = payload[1:]
			_, n, err := quicVarintParse(payload) // offset
			if err != nil {
				return nil, false
			}
			payload = payload[n:]
			dataLen, n, err := quicVarintParse(payload)
			if err != nil {
				return nil, false
			}
			payload = payload[n:]
			if uint64(len(payload)) < dataLen {
				return nil, false
			}
			crypto = append(crypto, payload[:dataLen]...)
			payload = payload[dataLen:]
		default:
			return nil, false
		}
	}
	if len(crypto) < 4 {
		return nil, false
	}
	return crypto, true
}
