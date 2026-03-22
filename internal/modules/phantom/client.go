package phantom

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type ClientConfig struct {
	ServerPublicKey string
	ShortId string
	PrivateKey []byte
}

type ClientAuth struct {
	config *ClientConfig
}

func NewClientAuth(cfg *ClientConfig) *ClientAuth {
	return &ClientAuth{config: cfg}
}

func (c *ClientAuth) GenerateAuthData() ([]byte, error) {
	data := make([]byte, 16)

	timestamp := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(data[0:8], timestamp)

	shortIdBytes, err := base64.StdEncoding.DecodeString(c.config.ShortId)
	if err != nil {
		shortIdBytes = []byte(c.config.ShortId)
	}
	copy(data[8:16], shortIdBytes)

	return data, nil
}

func (c *ClientAuth) GenerateAuthDataWithSignature() ([]byte, error) {
	data := make([]byte, 48)

	timestamp := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(data[0:8], timestamp)

	shortIdBytes, _ := base64.StdEncoding.DecodeString(c.config.ShortId)
	copy(data[8:16], shortIdBytes)

	if len(c.config.PrivateKey) == 32 && c.config.ServerPublicKey != "" {
		serverPub, err := base64.StdEncoding.DecodeString(c.config.ServerPublicKey)
		if err == nil && len(serverPub) == 32 {
			sharedSecret, err := curve25519.X25519(c.config.PrivateKey, serverPub)
			if err == nil {
				copy(data[16:48], sharedSecret)
			}
		}
	}

	return data, nil
}

func (c *ClientAuth) CreatePhantomExtension() (extensionType uint16, extensionData []byte, err error) {
	authData, err := c.GenerateAuthData()
	if err != nil {
		return 0, nil, err
	}

	return phantomExtensionID, authData, nil
}

func ValidateServerPublicKey(key string) bool {
	if len(key) >= 43 {
		if b, err := base64.StdEncoding.DecodeString(key); err == nil && len(b) == 32 {
			return true
		}
	}
	return false
}

func (c *ClientAuth) GenerateSessionID() (clientRandom, sessionID []byte, err error) {
	if c.config.ServerPublicKey == "" {
		return nil, nil, fmt.Errorf("server public key required")
	}

	serverPub, err := base64.StdEncoding.DecodeString(c.config.ServerPublicKey)
	if err != nil || len(serverPub) != 32 {
		return nil, nil, fmt.Errorf("invalid server public key (must be 32 bytes Base64)")
	}

	ephemeralPriv := make([]byte, 32)
	if len(c.config.PrivateKey) == 32 {
		copy(ephemeralPriv, c.config.PrivateKey)
	} else if _, err := rand.Read(ephemeralPriv); err != nil {
		return nil, nil, err
	}

	ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err := curve25519.X25519(ephemeralPriv, serverPub)
	if err != nil {
		return nil, nil, err
	}

	hkdfR := hkdf.New(sha256.New, sharedSecret, nil, []byte("whispera-auth-key"))
	authKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfR, authKey); err != nil {
		return nil, nil, err
	}

	timestamp := uint64(time.Now().UnixMilli())
	mac := hmac.New(sha256.New, authKey)
	mac.Write([]byte("whispera-session-id"))
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, timestamp)
	mac.Write(timestampBytes)
	hmacResult := mac.Sum(nil)

	sessionID = make([]byte, 32)
	binary.BigEndian.PutUint64(sessionID[0:8], timestamp)
	copy(sessionID[8:32], hmacResult[:24])
	return ephemeralPub, sessionID, nil
}

func (c *ClientAuth) WrapConn(conn net.Conn, sni string) error {
	clientRandom, sessionID, err := c.GenerateSessionID()
	if err != nil {
		return fmt.Errorf("phantom auth: %w", err)
	}

	hello := buildChromeClientHello(clientRandom, sessionID, sni)

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	return writeFragmentedClientHello(conn, hello)
}

func writeFragmentedClientHello(conn net.Conn, record []byte) error {
	if len(record) < 6 || record[0] != 0x16 {
		_, err := conn.Write(record)
		return err
	}

	contentType := record[0]
	majorVer := record[1]
	minorVer := record[2]
	payload := record[5:]
	fragSize := 40 + mrand.Intn(25)

	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > fragSize {
			chunk = payload[:fragSize]
		}
		payload = payload[len(chunk):]

		frag := make([]byte, 5+len(chunk))
		frag[0] = contentType
		frag[1] = majorVer
		frag[2] = minorVer
		frag[3] = byte(len(chunk) >> 8)
		frag[4] = byte(len(chunk))
		copy(frag[5:], chunk)

		if _, err := conn.Write(frag); err != nil {
			return err
		}

		if len(payload) > 0 {
			time.Sleep(time.Duration(1+mrand.Intn(10)) * time.Millisecond)
		}
	}
	return nil
}

func greaseValue() uint16 {
	grease := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
	return grease[mrand.Intn(len(grease))]
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func buildExtension(typ uint16, data []byte) []byte {
	ext := appendU16(nil, typ)
	ext = appendU16(ext, uint16(len(data)))
	return append(ext, data...)
}

func buildChromeClientHello(clientRandom, sessionID []byte, sni string) []byte {
	g1, g2, g3 := greaseValue(), greaseValue(), greaseValue()

	cipherSuites := appendU16(nil, g1)
	for _, cs := range []uint16{
		0x1301, 0x1302, 0x1303,
		0xc02c, 0xc02b, 0xc030, 0xc02f,
		0xcca9, 0xcca8,
		0xc024, 0xc023, 0xc028, 0xc027,
		0xc00a, 0xc009, 0xc014, 0xc013,
	} {
		cipherSuites = appendU16(cipherSuites, cs)
	}

	var exts []byte

	exts = append(exts, buildExtension(g2, []byte{0x00})...)

	sniBytes := []byte(sni)
	sniPayload := appendU16(nil, uint16(3+len(sniBytes)))
	sniPayload = append(sniPayload, 0x00)
	sniPayload = appendU16(sniPayload, uint16(len(sniBytes)))
	sniPayload = append(sniPayload, sniBytes...)
	exts = append(exts, buildExtension(0x0000, sniPayload)...)

	exts = append(exts, buildExtension(0x0017, nil)...)

	exts = append(exts, buildExtension(0xff01, []byte{0x00})...)

	groups := appendU16(nil, uint16(2*5))
	groups = appendU16(groups, g3)
	for _, g := range []uint16{0x001d, 0x0017, 0x0018, 0x0019} {
		groups = appendU16(groups, g)
	}
	exts = append(exts, buildExtension(0x000a, groups)...)

	exts = append(exts, buildExtension(0x000b, []byte{0x01, 0x00})...)

	exts = append(exts, buildExtension(0x0023, nil)...)

	alpnData := []byte{0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	alpnPayload := appendU16(nil, uint16(len(alpnData)))
	alpnPayload = append(alpnPayload, alpnData...)
	exts = append(exts, buildExtension(0x0010, alpnPayload)...)

	exts = append(exts, buildExtension(0x0005, []byte{0x01, 0x00, 0x00, 0x00, 0x00})...)

	sigAlgs := appendU16(nil, 16)
	for _, sa := range []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601} {
		sigAlgs = appendU16(sigAlgs, sa)
	}
	exts = append(exts, buildExtension(0x000d, sigAlgs)...)

	exts = append(exts, buildExtension(0x0012, nil)...)

	keySharePub := make([]byte, 32)
	rand.Read(keySharePub)
	ksEntry := appendU16(nil, 0x001d)
	ksEntry = appendU16(ksEntry, 32)
	ksEntry = append(ksEntry, keySharePub...)
	greaseKS := appendU16(nil, g3)
	greaseKS = appendU16(greaseKS, 1)
	greaseKS = append(greaseKS, 0x00)
	allKS := append(greaseKS, ksEntry...)
	ksPayload := appendU16(nil, uint16(len(allKS)))
	ksPayload = append(ksPayload, allKS...)
	exts = append(exts, buildExtension(0x0033, ksPayload)...)

	exts = append(exts, buildExtension(0x002d, []byte{0x01, 0x01})...)

	svData := []byte{0x05}
	svData = appendU16(svData, g1)
	svData = appendU16(svData, 0x0304)
	svData = appendU16(svData, 0x0303)
	svData[0] = byte(len(svData) - 1)
	exts = append(exts, buildExtension(0x002b, svData)...)

	exts = append(exts, buildExtension(0x001b, []byte{0x01, 0x00, 0x02})...)

	exts = append(exts, buildExtension(0x4469, []byte{0x00, 0x03, 0x02, 'h', '2'})...)

	exts = append(exts, buildExtension(greaseValue(), []byte{0x00})...)

	extLen := len(exts)
	bodyWithoutPad := 2 + 32 + 1 + 32 + 2 + len(cipherSuites) + 1 + 1 + 2 + extLen + 4 + 5
	if bodyWithoutPad < 517 {
		padLen := 517 - bodyWithoutPad - 4
		if padLen < 0 {
			padLen = 0
		}
		padding := make([]byte, padLen)
		exts = append(exts, buildExtension(0x0015, padding)...)
	}

	totalExtLen := len(exts)

	bodyLen := 2 + 32 + 1 + 32 + 2 + len(cipherSuites) + 1 + 1 + 2 + totalExtLen
	body := make([]byte, bodyLen)
	pos := 0

	body[pos] = 0x03; body[pos+1] = 0x03; pos += 2
	copy(body[pos:pos+32], clientRandom); pos += 32
	body[pos] = 32; pos++
	copy(body[pos:pos+32], sessionID); pos += 32
	binary.BigEndian.PutUint16(body[pos:pos+2], uint16(len(cipherSuites))); pos += 2
	copy(body[pos:], cipherSuites); pos += len(cipherSuites)
	body[pos] = 1; pos++
	body[pos] = 0x00; pos++
	binary.BigEndian.PutUint16(body[pos:pos+2], uint16(totalExtLen)); pos += 2
	copy(body[pos:], exts)

	handshake := make([]byte, 4+bodyLen)
	handshake[0] = 0x01
	handshake[1] = byte(bodyLen >> 16)
	handshake[2] = byte(bodyLen >> 8)
	handshake[3] = byte(bodyLen)
	copy(handshake[4:], body)

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	return record
}
