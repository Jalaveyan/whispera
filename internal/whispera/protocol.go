// Package whispera provides the Whispera Protocol (WLESS) - a lightweight VLESS-like protocol
// with minimal padding, integrated obfuscation, and compression
package whispera

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// Protocol version
	Version byte = 1

	// Maximum padding size (lower than VLESS for efficiency)
	MaxPadding = 64 // VLESS uses up to 900 bytes, we use 64

	// Minimum packet size
	MinPacketSize = 32
)

// Command types
type Command byte

const (
	CommandTCP   Command = 0x01
	CommandUDP   Command = 0x02
	CommandMux   Command = 0x03
	CommandPing  Command = 0x04
	CommandPong  Command = 0x05
	CommandData  Command = 0x10
	CommandClose Command = 0x11
	CommandReset Command = 0x12
)

// Addon flags (bitmask)
type Addon byte

const (
	AddonNone           Addon = 0x00
	AddonObfuscation    Addon = 0x01 // Apply obfuscation
	AddonCompression    Addon = 0x02 // Apply compression (lz4/zstd)
	AddonPadding        Addon = 0x04 // Add random padding
	AddonEncrypted      Addon = 0x08 // Data is encrypted
	AddonMLProfile      Addon = 0x10 // Use ML-selected profile
	AddonTimingMask     Addon = 0x20 // Apply timing masking
	AddonFragmented     Addon = 0x40 // Packet is fragmented
	AddonTLSFingerprint Addon = 0x80 // TLS fingerprint selection
)

// TLSFingerprintType defines browser fingerprint types
type TLSFingerprintType byte

const (
	FingerprintAuto    TLSFingerprintType = 0x00
	FingerprintChrome  TLSFingerprintType = 0x01
	FingerprintFirefox TLSFingerprintType = 0x02
	FingerprintSafari  TLSFingerprintType = 0x03
	FingerprintiOS     TLSFingerprintType = 0x04
	FingerprintAndroid TLSFingerprintType = 0x05
	FingerprintRandom  TLSFingerprintType = 0xFF
)

// AddressType
type AddressType byte

const (
	AddrTypeIPv4   AddressType = 0x01
	AddrTypeDomain AddressType = 0x02
	AddrTypeIPv6   AddressType = 0x03
)

// ObfuscationProfile
type ObfuscationProfile byte

const (
	ProfileNone     ObfuscationProfile = 0x00
	ProfileVK       ObfuscationProfile = 0x01
	ProfileYandex   ObfuscationProfile = 0x02
	ProfileMailRu   ObfuscationProfile = 0x03
	ProfileTelegram ObfuscationProfile = 0x04
	ProfileYouTube  ObfuscationProfile = 0x05
	ProfileGeneric  ObfuscationProfile = 0x06
	ProfileML       ObfuscationProfile = 0xFF // ML-selected
)

// CompressionType
type CompressionType byte

const (
	CompressionNone CompressionType = 0x00
	CompressionLZ4  CompressionType = 0x01
	CompressionZstd CompressionType = 0x02
)

// RequestHeader represents the Whispera Protocol request header
// Format: [Version:1][UUID:16][Addons:1][AddonData:N][Command:1][Port:2][AddrType:1][Address:N]
type RequestHeader struct {
	Version   byte
	UUID      [16]byte
	Addons    Addon
	AddonData *AddonData
	Command   Command
	Port      uint16
	AddrType  AddressType
	Address   []byte
}

// AddonData contains optional addon information
type AddonData struct {
	ObfuscationProfile ObfuscationProfile
	CompressionType    CompressionType
	PaddingLength      byte
	FragmentID         uint16
	FragmentTotal      byte
	FragmentSeq        byte
}

// ResponseHeader represents the server response header
// Format: [Version:1][Addons:1][AddonData:N]
type ResponseHeader struct {
	Version   byte
	Addons    Addon
	AddonData *AddonData
}

// ReadRequestHeader reads and parses a Whispera request header
func ReadRequestHeader(r io.Reader) (*RequestHeader, error) {
	hdr := &RequestHeader{}

	// Read version
	var version [1]byte
	if _, err := io.ReadFull(r, version[:]); err != nil {
		return nil, err
	}
	hdr.Version = version[0]

	if hdr.Version != Version {
		return nil, errors.New("unsupported Whispera protocol version")
	}

	// Read UUID (16 bytes)
	if _, err := io.ReadFull(r, hdr.UUID[:]); err != nil {
		return nil, err
	}

	// Read addons flags
	var addons [1]byte
	if _, err := io.ReadFull(r, addons[:]); err != nil {
		return nil, err
	}
	hdr.Addons = Addon(addons[0])

	// Read addon data if present
	if hdr.Addons != AddonNone {
		addonData, err := readAddonData(r, hdr.Addons)
		if err != nil {
			return nil, err
		}
		hdr.AddonData = addonData
	}

	// Read command
	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return nil, err
	}
	hdr.Command = Command(cmd[0])

	// For TCP/UDP commands, read destination
	if hdr.Command == CommandTCP || hdr.Command == CommandUDP {
		// Read port (2 bytes, big endian) - используем stack buffer
		var port [2]byte
		if _, err := io.ReadFull(r, port[:]); err != nil {
			return nil, err
		}
		hdr.Port = binary.BigEndian.Uint16(port[:])

		// Read address type
		var addrType [1]byte
		if _, err := io.ReadFull(r, addrType[:]); err != nil {
			return nil, err
		}
		hdr.AddrType = AddressType(addrType[0])

		// УЛУЧШЕНИЕ: Pre-allocate buffer для адреса базируясь на типе
		// Это избегает множественных аллокаций и append операций
		switch hdr.AddrType {
		case AddrTypeIPv4:
			// IPv4: 4 байта
			hdr.Address = make([]byte, 4)
			if _, err := io.ReadFull(r, hdr.Address); err != nil {
				return nil, err
			}
		case AddrTypeIPv6:
			// IPv6: 16 байт
			hdr.Address = make([]byte, 16)
			if _, err := io.ReadFull(r, hdr.Address); err != nil {
				return nil, err
			}
		case AddrTypeDomain:
			// Domain: length byte + domain
			var domainLen [1]byte
			if _, err := io.ReadFull(r, domainLen[:]); err != nil {
				return nil, err
			}
			if domainLen[0] == 0 {
				return nil, errors.New("empty domain name")
			}
			hdr.Address = make([]byte, domainLen[0])
			if _, err := io.ReadFull(r, hdr.Address); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("invalid address type")
		}
	}

	return hdr, nil
}

// readAddonData reads addon-specific data based on flags with minimal allocations
func readAddonData(r io.Reader, addons Addon) (*AddonData, error) {
	data := &AddonData{}

	// УЛУЧШЕНИЕ: Используем stack-allocated arrays вместо отдельных аллокаций
	var buf [256]byte // Максимум 255 байт padding + несколько байт для других данных

	// Read obfuscation profile if addon present
	if addons&AddonObfuscation != 0 || addons&AddonMLProfile != 0 {
		var profile [1]byte
		if _, err := io.ReadFull(r, profile[:]); err != nil {
			return nil, err
		}
		data.ObfuscationProfile = ObfuscationProfile(profile[0])
	}

	// Read compression type if addon present
	if addons&AddonCompression != 0 {
		var comp [1]byte
		if _, err := io.ReadFull(r, comp[:]); err != nil {
			return nil, err
		}
		data.CompressionType = CompressionType(comp[0])
	}

	// Read padding length if addon present
	if addons&AddonPadding != 0 {
		var padLen [1]byte
		if _, err := io.ReadFull(r, padLen[:]); err != nil {
			return nil, err
		}
		data.PaddingLength = padLen[0]

		// УЛУЧШЕНИЕ: Читаем padding в stack buffer без аллокации
		if data.PaddingLength > 0 {
			if _, err := io.ReadFull(r, buf[:data.PaddingLength]); err != nil {
				return nil, err
			}
		}
	}

	// Read fragmentation info if addon present
	if addons&AddonFragmented != 0 {
		var fragInfo [4]byte
		if _, err := io.ReadFull(r, fragInfo[:]); err != nil {
			return nil, err
		}
		data.FragmentID = binary.BigEndian.Uint16(fragInfo[0:2])
		data.FragmentTotal = fragInfo[2]
		data.FragmentSeq = fragInfo[3]
	}

	return data, nil
}

// WriteRequestHeader writes a Whispera request header
func WriteRequestHeader(w io.Writer, hdr *RequestHeader) error {
	// Write version
	if _, err := w.Write([]byte{hdr.Version}); err != nil {
		return err
	}

	// Write UUID
	if _, err := w.Write(hdr.UUID[:]); err != nil {
		return err
	}

	// Write addons
	if _, err := w.Write([]byte{byte(hdr.Addons)}); err != nil {
		return err
	}

	// Write addon data if present
	if hdr.Addons != AddonNone && hdr.AddonData != nil {
		if err := writeAddonData(w, hdr.Addons, hdr.AddonData); err != nil {
			return err
		}
	}

	// Write command
	if _, err := w.Write([]byte{byte(hdr.Command)}); err != nil {
		return err
	}

	// For TCP/UDP commands, write destination
	if hdr.Command == CommandTCP || hdr.Command == CommandUDP {
		// ОПТИМИЗАЦИЯ: Используем stack buffer вместо heap allocation для port
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], hdr.Port)
		if _, err := w.Write(port[:]); err != nil {
			return err
		}

		// Write address type
		if _, err := w.Write([]byte{byte(hdr.AddrType)}); err != nil {
			return err
		}

		// Write address
		if hdr.AddrType == AddrTypeDomain {
			if _, err := w.Write([]byte{byte(len(hdr.Address))}); err != nil {
				return err
			}
		}
		if _, err := w.Write(hdr.Address); err != nil {
			return err
		}
	}

	return nil
}

// writeAddonData writes addon-specific data based on flags
func writeAddonData(w io.Writer, addons Addon, data *AddonData) error {
	// Write obfuscation profile
	if addons&AddonObfuscation != 0 || addons&AddonMLProfile != 0 {
		if _, err := w.Write([]byte{byte(data.ObfuscationProfile)}); err != nil {
			return err
		}
	}

	// Write compression type
	if addons&AddonCompression != 0 {
		if _, err := w.Write([]byte{byte(data.CompressionType)}); err != nil {
			return err
		}
	}

	// Write padding
	if addons&AddonPadding != 0 {
		paddingLen := data.PaddingLength
		if paddingLen > MaxPadding {
			paddingLen = MaxPadding
		}
		if _, err := w.Write([]byte{paddingLen}); err != nil {
			return err
		}
		if paddingLen > 0 {
			// ОПТИМИЗАЦИЯ: Используем stack buffer (MaxPadding=64) вместо heap allocation
			var padding [MaxPadding]byte
			rand.Read(padding[:paddingLen]) // Random padding (only needed bytes)
			if _, err := w.Write(padding[:paddingLen]); err != nil {
				return err
			}
		}
	}

	// Write fragmentation info
	if addons&AddonFragmented != 0 {
		// ОПТИМИЗАЦИЯ: Используем stack buffer вместо heap allocation для fragInfo
		var fragInfo [4]byte
		binary.BigEndian.PutUint16(fragInfo[0:2], data.FragmentID)
		fragInfo[2] = data.FragmentTotal
		fragInfo[3] = data.FragmentSeq
		if _, err := w.Write(fragInfo[:]); err != nil {
			return err
		}
	}

	return nil
}

// ReadResponseHeader reads a Whispera response header
func ReadResponseHeader(r io.Reader) (*ResponseHeader, error) {
	hdr := &ResponseHeader{}

	// ОПТИМИЗАЦИЯ: Используем stack buffer для reading header bytes
	var buf [2]byte // Максимум что нужно: version (1) + addons (1)
	
	// Read version
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return nil, err
	}
	hdr.Version = buf[0]

	// Read addons
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return nil, err
	}
	hdr.Addons = Addon(buf[0])

	// Read addon data if present
	if hdr.Addons != AddonNone {
		addonData, err := readAddonData(r, hdr.Addons)
		if err != nil {
			return nil, err
		}
		hdr.AddonData = addonData
	}

	return hdr, nil
}

// WriteResponseHeader writes a Whispera response header
func WriteResponseHeader(w io.Writer, hdr *ResponseHeader) error {
	// Write version
	if _, err := w.Write([]byte{hdr.Version}); err != nil {
		return err
	}

	// Write addons
	if _, err := w.Write([]byte{byte(hdr.Addons)}); err != nil {
		return err
	}

	// Write addon data if present
	if hdr.Addons != AddonNone && hdr.AddonData != nil {
		if err := writeAddonData(w, hdr.Addons, hdr.AddonData); err != nil {
			return err
		}
	}

	return nil
}

// HeaderSize returns the minimum size of a request header
func HeaderSize(hdr *RequestHeader) int {
	size := 1 + 16 + 1 + 1 // version + uuid + addons + command

	if hdr.Addons != AddonNone {
		if hdr.Addons&AddonObfuscation != 0 || hdr.Addons&AddonMLProfile != 0 {
			size += 1
		}
		if hdr.Addons&AddonCompression != 0 {
			size += 1
		}
		if hdr.Addons&AddonPadding != 0 && hdr.AddonData != nil {
			size += 1 + int(hdr.AddonData.PaddingLength)
		}
		if hdr.Addons&AddonFragmented != 0 {
			size += 4
		}
	}

	if hdr.Command == CommandTCP || hdr.Command == CommandUDP {
		size += 2 + 1 // port + addrType
		switch hdr.AddrType {
		case AddrTypeIPv4:
			size += 4
		case AddrTypeIPv6:
			size += 16
		case AddrTypeDomain:
			size += 1 + len(hdr.Address)
		}
	}

	return size
}

// NewRequestHeader creates a new request header with sensible defaults
func NewRequestHeader(uuid [16]byte, cmd Command, addr string, port uint16) *RequestHeader {
	hdr := &RequestHeader{
		Version: Version,
		UUID:    uuid,
		Addons:  AddonObfuscation | AddonCompression,
		Command: cmd,
		Port:    port,
		AddonData: &AddonData{
			ObfuscationProfile: ProfileML,
			CompressionType:    CompressionLZ4,
		},
	}

	// Detect address type
	if ip := parseIP(addr); ip != nil {
		if len(ip) == 4 {
			hdr.AddrType = AddrTypeIPv4
		} else {
			hdr.AddrType = AddrTypeIPv6
		}
		hdr.Address = ip
	} else {
		hdr.AddrType = AddrTypeDomain
		hdr.Address = []byte(addr)
	}

	return hdr
}

// parseIP parses an IP address string
func parseIP(s string) []byte {
	// Simple IPv4 check
	var ip [4]byte
	n, _ := fmt.Sscanf(s, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])
	if n == 4 {
		return ip[:]
	}
	return nil
}
