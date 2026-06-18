package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
)

const (
	FrameConnect      uint8 = 0x01
	FrameConnectOK    uint8 = 0x02
	FrameConnectFail  uint8 = 0x03
	FrameData         uint8 = 0x04
	FrameClose        uint8 = 0x05
	FramePing         uint8 = 0x06
	FramePong         uint8 = 0x07
	FrameUDPData      uint8 = 0x08
	FrameRawPacket    uint8 = 0x09
	FrameWindowUpdate uint8 = 0x0A
	FramePadding      uint8 = 0x0B
)

const (
	FlagFin      uint8 = 0x01
	FlagAck      uint8 = 0x02
	FlagUrgent   uint8 = 0x04
	FlagCompress uint8 = 0x08
)

const (
	AddrTypeIPv4   uint8 = 0x01
	AddrTypeDomain uint8 = 0x03
	AddrTypeIPv6   uint8 = 0x04
)

const (
	HeaderSize    = 8
	MaxPayloadLen = 131072
)

var (
	ErrFrameTooLarge   = errors.New("frame payload too large")
	ErrInvalidFrame    = errors.New("invalid frame format")
	ErrStreamNotFound  = errors.New("stream not found")
	ErrStreamClosed    = errors.New("stream closed")
	ErrConnectionReset = errors.New("connection reset")
)

type Frame struct {
	StreamID uint16
	Type     uint8
	Flags    uint8
	Payload  []byte
}

func FrameTypeName(t uint8) string {
	switch t {
	case FrameConnect:
		return "CONNECT"
	case FrameConnectOK:
		return "CONNECT_OK"
	case FrameConnectFail:
		return "CONNECT_FAIL"
	case FrameData:
		return "DATA"
	case FrameClose:
		return "CLOSE"
	case FramePing:
		return "PING"
	case FramePong:
		return "PONG"
	case FrameUDPData:
		return "UDP_DATA"
	case FrameRawPacket:
		return "RAW_PACKET"
	case FrameWindowUpdate:
		return "WINDOW_UPDATE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

func (f *Frame) Encode() ([]byte, error) {
	payloadLen := len(f.Payload)
	if payloadLen > MaxPayloadLen {
		return nil, ErrFrameTooLarge
	}

	buf := make([]byte, HeaderSize+payloadLen)

	binary.BigEndian.PutUint16(buf[0:2], f.StreamID)

	buf[2] = f.Type
	buf[3] = f.Flags

	binary.BigEndian.PutUint32(buf[4:8], uint32(payloadLen))

	if payloadLen > 0 {
		copy(buf[HeaderSize:], f.Payload)
	}

	return buf, nil
}

func Decode(data []byte) (*Frame, error) {
	if len(data) < HeaderSize {
		return nil, ErrInvalidFrame
	}

	f := &Frame{
		StreamID: binary.BigEndian.Uint16(data[0:2]),
		Type:     data[2],
		Flags:    data[3],
	}

	payloadLen := binary.BigEndian.Uint32(data[4:8])
	if payloadLen > MaxPayloadLen {
		return nil, ErrFrameTooLarge
	}

	expectedLen := HeaderSize + int(payloadLen)
	if len(data) < expectedLen {
		return nil, ErrInvalidFrame
	}

	if payloadLen > 0 {
		f.Payload = data[HeaderSize:expectedLen]
	}

	return f, nil
}

type ConnectPayload struct {
	Profile  uint8
	AddrType uint8
	Addr     string
	Port     uint16
	Protocol uint8
}

const (
	ProtoTCP uint8 = 0x01
	ProtoUDP uint8 = 0x02
)

const (
	ProfileBalanced   uint8 = 0x00
	ProfileLowLatency uint8 = 0x01
	ProfileAggressive uint8 = 0x02
	ProfilePersonal   uint8 = 0x03
)

func (p *ConnectPayload) Encode() []byte {
	size := 1 + 1 + 1

	switch p.AddrType {
	case AddrTypeIPv4:
		size += 4
	case AddrTypeIPv6:
		size += 16
	case AddrTypeDomain:
		size += 1 + len(p.Addr)
	}

	size += 2

	buf := make([]byte, size)

	buf[0] = p.Profile
	buf[1] = p.Protocol
	buf[2] = p.AddrType

	offset := 3
	switch p.AddrType {
	case AddrTypeIPv4:
		copy(buf[offset:], parseIPv4(p.Addr))
		offset += 4
	case AddrTypeIPv6:
		copy(buf[offset:], parseIPv6(p.Addr))
		offset += 16
	case AddrTypeDomain:
		buf[offset] = byte(len(p.Addr))
		offset++
		copy(buf[offset:], p.Addr)
		offset += len(p.Addr)
	}

	binary.BigEndian.PutUint16(buf[offset:], p.Port)

	return buf
}

func DecodeConnectPayload(data []byte) (*ConnectPayload, error) {
	if len(data) < 5 {
		return nil, ErrInvalidFrame
	}

	p := &ConnectPayload{
		Profile:  data[0],
		Protocol: data[1],
		AddrType: data[2],
	}

	offset := 3

	switch p.AddrType {
	case AddrTypeIPv4:
		if len(data) < offset+4+2 {
			return nil, ErrInvalidFrame
		}
		p.Addr = fmt.Sprintf("%d.%d.%d.%d", data[offset], data[offset+1], data[offset+2], data[offset+3])
		offset += 4
	case AddrTypeIPv6:
		if len(data) < offset+16+2 {
			return nil, ErrInvalidFrame
		}
		p.Addr = fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			binary.BigEndian.Uint16(data[offset:]),
			binary.BigEndian.Uint16(data[offset+2:]),
			binary.BigEndian.Uint16(data[offset+4:]),
			binary.BigEndian.Uint16(data[offset+6:]),
			binary.BigEndian.Uint16(data[offset+8:]),
			binary.BigEndian.Uint16(data[offset+10:]),
			binary.BigEndian.Uint16(data[offset+12:]),
			binary.BigEndian.Uint16(data[offset+14:]))
		offset += 16
	case AddrTypeDomain:
		if len(data) < offset+1 {
			return nil, ErrInvalidFrame
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return nil, ErrInvalidFrame
		}
		p.Addr = string(data[offset : offset+domainLen])
		offset += domainLen
	default:
		return nil, ErrInvalidFrame
	}

	if len(data) < offset+2 {
		return nil, ErrInvalidFrame
	}
	p.Port = binary.BigEndian.Uint16(data[offset:])

	return p, nil
}

type StreamIDGenerator struct {
	counter uint32
}

func NewStreamIDGenerator() *StreamIDGenerator {
	return &StreamIDGenerator{counter: 0}
}
func (g *StreamIDGenerator) Next() uint16 {
	for {
		id := atomic.AddUint32(&g.counter, 1)
		streamID := uint16(id % 65535)
		if streamID == 0 {
			continue
		}

		hb := streamID >> 8
		lb := streamID & 0xFF
		if hb >= 0x14 && hb <= 0x17 && lb <= 0x04 {
			continue
		}

		return streamID
	}
}

func parseIPv4(addr string) []byte {
	ip := net.ParseIP(addr)
	if ip == nil {
		return make([]byte, 4)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return make([]byte, 4)
	}
	return ipv4
}

func parseIPv6(addr string) []byte {
	ip := net.ParseIP(addr)
	if ip == nil {
		return make([]byte, 16)
	}
	ipv6 := ip.To16()
	if ipv6 == nil {
		return make([]byte, 16)
	}
	return ipv6
}

func NewCloseFrame(streamID uint16) *Frame {
	return &Frame{
		StreamID: streamID,
		Type:     FrameClose,
		Flags:    FlagFin,
		Payload:  nil,
	}
}

func NewConnectFailFrame(streamID uint16, reason string) *Frame {
	return &Frame{
		StreamID: streamID,
		Type:     FrameConnectFail,
		Flags:    0,
		Payload:  []byte(reason),
	}
}

func NewPongFrame() *Frame {
	return &Frame{
		StreamID: 0,
		Type:     FramePong,
		Flags:    0,
		Payload:  nil,
	}
}

func ParseRawPacketFrame(f *Frame) (packetID uint32, rawPacket []byte, err error) {
	if f.Type != FrameRawPacket {
		return 0, nil, ErrInvalidFrame
	}

	if len(f.Payload) < 4 {
		return 0, nil, ErrInvalidFrame
	}

	packetID = uint32(f.Payload[0])<<24 |
		uint32(f.Payload[1])<<16 |
		uint32(f.Payload[2])<<8 |
		uint32(f.Payload[3])

	rawPacket = f.Payload[4:]

	return packetID, rawPacket, nil
}

func WriteFrameHeader(buf []byte, streamID uint16, fType uint8, flags uint8, payloadLen int) {
	binary.BigEndian.PutUint16(buf[0:2], streamID)
	buf[2] = fType
	buf[3] = flags
	binary.BigEndian.PutUint32(buf[4:8], uint32(payloadLen))
}

func SealUDPData(buf []byte, streamID uint16, addrType uint8, addr string, port uint16, dataOffset int) ([]byte, error) {
	if len(buf) < dataOffset {
		return nil, errors.New("buffer too small/offset mismatch")
	}

	dataLen := len(buf) - dataOffset

	udpHeaderLen := 1 + 2
	switch addrType {
	case AddrTypeIPv4:
		udpHeaderLen += 4
	case AddrTypeIPv6:
		udpHeaderLen += 16
	case AddrTypeDomain:
		udpHeaderLen += 1 + len(addr)
	}

	if dataOffset < HeaderSize+udpHeaderLen {
		return nil, errors.New("insufficient headroom for headers")
	}

	frameStart := dataOffset - udpHeaderLen - HeaderSize

	udpStart := frameStart + HeaderSize
	current := udpStart

	buf[current] = addrType
	current++

	switch addrType {
	case AddrTypeIPv4:
		copy(buf[current:], parseIPv4(addr))
		current += 4
	case AddrTypeIPv6:
		copy(buf[current:], parseIPv6(addr))
		current += 16
	case AddrTypeDomain:
		buf[current] = byte(len(addr))
		current++
		copy(buf[current:], addr)
		current += len(addr)
	}

	binary.BigEndian.PutUint16(buf[current:], port)

	totalPayloadLen := udpHeaderLen + dataLen
	WriteFrameHeader(buf[frameStart:], streamID, FrameUDPData, 0, totalPayloadLen)

	return buf[frameStart:], nil
}
