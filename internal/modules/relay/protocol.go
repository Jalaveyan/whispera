// Package relay provides the relay protocol for tunneled connections
//
// Frame Types:
//   - FrameConnect (0x01): Initiate connection to target
//   - FrameConnectOK (0x02): Connection established
//   - FrameConnectFail (0x03): Connection failed
//   - FrameData (0x04): Application data transfer
//   - FrameClose (0x05): Close stream
//   - FramePing (0x06): Keep-alive ping
//   - FramePong (0x07): Keep-alive pong
//   - FrameUDPData (0x08): UDP data (DNS, etc)
//   - FrameRawPacket (0x09): Raw IP packet from TUN (NEW)
//
// RawPacketFrame (0x09):
//
//	Purpose: Encapsulate any IP packet (TCP/UDP/ICMP/etc) for tunneling
//	Payload: [PacketID:4 bytes][RawPacket:N bytes]
//	Usage: Enables tunneling of non-SOCKS5 applications and protocols
//
// Processing:
//
//	Client side: TUN handler captures packet -> creates RawPacketFrame -> sends via tunnel
//	Server side: Receives RawPacketFrame -> validates IPv4 header -> injects to network
//	Response: Server receives response -> creates new RawPacketFrame -> sends back
package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
)

// Frame types
const (
	FrameConnect     uint8 = 0x01 // Request connection to target
	FrameConnectOK   uint8 = 0x02 // Connection successful
	FrameConnectFail uint8 = 0x03 // Connection failed
	FrameData        uint8 = 0x04 // Data transfer
	FrameClose       uint8 = 0x05 // Close stream
	FramePing        uint8 = 0x06 // Keep-alive ping
	FramePong        uint8 = 0x07 // Keep-alive pong
	FrameUDPData     uint8 = 0x08 // UDP data (for DNS etc)
	FrameRawPacket   uint8 = 0x09 // Raw IP packet (TCP/UDP/ICMP/etc from TUN)
)

// Frame flags
const (
	FlagFin      uint8 = 0x01 // Final frame for this stream
	FlagAck      uint8 = 0x02 // Acknowledgment
	FlagUrgent   uint8 = 0x04 // Urgent/priority data
	FlagCompress uint8 = 0x08 // Payload is compressed
)

// Address types (SOCKS5 compatible)
const (
	AddrTypeIPv4   uint8 = 0x01
	AddrTypeDomain uint8 = 0x03
	AddrTypeIPv6   uint8 = 0x04
)

// Header size
const (
	HeaderSize    = 8
	MaxPayloadLen = 65535
)

// Errors
var (
	ErrFrameTooLarge   = errors.New("frame payload too large")
	ErrInvalidFrame    = errors.New("invalid frame format")
	ErrStreamNotFound  = errors.New("stream not found")
	ErrStreamClosed    = errors.New("stream closed")
	ErrConnectionReset = errors.New("connection reset")
)

// Frame represents a single protocol frame
type Frame struct {
	StreamID uint16 // Stream identifier (0 = control channel)
	Type     uint8  // Frame type
	Flags    uint8  // Frame flags
	Payload  []byte // Frame payload
}

// FrameTypeName returns human-readable frame type name
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
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// Encode serializes the frame to bytes
// Format: [StreamID:2][Type:1][Flags:1][Length:4][Payload:N]
func (f *Frame) Encode() ([]byte, error) {
	payloadLen := len(f.Payload)
	if payloadLen > MaxPayloadLen {
		return nil, ErrFrameTooLarge
	}

	buf := make([]byte, HeaderSize+payloadLen)

	// StreamID (big-endian)
	binary.BigEndian.PutUint16(buf[0:2], f.StreamID)

	// Type and Flags
	buf[2] = f.Type
	buf[3] = f.Flags

	// Payload length (big-endian)
	binary.BigEndian.PutUint32(buf[4:8], uint32(payloadLen))

	// Payload
	if payloadLen > 0 {
		copy(buf[HeaderSize:], f.Payload)
	}

	return buf, nil
}

// Decode deserializes a frame from bytes
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
		f.Payload = make([]byte, payloadLen)
		copy(f.Payload, data[HeaderSize:expectedLen])
	}

	return f, nil
}

// ReadFrame reads a single frame from a reader
func ReadFrame(r io.Reader) (*Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	f := &Frame{
		StreamID: binary.BigEndian.Uint16(header[0:2]),
		Type:     header[2],
		Flags:    header[3],
	}

	payloadLen := binary.BigEndian.Uint32(header[4:8])
	if payloadLen > MaxPayloadLen {
		return nil, ErrFrameTooLarge
	}

	if payloadLen > 0 {
		f.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
	}

	return f, nil
}

// WriteFrame writes a frame to a writer
func WriteFrame(w io.Writer, f *Frame) error {
	data, err := f.Encode()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ConnectPayload represents a CONNECT frame payload
type ConnectPayload struct {
	AddrType uint8  // Address type
	Addr     string // Address (IP or domain)
	Port     uint16 // Port number
	Protocol uint8  // 0x01=TCP, 0x02=UDP
}

// Protocol types
const (
	ProtoTCP uint8 = 0x01
	ProtoUDP uint8 = 0x02
)

// Behavior Profiles (Legacy support)
const (
	ProfileBalanced   uint8 = 0x00
	ProfileLowLatency uint8 = 0x01
	ProfileAggressive uint8 = 0x02
	ProfilePersonal   uint8 = 0x03
)

// Encode serializes the connect payload
func (p *ConnectPayload) Encode() []byte {
	var buf []byte

	// Protocol
	buf = append(buf, p.Protocol)

	// Address type
	buf = append(buf, p.AddrType)

	// Address
	switch p.AddrType {
	case AddrTypeIPv4:
		// IPv4: 4 bytes
		ip := parseIPv4(p.Addr)
		buf = append(buf, ip...)
	case AddrTypeIPv6:
		// IPv6: 16 bytes
		ip := parseIPv6(p.Addr)
		buf = append(buf, ip...)
	case AddrTypeDomain:
		// Domain: 1 byte length + domain
		buf = append(buf, byte(len(p.Addr)))
		buf = append(buf, []byte(p.Addr)...)
	}

	// Port (big-endian)
	buf = append(buf, byte(p.Port>>8), byte(p.Port&0xff))

	return buf
}

// DecodeConnectPayload parses a connect payload
func DecodeConnectPayload(data []byte) (*ConnectPayload, error) {
	if len(data) < 5 { // Min length increased for Profile
		return nil, ErrInvalidFrame
	}

	p := &ConnectPayload{
		Protocol: data[0],
		AddrType: data[1],
	}

	offset := 2

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
		// Simplified IPv6 parsing
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

// StreamIDGenerator generates unique stream IDs
type StreamIDGenerator struct {
	counter uint32
}

// NewStreamIDGenerator creates a new stream ID generator
func NewStreamIDGenerator() *StreamIDGenerator {
	return &StreamIDGenerator{counter: 0}
}

// Next returns the next stream ID
func (g *StreamIDGenerator) Next() uint16 {
	// Increment and wrap at 65535, skip 0 (reserved for control)
	for {
		id := atomic.AddUint32(&g.counter, 1)
		streamID := uint16(id % 65535)
		if streamID == 0 {
			continue
		}

		// Avoid TLS Header collision (See tunnel.go readLoop)
		hb := streamID >> 8
		lb := streamID & 0xFF
		if hb >= 0x14 && hb <= 0x17 && lb <= 0x04 {
			continue
		}

		return streamID
	}
}

// Helper functions for IP parsing
func parseIPv4(addr string) []byte {
	var ip [4]byte
	fmt.Sscanf(addr, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])
	return ip[:]
}

func parseIPv6(addr string) []byte {
	// Simplified - in production use net.ParseIP
	ip := make([]byte, 16)
	// Parse hex groups
	var groups [8]uint16
	fmt.Sscanf(addr, "%x:%x:%x:%x:%x:%x:%x:%x",
		&groups[0], &groups[1], &groups[2], &groups[3],
		&groups[4], &groups[5], &groups[6], &groups[7])
	for i, g := range groups {
		binary.BigEndian.PutUint16(ip[i*2:], g)
	}
	return ip
}

// NewConnectFrame creates a CONNECT frame
func NewConnectFrame(streamID uint16, proto uint8, addrType uint8, addr string, port uint16) *Frame {
	payload := &ConnectPayload{
		Protocol: proto,
		AddrType: addrType,
		Addr:     addr,
		Port:     port,
	}
	return &Frame{
		StreamID: streamID,
		Type:     FrameConnect,
		Flags:    0,
		Payload:  payload.Encode(),
	}
}

// NewDataFrame creates a DATA frame
func NewDataFrame(streamID uint16, data []byte) *Frame {
	return &Frame{
		StreamID: streamID,
		Type:     FrameData,
		Flags:    0,
		Payload:  data,
	}
}

// NewCloseFrame creates a CLOSE frame
func NewCloseFrame(streamID uint16) *Frame {
	return &Frame{
		StreamID: streamID,
		Type:     FrameClose,
		Flags:    FlagFin,
		Payload:  nil,
	}
}

// NewConnectOKFrame creates a CONNECT_OK frame
func NewConnectOKFrame(streamID uint16) *Frame {
	return &Frame{
		StreamID: streamID,
		Type:     FrameConnectOK,
		Flags:    0,
		Payload:  nil,
	}
}

// NewConnectFailFrame creates a CONNECT_FAIL frame with error message
func NewConnectFailFrame(streamID uint16, reason string) *Frame {
	return &Frame{
		StreamID: streamID,
		Type:     FrameConnectFail,
		Flags:    0,
		Payload:  []byte(reason),
	}
}

// NewPingFrame creates a PING frame
func NewPingFrame() *Frame {
	return &Frame{
		StreamID: 0,
		Type:     FramePing,
		Flags:    0,
		Payload:  nil,
	}
}

// NewPongFrame creates a PONG frame
func NewPongFrame() *Frame {
	return &Frame{
		StreamID: 0,
		Type:     FramePong,
		Flags:    0,
		Payload:  nil,
	}
}

// NewUDPDataFrame creates a UDP_DATA frame
func NewUDPDataFrame(streamID uint16, addrType uint8, addr string, port uint16, data []byte) *Frame {
	// Format: [AddrType:1][Addr:N][Port:2][Data:N]
	var payload []byte

	// Address type
	payload = append(payload, addrType)

	// Address
	switch addrType {
	case AddrTypeIPv4:
		payload = append(payload, parseIPv4(addr)...)
	case AddrTypeIPv6:
		payload = append(payload, parseIPv6(addr)...)
	case AddrTypeDomain:
		payload = append(payload, byte(len(addr)))
		payload = append(payload, []byte(addr)...)
	}

	// Port
	payload = append(payload, byte(port>>8), byte(port&0xff))

	// Data
	payload = append(payload, data...)

	return &Frame{
		StreamID: streamID,
		Type:     FrameUDPData,
		Flags:    0,
		Payload:  payload,
	}
}

// NewRawPacketFrame creates a RAW_PACKET frame
// Payload format: [PacketID:4][RawPacketData:N]
func NewRawPacketFrame(packetID uint32, rawPacket []byte) *Frame {
	var payload []byte

	// PacketID (4 bytes, big-endian)
	payload = append(payload,
		byte(packetID>>24),
		byte((packetID>>16)&0xff),
		byte((packetID>>8)&0xff),
		byte(packetID&0xff),
	)

	// Raw packet data
	payload = append(payload, rawPacket...)

	return &Frame{
		StreamID: 0, // Raw packets use stream 0 (control channel)
		Type:     FrameRawPacket,
		Flags:    0,
		Payload:  payload,
	}
}

// ParseRawPacketFrame extracts packet ID and data from RAW_PACKET frame
func ParseRawPacketFrame(f *Frame) (packetID uint32, rawPacket []byte, err error) {
	if f.Type != FrameRawPacket {
		return 0, nil, ErrInvalidFrame
	}

	if len(f.Payload) < 4 {
		return 0, nil, ErrInvalidFrame
	}

	// Parse PacketID (first 4 bytes)
	packetID = uint32(f.Payload[0])<<24 |
		uint32(f.Payload[1])<<16 |
		uint32(f.Payload[2])<<8 |
		uint32(f.Payload[3])

	// Rest is raw packet data
	rawPacket = f.Payload[4:]

	return packetID, rawPacket, nil
}
