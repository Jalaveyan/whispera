package marionette

import (
	"encoding/binary"
	"net"
)

// isLocalDiscovery checks if the packet is destined for local discovery (multicast/broadcast)
// OR if it is unwanted QUIC (UDP 443) traffic.
func isLocalDiscovery(data []byte) bool {
	if len(data) < 20 {
		return false
	}

	// Assume IPv4 first (Version is first 4 bits)
	version := data[0] >> 4
	var protocol byte
	var dstIP net.IP
	var headerLen int

	switch version {
	case 4:
		headerLen = int(data[0]&0x0F) * 4
		if len(data) < headerLen {
			return false
		}
		protocol = data[9]
		dstIP = net.IP(data[16:20])
	case 6:
		// IPv6 fixed header is 40 bytes
		if len(data) < 40 {
			return false
		}
		headerLen = 40
		protocol = data[6] // Next Header
		dstIP = net.IP(data[24:40])
	default:
		return false
	}

	// 1. Check specific blocked IPs (Multicast/Broadcast)
	if dstIP.IsMulticast() || dstIP.IsLinkLocalMulticast() || dstIP.Equal(net.IPv4bcast) {
		return true
	}
	// SSDP specific check
	if dstIP.Equal(net.ParseIP("239.255.255.250")) {
		return true
	}

	// 2. Check UDP Ports (SSDP=1900, mDNS=5353, QUIC=443)
	if protocol == 17 { // UDP
		if len(data) < headerLen+4 {
			return false
		}
		// UDP Header: [SrcPort(2)][DstPort(2)]...
		udpBase := headerLen
		dstPort := binary.BigEndian.Uint16(data[udpBase+2 : udpBase+4])

		if dstPort == 1900 || dstPort == 5353 {
			return true
		}
	}

	return false
}
