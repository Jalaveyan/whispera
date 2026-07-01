package dns

import (
	"crypto/rand"
	"fmt"
	"net"
	"strings"
)

const (
	dnsTypeA    = 0x0001
	dnsTypeAAAA = 0x001C
)

// mergeDualStack queries A and AAAA via the given single-type query func and
// merges the results. It only fails if both queries fail.
func mergeDualStack(query func(qtype uint16) ([]net.IP, error)) ([]net.IP, error) {
	v4, errV4 := query(dnsTypeA)
	v6, errV6 := query(dnsTypeAAAA)
	if errV4 != nil && errV6 != nil {
		return nil, errV4
	}
	return append(v4, v6...), nil
}

func buildDNSMsg(domain string, qtype uint16) ([]byte, [2]byte) {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		id = [2]byte{0x12, 0x34}
	}
	buf := []byte{
		id[0], id[1],
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0x00, 0x01)
	return buf, id
}

func parseDNSResponse(response []byte, wantID [2]byte) ([]net.IP, error) {
	if len(response) < 12 {
		return nil, fmt.Errorf("dns response too short (%d bytes)", len(response))
	}
	if response[0] != wantID[0] || response[1] != wantID[1] {
		return nil, fmt.Errorf("dns: transaction id mismatch")
	}
	rcode := response[3] & 0x0F
	if rcode != 0 {
		return nil, fmt.Errorf("dns error rcode=%d", rcode)
	}
	ancount := int(response[6])<<8 | int(response[7])
	if ancount == 0 {
		return nil, fmt.Errorf("dns: no answers")
	}

	offset := 12
	for offset < len(response) {
		if response[offset] == 0 {
			offset++
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
			break
		}
		offset += int(response[offset]) + 1
	}
	offset += 4

	var ips []net.IP
	for i := 0; i < ancount && offset < len(response); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rtype := int(response[offset])<<8 | int(response[offset+1])
		offset += 8
		rdlen := int(response[offset])<<8 | int(response[offset+1])
		offset += 2
		if offset+rdlen > len(response) {
			break
		}
		if rtype == 1 && rdlen == 4 {
			ip := make(net.IP, 4)
			copy(ip, response[offset:offset+4])
			ips = append(ips, ip)
		} else if rtype == 28 && rdlen == 16 {
			ip := make(net.IP, 16)
			copy(ip, response[offset:offset+16])
			ips = append(ips, ip)
		}
		offset += rdlen
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dns: no A/AAAA records in response")
	}
	return ips, nil
}
