package transport

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
)

type TLSRecordConn struct {
	net.Conn
	readBuf bytes.Buffer
}

func WrapStreamTLS(conn net.Conn) *TLSRecordConn {
	return &TLSRecordConn{Conn: conn}
}

func (c *TLSRecordConn) Write(b []byte) (int, error) {
	const maxPayload = 16383
	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxPayload {
			chunk = b[:maxPayload]
		}
		rec := make([]byte, 5+len(chunk))
		rec[0] = 0x17
		rec[1] = 0x03
		rec[2] = 0x03
		binary.BigEndian.PutUint16(rec[3:5], uint16(len(chunk)))
		copy(rec[5:], chunk)
		if _, err := c.Conn.Write(rec); err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

func (c *TLSRecordConn) Read(b []byte) (int, error) {
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	var hdr [5]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}

	if hdr[0] != 0x17 {
		n := copy(b, hdr[:])
		if n < 5 {
			c.readBuf.Write(hdr[n:])
		}
		return n, nil
	}

	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen == 0 {
		return 0, nil
	}

	payload := make([]byte, recLen)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return 0, err
	}

	n := copy(b, payload)
	if n < len(payload) {
		c.readBuf.Write(payload[n:])
	}
	return n, nil
}
