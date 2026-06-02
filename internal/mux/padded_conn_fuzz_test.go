package mux

import (
	"bytes"
	"testing"
)

func FuzzPaddedConnRead(f *testing.F) {
	f.Add([]byte{0x00, 0x07, 0x00, 0x05, 'w', 'o', 'r', 'l', 'd'})
	f.Add([]byte{0x00, 0x01})
	f.Add([]byte{0xFF, 0xFF})
	f.Add([]byte{0x00, 0x02, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		conn := &padTestConn{}
		conn.buf.Write(data)
		pc := NewPaddedConn(conn, 128)
		tmp := make([]byte, 4096)
		for i := 0; i < 1<<20; i++ {
			n, err := pc.Read(tmp)
			if n < 0 || n > len(tmp) {
				t.Fatalf("Read returned n=%d out of range", n)
			}
			if err != nil {
				return
			}
		}
	})
}

func FuzzPaddedConnRoundTrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add(bytes.Repeat([]byte{0xAB}, 130000))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		conn := &padTestConn{}
		pc := NewPaddedConn(conn, 256)
		if _, err := pc.Write(data); err != nil {
			t.Fatalf("Write: %v", err)
		}
		got := make([]byte, 0, len(data))
		tmp := make([]byte, 8192)
		for len(got) < len(data) {
			n, err := pc.Read(tmp)
			if n > 0 {
				got = append(got, tmp[:n]...)
			}
			if err != nil {
				t.Fatalf("Read err after %d/%d: %v", len(got), len(data), err)
			}
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("round-trip mismatch len got=%d want=%d", len(got), len(data))
		}
	})
}
