package buf

import (
	"io"
	"net"
)

// Relay pumps data both ways between a and b until either direction ends,
// then closes both conns. aReader/bReader may override the read side of a/b
// (e.g. to intercept the first bytes); pass nil to read from the conn directly.
func Relay(a, b net.Conn, aReader, bReader io.Reader) {
	if aReader == nil {
		aReader = a
	}
	if bReader == nil {
		bReader = b
	}
	done := make(chan struct{}, 2)
	pump := func(dst net.Conn, src io.Reader) {
		_, _ = Copy(NewReader(src), NewWriter(dst))
		done <- struct{}{}
	}
	go pump(b, aReader)
	go pump(a, bReader)
	<-done
	a.Close()
	b.Close()
	<-done
}
