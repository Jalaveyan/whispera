package mux

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
)

func BenchmarkMuxStreamThroughput(b *testing.B) {
	benchMux(b, 1400)
}

func BenchmarkMuxStreamThroughput_64K(b *testing.B) {
	benchMux(b, 65536)
}

func BenchmarkMuxStreamLatency_Small(b *testing.B) {
	benchMux(b, 64)
}

func benchMux(b *testing.B, msgSize int) {
	client, server := net.Pipe()

	cfg := DefaultConfig()
	cliSess, err := Client(client, cfg)
	if err != nil {
		b.Fatal(err)
	}
	srvSess, err := Server(server, cfg)
	if err != nil {
		b.Fatal(err)
	}

	defer cliSess.Close()
	defer srvSess.Close()

	go func() {
		for {
			stream, err := srvSess.AcceptStream()
			if err != nil {
				return
			}
			go func(s net.Conn) {
				defer s.Close()
				buf := make([]byte, msgSize)
				for {
					n, err := s.Read(buf)
					if err != nil {
						return
					}
					if _, err := s.Write(buf[:n]); err != nil {
						return
					}
				}
			}(stream)
		}
	}()

	stream, err := cliSess.OpenStream()
	if err != nil {
		b.Fatal(err)
	}
	defer stream.Close()

	data := make([]byte, msgSize)
	resp := make([]byte, msgSize)

	b.SetBytes(int64(msgSize) * 2)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := stream.Write(data); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(stream, resp); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMuxOpenClose(b *testing.B) {
	client, server := net.Pipe()

	cfg := DefaultConfig()
	cliSess, err := Client(client, cfg)
	if err != nil {
		b.Fatal(err)
	}
	srvSess, err := Server(server, cfg)
	if err != nil {
		b.Fatal(err)
	}

	defer cliSess.Close()
	defer srvSess.Close()

	var accepted int64
	go func() {
		for {
			stream, err := srvSess.AcceptStream()
			if err != nil {
				return
			}
			atomic.AddInt64(&accepted, 1)
			stream.Close()
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream, err := cliSess.OpenStream()
		if err != nil {
			b.Fatal(err)
		}
		stream.Close()
	}
}

func BenchmarkMuxParallel(b *testing.B) {
	client, server := net.Pipe()

	cfg := DefaultConfig()
	cliSess, err := Client(client, cfg)
	if err != nil {
		b.Fatal(err)
	}
	srvSess, err := Server(server, cfg)
	if err != nil {
		b.Fatal(err)
	}

	defer cliSess.Close()
	defer srvSess.Close()

	go func() {
		for {
			stream, err := srvSess.AcceptStream()
			if err != nil {
				return
			}
			go func(s net.Conn) {
				defer s.Close()
				buf := make([]byte, 1400)
				for {
					n, err := s.Read(buf)
					if err != nil {
						return
					}
					s.Write(buf[:n])
				}
			}(stream)
		}
	}()

	b.SetBytes(1400 * 2)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		stream, err := cliSess.OpenStream()
		if err != nil {
			b.Fatal(err)
		}
		defer stream.Close()

		data := make([]byte, 1400)
		resp := make([]byte, 1400)
		for pb.Next() {
			stream.Write(data)
			_, _ = io.ReadFull(stream, resp)
		}
	})
}
