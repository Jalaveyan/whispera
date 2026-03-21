package evasion

import (
	"crypto/rand"
	"testing"
)

func BenchmarkAdversarialApply_256(b *testing.B) {
	benchAdversarialApply(b, 256)
}

func BenchmarkAdversarialApply_1400(b *testing.B) {
	benchAdversarialApply(b, 1400)
}

func BenchmarkAdversarialApply_8192(b *testing.B) {
	benchAdversarialApply(b, 8192)
}

func benchAdversarialApply(b *testing.B, size int) {
	ae := NewAdversarialEngine()
	data := make([]byte, size)
	rand.Read(data)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ae.Apply(data)
	}
}

func BenchmarkExtractFeatures(b *testing.B) {
	ae := NewAdversarialEngine()
	data := make([]byte, 1400)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ae.extractFeatures(data)
	}
}

func BenchmarkSurrogatePredict(b *testing.B) {
	ae := NewAdversarialEngine()
	data := make([]byte, 1400)
	rand.Read(data)
	features := ae.extractFeatures(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ae.surrogate.predict(features)
	}
}

func BenchmarkProcessPacket_Outbound(b *testing.B) {
	m := NewMarionette()
	data := make([]byte, 1400)
	rand.Read(data)
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = m.ProcessPacket(data, "outbound")
	}
}

func BenchmarkProcessPacket_Inbound(b *testing.B) {
	m := NewMarionette()
	data := make([]byte, 1400)
	rand.Read(data)
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = m.ProcessPacket(data, "inbound")
	}
}

func BenchmarkAdversarialApply_Parallel(b *testing.B) {
	ae := NewAdversarialEngine()
	data := make([]byte, 1400)
	rand.Read(data)
	b.SetBytes(1400)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		local := make([]byte, 1400)
		copy(local, data)
		for pb.Next() {
			ae.Apply(local)
		}
	})
}
