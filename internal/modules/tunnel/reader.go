package tunnel

import (
	"io"
	"whispera/internal/core/interfaces"
)

// DeobfuscatingReader wrapper
type deobfuscatingReader struct {
	r   io.Reader
	obf interfaces.Obfuscator
}

func (dr *deobfuscatingReader) Read(p []byte) (int, error) {
	// Paranoid Mode: Allocate a temporary buffer to ensure memory isolation.
	// This prevents any potential in-place decryption artifacts or buffer overlaps
	// that could corrupt data (causing TCP Checksum failures downstream).
	tempBuf := make([]byte, len(p))

	// 1. Read raw data into temp buffer
	n, err := dr.r.Read(tempBuf)
	if n > 0 {
		// 2. Deobfuscate
		res, _, derr := dr.obf.Process(tempBuf[:n], interfaces.DirectionInbound)
		if derr != nil {
			// fmt.Printf("[ERROR] DR: Deobfuscation failed: %v\n", derr)
			return 0, derr
		}
		// 3. Copy result to caller's buffer
		copy(p, res)
		return len(res), err
	}
	return n, err
}
