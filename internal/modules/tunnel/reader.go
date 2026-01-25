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
	// 1. Read raw data
	n, err := dr.r.Read(p)
	if n > 0 {
		// 2. Deobfuscate in-place (if possible) or allocate
		// We pass 'p[:n]' which contains the data
		// 'Process' returns new slice usually.
		res, _, derr := dr.obf.Process(p[:n], interfaces.DirectionInbound)
		if derr != nil {
			return 0, derr
		}
		// Copy back
		copy(p, res)
		return len(res), err
	}
	return n, err
}
