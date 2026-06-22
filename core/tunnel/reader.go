package tunnel

import (
	"io"
	"whispera/common/runtime/interfaces"
)

type deobfuscatingReader struct {
	r   io.Reader
	obf interfaces.ObfuscationProcessor
}

func (dr *deobfuscatingReader) Read(p []byte) (int, error) {
	n, err := dr.r.Read(p)
	if n > 0 {
		res, _, derr := dr.obf.Process(p[:n], interfaces.DirectionInbound)
		if derr != nil {
			return 0, derr
		}
		copy(p, res)
		return len(res), err
	}
	return n, err
}
