package relay

import (
	"encoding/binary"
	"log"
	"sync"

	"github.com/klauspost/reedsolomon"
)

var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65536)
	},
}

type FECEncoder struct {
	k         int
	m         int
	enc       reedsolomon.Encoder
	shards    [][]byte
	shardSize int
	idx       int
}

func NewFECEncoder(k, m int) *FECEncoder {
	enc, err := reedsolomon.New(k, m)
	if err != nil {
		log.Printf("[FEC] Failed to create encoder (k=%d, m=%d): %v", k, m, err)
		return nil
	}
	return &FECEncoder{
		k:      k,
		m:      m,
		enc:    enc,
		shards: make([][]byte, k+m),
	}
}

func (fe *FECEncoder) EncodeFEC(data []byte, seqNum uint32, headroom int) []byte {
	rsShardLen := 2 + len(data)
	payloadLen := 7 + rsShardLen
	totalLen := headroom + payloadLen

	buf := packetPool.Get().([]byte)

	if cap(buf) < totalLen {
		packetPool.Put(buf)
		buf = make([]byte, totalLen)
	}

	buf = buf[:totalLen]

	ptr := headroom
	buf[ptr] = 0xFF
	binary.BigEndian.PutUint32(buf[ptr+1:ptr+5], seqNum)
	buf[ptr+5] = byte(fe.k)
	buf[ptr+6] = byte(fe.m)

	binary.BigEndian.PutUint16(buf[ptr+7:ptr+9], uint16(len(data)))
	copy(buf[ptr+9:], data)

	shardBuf := packetPool.Get().([]byte)
	if cap(shardBuf) < rsShardLen {
		packetPool.Put(shardBuf)
		shardBuf = make([]byte, rsShardLen)
	}
	shardBuf = shardBuf[:rsShardLen]
	copy(shardBuf, buf[ptr+7:ptr+7+rsShardLen])

	fe.shards[fe.idx] = shardBuf
	if rsShardLen > fe.shardSize {
		fe.shardSize = rsShardLen
	}

	fe.idx++
	return buf
}

func (fe *FECEncoder) GetParityPackets(baseSeq uint32, headroom int) [][]byte {
	if fe.idx < fe.k {
		return nil
	}

	for i := 0; i < fe.k; i++ {
		shard := fe.shards[i]
		if len(shard) < fe.shardSize {
			newShard := shard[:fe.shardSize]
			for j := len(shard); j < fe.shardSize; j++ {
				newShard[j] = 0
			}
			fe.shards[i] = newShard
		}
	}

	for i := 0; i < fe.m; i++ {
		buf := packetPool.Get().([]byte)
		if cap(buf) < fe.shardSize {
			packetPool.Put(buf)
			buf = make([]byte, fe.shardSize)
		}
		fe.shards[fe.k+i] = buf[:fe.shardSize]
	}

	if err := fe.enc.Encode(fe.shards); err != nil {
		fe.reset()
		return nil
	}

	parityPackets := make([][]byte, fe.m)
	for i := 0; i < fe.m; i++ {
		parityData := fe.shards[fe.k+i]

		pktLen := 7 + len(parityData)
		totalLen := headroom + pktLen

		buf := packetPool.Get().([]byte)
		if cap(buf) < totalLen {
			packetPool.Put(buf)
			buf = make([]byte, totalLen)
		}
		buf = buf[:totalLen]

		ptr := headroom
		buf[ptr] = 0xFF
		binary.BigEndian.PutUint32(buf[ptr+1:ptr+5], baseSeq+uint32(i))
		buf[ptr+5] = byte(fe.k)
		buf[ptr+6] = byte(fe.m)
		copy(buf[ptr+7:], parityData)

		parityPackets[i] = buf
	}

	for i := 0; i < fe.k+fe.m; i++ {
		if fe.shards[i] != nil {
			packetPool.Put(fe.shards[i])
			fe.shards[i] = nil
		}
	}

	fe.idx = 0
	fe.shardSize = 0

	return parityPackets
}

func (fe *FECEncoder) reset() {
	for i := 0; i < len(fe.shards); i++ {
		if fe.shards[i] != nil {
			packetPool.Put(fe.shards[i])
			fe.shards[i] = nil
		}
	}
	fe.idx = 0
	fe.shardSize = 0
}

type FECDecoder struct {
	k             int
	m             int
	packetBuffer  map[uint32][]byte
	bufferMutex   sync.RWMutex
	recoveryCount int
	totalPackets  int
}

func NewFECDecoder(k, m int) *FECDecoder {
	return &FECDecoder{
		k:            k,
		m:            m,
		packetBuffer: make(map[uint32][]byte),
	}
}

func (fd *FECDecoder) DecodeFEC(packet []byte, seqNum uint32) (recovered []byte, canRecover bool) {
	fd.bufferMutex.Lock()
	defer fd.bufferMutex.Unlock()

	fd.totalPackets++

	if len(packet) < 7 {
		return nil, false
	}

	if packet[0] != 0xFF {
		return packet[7:], false
	}

	recvSeqNum := binary.BigEndian.Uint32(packet[1:5])

	fd.packetBuffer[recvSeqNum] = packet[7:]

	return nil, false
}

func (fd *FECDecoder) Forget(blockStartSeq uint32, k, m int) {
	fd.bufferMutex.Lock()
	defer fd.bufferMutex.Unlock()
	for i := 0; i < k+m; i++ {
		delete(fd.packetBuffer, blockStartSeq+uint32(i))
	}
}

func (fd *FECDecoder) Reconstruct(blockStartSeq uint32, k, m int) [][]byte {
	shards := make([][]byte, k+m)
	haveObj := 0
	maxLen := 0

	for i := 0; i < k+m; i++ {
		seq := blockStartSeq + uint32(i)
		if data, ok := fd.packetBuffer[seq]; ok {
			shards[i] = data
			haveObj++
			if len(data) > maxLen {
				maxLen = len(data)
			}
		}
	}

	if haveObj < k {
		return nil
	}

	for i := range shards {
		if shards[i] != nil && len(shards[i]) < maxLen {
			padded := make([]byte, maxLen)
			copy(padded, shards[i])
			shards[i] = padded
		}
	}

	enc, err := reedsolomon.New(k, m)
	if err != nil {
		return nil
	}

	if err := enc.Reconstruct(shards); err != nil {
		return nil
	}

	var recovered [][]byte
	for i := 0; i < k; i++ {
		seq := blockStartSeq + uint32(i)
		if _, ok := fd.packetBuffer[seq]; !ok {
			shard := shards[i]
			if len(shard) < 2 {
				continue
			}
			dataLen := binary.BigEndian.Uint16(shard[0:2])
			if int(dataLen)+2 > len(shard) {
				continue
			}
			data := shard[2 : 2+dataLen]

			res := packetPool.Get().([]byte)
			if cap(res) < len(data) {
				packetPool.Put(res)
				res = make([]byte, len(data))
			}
			res = res[:len(data)]
			copy(res, data)

			recovered = append(recovered, res)
		}
	}

	return recovered
}
