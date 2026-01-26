package headers

import (
	"encoding/binary"
	"errors"
)

// V2 Fragmentation - улучшенная фрагментация с меньшим overhead

// CompactFragmentHeader - компактный заголовок фрагмента для V2
// Формат: [Flags:1][FragID:3][FragIdx:2][FragCnt:1-2][StreamID:2][ChunkLen:1-2]
// Вместо 9 bytes (V1) -> 6-9 bytes (V2) с оптимизациями
type CompactFragmentHeader struct {
	// Flags: [Version:3][IsLast:1][HasStreamID:1][Reserved:3]
	Flags    byte
	FragID   uint32 // 24-bit (3 bytes)
	FragIdx  uint16 // Fragment index (0-based)
	FragCnt  uint16 // Fragment count (variable length)
	StreamID uint16 // Stream ID (optional, 0 = default)
	ChunkLen uint16 // Chunk length (variable length)
}

const (
	// Fragment flags (используются в Flags байте)
	// В первом байте (Version+Flags): [Version:3][IsLast:1][HasStream:1][LargeChunk:1][LargeCount:1][Reserved:1]
	FragFlagLast       byte = 1 << 0 // Последний фрагмент (бит 0 в flags байте)
	FragFlagHasStream  byte = 1 << 1 // Имеет StreamID (бит 1)
	FragFlagLargeChunk byte = 1 << 2 // Large chunk (>255 bytes) (бит 2)
	FragFlagLargeCount byte = 1 << 3 // Large count (>255 fragments) (бит 3)
)

const (
	// Размеры заголовков фрагментов
	CompactFragmentHeaderMinLen = 6  // Минимальный размер (без StreamID, маленький chunk)
	CompactFragmentHeaderMaxLen = 11 // Максимальный размер (с StreamID, большой chunk)
)

// MarshalBinary сериализует компактный заголовок фрагмента
func (f *CompactFragmentHeader) MarshalBinary() ([]byte, error) {
	// Определяем размер заголовка
	hasStream := f.StreamID != 0
	largeChunk := f.ChunkLen > 255
	largeCount := f.FragCnt > 255

	// Вычисляем размер
	headerLen := 1 // Flags
	headerLen += 3 // FragID (24-bit)
	headerLen += 2 // FragIdx
	if largeCount {
		headerLen += 2 // FragCnt (2 bytes)
	} else {
		headerLen += 1 // FragCnt (1 byte)
	}
	if hasStream {
		headerLen += 2 // StreamID
	}
	if largeChunk {
		headerLen += 2 // ChunkLen (2 bytes)
	} else {
		headerLen += 1 // ChunkLen (1 byte)
	}

	buf := make([]byte, headerLen)
	offset := 0

	// Flags: [Version:3][LargeCount:1][LargeChunk:1][HasStream:1][IsLast:1][Reserved:1]
	flags := Version2 << 5
	if largeCount {
		flags |= FragFlagLargeCount << 2 // Бит 5 (после Version)
	}
	if largeChunk {
		flags |= FragFlagLargeChunk << 2 // Бит 4
	}
	if hasStream {
		flags |= FragFlagHasStream << 2 // Бит 3
	}
	if f.Flags&FragFlagLast != 0 {
		flags |= FragFlagLast << 2 // Бит 2
	}
	buf[offset] = flags
	offset++

	// FragID (24-bit, 3 bytes)
	buf[offset] = byte(f.FragID >> 16)
	buf[offset+1] = byte(f.FragID >> 8)
	buf[offset+2] = byte(f.FragID)
	offset += 3

	// FragIdx (2 bytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], f.FragIdx)
	offset += 2

	// FragCnt (variable: 1-2 bytes)
	if largeCount {
		buf[offset] = 0xFF
		binary.BigEndian.PutUint16(buf[offset+1:offset+3], f.FragCnt)
		offset += 3
	} else {
		buf[offset] = byte(f.FragCnt)
		offset += 1
	}

	// StreamID (optional, 2 bytes)
	if hasStream {
		binary.BigEndian.PutUint16(buf[offset:offset+2], f.StreamID)
		offset += 2
	}

	// ChunkLen (variable: 1-2 bytes)
	if largeChunk {
		buf[offset] = 0xFF
		binary.BigEndian.PutUint16(buf[offset+1:offset+3], f.ChunkLen)
	} else {
		buf[offset] = byte(f.ChunkLen)
	}

	return buf, nil
}

// UnmarshalBinary десериализует компактный заголовок фрагмента
func (f *CompactFragmentHeader) UnmarshalBinary(b []byte) error {
	if len(b) < CompactFragmentHeaderMinLen {
		return errors.New("short fragment header")
	}

	offset := 0

	// Flags
	flags := b[offset]
	version := (flags >> 5) & 0x07
	if version != Version2 {
		return errors.New("version mismatch")
	}
	f.Flags = flags & 0x1F
	largeCount := (flags & (FragFlagLargeCount << 2)) != 0
	largeChunk := (flags & (FragFlagLargeChunk << 2)) != 0
	hasStream := (flags & (FragFlagHasStream << 2)) != 0
	isLast := (flags & (FragFlagLast << 2)) != 0
	if isLast {
		f.Flags |= FragFlagLast
	}
	offset++

	// FragID (24-bit, 3 bytes)
	f.FragID = uint32(b[offset])<<16 | uint32(b[offset+1])<<8 | uint32(b[offset+2])
	offset += 3

	// FragIdx (2 bytes)
	f.FragIdx = binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2

	// FragCnt (variable: 1-2 bytes)
	if largeCount || (b[offset] == 0xFF && len(b) > offset+2) {
		if len(b) < offset+3 {
			return errors.New("short fragment count")
		}
		f.FragCnt = binary.BigEndian.Uint16(b[offset+1 : offset+3])
		offset += 3
	} else {
		f.FragCnt = uint16(b[offset])
		offset += 1
	}

	// StreamID (optional, 2 bytes)
	if hasStream {
		if len(b) < offset+2 {
			return errors.New("short stream id")
		}
		f.StreamID = binary.BigEndian.Uint16(b[offset : offset+2])
		offset += 2
	} else {
		f.StreamID = 0
	}

	// ChunkLen (variable: 1-2 bytes)
	if largeChunk {
		if len(b) < offset+3 || b[offset] != 0xFF {
			return errors.New("invalid large chunk length")
		}
		f.ChunkLen = binary.BigEndian.Uint16(b[offset+1 : offset+3])
		offset += 3
	} else {
		if len(b) <= offset {
			return errors.New("short chunk length")
		}
		f.ChunkLen = uint16(b[offset])
		offset += 1
	}

	return nil
}

// FragmentPacket разбивает большой пакет на фрагменты
// Возвращает список фрагментов с компактными заголовками
func FragmentPacketV2(payload []byte, maxChunkSize int, streamID uint16) ([]Fragment, error) {
	if len(payload) == 0 {
		return nil, errors.New("empty payload")
	}

	// Вычисляем overhead для одного фрагмента
	// Минимальный: 6 bytes (компактный заголовок) + 16 bytes (tag) = 22 bytes
	// Максимальный: 11 bytes + 16 bytes = 27 bytes
	avgOverhead := 24
	effectiveChunkSize := maxChunkSize - avgOverhead

	if effectiveChunkSize <= 0 {
		return nil, errors.New("max chunk size too small")
	}

	// Генерируем FragID (24-bit)
	fragID := uint32(len(payload)) ^ uint32(streamID) // Простой ID на основе размера и stream
	fragCnt := (len(payload) + effectiveChunkSize - 1) / effectiveChunkSize

	if fragCnt > 65535 {
		return nil, errors.New("too many fragments")
	}

	fragments := make([]Fragment, 0, fragCnt)

	for i := 0; i < fragCnt; i++ {
		start := i * effectiveChunkSize
		end := start + effectiveChunkSize
		if end > len(payload) {
			end = len(payload)
		}

		chunk := payload[start:end]
		chunkLen := uint16(len(chunk))

		// Определяем, является ли это последним фрагментом
		isLast := (i == fragCnt-1)

		header := &CompactFragmentHeader{
			Flags:    0,
			FragID:   fragID,
			FragIdx:  uint16(i),
			FragCnt:  uint16(fragCnt),
			StreamID: streamID,
			ChunkLen: chunkLen,
		}

		if isLast {
			header.Flags |= FragFlagLast
		}

		frag := Fragment{
			Header:   header,
			Chunk:    chunk,
			IsLast:   isLast,
			StreamID: streamID,
		}

		fragments = append(fragments, frag)
	}

	return fragments, nil
}

// Fragment представляет один фрагмент пакета
type Fragment struct {
	Header   *CompactFragmentHeader
	Chunk    []byte
	IsLast   bool
	StreamID uint16
}

// MarshalFragment сериализует фрагмент в байты для отправки
func MarshalFragment(frag Fragment) ([]byte, error) {
	headerBytes, err := frag.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// ОПТИМИЗАЦИЯ: Объединяем заголовок и данные в один allocation с двумя copy операциями
	// (это эффективнее чем 3+ операции на построение слайса)
	result := make([]byte, len(headerBytes)+len(frag.Chunk))
	copy(result, headerBytes)
	copy(result[len(headerBytes):], frag.Chunk)

	return result, nil
}

// UnmarshalFragment десериализует фрагмент из байтов
func UnmarshalFragment(data []byte) (*Fragment, error) {
	header := &CompactFragmentHeader{}

	// Пробуем десериализовать заголовок
	// Сначала пробуем минимальный размер
	var headerLen int
	for i := CompactFragmentHeaderMinLen; i <= CompactFragmentHeaderMaxLen && i <= len(data); i++ {
		if err := header.UnmarshalBinary(data[:i]); err == nil {
			headerLen = i
			break
		}
	}

	if headerLen == 0 {
		return nil, errors.New("failed to unmarshal fragment header")
	}

	// Проверяем, что ChunkLen соответствует оставшимся данным
	if len(data) < headerLen+int(header.ChunkLen) {
		return nil, errors.New("short fragment data")
	}

	chunk := data[headerLen : headerLen+int(header.ChunkLen)]

	frag := &Fragment{
		Header:   header,
		Chunk:    chunk,
		IsLast:   (header.Flags & FragFlagLast) != 0,
		StreamID: header.StreamID,
	}

	return frag, nil
}

// CalculateFragmentOverhead вычисляет overhead для фрагментации
// Возвращает: overhead на фрагмент, эффективный размер chunk
func CalculateFragmentOverhead(maxPacketSize int, streamID uint16) (int, int) {
	// Минимальный overhead: 6 bytes (компактный заголовок) + 16 bytes (tag) = 22 bytes
	// Максимальный overhead: 11 bytes + 16 bytes = 27 bytes
	// Используем среднее: 24 bytes
	avgOverhead := 24

	effectiveChunkSize := maxPacketSize - avgOverhead
	if effectiveChunkSize <= 0 {
		return 0, 0
	}

	return avgOverhead, effectiveChunkSize
}
