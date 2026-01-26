package mux

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"sync"
	"time"
)

// ОПТИМИЗАЦИЯ: Пул буферов для переиспользования памяти при генерации padding
var (
	// Пул для маленьких буферов (до 256 байт для padding)
	smallPaddingPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 256)
		},
	}

	// Пул для средних буферов (до 1024 байт)
	mediumPaddingPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 1024)
		},
	}

	// Пул для буферов результата (до 4096 байт)
	resultBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 4096)
		},
	}
)

// MuxPaddingConfig - конфигурация padding для Mux потоков
type MuxPaddingConfig struct {
	Enabled bool
	MinSize int // Минимальный размер padding в байтах
	MaxSize int // Максимальный размер padding в байтах
}

// DefaultMuxPaddingConfig возвращает конфигурацию padding по умолчанию
func DefaultMuxPaddingConfig() *MuxPaddingConfig {
	return &MuxPaddingConfig{
		Enabled: true,
		MinSize: 0, // По умолчанию без padding
		MaxSize: 0,
	}
}

// MuxPadding - обработчик padding для Mux потоков
type MuxPadding struct {
	config *MuxPaddingConfig
	mu     sync.RWMutex
}

// NewMuxPadding создает новый обработчик padding для Mux
func NewMuxPadding(config *MuxPaddingConfig) *MuxPadding {
	if config == nil {
		config = DefaultMuxPaddingConfig()
	}
	return &MuxPadding{
		config: config,
	}
}

// SetConfig обновляет конфигурацию padding
func (mp *MuxPadding) SetConfig(config *MuxPaddingConfig) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.config = config
}

// GetConfig возвращает текущую конфигурацию padding
func (mp *MuxPadding) GetConfig() *MuxPaddingConfig {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.config
}

// ApplyPadding применяет padding к данным потока
// Формат: [2B realLen][data][pad]
func (mp *MuxPadding) ApplyPadding(data []byte) []byte {
	mp.mu.RLock()
	config := mp.config
	mp.mu.RUnlock()

	if !config.Enabled || config.MinSize == 0 && config.MaxSize == 0 {
		// Padding отключен или не настроен
		return data
	}

	// Вычисляем размер padding
	padSize := mp.calculatePaddingSize(len(data))
	if padSize <= 0 {
		return data
	}

	// Генерируем случайный padding
	padding := mp.generatePadding(padSize)

	// ОПТИМИЗАЦИЯ: Stack-allocated buffer для типичного случая (<512 bytes)
	realLen := uint16(len(data))
	totalSize := 2 + len(data) + len(padding)

	var result []byte
	if totalSize <= 512 {
		// Используем stack для малых пакетов - избегаем heap allocation
		var stackBuf [512]byte
		result = stackBuf[:totalSize]
	} else if totalSize <= 4096 {
		// Для средних пакетов используем пул
		result = resultBufferPool.Get().([]byte)
		if cap(result) < totalSize {
			result = make([]byte, totalSize)
		} else {
			result = result[:totalSize]
		}
	} else {
		// Для больших пакетов напрямую выделяем память
		result = make([]byte, totalSize)
	}

	result[0] = byte(realLen >> 8)
	result[1] = byte(realLen & 0xFF)
	copy(result[2:], data)
	copy(result[2+len(data):], padding)

	// ОПТИМИЗАЦИЯ: Для stack буфера нужна копия (stack escaping), для heap - возвращаем напрямую
	if totalSize <= 512 {
		// Stack буфер - нужна копия для heap return
		resultCopy := make([]byte, totalSize)
		copy(resultCopy, result)
		return resultCopy
	}
	
	// Heap буфер - возвращаем БЕЗ доп копирования
	return result
}

// RemovePadding удаляет padding из данных
// Ожидает формат: [2B realLen][data][pad]
func (mp *MuxPadding) RemovePadding(data []byte) []byte {
	if len(data) < 2 {
		// Нет заголовка длины - возвращаем как есть
		return data
	}

	// Читаем реальную длину данных
	realLen := int(binary.BigEndian.Uint16(data[0:2]))

	if realLen <= 0 || realLen > len(data)-2 {
		// Некорректная длина - возвращаем как есть
		return data
	}

	// Возвращаем только реальные данные (без padding)
	return data[2 : 2+realLen]
}

// HasPadding проверяет, содержит ли данные padding
func (mp *MuxPadding) HasPadding(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	realLen := int(binary.BigEndian.Uint16(data[0:2]))
	return realLen > 0 && realLen < len(data)-2
}

// calculatePaddingSize вычисляет размер padding для данных
func (mp *MuxPadding) calculatePaddingSize(dataSize int) int {
	mp.mu.RLock()
	config := mp.config
	mp.mu.RUnlock()

	if !config.Enabled {
		return 0
	}

	minSize := config.MinSize
	maxSize := config.MaxSize

	if minSize <= 0 && maxSize <= 0 {
		return 0
	}

	if minSize > maxSize {
		minSize, maxSize = maxSize, minSize
	}

	if minSize == maxSize {
		return minSize
	}

	// Генерируем случайный размер padding в диапазоне [minSize, maxSize]
	var padSize int
	if maxSize > minSize {
		// Используем crypto/rand для криптографически стойкого генератора
		var b [4]byte
		if _, err := crand.Read(b[:]); err == nil {
			// Используем первые 4 байта для генерации размера
			randValue := int(binary.BigEndian.Uint32(b[:])) & 0x7FFFFFFF
			padSize = minSize + (randValue % (maxSize - minSize + 1))
		} else {
			// Fallback на math/rand
			padSize = minSize + rand.Intn(maxSize-minSize+1)
		}
	} else {
		padSize = minSize
	}

	// Адаптивный padding: для больших пакетов добавляем больше padding
	// Это помогает маскировать размеры больших пакетов
	if dataSize > 1024 {
		// Для пакетов > 1KB увеличиваем padding на 20-50%
		increase := padSize / 5
		if increase > 0 {
			var b [1]byte
			if _, err := crand.Read(b[:]); err == nil {
				increase = int(b[0]) % (increase + 1)
			} else {
				increase = rand.Intn(increase + 1)
			}
			padSize += increase
		}
	}

	return padSize
}

// generatePadding генерирует случайный padding заданного размера
// ОПТИМИЗАЦИЯ: Используем пул буферов для уменьшения аллокаций
func (mp *MuxPadding) generatePadding(size int) []byte {
	if size <= 0 {
		return nil
	}

	// ОПТИМИЗАЦИЯ: Используем пул буферов для padding
	var padding []byte
	if size <= 256 {
		padding = smallPaddingPool.Get().([]byte)
		if cap(padding) < size {
			padding = make([]byte, size)
		} else {
			padding = padding[:size]
		}
	} else if size <= 1024 {
		padding = mediumPaddingPool.Get().([]byte)
		if cap(padding) < size {
			padding = make([]byte, size)
		} else {
			padding = padding[:size]
		}
	} else {
		padding = make([]byte, size)
	}

	// Используем crypto/rand для криптографически стойкого padding
	if _, err := crand.Read(padding); err != nil {
		// Fallback на math/rand если crypto/rand недоступен
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		for i := range padding {
			padding[i] = byte(r.Intn(256))
		}
	}

	return padding
}

// ApplyStreamPadding применяет padding к данным конкретного потока
// Учитывает приоритет потока и его характеристики
func (mp *MuxPadding) ApplyStreamPadding(streamID uint16, priority StreamPriority, data []byte) []byte {
	mp.mu.RLock()
	config := mp.config
	mp.mu.RUnlock()

	if !config.Enabled {
		return data
	}

	// Для потоков с высоким приоритетом применяем минимальный padding
	// чтобы не замедлять критичные потоки
	if priority == PriorityCritical || priority == PriorityHigh {
		// Уменьшаем padding для критичных потоков
		originalMin := config.MinSize
		originalMax := config.MaxSize

		// Временно уменьшаем размеры padding
		config.MinSize = originalMin / 2
		config.MaxSize = originalMax / 2
		if config.MinSize < 0 {
			config.MinSize = 0
		}
		if config.MaxSize < 0 {
			config.MaxSize = 0
		}

		result := mp.ApplyPadding(data)

		// Восстанавливаем оригинальные значения
		config.MinSize = originalMin
		config.MaxSize = originalMax

		return result
	}

	// Для обычных потоков применяем стандартный padding
	return mp.ApplyPadding(data)
}

// GetPaddingStats возвращает статистику использования padding
func (mp *MuxPadding) GetPaddingStats() map[string]interface{} {
	mp.mu.RLock()
	config := mp.config
	mp.mu.RUnlock()

	return map[string]interface{}{
		"enabled":  config.Enabled,
		"min_size": config.MinSize,
		"max_size": config.MaxSize,
	}
}
