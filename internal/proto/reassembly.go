package proto

import (
	"sync"
	"time"
)

// Пул буферов для переиспользования памяти при сборке пакетов
var (
	// Пул для финальных собранных пакетов
	reassemblyBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 1500) // Предварительно выделяем память для типичного MTU
		},
	}
	
	// Пул для слайсов expired IDs
	expiredIDsPool = sync.Pool{
		New: func() interface{} {
			return make([]uint32, 0, 16) // Предварительно выделяем память для типичного количества
		},
	}
)

// ReassemblerMetrics содержит метрики для мониторинга Reassembler
type ReassemblerMetrics struct {
	FragmentsInserted    int64 // Общее количество вставленных фрагментов
	PacketsReassembled   int64 // Количество полностью собранных пакетов
	FragmentsExpired     int64 // Количество истекших фрагментов
	FragmentsDropped     int64 // Количество отброшенных фрагментов (неверный формат)
	CapacityEvictions    int64 // Количество пакетов удаленных из-за переполнения capacity
	CurrentBuffers       int   // Текущее количество активных буферов
	TotalBytesReassembled int64 // Общий объем собранных данных (байты)
}

// Reassembler collects fragments until a full packet is reconstructed.
// It evicts stale/old entries after ttl or when capacity is exceeded.
type Reassembler struct {
	mu       sync.Mutex
	byID     map[uint32]*fragBuf
	ttl      time.Duration
	capacity int
	metrics  ReassemblerMetrics
}

type fragBuf struct {
	created time.Time
	cnt     int
	chunks  [][]byte
	have    int
}

func NewReassembler(ttl time.Duration, capacity int) *Reassembler {
	return &Reassembler{
		byID:     make(map[uint32]*fragBuf),
		ttl:      ttl,
		capacity: capacity,
		metrics:  ReassemblerMetrics{},
	}
}

// GetMetrics возвращает текущие метрики (thread-safe копия)
func (r *Reassembler) GetMetrics() ReassemblerMetrics {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Копируем метрики и добавляем текущее количество буферов
	m := r.metrics
	m.CurrentBuffers = len(r.byID)
	return m
}

// Insert adds a fragment (0-based index) for a given ID.
// Returns (complete, fullPayload, expiredIDs) where expiredIDs were evicted.
//
//nolint:gocyclo // Complex packet reassembly logic
func (r *Reassembler) Insert(id uint32, idx int, cnt int, chunk []byte, now time.Time) (bool, []byte, []uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	expired := r.evictLocked(now)
	r.metrics.FragmentsExpired += int64(len(expired))

	r.metrics.FragmentsInserted++

	fb := r.byID[id]
	//nolint:nestif // Complex fragment buffer initialization
	if fb == nil {
		if cnt <= 0 || idx < 0 || idx >= cnt {
			r.metrics.FragmentsDropped++
			return false, nil, expired
		}
		// capacity check - УЛУЧШЕНО: Aggressively evict multiple old entries
		if r.capacity > 0 && len(r.byID) >= r.capacity {
			// УЛУЧШЕНИЕ: Удаляем 10% самых старых элементов вместо одного для предотвращения частых evictions
			toEvict := (r.capacity / 10)
			if toEvict < 1 {
				toEvict = 1
			}
			
			type entry struct {
				id   uint32
				time time.Time
			}
			entries := make([]entry, 0, len(r.byID))
			// Собираем все элементы с их временем создания
			for k, v := range r.byID {
				entries = append(entries, entry{id: k, time: v.created})
			}
			
			// Простая сортировка по времени для поиска N самых старых
			for i := 0; i < toEvict && len(entries) > 0; i++ {
				oldestIdx := 0
				for j := 1; j < len(entries); j++ {
					if entries[j].time.Before(entries[oldestIdx].time) {
						oldestIdx = j
					}
				}
				oldestID := entries[oldestIdx].id
				delete(r.byID, oldestID)
				if expired == nil {
					expired = make([]uint32, 0, toEvict)
				}
				expired = append(expired, oldestID)
				r.metrics.CapacityEvictions++
				
				// Удаляем из списка для следующей итерации
				entries = append(entries[:oldestIdx], entries[oldestIdx+1:]...)
			}
		}
		fb = &fragBuf{created: now, cnt: cnt, chunks: make([][]byte, cnt)}
		r.byID[id] = fb
	} else if fb.cnt != cnt || idx < 0 || idx >= fb.cnt {
		// malformed (inconsistent count); drop
		r.metrics.FragmentsDropped++
		return false, nil, expired
	}

	if fb.chunks[idx] == nil {
		// ОПТИМИЗАЦИЯ: Сохраняем ссылку на chunk без копирования
		fb.chunks[idx] = chunk // Zero-copy: just store slice reference
		fb.have++
	}
	if fb.have < fb.cnt {
		return false, nil, expired
	}
	// Assemble
	total := 0
	for i := 0; i < fb.cnt; i++ {
		total += len(fb.chunks[i])
	}
	
	// ОПТИМИЗАЦИЯ: Прямое копирование в результирующий буфер без промежуточных аллокаций
	result := make([]byte, total)
	pos := 0
	for i := 0; i < fb.cnt; i++ {
		pos += copy(result[pos:], fb.chunks[i])
	}
	
	delete(r.byID, id)
	
	// Обновляем метрики успешной сборки
	r.metrics.PacketsReassembled++
	r.metrics.TotalBytesReassembled += int64(total)
	
	return true, result, expired
}

func (r *Reassembler) evictLocked(now time.Time) []uint32 {
	if r.ttl <= 0 {
		return nil
	}
	// ОПТИМИЗАЦИЯ: Используем пул для слайсов expired IDs
	expired := expiredIDsPool.Get().([]uint32)
	expired = expired[:0]
	
	for id, fb := range r.byID {
		if now.Sub(fb.created) > r.ttl {
			delete(r.byID, id)
			// ОПТИМИЗАЦИЯ: Используем reslice вместо append если возможно
			if len(expired) < cap(expired) {
				expired = expired[:len(expired)+1]
				expired[len(expired)-1] = id
			} else {
				expired = append(expired, id)
			}
		}
	}
	
	// Если expired пустой, возвращаем nil и буфер в пул
	if len(expired) == 0 {
		expiredIDsPool.Put(expired[:0])
		return nil
	}
	
	// ОПТИМИЗАЦИЯ: Возвращаем результат БЕЗ копирования - используем пул буфер напрямую
	// (caller обработает и не будет его переиспользовать)
	result := expired
	return result
}
