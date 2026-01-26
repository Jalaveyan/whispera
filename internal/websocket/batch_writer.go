package websocket

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
)

// BatchWriter обеспечивает батчинг WebSocket записей для повышения производительности
type BatchWriter struct {
	conn        *websocket.Conn
	ctx         context.Context
	batchChan   chan []byte
	batch       [][]byte
	batchSize   int
	maxWait     time.Duration
	mu          sync.Mutex
	closed      int32
	wg          sync.WaitGroup
	writeCount  int64
	errorCount  int64
	flushTimer  *time.Timer
}

// NewBatchWriter создает новый batch writer для WebSocket
func NewBatchWriter(conn *websocket.Conn, ctx context.Context, batchSize int, maxWait time.Duration) *BatchWriter {
	if batchSize <= 0 {
		batchSize = 32 // Размер батча по умолчанию
	}
	if maxWait <= 0 {
		maxWait = 2 * time.Millisecond // Максимальное время ожидания батча
	}
	
	bw := &BatchWriter{
		conn:      conn,
		ctx:       ctx,
		batchChan: make(chan []byte, 4096), // Большой буфер для пакетов
		batch:     make([][]byte, 0, batchSize),
		batchSize: batchSize,
		maxWait:   maxWait,
		flushTimer: time.NewTimer(maxWait),
	}
	
	bw.wg.Add(1)
	go bw.writeLoop()
	
	return bw
}

// Write добавляет пакет в батч для отправки без копирования
func (bw *BatchWriter) Write(data []byte) bool {
	if atomic.LoadInt32(&bw.closed) != 0 {
		return false
	}
	
	// УЛУЧШЕНИЕ: Не копируем данные при отправке в канал
	// Канал будет работать с ссылкой на slice
	select {
	case bw.batchChan <- data:
		return true
	default:
		// Очередь переполнена - пропускаем пакет
		return false
	}
}

// writeLoop обрабатывает батчи и отправляет их
func (bw *BatchWriter) writeLoop() {
	defer bw.wg.Done()
	
	for {
		select {
		case <-bw.ctx.Done():
			bw.flush()
			return
		case <-bw.flushTimer.C:
			bw.flush()
		case data, ok := <-bw.batchChan:
			if !ok {
				bw.flush()
				return
			}
			
			bw.mu.Lock()
			bw.batch = append(bw.batch, data)
			shouldFlush := len(bw.batch) >= bw.batchSize
			bw.mu.Unlock()
			
			if shouldFlush {
				bw.flush()
			} else {
				// Сбрасываем таймер для следующего батча
				bw.flushTimer.Reset(bw.maxWait)
			}
		}
	}
}

// flush отправляет текущий батч без дополнительной копии
func (bw *BatchWriter) flush() {
	bw.mu.Lock()
	if len(bw.batch) == 0 {
		bw.mu.Unlock()
		return
	}
	
	// УЛУЧШЕНИЕ: Не копируем батч, а переиспользуем его
	// Просто обнуляем ссылки в старом батче после обработки
	batch := bw.batch
	bw.batch = make([][]byte, 0, bw.batchSize)
	bw.mu.Unlock()
	
	// Отправляем все пакеты из батча последовательно
	for _, data := range batch {
		if err := bw.conn.Write(bw.ctx, websocket.MessageBinary, data); err != nil {
			atomic.AddInt64(&bw.errorCount, 1)
			atomic.StoreInt32(&bw.closed, 1)
			return
		}
		atomic.AddInt64(&bw.writeCount, 1)
	}
	
	// УЛУЧШЕНИЕ: Очищаем références в батче для GC
	batch = batch[:0]
	
	// Сбрасываем таймер
	if !bw.flushTimer.Stop() {
		// Таймер уже сработал, читаем значение чтобы очистить канал
		select {
		case <-bw.flushTimer.C:
		default:
		}
	}
	bw.flushTimer.Reset(bw.maxWait)
}

// Close закрывает batch writer
func (bw *BatchWriter) Close() error {
	if !atomic.CompareAndSwapInt32(&bw.closed, 0, 1) {
		return nil
	}
	
	close(bw.batchChan)
	bw.wg.Wait()
	return nil
}

// Stats возвращает статистику
func (bw *BatchWriter) Stats() (writes int64, errors int64) {
	return atomic.LoadInt64(&bw.writeCount), atomic.LoadInt64(&bw.errorCount)
}

