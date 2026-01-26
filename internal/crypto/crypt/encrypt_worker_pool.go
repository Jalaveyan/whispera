package crypt

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	cryptopkg "whispera/internal/crypto"
)

// EncryptJob представляет задачу для шифрования пакета
type EncryptJob struct {
	Seq       uint32
	AAD       []byte
	Plaintext []byte
	AEADState *cryptopkg.AEADState
	Result    chan []byte
	Error     chan error
	Timeout   time.Duration
}

// EncryptWorkerPool - пул воркеров для асинхронного шифрования пакетов
type EncryptWorkerPool struct {
	workers       int
	jobQueue      chan *EncryptJob
	workerPool    chan chan *EncryptJob
	quit          chan struct{}
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	jobsSubmitted int64
	jobsProcessed int64
	jobsDropped   int64
	jobsFailed    int64
}

var (
	globalEncryptWorkerPool *EncryptWorkerPool
	encryptPoolOnce         sync.Once
)

// NewEncryptWorkerPool создает и запускает новый пул воркеров для шифрования.
// ctx - контекст для управления жизненным циклом пула.
// workers - желаемое количество воркеров. Если 0, будет использовано runtime.NumCPU().
// state - начальное состояние AEAD для воркеров (может быть nil, если состояние передается с каждой задачей).
func NewEncryptWorkerPool(ctx context.Context, workers int, state *cryptopkg.AEADState) *EncryptWorkerPool {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > 64 {
		workers = 64
	}
	if workers < 8 {
		workers = 8
	}

	poolCtx, cancel := context.WithCancel(ctx)
	pool := &EncryptWorkerPool{
		workers:    workers,
		jobQueue:   make(chan *EncryptJob, 262144), // Увеличено с 32768 до 262144 для предотвращения переполнения при высокой нагрузке
		workerPool: make(chan chan *EncryptJob, workers),
		quit:       make(chan struct{}),
		ctx:        poolCtx,
		cancel:     cancel,
	}
	pool.start()
	return pool
}

// GetGlobalEncryptWorkerPool возвращает глобальный пул воркеров для шифрования
func GetGlobalEncryptWorkerPool() *EncryptWorkerPool {
	encryptPoolOnce.Do(func() {
		workers := runtime.NumCPU()
		// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Увеличено максимальное количество воркеров для высокой пропускной способности
		if workers > 64 {
			workers = 64
		}
		if workers < 8 {
			workers = 8 // Увеличено минимум для лучшей параллельности
		}

		ctx, cancel := context.WithCancel(context.Background())
		globalEncryptWorkerPool = &EncryptWorkerPool{
			workers:    workers,
			jobQueue:   make(chan *EncryptJob, 262144), // Увеличено до 262144 для предотвращения потери пакетов при переполнении очереди
			workerPool: make(chan chan *EncryptJob, workers),
			quit:       make(chan struct{}),
			ctx:        ctx,
			cancel:     cancel,
		}
		globalEncryptWorkerPool.start()
	})
	return globalEncryptWorkerPool
}

// start запускает пул воркеров
func (p *EncryptWorkerPool) start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	go p.dispatcher()
}

// dispatcher распределяет задачи по воркерам
func (p *EncryptWorkerPool) dispatcher() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		case job := <-p.jobQueue:
			select {
			case workerChan := <-p.workerPool:
				select {
				case workerChan <- job:
				default:
					// Воркер занят, отбрасываем
					atomic.AddInt64(&p.jobsDropped, 1)
				}
			default:
				// Нет свободных воркеров, отбрасываем
				atomic.AddInt64(&p.jobsDropped, 1)
			}
		}
	}
}

// worker обрабатывает задачи из очереди
func (p *EncryptWorkerPool) worker() {
	defer p.wg.Done()
	workerChan := make(chan *EncryptJob, 1)
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-p.quit:
			return
		case p.workerPool <- workerChan: // Регистрируем воркера в пуле
			select {
			case <-p.ctx.Done():
				return
			case <-p.quit:
				return
			case job := <-workerChan:
				atomic.AddInt64(&p.jobsProcessed, 1)
				// Выполняем шифрование
				ciphertext, err := job.AEADState.Encrypt(job.Seq, job.AAD, job.Plaintext)
				if err != nil {
					atomic.AddInt64(&p.jobsFailed, 1)
					select {
					case job.Error <- err:
					default:
					}
				} else {
					select {
					case job.Result <- ciphertext:
					default:
					}
				}
			}
		}
	}
}

// EncryptAsync отправляет задачу шифрования в пул воркеров
func (p *EncryptWorkerPool) EncryptAsync(seq uint32, aad, plaintext []byte, aeadState *cryptopkg.AEADState, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 50 * time.Millisecond // Увеличено до 50ms для предотвращения таймаутов при congested сетях
	}

	job := &EncryptJob{
		Seq:       seq,
		AAD:       aad,
		Plaintext: plaintext,
		AEADState: aeadState,
		Result:    make(chan []byte, 1),
		Error:     make(chan error, 1),
		Timeout:   timeout,
	}

	atomic.AddInt64(&p.jobsSubmitted, 1)

	select {
	case p.jobQueue <- job:
		// Ждем результат с таймаутом
		select {
		case result := <-job.Result:
			return result, nil
		case err := <-job.Error:
			return nil, err
		case <-time.After(timeout):
			atomic.AddInt64(&p.jobsDropped, 1)
			return nil, ErrEncryptTimeout
		}
	default:
		// КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Очередь переполнена - выполняем синхронно немедленно
		// Это быстрее чем создавать goroutine для критичных пакетов
		res, err := aeadState.Encrypt(seq, aad, plaintext)
		if err != nil {
			atomic.AddInt64(&p.jobsFailed, 1)
			return nil, err
		}
		atomic.AddInt64(&p.jobsProcessed, 1)
		return res, nil
	}
}

// Stop останавливает пул воркеров
func (p *EncryptWorkerPool) Stop() {
	close(p.quit)
	p.cancel()
	p.wg.Wait()
}

// GetStats возвращает статистику пула
func (p *EncryptWorkerPool) GetStats() (submitted, processed, dropped, failed int64) {
	return atomic.LoadInt64(&p.jobsSubmitted), atomic.LoadInt64(&p.jobsProcessed),
		atomic.LoadInt64(&p.jobsDropped), atomic.LoadInt64(&p.jobsFailed)
}

// ErrEncryptTimeout - ошибка таймаута шифрования
var ErrEncryptTimeout = &EncryptError{Message: "encrypt timeout"}

// EncryptError - ошибка шифрования
type EncryptError struct {
	Message string
}

func (e *EncryptError) Error() string {
	return e.Message
}
