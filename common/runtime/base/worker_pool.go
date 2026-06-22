package base

import (
	"context"
	"runtime/debug"
	"sync"
	"whispera/common/log"
)

var workerPoolLog = logger.Module("worker_pool")

type WorkerPool struct {
	workers  int
	workChan chan func()
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	started  bool
}

func NewWorkerPool(workers int, queueSize int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		workers:  workers,
		workChan: make(chan func(), queueSize),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (wp *WorkerPool) Start() {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if wp.started {
		return
	}
	wp.started = true

	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	for {
		select {
		case <-wp.ctx.Done():
			return
		case work, ok := <-wp.workChan:
			if !ok {
				return
			}
			wp.runWork(work)
		}
	}
}

func (wp *WorkerPool) runWork(work func()) {
	defer func() {
		if r := recover(); r != nil {
			workerPoolLog.Error("PANIC in worker pool task: %v\n%s", r, debug.Stack())
		}
	}()
	work()
}

func (wp *WorkerPool) Submit(work func()) bool {
	select {
	case wp.workChan <- work:
		return true
	case <-wp.ctx.Done():
		return false
	}
}

func (wp *WorkerPool) SubmitAsync(work func()) {
	select {
	case wp.workChan <- work:
	case <-wp.ctx.Done():
	}
}

func (wp *WorkerPool) TrySubmit(work func()) bool {
	select {
	case wp.workChan <- work:
		return true
	default:
		return false
	}
}

func (wp *WorkerPool) Stop() {
	wp.mu.Lock()
	if !wp.started {
		wp.mu.Unlock()
		return
	}
	wp.mu.Unlock()

	wp.cancel()
	close(wp.workChan)
	wp.wg.Wait()
}
