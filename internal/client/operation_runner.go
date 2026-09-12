package client

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/https-cert/deploy/pkg/logger"
)

// operationRunner 管理客户端业务并发槽、资源串行锁和 busy 计数。
type operationRunner struct {
	sem           chan struct{}
	wg            sync.WaitGroup
	busy          atomic.Int32
	locksMu       sync.Mutex
	locks         map[string]*resourceOperationLock
	once          sync.Once
	maxConcurrent int
}

func newOperationRunner(maxConcurrent int) *operationRunner {
	if maxConcurrent <= 0 {
		maxConcurrent = maxConcurrentOps
	}
	return &operationRunner{
		sem:           make(chan struct{}, maxConcurrent),
		locks:         make(map[string]*resourceOperationLock),
		maxConcurrent: maxConcurrent,
	}
}

func (r *operationRunner) ensure() {
	r.once.Do(func() {
		if r.sem == nil {
			r.sem = make(chan struct{}, r.maxConcurrent)
		}
		if r.locks == nil {
			r.locks = make(map[string]*resourceOperationLock)
		}
	})
}

// Run 启动有并发上限的异步业务，并在容量耗尽时调用 onBusy。
func (r *operationRunner) Run(name string, onBusy func(), operation func()) {
	r.ensure()
	// 捕获当前 channel，避免 defer 期间再读可变字段导致与测试替换并发竞争。
	sem := r.sem
	select {
	case sem <- struct{}{}:
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer func() { <-sem }()
			operation()
		}()
	default:
		logger.Warn("客户端业务并发已达上限", "operation", name, "limit", r.maxConcurrent)
		if onBusy != nil {
			onBusy()
		}
	}
}

// LockResource 获取可取消的资源串行锁，取消时不会占用业务槽位。
func (r *operationRunner) LockResource(ctx context.Context, resourceKey string) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.ensure()
	r.locksMu.Lock()
	entry := r.locks[resourceKey]
	if entry == nil {
		entry = &resourceOperationLock{mu: make(chan struct{}, 1)}
		r.locks[resourceKey] = entry
	}
	entry.refs++
	r.locksMu.Unlock()

	select {
	case entry.mu <- struct{}{}:
		return func() {
			<-entry.mu
			r.locksMu.Lock()
			entry.refs--
			if entry.refs == 0 {
				delete(r.locks, resourceKey)
			}
			r.locksMu.Unlock()
		}, nil
	case <-ctx.Done():
		r.locksMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(r.locks, resourceKey)
		}
		r.locksMu.Unlock()
		return nil, ctx.Err()
	}
}

// AddBusy / Busy 维护正在执行的业务计数。
func (r *operationRunner) AddBusy(delta int32) { r.busy.Add(delta) }
func (r *operationRunner) Busy() int32         { return r.busy.Load() }

// Wait 等待已经启动的业务收敛。
func (r *operationRunner) Wait() { r.wg.Wait() }
