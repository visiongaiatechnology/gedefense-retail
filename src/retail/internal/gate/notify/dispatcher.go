package notify

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// DispatcherConfig bounds the asynchronous delivery path.
type DispatcherConfig struct {
	// QueueSize is the hard capacity of the notification queue (default 64,
	// maximum 4096). A full queue rejects new notifications; it never blocks the
	// Gate core.
	QueueSize int
	// Workers is the number of delivery goroutines (default 2, maximum 8).
	Workers int
	// OnError observes a failed delivery (for counters/logging). It runs in the
	// worker goroutine and must not block.
	OnError func(Notification, error)
}

// DispatcherStats is a snapshot of the delivery counters.
type DispatcherStats struct {
	Enqueued  uint64 `json:"enqueued"`
	Delivered uint64 `json:"delivered"`
	Failed    uint64 `json:"failed"`
	Dropped   uint64 `json:"dropped"`
	QueueLen  int    `json:"queue_len"`
}

// Dispatcher decouples the Gate core from delivery latency. Notify only enqueues
// (non-blocking, bounded); worker goroutines perform the actual delivery and are
// owned, cancellable and joinable.
type Dispatcher struct {
	sender  Notifier
	queue   chan Notification
	workers int
	onError func(Notification, error)

	mu      sync.Mutex
	started bool
	stopped bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	enqueued  atomic.Uint64
	delivered atomic.Uint64
	failed    atomic.Uint64
	dropped   atomic.Uint64
}

// NewDispatcher validates the configuration and creates the queue. The workers
// start when Start is called.
func NewDispatcher(sender Notifier, cfg DispatcherConfig) (*Dispatcher, error) {
	if sender == nil {
		return nil, fmt.Errorf("notify: dispatcher requires a sender")
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = 64
	}
	if cfg.QueueSize < 1 || cfg.QueueSize > 4096 {
		return nil, fmt.Errorf("notify: queue size must be in [1, 4096]")
	}
	if cfg.Workers == 0 {
		cfg.Workers = 2
	}
	if cfg.Workers < 1 || cfg.Workers > 8 {
		return nil, fmt.Errorf("notify: worker count must be in [1, 8]")
	}
	return &Dispatcher{
		sender:  sender,
		queue:   make(chan Notification, cfg.QueueSize),
		workers: cfg.Workers,
		onError: cfg.OnError,
	}, nil
}

// Start launches the delivery workers. It is idempotent and a no-op after Stop.
// The provided context bounds the workers' lifetime.
func (d *Dispatcher) Start(ctx context.Context) {
	if d == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	d.mu.Lock()
	if d.started || d.stopped {
		d.mu.Unlock()
		return
	}
	d.started = true
	workerCtx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	d.mu.Unlock()
	for i := 0; i < d.workers; i++ {
		d.wg.Add(1)
		go d.worker(workerCtx)
	}
}

// Notify enqueues one notification without blocking. It implements Notifier.
// A full queue or a stopped dispatcher returns an error, which the caller must
// treat as a dropped notification (the Gate keeps enforcing).
func (d *Dispatcher) Notify(_ context.Context, n Notification) error {
	if d == nil {
		return ErrStopped
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return ErrStopped
	}
	if len(d.queue) >= cap(d.queue) {
		d.dropped.Add(1)
		return ErrQueueFull
	}
	d.queue <- n
	d.enqueued.Add(1)
	return nil
}

// Stop closes the queue, drains pending notifications and joins the workers. It
// is idempotent and safe to call after the workers' context was cancelled.
func (d *Dispatcher) Stop() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		return
	}
	d.stopped = true
	close(d.queue)
	cancel := d.cancel
	d.mu.Unlock()
	d.wg.Wait()
	if cancel != nil {
		cancel()
	}
}

// Stats returns a consistent-enough snapshot of the counters for the status API.
func (d *Dispatcher) Stats() DispatcherStats {
	if d == nil {
		return DispatcherStats{}
	}
	stats := DispatcherStats{
		Enqueued:  d.enqueued.Load(),
		Delivered: d.delivered.Load(),
		Failed:    d.failed.Load(),
		Dropped:   d.dropped.Load(),
	}
	d.mu.Lock()
	stats.QueueLen = len(d.queue)
	d.mu.Unlock()
	return stats
}

func (d *Dispatcher) worker(ctx context.Context) {
	defer d.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case n, ok := <-d.queue:
			if !ok {
				return
			}
			if err := d.sender.Notify(ctx, n); err != nil {
				d.failed.Add(1)
				if d.onError != nil {
					d.onError(n, err)
				}
				continue
			}
			d.delivered.Add(1)
		}
	}
}
