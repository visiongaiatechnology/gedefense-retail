package notify_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/notify"
)

// recordingSender captures deliveries and can block inside Notify to simulate a
// busy delivery path.
type recordingSender struct {
	mu      sync.Mutex
	got     []notify.Notification
	started chan struct{}
	unblock chan struct{}
	once    sync.Once
	fail    bool
}

func newRecordingSender() *recordingSender {
	return &recordingSender{started: make(chan struct{})}
}

func (s *recordingSender) Notify(ctx context.Context, n notify.Notification) error {
	s.once.Do(func() { close(s.started) })
	if s.unblock != nil {
		select {
		case <-s.unblock:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	s.got = append(s.got, n)
	s.mu.Unlock()
	if s.fail {
		return errors.New("sender failure")
	}
	return nil
}

func (s *recordingSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

func (s *recordingSender) deliveries() []notify.Notification {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]notify.Notification(nil), s.got...)
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached before deadline")
}

func notificationWithID(id string) notify.Notification {
	n := testNotification()
	n.ID = id
	return n
}

func TestDispatcherDeliversAsynchronously(t *testing.T) {
	t.Parallel()
	sender := newRecordingSender()
	dispatcher, err := notify.NewDispatcher(sender, notify.DispatcherConfig{QueueSize: 8, Workers: 2})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	dispatcher.Start(context.Background())
	defer dispatcher.Stop()
	for i := 0; i < 5; i++ {
		if err := dispatcher.Notify(context.Background(), notificationWithID("gal_async_"+string(rune('a'+i)))); err != nil {
			t.Fatalf("Notify: %v", err)
		}
	}
	waitFor(t, func() bool { return sender.count() == 5 })
	stats := dispatcher.Stats()
	if stats.Enqueued != 5 || stats.Delivered != 5 || stats.Failed != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	dispatcher.Stop() // idempotent
	dispatcher.Stop()
}

func TestDispatcherQueueFullDoesNotBlock(t *testing.T) {
	t.Parallel()
	sender := newRecordingSender()
	sender.unblock = make(chan struct{})
	dispatcher, err := notify.NewDispatcher(sender, notify.DispatcherConfig{QueueSize: 1, Workers: 1})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	dispatcher.Start(context.Background())
	// First notification is consumed by the worker (which blocks). Wait until the
	// worker is inside Notify so the queue is empty again.
	if err := dispatcher.Notify(context.Background(), notificationWithID("gal_q1")); err != nil {
		t.Fatalf("first Notify: %v", err)
	}
	<-sender.started
	// Second fills the single queue slot.
	if err := dispatcher.Notify(context.Background(), notificationWithID("gal_q2")); err != nil {
		t.Fatalf("second Notify: %v", err)
	}
	if err := dispatcher.Notify(context.Background(), notificationWithID("gal_q3")); !errors.Is(err, notify.ErrQueueFull) {
		t.Fatalf("expected ErrQueueFull, got %v", err)
	}
	close(sender.unblock)
	dispatcher.Stop()
	if stats := dispatcher.Stats(); stats.Dropped != 1 {
		t.Fatalf("expected one dropped notification, got %+v", stats)
	}
}

func TestDispatcherStopDrainsQueue(t *testing.T) {
	t.Parallel()
	sender := newRecordingSender()
	dispatcher, err := notify.NewDispatcher(sender, notify.DispatcherConfig{QueueSize: 32, Workers: 2})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	for i := 0; i < 10; i++ {
		if err := dispatcher.Notify(context.Background(), notificationWithID("gal_drain_"+string(rune('a'+i)))); err != nil {
			t.Fatalf("Notify: %v", err)
		}
	}
	dispatcher.Start(context.Background())
	dispatcher.Stop()
	if got := sender.count(); got != 10 {
		t.Fatalf("Stop must drain queued notifications, got %d of 10", got)
	}
}

func TestDispatcherBuffersBeforeStart(t *testing.T) {
	t.Parallel()
	sender := newRecordingSender()
	dispatcher, err := notify.NewDispatcher(sender, notify.DispatcherConfig{QueueSize: 4})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := dispatcher.Notify(context.Background(), notificationWithID("gal_buffer_"+string(rune('a'+i)))); err != nil {
			t.Fatalf("Notify before start: %v", err)
		}
	}
	if sender.count() != 0 {
		t.Fatal("nothing may be delivered before Start")
	}
	dispatcher.Start(context.Background())
	waitFor(t, func() bool { return sender.count() == 3 })
	dispatcher.Stop()
}

func TestDispatcherRejectsAfterStop(t *testing.T) {
	t.Parallel()
	dispatcher, err := notify.NewDispatcher(newRecordingSender(), notify.DispatcherConfig{})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	dispatcher.Stop()
	if err := dispatcher.Notify(context.Background(), testNotification()); !errors.Is(err, notify.ErrStopped) {
		t.Fatalf("expected ErrStopped, got %v", err)
	}
}

func TestDispatcherCountsFailures(t *testing.T) {
	t.Parallel()
	sender := newRecordingSender()
	sender.fail = true
	var failures atomic.Int32
	dispatcher, err := notify.NewDispatcher(sender, notify.DispatcherConfig{
		QueueSize: 4,
		Workers:   1,
		OnError:   func(notify.Notification, error) { failures.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	dispatcher.Start(context.Background())
	if err := dispatcher.Notify(context.Background(), testNotification()); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	waitFor(t, func() bool { return failures.Load() == 1 })
	dispatcher.Stop()
	if stats := dispatcher.Stats(); stats.Failed != 1 || stats.Delivered != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestDispatcherConcurrentNotifyAndStop(t *testing.T) {
	t.Parallel()
	sender := newRecordingSender()
	dispatcher, err := notify.NewDispatcher(sender, notify.DispatcherConfig{QueueSize: 16, Workers: 2})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	dispatcher.Start(context.Background())
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				// Errors are expected after Stop; the point is that no send on a
				// closed channel panics and the race detector stays clean.
				_ = dispatcher.Notify(context.Background(), notificationWithID("gal_race_"+string(rune('a'+worker))+string(rune('0'+i%10))))
			}
		}(worker)
	}
	dispatcher.Stop()
	wg.Wait()
}

func TestNewDispatcherValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		sender notify.Notifier
		cfg    notify.DispatcherConfig
	}{
		{name: "nil sender", sender: nil, cfg: notify.DispatcherConfig{}},
		{name: "queue too large", sender: newRecordingSender(), cfg: notify.DispatcherConfig{QueueSize: 5000}},
		{name: "negative queue", sender: newRecordingSender(), cfg: notify.DispatcherConfig{QueueSize: -1}},
		{name: "too many workers", sender: newRecordingSender(), cfg: notify.DispatcherConfig{Workers: 9}},
		{name: "negative workers", sender: newRecordingSender(), cfg: notify.DispatcherConfig{Workers: -1}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := notify.NewDispatcher(tc.sender, tc.cfg); err == nil {
				t.Fatalf("expected configuration error for %s", tc.name)
			}
		})
	}
}
