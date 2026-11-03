package collect

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// fakeClock is a deterministic ports.Clock.
type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

// testAdapter is a controllable collector for registry tests.
type testAdapter struct {
	id         string
	mode       string // "emit", "panic", "error", "stop"
	readOnly   bool
	collection string
	emitted    atomic.Int64
	returned   atomic.Bool
	sinkErr    error
}

func (a *testAdapter) Info() ports.Info {
	return ports.Info{AdapterID: a.id, Version: "1", Protocols: []string{"test"},
		Collection: a.collection, ReadOnly: a.readOnly}
}

func (a *testAdapter) Start(ctx context.Context, sink ports.Sink) error {
	defer a.returned.Store(true)
	switch a.mode {
	case "panic":
		panic("simulated adapter panic")
	case "error":
		return errors.New("simulated adapter failure")
	case "stop":
		<-ctx.Done()
		return nil
	}
	ev, err := Meta{SiteID: "filiale-001", Source: a.id, Collection: CollectionPassiveTap}.NewEvent(domain.EventAssetSeen, time.Time{})
	if err != nil {
		return err
	}
	for {
		if err := sink.Emit(ctx, ev); err != nil && a.sinkErr == nil {
			return err
		}
		a.emitted.Add(1)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Millisecond):
		}
	}
}

func testFactory(kind string, a *testAdapter) Factory {
	return Factory{AdapterID: kind, New: func(cfg AdapterConfig) (ports.Collector, error) {
		a.id = cfg.AdapterID
		return a, nil
	}}
}

func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	return NewRegistry(fakeClock{now: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)})
}

// waitingSink blocks until the first event arrives and then counts.
type waitingSink struct {
	mu     sync.Mutex
	events []domain.Event
	first  chan struct{}
	once   sync.Once
}

func newWaitingSink() *waitingSink {
	return &waitingSink{first: make(chan struct{})}
}

func (s *waitingSink) Emit(_ context.Context, ev domain.Event) error {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	s.once.Do(func() { close(s.first) })
	return nil
}

func (s *waitingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func TestRegistryEmitsAndStops(t *testing.T) {
	t.Parallel()
	adapter := &testAdapter{id: "test", mode: "emit", readOnly: true, collection: CollectionPassiveTap}
	reg := newTestRegistry(t)
	if err := reg.Register(testFactory("test", adapter)); err != nil {
		t.Fatalf("register: %v", err)
	}
	sink := newWaitingSink()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := AdapterConfig{AdapterID: "test.emit", SiteID: "filiale-001"}
	if err := reg.Start(ctx, []AdapterConfig{cfg}, sink); err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case <-sink.first:
	case <-time.After(2 * time.Second):
		t.Fatal("adapter did not emit an event")
	}
	health := reg.Health()
	if len(health) != 1 || health[0].State != "running" || health[0].Events == 0 {
		t.Fatalf("unexpected health: %+v", health)
	}
	cancel()
	reg.Stop()
	if !adapter.returned.Load() {
		t.Fatal("adapter goroutine was not joined by Stop")
	}
	health = reg.Health()
	if health[0].State != "stopped" {
		t.Fatalf("state after stop = %q", health[0].State)
	}
	// Stop is idempotent.
	reg.Stop()
}

func TestRegistryContainsPanic(t *testing.T) {
	t.Parallel()
	panicking := &testAdapter{id: "test", mode: "panic", readOnly: true, collection: CollectionPassiveTap}
	healthy := &testAdapter{id: "test", mode: "emit", readOnly: true, collection: CollectionPassiveTap}
	reg := newTestRegistry(t)
	if err := reg.Register(testFactory("panic", panicking)); err != nil {
		t.Fatalf("register panic: %v", err)
	}
	if err := reg.Register(Factory{AdapterID: "healthy", New: func(cfg AdapterConfig) (ports.Collector, error) {
		healthy.id = cfg.AdapterID
		return healthy, nil
	}}); err != nil {
		t.Fatalf("register healthy: %v", err)
	}
	sink := newWaitingSink()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := reg.Start(ctx, []AdapterConfig{
		{AdapterID: "panic.adapter", SiteID: "filiale-001"},
		{AdapterID: "healthy.adapter", SiteID: "filiale-001"},
	}, sink); err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case <-sink.first:
	case <-time.After(2 * time.Second):
		t.Fatal("healthy adapter stopped emitting after a sibling panic")
	}
	reg.Stop()
	for _, h := range reg.Health() {
		switch h.AdapterID {
		case "panic.adapter":
			if h.State != "failed" || h.Errors == 0 || h.LastError == "" {
				t.Fatalf("panic adapter health = %+v", h)
			}
		case "healthy.adapter":
			if h.Events == 0 {
				t.Fatalf("healthy adapter reports no events: %+v", h)
			}
		}
	}
}

func TestRegistrySinkErrorsAreCountedAndContained(t *testing.T) {
	t.Parallel()
	adapter := &testAdapter{id: "test", mode: "emit", readOnly: true, collection: CollectionPassiveTap, sinkErr: errors.New("sink full")}
	reg := newTestRegistry(t)
	if err := reg.Register(testFactory("test", adapter)); err != nil {
		t.Fatalf("register: %v", err)
	}
	failing := ports.SinkFunc(func(context.Context, domain.Event) error { return errors.New("sink full") })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := reg.Start(ctx, []AdapterConfig{{AdapterID: "test.emit", SiteID: "filiale-001"}}, failing); err != nil {
		t.Fatalf("start: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	reg.Stop()
	health := reg.Health()
	if len(health) != 1 {
		t.Fatalf("health len = %d", len(health))
	}
	if health[0].Errors == 0 {
		t.Fatalf("sink errors were not counted: %+v", health[0])
	}
	if health[0].LastError == "" {
		t.Fatalf("sink error text missing: %+v", health[0])
	}
}

func TestRegistryRejectsWritableAdapter(t *testing.T) {
	t.Parallel()
	adapter := &testAdapter{id: "test", mode: "emit", readOnly: false, collection: CollectionPassiveTap}
	reg := newTestRegistry(t)
	if err := reg.Register(testFactory("test", adapter)); err != nil {
		t.Fatalf("register: %v", err)
	}
	err := reg.Start(context.Background(), []AdapterConfig{{AdapterID: "test.emit", SiteID: "filiale-001"}}, ports.SinkFunc(func(context.Context, domain.Event) error { return nil }))
	if !errors.Is(err, ErrNotReadOnly) {
		t.Fatalf("want ErrNotReadOnly, got %v", err)
	}
}

func TestRegistryStartErrors(t *testing.T) {
	t.Parallel()
	reg := NewRegistry(nil)
	if err := reg.Register(Factory{}); !errors.Is(err, ErrInvalidFactory) {
		t.Fatalf("invalid factory error = %v", err)
	}
	adapter := &testAdapter{id: "test", mode: "stop", readOnly: true, collection: CollectionPassiveTap}
	if err := reg.Register(testFactory("test", adapter)); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Start(context.Background(), nil, nil); !errors.Is(err, ErrInvalidSink) {
		t.Fatalf("nil sink error = %v", err)
	}
	err := reg.Start(context.Background(), []AdapterConfig{{AdapterID: "unknown.adapter", SiteID: "filiale-001"}},
		ports.SinkFunc(func(context.Context, domain.Event) error { return nil }))
	if !errors.Is(err, ErrUnknownAdapter) {
		t.Fatalf("unknown adapter error = %v", err)
	}
	// Duplicate instance ids are rejected before anything starts.
	err = reg.Start(context.Background(), []AdapterConfig{
		{AdapterID: "test.a", SiteID: "filiale-001"},
		{AdapterID: "test.a", SiteID: "filiale-001"},
	}, ports.SinkFunc(func(context.Context, domain.Event) error { return nil }))
	if !errors.Is(err, ErrDuplicateInstance) {
		t.Fatalf("duplicate instance error = %v", err)
	}
}

func TestRegistryHealthIsDeterministic(t *testing.T) {
	t.Parallel()
	reg := newTestRegistry(t)
	a := &testAdapter{id: "a", mode: "stop", readOnly: true, collection: CollectionPassiveTap}
	b := &testAdapter{id: "b", mode: "stop", readOnly: true, collection: CollectionPassiveTap}
	for _, adapter := range []*testAdapter{a, b} {
		adapter := adapter
		if err := reg.Register(Factory{AdapterID: adapter.id, New: func(cfg AdapterConfig) (ports.Collector, error) {
			adapter.id = cfg.AdapterID
			return adapter, nil
		}}); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := reg.Start(ctx, []AdapterConfig{
		{AdapterID: "a.one", SiteID: "filiale-001"},
		{AdapterID: "b.two", SiteID: "filiale-001"},
	}, ports.SinkFunc(func(context.Context, domain.Event) error { return nil })); err != nil {
		t.Fatalf("start: %v", err)
	}
	health := reg.Health()
	if len(health) != 2 || health[0].AdapterID != "a.one" || health[1].AdapterID != "b.two" {
		t.Fatalf("health is not sorted: %+v", health)
	}
	cancel()
	reg.Stop()
}

func TestAdapterConfigResolveSite(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cfg     AdapterConfig
		wantErr bool
	}{
		{"field", AdapterConfig{AdapterID: "x", SiteID: "filiale-001"}, false},
		{"option", AdapterConfig{AdapterID: "x", Options: map[string]string{"site_id": "filiale-002"}}, false},
		{"missing", AdapterConfig{AdapterID: "x"}, true},
		{"invalid", AdapterConfig{AdapterID: "x", SiteID: "not valid!"}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			site, err := tc.cfg.ResolveSite()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got site %q", site)
				}
				return
			}
			if err != nil || site == "" {
				t.Fatalf("resolve site: %v %q", err, site)
			}
		})
	}
}

func TestMetaNewEventValidation(t *testing.T) {
	t.Parallel()
	if _, err := (Meta{SiteID: "filiale-001", Collection: CollectionPassiveTap}).NewEvent(domain.EventAssetSeen, time.Time{}); err == nil {
		t.Fatal("missing source must fail")
	}
	meta := Meta{SiteID: "filiale-001", Source: "adapter", Collection: CollectionPassiveTap, Clock: fakeClock{now: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}}
	ev, err := meta.NewEvent(domain.EventAssetSeen, time.Time{})
	if err != nil {
		t.Fatalf("new event: %v", err)
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("event invalid: %v", err)
	}
	if !ev.ObservedAt.Equal(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("observed_at = %v", ev.ObservedAt)
	}
	if _, err := meta.NewEvent(domain.EventKind("bogus"), time.Time{}); err == nil {
		t.Fatal("invalid kind must fail")
	}
	if _, err := (Meta{}).NewEvent(domain.EventFlow, time.Time{}); err == nil {
		t.Fatal("invalid meta must fail")
	}
}

func TestEmitAllStopsAtFirstError(t *testing.T) {
	t.Parallel()
	meta := Meta{SiteID: "filiale-001", Source: "adapter", Collection: CollectionPassiveTap}
	ev1, err := meta.NewEvent(domain.EventAssetSeen, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	ev2 := ev1
	ev2.EventID = "evt_second"
	calls := 0
	sink := ports.SinkFunc(func(context.Context, domain.Event) error {
		calls++
		return errors.New("boom")
	})
	if err := EmitAll(context.Background(), sink, []domain.Event{ev1, ev2}); err == nil {
		t.Fatal("expected sink error")
	}
	if calls != 1 {
		t.Fatalf("EmitAll kept going after an error (%d calls)", calls)
	}
	if err := EmitAll(context.Background(), ports.SinkFunc(func(context.Context, domain.Event) error { return nil }), nil); err != nil {
		t.Fatalf("empty emit: %v", err)
	}
}

func TestBackoffGrowsAndResets(t *testing.T) {
	t.Parallel()
	b := NewBackoff(10*time.Millisecond, 80*time.Millisecond)
	first := b.Next()
	if first < 10*time.Millisecond {
		t.Fatalf("first backoff too small: %v", first)
	}
	var last time.Duration
	for i := 0; i < 6; i++ {
		last = b.Next()
	}
	if last > 100*time.Millisecond {
		t.Fatalf("backoff exceeded cap+jitter: %v", last)
	}
	b.Reset()
	if b.Next() > 20*time.Millisecond {
		t.Fatal("reset did not restore the base delay")
	}
}
