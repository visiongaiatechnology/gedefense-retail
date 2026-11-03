// Registry lifecycle: start, isolate, account, stop.
package collect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// Registry owns a set of adapter instances. The zero value is not usable; use
// NewRegistry.
type Registry struct {
	clock ports.Clock

	mu        sync.Mutex
	factories map[string]Factory
	instances []*instance
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	sink      ports.Sink
	started   bool
	stopped   bool
}

// NewRegistry creates an empty registry. clock may be nil; adapters then use
// the system clock.
func NewRegistry(clock ports.Clock) *Registry {
	return &Registry{clock: clock, factories: make(map[string]Factory)}
}

// Register adds one adapter factory. The registry rejects duplicate factory
// kinds and obviously broken factories before anything runs.
func (r *Registry) Register(f Factory) error {
	if f.New == nil || !validAdapterID(f.AdapterID) {
		return fmt.Errorf("%w: adapter_id %q", ErrInvalidFactory, f.AdapterID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return ErrAlreadyStarted
	}
	if _, dup := r.factories[f.AdapterID]; dup {
		return fmt.Errorf("%w: %q", ErrDuplicateAdapter, f.AdapterID)
	}
	r.factories[f.AdapterID] = f
	return nil
}

// validAdapterID allows lower-case ASCII letters, digits and the separators
// '.', '_' and '-'. The same rule applies to instance ids so that they are safe
// in logs, JSON and the audit trail.
func validAdapterID(id string) bool {
	if id == "" || len(id) > 96 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

// factoryForLocked resolves an instance id to a registered factory: exact match
// first, then the kind before the first dot ("modbus.pool1" -> "modbus").
// Callers must hold r.mu.
func (r *Registry) factoryForLocked(adapterID string) (Factory, bool) {
	if f, ok := r.factories[adapterID]; ok {
		return f, true
	}
	for i := 0; i < len(adapterID); i++ {
		if adapterID[i] == '.' {
			f, ok := r.factories[adapterID[:i]]
			return f, ok
		}
	}
	return Factory{}, false
}

// Start creates, validates and launches every configured adapter in its own
// goroutine. Startup is transactional for configuration errors: if any adapter
// cannot be created, no adapter is started and the error names the instance.
//
// Start returns after the goroutines have been launched; the collectors run
// until ctx is cancelled or Stop is called.
func (r *Registry) Start(ctx context.Context, cfgs []AdapterConfig, sink ports.Sink) error {
	if ctx == nil {
		return errors.New("collect: nil context")
	}
	if sink == nil {
		return ErrInvalidSink
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return ErrAlreadyStarted
	}

	planned := make([]*instance, 0, len(cfgs))
	seen := make(map[string]struct{}, len(cfgs))
	for _, cfg := range cfgs {
		cfg.AdapterID = trimSpace(cfg.AdapterID)
		if !validAdapterID(cfg.AdapterID) {
			return fmt.Errorf("%w: instance id %q", ErrUnknownAdapter, cfg.AdapterID)
		}
		if _, dup := seen[cfg.AdapterID]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateInstance, cfg.AdapterID)
		}
		seen[cfg.AdapterID] = struct{}{}

		factory, ok := r.factoryForLocked(cfg.AdapterID)
		if !ok {
			return fmt.Errorf("%w: %q", ErrUnknownAdapter, cfg.AdapterID)
		}
		if cfg.Clock == nil {
			cfg.Clock = r.clock
		}
		col, err := factory.New(cfg)
		if err != nil {
			return fmt.Errorf("collect: create adapter %q: %w", cfg.AdapterID, err)
		}
		if col == nil {
			return fmt.Errorf("collect: create adapter %q: nil collector", cfg.AdapterID)
		}
		info := col.Info()
		if info.AdapterID != cfg.AdapterID {
			return fmt.Errorf("collect: adapter %q reports id %q", cfg.AdapterID, info.AdapterID)
		}
		if !info.ReadOnly {
			return fmt.Errorf("%w: %q", ErrNotReadOnly, cfg.AdapterID)
		}
		if !ValidCollection(info.Collection) {
			return fmt.Errorf("collect: adapter %q reports invalid collection %q", cfg.AdapterID, info.Collection)
		}
		planned = append(planned, newInstance(cfg, col, info))
	}

	regCtx, cancel := context.WithCancel(ctx)
	r.ctx = regCtx
	r.cancel = cancel
	r.sink = sink
	r.started = true
	r.instances = planned
	for _, inst := range planned {
		inst.setState("running")
		r.wg.Add(1)
		go r.run(regCtx, inst, sink)
	}
	return nil
}

// run is the isolation boundary: every adapter runs here and any panic is
// recovered, counted and contained.
func (r *Registry) run(ctx context.Context, inst *instance, sink ports.Sink) {
	defer r.wg.Done()
	defer func() {
		if p := recover(); p != nil {
			inst.recordError(fmt.Sprintf("adapter panic: %v", p))
			inst.setState("failed")
		}
	}()

	wrapped := &instrumentedSink{inner: sink, inst: inst}
	err := inst.collector.Start(ctx, wrapped)
	switch {
	case ctx.Err() != nil:
		inst.setState("stopped")
	case err != nil:
		inst.recordError(err.Error())
		inst.setState("failed")
	default:
		inst.setState("stopped")
	}
}

// Health returns one snapshot per configured adapter, sorted by adapter id so
// that API/UI output is deterministic.
func (r *Registry) Health() []ports.CollectorHealth {
	r.mu.Lock()
	instances := make([]*instance, len(r.instances))
	copy(instances, r.instances)
	r.mu.Unlock()

	out := make([]ports.CollectorHealth, 0, len(instances))
	for _, inst := range instances {
		out = append(out, inst.health())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AdapterID < out[j].AdapterID })
	return out
}

// Stop cancels every adapter and waits for the goroutines to return. It is
// idempotent and safe to call after a failed Start.
func (r *Registry) Stop() {
	r.mu.Lock()
	if !r.started || r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	cancel := r.cancel
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// An adapter that ignores context cancellation cannot be killed from Go;
		// we surface the contract violation instead of hanging the shutdown.
		r.mu.Lock()
		for _, inst := range r.instances {
			if inst.stateValue() == "running" {
				inst.recordError("shutdown timeout: adapter did not return within 5s")
				inst.setState("failed")
			}
		}
		r.mu.Unlock()
	}
}

// instance is the registry-side bookkeeping of one adapter.
type instance struct {
	cfg       AdapterConfig
	collector ports.Collector
	info      ports.Info

	events       atomic.Uint64
	errors       atomic.Uint64
	lastEventAt  atomic.Int64 // unix nanos; 0 = never
	state        atomic.Value // string
	lastErrValue atomic.Value // string
}

func newInstance(cfg AdapterConfig, col ports.Collector, info ports.Info) *instance {
	inst := &instance{cfg: cfg, collector: col, info: info}
	inst.state.Store("created")
	inst.lastErrValue.Store("")
	return inst
}

func (i *instance) recordEvent() {
	i.events.Add(1)
	i.lastEventAt.Store(time.Now().UnixNano())
}

func (i *instance) recordError(msg string) {
	i.errors.Add(1)
	if len(msg) > 240 {
		msg = msg[:240]
	}
	i.lastErrValue.Store(msg)
}

func (i *instance) setState(state string) { i.state.Store(state) }

func (i *instance) stateValue() string {
	if v, ok := i.state.Load().(string); ok {
		return v
	}
	return "unknown"
}

func (i *instance) lastErr() string {
	if v, ok := i.lastErrValue.Load().(string); ok {
		return v
	}
	return ""
}

// health builds the ports.CollectorHealth snapshot, merging framework counters
// (events, sink errors) with the adapter's own parser/unsupported counters.
func (i *instance) health() ports.CollectorHealth {
	h := ports.CollectorHealth{
		AdapterID: i.cfg.AdapterID,
		State:     i.stateValue(),
		Events:    i.events.Load(),
		Errors:    i.errors.Load(),
	}
	if ns := i.lastEventAt.Load(); ns > 0 {
		h.LastEventAt = time.Unix(0, ns).UTC().Format(time.RFC3339)
	}
	if instrumented, ok := i.collector.(Instrumented); ok {
		snap := instrumented.HealthCounters()
		h.Errors += snap.Errors
		h.ParserErrors = snap.ParserErrors
		h.Unsupported = snap.Unsupported
		if snap.LastError != "" {
			h.LastError = snap.LastError
		}
	}
	if h.LastError == "" {
		h.LastError = i.lastErr()
	}
	if hs, ok := i.collector.(HealthState); ok {
		state, warning := hs.HealthState()
		switch state {
		case "running", "degraded", "stopped", "failed":
			h.State = state
		}
		if warning != "" {
			if h.LastError == "" {
				h.LastError = warning
			}
			if h.State == "running" {
				h.State = "degraded"
			}
		}
	}
	return h
}

// instrumentedSink counts successful emissions and sink errors at the
// framework boundary. Adapters therefore never need their own sink accounting.
type instrumentedSink struct {
	inner ports.Sink
	inst  *instance
}

func (s *instrumentedSink) Emit(ctx context.Context, ev domain.Event) error {
	err := s.inner.Emit(ctx, ev)
	if err != nil {
		s.inst.recordError(err.Error())
		return err
	}
	s.inst.recordEvent()
	return nil
}
