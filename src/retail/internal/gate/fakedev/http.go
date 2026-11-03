// Loopback-only fake HTTP supervisor for gate proxy tests.
package fakedev

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// HTTPConfig configures the fake supervisor.
type HTTPConfig struct {
	Listen string // loopback only; default 127.0.0.1:0
	Delay  time.Duration
}

// HTTPState is the observable fixture state after a test.
type HTTPState struct {
	Requests    uint64
	Writes      uint64
	LastMethod  string
	LastPath    string
	LastBody    string
	LastHeaders http.Header
	Config      map[string]string
}

// Supervisor is a loopback-only fake supervisor UI (no authentication: the gate
// login is the only authentication of the management path).
type Supervisor struct {
	cfg    HTTPConfig
	server *http.Server

	mu         sync.Mutex
	ln         net.Listener
	config     map[string]string
	lastMethod string
	lastPath   string
	lastBody   string
	lastHeader http.Header
	closed     bool
	wg         sync.WaitGroup

	requests atomic.Uint64
	writes   atomic.Uint64
}

// NewSupervisor validates the configuration and returns an unstarted fixture.
func NewSupervisor(cfg HTTPConfig) (*Supervisor, error) {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	if err := requireLoopback(cfg.Listen); err != nil {
		return nil, err
	}
	if cfg.Delay < 0 || cfg.Delay > 10*time.Second {
		return nil, errors.New("fakedev: supervisor delay out of range")
	}
	s := &Supervisor{cfg: cfg, config: map[string]string{"setpoint": "4.0", "defrost_mode": "0"}}
	s.server = &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	return s, nil
}

// Start binds the loopback listener.
func (s *Supervisor) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		return errors.New("fakedev: supervisor already started")
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("fakedev supervisor: listen: %w", err)
	}
	s.ln = ln
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = s.server.Serve(ln)
	}()
	return nil
}

// Addr returns the bound address.
func (s *Supervisor) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Handler exposes the fixture handler for httptest.
func (s *Supervisor) Handler() http.Handler { return s.server.Handler }

// Close stops the fixture.
func (s *Supervisor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	_ = s.server.Close()
	s.wg.Wait()
	return nil
}

// State returns a snapshot of the fixture.
func (s *Supervisor) State() HTTPState {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := make(map[string]string, len(s.config))
	for key, value := range s.config {
		cfg[key] = value
	}
	headers := http.Header{}
	for key, values := range s.lastHeader {
		headers[key] = append([]string{}, values...)
	}
	return HTTPState{
		Requests:    s.requests.Load(),
		Writes:      s.writes.Load(),
		LastMethod:  s.lastMethod,
		LastPath:    s.lastPath,
		LastBody:    s.lastBody,
		LastHeaders: headers,
		Config:      cfg,
	}
}

func (s *Supervisor) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/cgi-bin/config", s.handleConfig)
	mux.HandleFunc("/cgi-bin/redirect", s.handleRedirect)
	mux.HandleFunc("/cgi-bin/setcookie", s.handleSetCookie)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		s.mu.Lock()
		s.lastMethod = r.Method
		s.lastPath = r.URL.Path
		s.lastHeader = r.Header.Clone()
		s.mu.Unlock()
		if s.cfg.Delay > 0 {
			time.Sleep(s.cfg.Delay)
		}
		w.Header().Set("Server", "GeDefense-FakeSupervisor")
		mux.ServeHTTP(w, r)
	})
}

func (s *Supervisor) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<html><body><h1>Fake Supervisor</h1>
<form method="post" action="/cgi-bin/config">
<input name="setpoint" value="%s"><input name="defrost_mode" value="%s">
<button type="submit">Apply</button></form></body></html>`,
		html.EscapeString(s.configValue("setpoint")), html.EscapeString(s.configValue("defrost_mode")))
}

func (s *Supervisor) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.mu.Lock()
		cfg := make(map[string]string, len(s.config))
		for key, value := range s.config {
			cfg[key] = value
		}
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"config": cfg})
	case http.MethodPost, http.MethodPut:
		body, err := readLimitedBody(r, 64<<10)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		updates := map[string]string{}
		if len(body) > 0 && (r.Header.Get("Content-Type") == "application/json") {
			if err := json.Unmarshal(body, &updates); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
		} else {
			values, err := url.ParseQuery(string(body))
			if err != nil {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}
			for key := range values {
				updates[key] = values.Get(key)
			}
		}
		s.mu.Lock()
		s.lastBody = string(body)
		for key, value := range updates {
			if len(key) > 64 || len(value) > 256 {
				continue
			}
			s.config[key] = value
		}
		s.mu.Unlock()
		s.writes.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "written": len(updates)})
	default:
		w.Header().Set("Allow", "GET, HEAD, POST, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSetCookie simulates a device that sets an insecure cookie without SSL
// flags and with a Domain attribute (the gate must re-issue it safely).
func (s *Supervisor) handleSetCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "device-session", Path: "/", Domain: "device.local"})
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("cookie-set"))
}

// handleRedirect simulates a device that answers with an absolute redirect to
// itself (the gate must rewrite it to a gate-relative path).
func (s *Supervisor) handleRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+"/cgi-bin/config", http.StatusFound)
}

func (s *Supervisor) configValue(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config[key]
}

func readLimitedBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer func() { _ = r.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("body too large")
	}
	return data, nil
}
