package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
	"github.com/visiongaiatechnology/gedefense/retail/internal/version"
)

const forwarderMaxResponse = 4 << 10

var forwarderUserAgent = "GeDefense-Retail-Forwarder/" + version.Version

// errNilContext is returned when a caller passes a nil context.
var errNilContext = errors.New("app: nil context")

// logNotifier is the MVP local notification channel: a structured warning log.
// Operator-facing escalation channels (e-mail, webhook, SMS) are a 0.2 feature and
// are documented as such; a log line is honest, a fake "sent" state is not.
type logNotifier struct{ log *slog.Logger }

// Notify implements ports.Notifier.
func (n logNotifier) Notify(_ context.Context, alert domain.Alert) error {
	n.log.Warn("local alert notification",
		"alert_id", string(alert.AlertID),
		"severity", string(alert.Severity),
		"category", string(alert.Category),
		"site_id", string(alert.SiteID),
		"rule_id", string(alert.RuleID),
		"title", alert.Title,
	)
	return nil
}

// newLogNotifier returns the default notifier.
func newLogNotifier(log *slog.Logger) ports.Notifier { return logNotifier{log: log} }

// httpForwarder delivers events to the optional central management plane using
// mutual TLS and outbound-only connections. It never accepts inbound traffic and
// never trusts a plain-HTTP endpoint outside loopback (validated by config).
type httpForwarder struct {
	endpoint string
	siteID   domain.SiteID
	client   *http.Client
}

// newHTTPForwarder builds a forwarder from the central configuration.
func newHTTPForwarder(cfg *config.CentralConfig, site domain.SiteID) (ports.Forwarder, error) {
	if cfg == nil {
		return nil, errors.New("app: nil central configuration")
	}
	// Reject URLs with query strings, fragments or user info: the endpoint is a
	// fixed API path, not a user-controlled redirect target.
	u, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil {
		return nil, fmt.Errorf("parse central url: %w", err)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("central url must not contain query, fragment or user info")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, rerr := os.ReadFile(cfg.CAFile)
		if rerr != nil {
			return nil, fmt.Errorf("read central CA: %w", rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("central CA file contains no certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		cert, cerr := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if cerr != nil {
			return nil, fmt.Errorf("load central client certificate: %w", cerr)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	timeout := time.Duration(cfg.TimeoutS) * time.Second
	return &httpForwarder{
		endpoint: u.String(),
		siteID:   site,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        4,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// A redirect could leak events to an unapproved host.
				return errors.New("central forwarder does not follow redirects")
			},
		},
	}, nil
}

// Forward implements ports.Forwarder.
func (f *httpForwarder) Forward(ctx context.Context, events []domain.Event) error {
	if len(events) == 0 {
		return nil
	}
	payload := struct {
		SiteID string         `json:"site_id"`
		Events []domain.Event `json:"events"`
	}{SiteID: string(f.siteID), Events: events}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("forwarder: encode batch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("forwarder: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", forwarderUserAgent)
	req.Header.Set("X-GeDefense-Site", string(f.siteID))

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("forwarder: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, forwarderMaxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("forwarder: central returned HTTP %d", resp.StatusCode)
	}
	return nil
}
