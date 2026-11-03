// feed subcommand: synthetic events via POST /api/v1/dev/events.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

const (
	devIngestPath    = "/api/v1/dev/events"
	maxBatchSize     = 200
	maxFeedEvents    = 200000
	defaultFeedURL   = "http://127.0.0.1:8080"
	simTokenEnvVar   = "GEDEFENSE_SIM_TOKEN"
	requestTimeout   = 10 * time.Second
	maxResponseBytes = 64 << 10
)

// feedSummary is the machine-readable closing line required by the acceptance
// harness: FEED_SUMMARY sent=<n> failed=<n> http_status=<codes>
type feedSummary struct {
	sent       int
	failed     int
	statuses   map[int]struct{}
	firstError string
}

func (s *feedSummary) statusText() string {
	if len(s.statuses) == 0 {
		return "-"
	}
	codes := make([]int, 0, len(s.statuses))
	for code := range s.statuses {
		codes = append(codes, code)
	}
	for i := 1; i < len(codes); i++ {
		for j := i; j > 0 && codes[j] < codes[j-1]; j-- {
			codes[j], codes[j-1] = codes[j-1], codes[j]
		}
	}
	parts := make([]string, 0, len(codes))
	for _, code := range codes {
		parts = append(parts, strconv.Itoa(code))
	}
	return strings.Join(parts, ",")
}

func (s *feedSummary) print(w io.Writer) {
	fmt.Fprintf(w, "FEED_SUMMARY sent=%d failed=%d http_status=%s\n", s.sent, s.failed, s.statusText())
}

// runFeed implements the feed subcommand.
func runFeed(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("feed", stderr)
	rawURL := fs.String("url", defaultFeedURL, "base URL of the retaild API (loopback only)")
	token := fs.String("token", "", "Bearer token for the API (or env "+simTokenEnvVar+")")
	scenario := fs.String("scenario", scenarioNormal, "normal|abtau|tuer|angriff|angriff-management-ui")
	duration := fs.Float64("duration", 10, "feed duration in seconds (ignored when --count > 0)")
	count := fs.Int("count", 0, "number of events (overrides --duration)")
	rate := fs.Float64("rate", 20, "events per second")
	batch := fs.Int("batch", 50, "events per HTTP request (1..200)")
	site := fs.String("site", "filiale-001", "site id")
	zone := fs.String("zone", "zone-kaelte-1", "zone id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		*token = strings.TrimSpace(os.Getenv(simTokenEnvVar))
	}
	if *token == "" {
		return fmt.Errorf("feed: a Bearer token is required (--token or %s); the dev-ingest endpoint is authenticated", simTokenEnvVar)
	}
	endpoint, err := buildIngestEndpoint(*rawURL)
	if err != nil {
		return fmt.Errorf("feed: %w", err)
	}
	if *rate <= 0 || *rate > 5000 {
		return fmt.Errorf("feed: --rate must be > 0 and <= 5000")
	}
	if *batch < 1 || *batch > maxBatchSize {
		return fmt.Errorf("feed: --batch must be 1..%d", maxBatchSize)
	}
	if *duration < 0 {
		return fmt.Errorf("feed: --duration must be >= 0")
	}
	total := *count
	if total == 0 {
		if *duration == 0 {
			return fmt.Errorf("feed: either --duration or --count is required")
		}
		total = int(*duration * *rate)
	}
	if total <= 0 {
		return fmt.Errorf("feed: computed event count is 0")
	}
	if total > maxFeedEvents {
		return fmt.Errorf("feed: refusing to send %d events (max %d)", total, maxFeedEvents)
	}
	generator, err := newFeedGenerator(*scenario, *site, *zone)
	if err != nil {
		return fmt.Errorf("feed: %w", err)
	}

	ctx, cancel := signalContext()
	defer cancel()
	client := &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Never follow a redirect: the synthetic ingest must stay on the
			// configured loopback endpoint.
			return http.ErrUseLastResponse
		},
	}
	summary := &feedSummary{statuses: make(map[int]struct{})}
	fmt.Fprintf(stdout, "FEED_START scenario=%s events=%d rate=%.0f/s endpoint=%s\n", *scenario, total, *rate, endpoint)

	remaining := total
	consecutiveFailures := 0
	for remaining > 0 {
		size := *batch
		if remaining < size {
			size = remaining
		}
		events := make([]domain.Event, 0, size)
		for i := 0; i < size; i++ {
			ev, err := generator.Next()
			if err != nil {
				summary.failed++
				remaining--
				if summary.firstError == "" {
					summary.firstError = err.Error()
				}
				continue
			}
			if err := ev.Validate(); err != nil {
				summary.failed++
				remaining--
				if summary.firstError == "" {
					summary.firstError = "invalid synthetic event: " + err.Error()
				}
				continue
			}
			events = append(events, ev)
		}
		remaining -= size
		if len(events) > 0 {
			accepted, rejected, status, err := postEvents(ctx, client, endpoint, *token, events)
			summary.sent += accepted
			if rejected > 0 {
				summary.failed += rejected
			}
			if status != 0 {
				summary.statuses[status] = struct{}{}
			}
			if err != nil {
				summary.failed += len(events) - accepted - rejected
				if summary.firstError == "" {
					summary.firstError = err.Error()
				}
				if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound {
					summary.print(stdout)
					return fmt.Errorf("feed: dev-ingest rejected the batch with HTTP %d: %v "+
						"(check Simulation.Enabled, loopback client and X-GeDefense-Sim header)", status, err)
				}
				consecutiveFailures++
				if consecutiveFailures >= 5 {
					summary.print(stdout)
					return fmt.Errorf("feed: aborting after %d consecutive failed batches: %v", consecutiveFailures, err)
				}
			} else {
				consecutiveFailures = 0
			}
		}
		if remaining > 0 {
			pause := time.Duration(float64(size) / *rate * float64(time.Second))
			select {
			case <-time.After(pause):
			case <-ctx.Done():
				summary.print(stdout)
				return nil
			}
		}
	}
	summary.print(stdout)
	if summary.failed > 0 && summary.sent == 0 {
		return fmt.Errorf("feed: no event was accepted (first error: %s)", summary.firstError)
	}
	return nil
}

// buildIngestEndpoint validates that the URL is loopback-only and appends the
// dev-ingest path.
func buildIngestEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid --url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("invalid --url scheme %q (http/https only)", parsed.Scheme)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid --url: credentials, query and fragment are not allowed")
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("invalid --url: missing host")
	}
	if !isLoopbackHost(host) {
		return "", fmt.Errorf("invalid --url: dev-ingest is loopback-only, refusing host %q", host)
	}
	path := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(path, devIngestPath) {
		path += devIngestPath
	}
	parsed.Path = path
	return parsed.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr := net.ParseIP(host)
	if addr == nil {
		return false
	}
	return addr.IsLoopback()
}

// postEvents sends one batch and returns accepted/rejected counts.
func postEvents(ctx context.Context, client *http.Client, endpoint, token string, events []domain.Event) (accepted, rejected, status int, err error) {
	body, err := json.Marshal(struct {
		Events []domain.Event `json:"events"`
	}{Events: events})
	if err != nil {
		return 0, 0, 0, fmt.Errorf("encode batch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, 0, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GeDefense-Sim", "1")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("post: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return 0, 0, resp.StatusCode, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, 0, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	var decoded struct {
		Accepted int `json:"accepted"`
		Rejected int `json:"rejected"`
		Errors   []struct {
			Index  int    `json:"index"`
			Reason string `json:"reason"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return 0, 0, resp.StatusCode, fmt.Errorf("decode response: %w", err)
	}
	if decoded.Accepted < 0 || decoded.Rejected < 0 || len(decoded.Errors) > maxBatchSize {
		return 0, 0, resp.StatusCode, errors.New("invalid ingest response")
	}
	return decoded.Accepted, decoded.Rejected, resp.StatusCode, nil
}
