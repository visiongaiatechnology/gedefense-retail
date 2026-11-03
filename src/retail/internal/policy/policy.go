// Package policy owns the versioned, audited operator policy of one site.
//
// Every change creates a new immutable version in policy-versions.jsonl, rewrites
// policy.json atomically and appends a hash-linked audit entry. Nothing is ever
// deleted: the version history is the evidence that a temperature limit was not
// changed silently.
package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

const (
	currentFileName  = "policy.json"
	versionsFileName = "policy-versions.jsonl"

	defaultVersionLimit = 50
	maxVersionLimit     = 200
	maxReasonLength     = 512
)

// Sentinel errors returned by the manager.
var (
	// ErrNotFound reports a version that does not exist.
	ErrNotFound = errors.New("policy: version not found")
	// ErrSiteMismatch reports a policy for a different site.
	ErrSiteMismatch = errors.New("policy: site mismatch")
	// ErrReasonRequired reports a change without an operator justification.
	ErrReasonRequired = errors.New("policy: a reason is required")
	// ErrInvalidActor reports a missing or malformed actor.
	ErrInvalidActor = errors.New("policy: invalid actor")
	// ErrForbidden reports a change attempt by an insufficient role.
	ErrForbidden = errors.New("policy: role not permitted to change the policy")
	// ErrCorruptState reports a version history that does not verify.
	ErrCorruptState = errors.New("policy: persisted version history is corrupt")
	// ErrNoPolicyFile reports a missing policy.json during Reload.
	ErrNoPolicyFile = errors.New("policy: policy.json does not exist")
)

// Options configures the policy manager.
type Options struct {
	// Dir is the directory that holds policy.json and policy-versions.jsonl.
	Dir string
	// Site is the site this manager owns; policies for other sites are rejected.
	Site domain.SiteID
	// Clock provides UTC timestamps; nil uses the system clock.
	Clock ports.Clock
	// Audit receives one hash-chained entry per change. It is mandatory: an
	// unaudited policy change would be a security regression.
	Audit ports.AuditStore
	// Initial is the policy used to bootstrap an empty version history. When nil,
	// domain.DefaultPolicy is used.
	Initial *domain.Policy
}

// wallClock is the default ports.Clock implementation.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

// Manager is the versioned policy store of one site.
type Manager struct {
	dir   string
	site  domain.SiteID
	clock ports.Clock
	audit ports.AuditStore

	mu       sync.RWMutex
	current  domain.Policy
	versions []domain.PolicyVersion
}

// OpenManager loads (and if necessary bootstraps) the policy history.
func OpenManager(opts Options) (*Manager, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("policy: options: Dir is required")
	}
	if err := opts.Site.Validate(); err != nil {
		return nil, fmt.Errorf("policy: options: %w", err)
	}
	if opts.Audit == nil {
		return nil, fmt.Errorf("policy: options: Audit store is required (policy changes must be auditable)")
	}
	if opts.Clock == nil {
		opts.Clock = wallClock{}
	}
	if err := ensurePrivateDir(opts.Dir); err != nil {
		return nil, err
	}

	m := &Manager{dir: opts.Dir, site: opts.Site, clock: opts.Clock, audit: opts.Audit}
	versions, err := readVersions(filepath.Join(opts.Dir, versionsFileName))
	if err != nil {
		return nil, err
	}
	if err := verifyVersions(versions, opts.Site); err != nil {
		return nil, err
	}
	m.versions = versions

	if len(versions) == 0 {
		initial := domain.DefaultPolicy(opts.Site, m.clock.Now())
		if opts.Initial != nil {
			initial = *opts.Initial
		}
		bootstrapped, berr := m.bootstrap(initial)
		if berr != nil {
			return nil, berr
		}
		m.versions = append(m.versions, bootstrapped)
		m.current = bootstrapped.Policy
		return m, nil
	}

	m.current = versions[len(versions)-1].Policy
	// The atomic mirror must always match the authoritative version history.
	if err := m.writeCurrentFile(m.current); err != nil {
		return nil, err
	}
	return m, nil
}

// Current returns a deep copy of the active policy.
func (m *Manager) Current() domain.Policy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return copyPolicy(m.current)
}

// Versions returns up to limit versions, newest first.
func (m *Manager) Versions(limit int) []domain.PolicyVersion {
	if limit <= 0 {
		limit = defaultVersionLimit
	}
	if limit > maxVersionLimit {
		limit = maxVersionLimit
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.PolicyVersion, 0, min(limit, len(m.versions)))
	for i := len(m.versions) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, copyVersion(m.versions[i]))
	}
	return out
}

// Get returns one stored version.
func (m *Manager) Get(version int) (domain.PolicyVersion, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, record := range m.versions {
		if record.Policy.Version == version {
			return copyVersion(record), true
		}
	}
	return domain.PolicyVersion{}, false
}

// Count returns the number of stored versions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.versions)
}

// Site returns the site this manager owns.
func (m *Manager) Site() domain.SiteID { return m.site }

// bootstrap creates version 1 for a store without history.
func (m *Manager) bootstrap(initial domain.Policy) (domain.PolicyVersion, error) {
	prepared, err := m.prepare(initial, domain.UserID("system"), "system", "initial policy", 1, "")
	if err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("policy: bootstrap: %w", err)
	}
	record, err := m.persist(prepared)
	if err != nil {
		return domain.PolicyVersion{}, err
	}
	return record, nil
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// copyPolicy deep-copies a policy including all slice fields.
func copyPolicy(p domain.Policy) domain.Policy {
	out := p
	out.Temperature.Limits = append([]domain.TemperatureLimit(nil), p.Temperature.Limits...)
	for i := range out.Temperature.Limits {
		out.Temperature.Limits[i] = copyTemperatureLimit(out.Temperature.Limits[i])
	}
	out.Network.AllowedPairs = append([]domain.AllowedPair(nil), p.Network.AllowedPairs...)
	out.Network.MonitoredPorts = append([]int(nil), p.Network.MonitoredPorts...)
	out.Maintenance.TrustedVendors = append([]string(nil), p.Maintenance.TrustedVendors...)
	out.Alerting.Escalation = append([]domain.EscalationStep(nil), p.Alerting.Escalation...)
	if p.Temperature.AbsoluteImpossibleMinC != nil {
		value := *p.Temperature.AbsoluteImpossibleMinC
		out.Temperature.AbsoluteImpossibleMinC = &value
	}
	if p.Temperature.AbsoluteImpossibleMaxC != nil {
		value := *p.Temperature.AbsoluteImpossibleMaxC
		out.Temperature.AbsoluteImpossibleMaxC = &value
	}
	if p.Sensors.DivergenceC != nil {
		value := *p.Sensors.DivergenceC
		out.Sensors.DivergenceC = &value
	}
	return out
}

// copyTemperatureLimit deep-copies the pointer fields of one limit.
func copyTemperatureLimit(limit domain.TemperatureLimit) domain.TemperatureLimit {
	out := limit
	for _, field := range []**float64{
		&out.MinC, &out.MaxC, &out.MaxRateCPerMin, &out.SetpointToleranceC,
	} {
		if *field != nil {
			value := **field
			*field = &value
		}
	}
	return out
}

// copyVersion deep-copies one version record.
func copyVersion(record domain.PolicyVersion) domain.PolicyVersion {
	out := record
	out.Policy = copyPolicy(record.Policy)
	return out
}

// readVersions decodes the append-only version file.
func readVersions(path string) (versions []domain.PolicyVersion, err error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("policy: open version history: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("policy: close version history: %w", cerr)
		}
	}()

	versions = make([]domain.PolicyVersion, 0, 16)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		var record domain.PolicyVersion
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if derr := dec.Decode(&record); derr != nil {
			return nil, fmt.Errorf("policy: %w: line %d: %v", ErrCorruptState, line, derr)
		}
		versions = append(versions, record)
	}
	if serr := scanner.Err(); serr != nil {
		return nil, fmt.Errorf("policy: read version history: %w", serr)
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Policy.Version < versions[j].Policy.Version
	})
	return versions, nil
}

// verifyVersions checks the version chain: contiguous versions, matching site,
// matching canonical hashes and a linked prev-hash.
func verifyVersions(versions []domain.PolicyVersion, site domain.SiteID) error {
	prevHash := ""
	for i, record := range versions {
		if record.Policy.Version != i+1 {
			return fmt.Errorf("policy: %w: version %d found at position %d", ErrCorruptState, record.Policy.Version, i+1)
		}
		if record.Policy.SiteID != site {
			return fmt.Errorf("policy: %w: version %d belongs to site %q, expected %q", ErrCorruptState, record.Policy.Version, record.Policy.SiteID, site)
		}
		if record.PrevHash != prevHash {
			return fmt.Errorf("policy: %w: version %d prev_hash does not link to version %d", ErrCorruptState, record.Policy.Version, record.Policy.Version-1)
		}
		hash, err := canonicalHash(record.Policy)
		if err != nil {
			return fmt.Errorf("policy: %w: version %d: %v", ErrCorruptState, record.Policy.Version, err)
		}
		if record.Policy.Hash != hash {
			return fmt.Errorf("policy: %w: version %d hash mismatch", ErrCorruptState, record.Policy.Version)
		}
		prevHash = record.Policy.Hash
	}
	return nil
}

// readCurrentFile decodes policy.json.
func readCurrentFile(path string) (domain.Policy, error) {
	raw, err := readFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return domain.Policy{}, ErrNoPolicyFile
		}
		return domain.Policy{}, fmt.Errorf("policy: read %q: %w", filepath.Base(path), err)
	}
	var loaded domain.Policy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&loaded); derr != nil {
		return domain.Policy{}, fmt.Errorf("policy: decode %q: %w", filepath.Base(path), derr)
	}
	return loaded, nil
}
