package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// roleAdmin is the only role allowed to change the operator policy. The HTTP API
// enforces the same rule; enforcing it here as well makes the package safe to use
// from any composition root.
const roleAdmin = "admin"

// Update validates p, creates the next immutable version, rewrites policy.json
// atomically and appends an audit entry.
func (m *Manager) Update(p domain.Policy, actor domain.UserID, role string, reason string) (domain.PolicyVersion, error) {
	if role != roleAdmin {
		return domain.PolicyVersion{}, fmt.Errorf("%w: %q", ErrForbidden, role)
	}
	if err := actor.Validate(); err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("%w: %v", ErrInvalidActor, err)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return domain.PolicyVersion{}, ErrReasonRequired
	}
	if len(reason) > maxReasonLength {
		return domain.PolicyVersion{}, fmt.Errorf("%w: reason is longer than %d characters", ErrReasonRequired, maxReasonLength)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	nextVersion := len(m.versions) + 1
	prevHash := ""
	if len(m.versions) > 0 {
		prevHash = m.versions[len(m.versions)-1].Policy.Hash
	}
	prepared, err := m.prepare(p, actor, role, reason, nextVersion, prevHash)
	if err != nil {
		return domain.PolicyVersion{}, err
	}
	record, err := m.persist(prepared)
	if err != nil {
		return domain.PolicyVersion{}, err
	}
	m.current = record.Policy
	m.versions = append(m.versions, record)
	if err := m.appendAudit(record, string(actor), role, "policy.update", reason, prevHash); err != nil {
		return record, err
	}
	return record, nil
}

// Reload reads policy.json from disk and stores it as a new audited version. It
// is the operator escape hatch for editing the file directly.
func (m *Manager) Reload() (domain.PolicyVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	path := filepath.Join(m.dir, currentFileName)
	loaded, err := readCurrentFile(path)
	if err != nil {
		return domain.PolicyVersion{}, err
	}

	nextVersion := len(m.versions) + 1
	prevHash := ""
	if len(m.versions) > 0 {
		prevHash = m.versions[len(m.versions)-1].Policy.Hash
	}
	actor := domain.UserID("system")
	prepared, err := m.prepare(loaded, actor, "system", "reload from policy.json", nextVersion, prevHash)
	if err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("policy: reload: %w", err)
	}
	record, err := m.persist(prepared)
	if err != nil {
		return domain.PolicyVersion{}, err
	}
	m.current = record.Policy
	m.versions = append(m.versions, record)
	if err := m.appendAudit(record, string(actor), "system", "policy.reload", record.ChangeNote, prevHash); err != nil {
		return record, err
	}
	return record, nil
}

// prepare normalises and hashes a policy before it becomes a version.
func (m *Manager) prepare(p domain.Policy, actor domain.UserID, role, reason string, version int, prevHash string) (domain.PolicyVersion, error) {
	if p.SiteID == "" {
		p.SiteID = m.site
	}
	if p.SiteID != m.site {
		return domain.PolicyVersion{}, fmt.Errorf("%w: policy is for %q, manager owns %q", ErrSiteMismatch, p.SiteID, m.site)
	}
	if p.PolicyID == "" {
		p.PolicyID = domain.PolicyID("policy-" + string(m.site))
	}
	now := m.clock.Now().UTC()
	p.Version = version
	p.UpdatedAt = now
	p.UpdatedBy = actor
	p.Reason = reason
	p.Hash = ""
	for i := range p.Temperature.Limits {
		if !p.Temperature.Limits[i].ValidFrom.IsZero() {
			p.Temperature.Limits[i].ValidFrom = p.Temperature.Limits[i].ValidFrom.UTC()
		}
	}
	hash, err := canonicalHash(p)
	if err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("policy: hash: %w", err)
	}
	p.Hash = hash
	if err := p.Validate(); err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("policy: %w", err)
	}
	return domain.PolicyVersion{
		Policy:     p,
		StoredAt:   now,
		StoredBy:   actor,
		ChangeNote: reason,
		PrevHash:   prevHash,
	}, nil
}

// persist appends the version record and rewrites the atomic current file.
// The caller holds the manager lock (or is the single-threaded bootstrap).
func (m *Manager) persist(record domain.PolicyVersion) (domain.PolicyVersion, error) {
	line, err := json.Marshal(record)
	if err != nil {
		return domain.PolicyVersion{}, fmt.Errorf("policy: marshal version: %w", err)
	}
	if err := appendLine(filepath.Join(m.dir, versionsFileName), append(line, '\n')); err != nil {
		return domain.PolicyVersion{}, err
	}
	current := record.Policy
	if err := m.writeCurrentFile(current); err != nil {
		return domain.PolicyVersion{}, err
	}
	return record, nil
}

// writeCurrentFile atomically mirrors the active policy to policy.json.
func (m *Manager) writeCurrentFile(p domain.Policy) error {
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("policy: marshal current policy: %w", err)
	}
	return writeFileAtomic(filepath.Join(m.dir, currentFileName), append(raw, '\n'))
}

// appendAudit records one policy change in the hash-chained audit log.
func (m *Manager) appendAudit(record domain.PolicyVersion, actor, role, action, reason, beforeHash string) error {
	entry := domain.AuditEntry{
		At:         record.StoredAt,
		Actor:      actor,
		Role:       role,
		Action:     action,
		ObjectType: "policy",
		ObjectID:   string(record.Policy.PolicyID),
		Reason:     reason,
		BeforeHash: beforeHash,
		AfterHash:  record.Policy.Hash,
	}
	// The audit store is a local, append-only file; the contract signature of
	// Update/Reload carries no context, so the call is bounded by the store
	// itself rather than by a request deadline.
	if _, err := m.audit.Append(context.Background(), entry); err != nil {
		return fmt.Errorf("policy: append audit entry: %w", err)
	}
	return nil
}

// canonicalHash returns the SHA-256 of the canonical JSON form of p: the hash
// field itself is cleared and every time value is normalised to UTC.
func canonicalHash(p domain.Policy) (string, error) {
	canonical := copyPolicy(p)
	canonical.Hash = ""
	canonical.UpdatedAt = canonical.UpdatedAt.UTC()
	for i := range canonical.Temperature.Limits {
		if !canonical.Temperature.Limits[i].ValidFrom.IsZero() {
			canonical.Temperature.Limits[i].ValidFrom = canonical.Temperature.Limits[i].ValidFrom.UTC()
		}
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal canonical policy: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
