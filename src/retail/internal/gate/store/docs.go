package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// SavePlan stores (creates or replaces) one write plan atomically.
func (s *Store) SavePlan(ctx context.Context, plan domain.WritePlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.ensureOpen(); err != nil {
		return err
	}
	if err := plan.PlanID.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("gate store: plan %q: %w", plan.PlanID, err)
	}
	return saveDocument(filepath.Join(s.dir, plansDirName), string(plan.PlanID)+".json", plan)
}

// GetPlan loads one plan.
func (s *Store) GetPlan(ctx context.Context, id domain.PlanID) (domain.WritePlan, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.WritePlan{}, false, err
	}
	if err := id.Validate(); err != nil {
		return domain.WritePlan{}, false, fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	path := filepath.Join(s.dir, plansDirName, string(id)+".json")
	var plan domain.WritePlan
	found, err := readDocFile(path, maxPlanDocBytes, &plan)
	if err != nil {
		return domain.WritePlan{}, false, err
	}
	if !found {
		return domain.WritePlan{}, false, nil
	}
	if plan.PlanID != id {
		return domain.WritePlan{}, false, fmt.Errorf("%w: plan document id mismatch", ErrCorruptState)
	}
	return plan, true, nil
}

// ListPlans loads every persisted plan ordered by requested_at.
func (s *Store) ListPlans(ctx context.Context) ([]domain.WritePlan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	files, err := listDocumentFiles(filepath.Join(s.dir, plansDirName))
	if err != nil {
		return nil, err
	}
	plans := make([]domain.WritePlan, 0, len(files))
	for _, path := range files {
		var plan domain.WritePlan
		found, rerr := readDocFile(path, maxPlanDocBytes, &plan)
		if rerr != nil {
			return nil, rerr
		}
		if found {
			plans = append(plans, plan)
		}
	}
	sort.Slice(plans, func(i, j int) bool {
		if !plans[i].RequestedAt.Equal(plans[j].RequestedAt) {
			return plans[i].RequestedAt.After(plans[j].RequestedAt)
		}
		return plans[i].PlanID < plans[j].PlanID
	})
	return plans, nil
}

// SaveToken stores (creates or replaces) one one-time token record.
func (s *Store) SaveToken(ctx context.Context, token domain.WriteToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.ensureOpen(); err != nil {
		return err
	}
	if err := token.TokenID.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	if err := token.Validate(); err != nil {
		return fmt.Errorf("gate store: token %q: %w", token.TokenID, err)
	}
	return saveDocument(filepath.Join(s.dir, ordersDirName), string(token.TokenID)+".json", token)
}

// GetToken loads one token record.
func (s *Store) GetToken(ctx context.Context, id domain.TokenID) (domain.WriteToken, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.WriteToken{}, false, err
	}
	if err := id.Validate(); err != nil {
		return domain.WriteToken{}, false, fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	var token domain.WriteToken
	found, err := readDocFile(filepath.Join(s.dir, ordersDirName, string(id)+".json"), maxTokenDocBytes, &token)
	if err != nil {
		return domain.WriteToken{}, false, err
	}
	if !found {
		return domain.WriteToken{}, false, nil
	}
	return token, true, nil
}

// ListTokens loads every persisted token record.
func (s *Store) ListTokens(ctx context.Context) ([]domain.WriteToken, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	files, err := listDocumentFiles(filepath.Join(s.dir, ordersDirName))
	if err != nil {
		return nil, err
	}
	tokens := make([]domain.WriteToken, 0, len(files))
	for _, path := range files {
		var token domain.WriteToken
		found, rerr := readDocFile(path, maxTokenDocBytes, &token)
		if rerr != nil {
			return nil, rerr
		}
		if found {
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}

// SaveSession stores (creates or replaces) one write session.
func (s *Store) SaveSession(ctx context.Context, session domain.WriteSession) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.ensureOpen(); err != nil {
		return err
	}
	if err := session.SessionID.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	if err := session.Validate(); err != nil {
		return fmt.Errorf("gate store: session %q: %w", session.SessionID, err)
	}
	return saveDocument(filepath.Join(s.dir, sessionsDirName), string(session.SessionID)+".json", session)
}

// GetSession loads one write session.
func (s *Store) GetSession(ctx context.Context, id domain.SessionID) (domain.WriteSession, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.WriteSession{}, false, err
	}
	if err := id.Validate(); err != nil {
		return domain.WriteSession{}, false, fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	var session domain.WriteSession
	found, err := readDocFile(filepath.Join(s.dir, sessionsDirName, string(id)+".json"), maxSessionDocBytes, &session)
	if err != nil {
		return domain.WriteSession{}, false, err
	}
	if !found {
		return domain.WriteSession{}, false, nil
	}
	return session, true, nil
}

// ListSessions loads every persisted write session.
func (s *Store) ListSessions(ctx context.Context) ([]domain.WriteSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	files, err := listDocumentFiles(filepath.Join(s.dir, sessionsDirName))
	if err != nil {
		return nil, err
	}
	sessions := make([]domain.WriteSession, 0, len(files))
	for _, path := range files {
		var session domain.WriteSession
		found, rerr := readDocFile(path, maxSessionDocBytes, &session)
		if rerr != nil {
			return nil, rerr
		}
		if found {
			sessions = append(sessions, session)
		}
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].CreatedAt.After(sessions[j].CreatedAt) })
	return sessions, nil
}

// AppendDeny persists one denial evidence record.
func (s *Store) AppendDeny(ctx context.Context, deny domain.DeniedWriteAttempt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.ensureOpen(); err != nil {
		return err
	}
	if err := deny.DenyID.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	if err := deny.Validate(); err != nil {
		return fmt.Errorf("gate store: deny %q: %w", deny.DenyID, err)
	}
	return saveDocument(filepath.Join(s.dir, deniesDirName), string(deny.DenyID)+".json", deny)
}

// ListDenies loads denial evidence records newest first. limit<=0 returns all
// (used by the startup validation).
func (s *Store) ListDenies(ctx context.Context, limit int) ([]domain.DeniedWriteAttempt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	files, err := listDocumentFiles(filepath.Join(s.dir, deniesDirName))
	if err != nil {
		return nil, err
	}
	denies := make([]domain.DeniedWriteAttempt, 0, len(files))
	for _, path := range files {
		var deny domain.DeniedWriteAttempt
		found, rerr := readDocFile(path, maxDenyDocBytes, &deny)
		if rerr != nil {
			return nil, rerr
		}
		if found {
			denies = append(denies, deny)
		}
	}
	sort.Slice(denies, func(i, j int) bool {
		if !denies[i].At.Equal(denies[j].At) {
			return denies[i].At.After(denies[j].At)
		}
		return denies[i].DenyID < denies[j].DenyID
	})
	if limit > 0 && len(denies) > limit {
		denies = denies[:limit]
	}
	return denies, nil
}

// SaveWriteUnknown stores one write-unknown evidence record. The record type is
// owned by the approval package; the store treats it as an opaque bounded JSON
// document (no secrets are present by construction).
func (s *Store) SaveWriteUnknown(ctx context.Context, id string, document any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.ensureOpen(); err != nil {
		return err
	}
	if err := safeName(id + ".json"); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	dir := filepath.Join(s.dir, unknownDirName)
	if err := ensureDir(dir); err != nil {
		return err
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("gate store: marshal write-unknown record: %w", err)
	}
	if int64(len(raw)) > maxDenyDocBytes {
		return fmt.Errorf("gate store: write-unknown record too large")
	}
	return writeFileAtomic(filepath.Join(dir, id+".json"), append(raw, '\n'))
}

// ListWriteUnknown returns the raw write-unknown documents.
func (s *Store) ListWriteUnknown(ctx context.Context) ([][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	files, err := listDocumentFiles(filepath.Join(s.dir, unknownDirName))
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(files))
	for _, path := range files {
		raw, rerr := readDocument(path, maxDenyDocBytes)
		if rerr != nil {
			if errors.Is(rerr, fs.ErrNotExist) {
				continue
			}
			return nil, rerr
		}
		out = append(out, raw)
	}
	return out, nil
}

// AppendEvent appends one line to the optional stateless export file
// data_dir/gate-events.jsonl for the 0.1 monitoring bridge.
func (s *Store) AppendEvent(ctx context.Context, event domain.GateEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.ensureOpen(); err != nil {
		return err
	}
	if !validGateEventKind(event.Kind) {
		return fmt.Errorf("gate store: invalid gate event kind %q", event.Kind)
	}
	at := event.At
	if at.IsZero() {
		at = s.clock.Now().UTC()
		event.At = at
	}
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("gate store: marshal gate event: %w", err)
	}
	path := filepath.Join(s.dir, eventsFileName)
	file, err := openAppendPrivate(path)
	if err != nil {
		return err
	}
	if _, werr := file.Write(append(line, '\n')); werr != nil {
		closeErr := file.Close()
		return fmt.Errorf("gate store: append gate event: %w", errors.Join(werr, closeErr))
	}
	if cerr := file.Close(); cerr != nil {
		return fmt.Errorf("gate store: close gate event file: %w", cerr)
	}
	return nil
}

// AppendAudit chains and persists one audit entry (0.1 compatible structure).
func (s *Store) AppendAudit(ctx context.Context, entry domain.AuditEntry) (domain.AuditEntry, error) {
	return s.chain.Append(ctx, entry)
}

// ListAudit returns the newest audit entries in ascending sequence order.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]domain.AuditEntry, error) {
	return s.chain.List(ctx, limit)
}

// VerifyAudit re-reads and verifies the hash chain.
func (s *Store) VerifyAudit(ctx context.Context) (bool, uint64, error) {
	return s.chain.Verify(ctx)
}

// AuditCount returns the number of persisted audit entries.
func (s *Store) AuditCount() int { return s.chain.Count() }

// AuditFirstSeq returns the oldest persisted audit sequence number.
func (s *Store) AuditFirstSeq() uint64 { return s.chain.FirstSeq() }

// unknownDirName and eventsFileName extend the store layout for write-unknown
// evidence and the optional monitoring export.
const (
	unknownDirName = "unknown"
	eventsFileName = "gate-events.jsonl"
)

// validGateEventKind reports whether the event kind is one of the documented
// gate event kinds (domain.GateEventKind has no Valid method by design).
func validGateEventKind(kind domain.GateEventKind) bool {
	switch kind {
	case domain.GateEventPlanCreated, domain.GateEventPlanApproved, domain.GateEventPlanRejected,
		domain.GateEventPlanExpired, domain.GateEventSessionOpen, domain.GateEventSessionClose,
		domain.GateEventWriteDenied, domain.GateEventWriteAllowed, domain.GateEventWriteUnknown, domain.GateEventFailsafe,
		domain.GateEventBypass:
		return true
	}
	return false
}
