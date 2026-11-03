package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AuditEntry is a tamper-evident record of a state-changing action. Entries are
// hash-chained: Hash = SHA256(PrevHash || canonical_json(entry_without_hash)).
// Verification walks the chain and reports the first divergence.
type AuditEntry struct {
	Seq        uint64    `json:"seq"`
	At         time.Time `json:"at"`
	Actor      string    `json:"actor"`
	Role       string    `json:"role"`
	Action     string    `json:"action"`
	ObjectType string    `json:"object_type"`
	ObjectID   string    `json:"object_id"`
	Reason     string    `json:"reason,omitempty"`
	BeforeHash string    `json:"before_hash,omitempty"`
	AfterHash  string    `json:"after_hash,omitempty"`
	PrevHash   string    `json:"prev_hash"`
	Hash       string    `json:"hash"`
}

// HashInput is the canonical value that is hashed for an entry.
type HashInput struct {
	Seq        uint64    `json:"seq"`
	At         time.Time `json:"at"`
	Actor      string    `json:"actor"`
	Role       string    `json:"role"`
	Action     string    `json:"action"`
	ObjectType string    `json:"object_type"`
	ObjectID   string    `json:"object_id"`
	Reason     string    `json:"reason,omitempty"`
	BeforeHash string    `json:"before_hash,omitempty"`
	AfterHash  string    `json:"after_hash,omitempty"`
	PrevHash   string    `json:"prev_hash"`
}

// NewAuditEntry computes the chain hash for the given entry. Callers set Seq,
// At and PrevHash; everything else is the operator-visible content.
func NewAuditEntry(e AuditEntry) (AuditEntry, error) {
	if e.At.IsZero() {
		return AuditEntry{}, fmt.Errorf("audit: at is required")
	}
	if e.Actor == "" || e.Action == "" || e.ObjectType == "" || e.ObjectID == "" {
		return AuditEntry{}, fmt.Errorf("audit: actor, action, object_type and object_id are required")
	}
	if e.PrevHash == "" {
		e.PrevHash = strings.Repeat("0", 64)
	}
	input := HashInput{
		Seq: e.Seq, At: e.At.UTC(), Actor: e.Actor, Role: e.Role, Action: e.Action,
		ObjectType: e.ObjectType, ObjectID: e.ObjectID, Reason: e.Reason,
		BeforeHash: e.BeforeHash, AfterHash: e.AfterHash, PrevHash: e.PrevHash,
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return AuditEntry{}, fmt.Errorf("audit: canonical marshal: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write([]byte{0})
	h.Write(canonical)
	e.Hash = hex.EncodeToString(h.Sum(nil))
	return e, nil
}

// VerifyAuditChain walks entries in sequence order and verifies both the
// per-entry hash and the prev-hash linkage. The returned sequence number is the
// first failing entry, or 0 when the chain is intact.
func VerifyAuditChain(entries []AuditEntry) (bool, uint64) {
	var prev string = strings.Repeat("0", 64)
	for _, e := range entries {
		if e.PrevHash != prev {
			return false, e.Seq
		}
		input := HashInput{
			Seq: e.Seq, At: e.At.UTC(), Actor: e.Actor, Role: e.Role, Action: e.Action,
			ObjectType: e.ObjectType, ObjectID: e.ObjectID, Reason: e.Reason,
			BeforeHash: e.BeforeHash, AfterHash: e.AfterHash, PrevHash: e.PrevHash,
		}
		canonical, err := json.Marshal(input)
		if err != nil {
			return false, e.Seq
		}
		h := sha256.New()
		h.Write([]byte(e.PrevHash))
		h.Write([]byte{0})
		h.Write(canonical)
		if hex.EncodeToString(h.Sum(nil)) != e.Hash {
			return false, e.Seq
		}
		prev = e.Hash
	}
	return true, 0
}
