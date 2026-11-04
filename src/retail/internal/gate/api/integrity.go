package api

import "net/http"

// IntegrityReferenceStatus is the read-only view of one setpoint reference.
type IntegrityReferenceStatus struct {
	TargetID            string                     `json:"target_id"`
	FC                  int                        `json:"fc"`
	Register            int                        `json:"register"`
	Unit                string                     `json:"unit,omitempty"`
	Reference           string                     `json:"reference"`
	Current             string                     `json:"current,omitempty"`
	State               string                     `json:"state"`
	LastReadAt          string                     `json:"last_read_at,omitempty"`
	ConfirmedMismatches int                        `json:"confirmed_mismatches"`
	Recovery            IntegrityRecoveryRefStatus `json:"recovery"`
}

// IntegrityRecoveryRefStatus is the per-reference recovery view.
type IntegrityRecoveryRefStatus struct {
	Enabled       bool   `json:"enabled"`
	LastAttemptAt string `json:"last_attempt_at,omitempty"`
	LastResult    string `json:"last_result,omitempty"`
	CooldownUntil string `json:"cooldown_until,omitempty"`
}

// IntegrityRecoveryStatus is the global recovery view.
type IntegrityRecoveryStatus struct {
	Enabled         bool `json:"enabled"`
	ActionsLastHour int  `json:"actions_last_hour"`
	ActionsLastDay  int  `json:"actions_last_day"`
}

// IntegrityStatus is the response of GET /api/v1/gate/integrity.
type IntegrityStatus struct {
	Enabled    bool                       `json:"enabled"`
	IntervalS  int                        `json:"interval_s"`
	References []IntegrityReferenceStatus `json:"references"`
	Recovery   IntegrityRecoveryStatus    `json:"recovery"`
}

// IntegrityProvider returns a consistent integrity snapshot.
type IntegrityProvider func() IntegrityStatus

// handleIntegrity serves GET /api/v1/gate/integrity (viewer and above).
func (s *Server) handleIntegrity(w http.ResponseWriter, r *http.Request, _ params, _ apiSession) {
	if s.deps.Integrity == nil {
		s.respondJSON(w, r, http.StatusOK, IntegrityStatus{Enabled: false, References: []IntegrityReferenceStatus{}})
		return
	}
	s.respondJSON(w, r, http.StatusOK, s.deps.Integrity())
}
