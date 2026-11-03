package api

import (
	"errors"
	"net/http"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/approval"
)

// failGate maps an approval error onto the documented HTTP status and semantic
// error code. Server-side failures are logged with the request id, never exposed.
func (s *Server) failGate(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, approval.ErrRoleRequired):
		s.fail(w, r, http.StatusForbidden, "role_required", "insufficient permissions")
	case errors.Is(err, approval.ErrSelfApproval):
		s.fail(w, r, http.StatusConflict, "self_approval", "a requester must not approve their own plan")
	case errors.Is(err, approval.ErrAlreadyDecided), errors.Is(err, approval.ErrAlreadyApproved):
		s.fail(w, r, http.StatusConflict, "plan_already_decided", "plan is no longer pending")
	case errors.Is(err, approval.ErrPlanHashMismatch):
		s.fail(w, r, http.StatusConflict, "plan_hash_mismatch", "plan content changed since the approval view")
	case errors.Is(err, approval.ErrWindowExpired):
		s.fail(w, r, http.StatusConflict, "window_expired", "plan window expired")
	case errors.Is(err, approval.ErrMFARequired):
		s.fail(w, r, http.StatusForbidden, "mfa_required", "MFA confirmation is required")
	case errors.Is(err, approval.ErrTokenInvalid):
		s.fail(w, r, http.StatusUnauthorized, "token_invalid", "token is invalid")
	case errors.Is(err, approval.ErrTokenExpired):
		s.fail(w, r, http.StatusConflict, "token_expired", "token expired")
	case errors.Is(err, approval.ErrTokenUsed):
		s.fail(w, r, http.StatusConflict, "token_used", "token already used")
	case errors.Is(err, approval.ErrWrongSource):
		s.fail(w, r, http.StatusForbidden, "wrong_source", "source address does not match the token binding")
	case errors.Is(err, approval.ErrNotApproved):
		s.fail(w, r, http.StatusConflict, "not_approved", "plan is not approved")
	case errors.Is(err, approval.ErrOutsideWindow):
		s.fail(w, r, http.StatusConflict, "outside_window", "outside the approved window")
	case errors.Is(err, approval.ErrTargetNotAllowed):
		s.fail(w, r, http.StatusForbidden, "target_not_allowed", "target or operation is not allowed by the policy")
	case errors.Is(err, approval.ErrNotRequester):
		s.fail(w, r, http.StatusForbidden, "forbidden", "only the requester may act on this plan")
	case errors.Is(err, approval.ErrForbidden):
		s.fail(w, r, http.StatusForbidden, "forbidden", "insufficient permissions")
	case errors.Is(err, approval.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, approval.ErrFailsafe):
		s.fail(w, r, http.StatusServiceUnavailable, "unavailable", "gate is in fail-safe state")
	case errors.Is(err, approval.ErrStore):
		s.logger.Error("gate store failure", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusServiceUnavailable, "unavailable", "gate store unavailable")
	case errors.Is(err, approval.ErrCorruptState):
		s.logger.Error("gate state corrupt", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
	case errors.Is(err, approval.ErrInvalidPlan), errors.Is(err, approval.ErrInvalidDenyReason),
		errors.Is(err, approval.ErrInvalidWriteUnknown):
		s.fail(w, r, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		s.logger.Error("gate request failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
	}
}

// planView extends a plan with its write-unknown evidence, if any.
type planView struct {
	domain.WritePlan
	WriteUnknown []approval.WriteUnknown `json:"write_unknown,omitempty"`
}

// writeUnknownByPlan groups write-unknown evidence by plan.
func (s *Server) writeUnknownByPlan(r *http.Request) (map[domain.PlanID][]approval.WriteUnknown, error) {
	records, err := s.deps.Gate.ListWriteUnknown(r.Context(), "")
	if err != nil {
		return nil, err
	}
	grouped := make(map[domain.PlanID][]approval.WriteUnknown, len(records))
	for _, record := range records {
		grouped[record.PlanID] = append(grouped[record.PlanID], record)
	}
	return grouped, nil
}

// viewPlan enriches one plan.
func viewPlan(plan domain.WritePlan, grouped map[domain.PlanID][]approval.WriteUnknown) planView {
	return planView{WritePlan: plan, WriteUnknown: grouped[plan.PlanID]}
}
