package api

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/approval"
)

// createPlanBody is the POST /plans request body.
type createPlanBody struct {
	TargetID    domain.TargetID         `json:"target_id"`
	AssetID     domain.AssetID          `json:"asset_id"`
	Protocol    string                  `json:"protocol"`
	Operations  []domain.WriteOperation `json:"operations"`
	Reason      string                  `json:"reason"`
	TicketRef   string                  `json:"ticket_ref,omitempty"`
	WindowStart time.Time               `json:"window_start"`
	WindowEnd   time.Time               `json:"window_end"`
}

// approveBody is the POST /plans/{id}/approve request body.
type approveBody struct {
	Comment  string `json:"comment,omitempty"`
	PlanHash string `json:"plan_hash,omitempty"`
}

// rejectBody is the POST /plans/{id}/reject request body.
type rejectBody struct {
	Reason string `json:"reason"`
}

// planEnvelope wraps one plan view.
type planEnvelope struct {
	Plan planView `json:"plan"`
}

// approveResponse is the approval result, including the one-time token if final.
type approveResponse struct {
	Plan  planView             `json:"plan"`
	Token *approval.TokenGrant `json:"token"`
}

// plansEnvelope is the plan list payload.
type plansEnvelope struct {
	Items  []planView `json:"items"`
	Total  int        `json:"total"`
	Limit  int        `json:"limit,omitempty"`
	Offset int        `json:"offset,omitempty"`
}

// handlePlans serves GET /api/v1/gate/plans.
func (s *Server) handlePlans(w http.ResponseWriter, r *http.Request, _ params, session apiSession) {
	q := parseQuery(r, "state", "target_id", "limit", "offset")
	state := domain.WritePlanState(q.enumValue("state", []string{
		string(domain.PlanPending), string(domain.PlanApproved), string(domain.PlanExecuted),
		string(domain.PlanRejected), string(domain.PlanExpired), string(domain.PlanCancelled),
	}))
	targetFilter := domain.TargetID(q.targetID("target_id"))
	limit, offset := q.limit(), q.offset()
	if !s.checkQuery(w, r, q) {
		return
	}
	plans, err := s.deps.Gate.ListPlans(r.Context())
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	grouped, err := s.writeUnknownByPlan(r)
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	filtered := make([]planView, 0, len(plans))
	for _, plan := range plans {
		if isVendorOnly(session.User) && plan.RequestedBy != session.User.UserID {
			continue
		}
		if state != "" && plan.State != state {
			continue
		}
		if targetFilter != "" && plan.TargetID != targetFilter {
			continue
		}
		filtered = append(filtered, viewPlan(plan, grouped))
	}
	total := len(filtered)
	if offset >= total {
		filtered = []planView{}
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		filtered = filtered[offset:end]
	}
	s.respondJSON(w, r, http.StatusOK, plansEnvelope{Items: filtered, Total: total, Limit: limit, Offset: offset})
}

// handlePlan serves GET /api/v1/gate/plans/{plan_id}.
func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request, p params, session apiSession) {
	planID := domain.PlanID(pathParam(p, "plan_id"))
	if err := planID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "plan_id is not a valid identifier")
		return
	}
	plan, found, err := s.deps.Gate.GetPlan(r.Context(), planID)
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	if !found {
		s.fail(w, r, http.StatusNotFound, "not_found", "plan not found")
		return
	}
	if isVendorOnly(session.User) && plan.RequestedBy != session.User.UserID {
		s.fail(w, r, http.StatusForbidden, "forbidden", "vendors may only read their own plans")
		return
	}
	grouped, err := s.writeUnknownByPlan(r)
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, planEnvelope{Plan: viewPlan(plan, grouped)})
}

// handleCreatePlan serves POST /api/v1/gate/plans.
func (s *Server) handleCreatePlan(w http.ResponseWriter, r *http.Request, _ params, session apiSession) {
	var body createPlanBody
	if !s.decodeJSON(w, r, &body) {
		return
	}
	plan, err := s.deps.Gate.CreatePlan(r.Context(), session.User, approval.CreatePlanRequest{
		TargetID:    body.TargetID,
		AssetID:     body.AssetID,
		Protocol:    body.Protocol,
		Operations:  body.Operations,
		Reason:      body.Reason,
		TicketRef:   body.TicketRef,
		WindowStart: body.WindowStart,
		WindowEnd:   body.WindowEnd,
	})
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusCreated, planEnvelope{Plan: planView{WritePlan: plan}})
}

// handleApprove serves POST /api/v1/gate/plans/{plan_id}/approve.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, p params, session apiSession) {
	planID := domain.PlanID(pathParam(p, "plan_id"))
	if err := planID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "plan_id is not a valid identifier")
		return
	}
	var body approveBody
	if !s.decodeJSONOptional(w, r, &body) {
		return
	}
	if err := s.verifyMFAHeader(r, session); err != nil {
		// Audit the failed step-up without any code material.
		s.auditLogin(r, string(session.User.UserID), roleList(session.User), approval.ActionLoginFailed, "approval mfa failed: "+loginErrorReason(err))
		s.fail(w, r, http.StatusForbidden, "mfa_required", "MFA confirmation is required")
		return
	}
	result, err := s.deps.Gate.Approve(r.Context(), session.User, planID, approval.ApproveRequest{
		Comment:  body.Comment,
		PlanHash: body.PlanHash,
		MFAUsed:  true,
	})
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, approveResponse{
		Plan:  planView{WritePlan: result.Plan},
		Token: result.Token,
	})
}

// handleReject serves POST /api/v1/gate/plans/{plan_id}/reject.
func (s *Server) handleReject(w http.ResponseWriter, r *http.Request, p params, session apiSession) {
	planID := domain.PlanID(pathParam(p, "plan_id"))
	if err := planID.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "plan_id is not a valid identifier")
		return
	}
	var body rejectBody
	if !s.decodeJSON(w, r, &body) {
		return
	}
	plan, err := s.deps.Gate.Reject(r.Context(), session.User, planID, body.Reason)
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, planEnvelope{Plan: planView{WritePlan: plan}})
}

// handleCancel serves POST /api/v1/gate/plans/{plan_id}/cancel.
func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request, p params, session apiSession) {
	id := domain.PlanID(pathParam(p, "plan_id"))
	if err := id.Validate(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "plan_id is not a valid identifier")
		return
	}
	plan, err := s.deps.Gate.Cancel(r.Context(), session.User, id)
	if err != nil {
		s.failGate(w, r, err)
		return
	}
	s.respondJSON(w, r, http.StatusOK, planEnvelope{Plan: planView{WritePlan: plan}})
}

// decodeJSONOptional decodes an optional body: an empty body is treated as {}.
func (s *Server) decodeJSONOptional(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	return s.decodeJSON(w, r, dst)
}

// ensure errors/io remain available for the optional body helper above.
var (
	_ = errors.Is
	_ = io.EOF
)
