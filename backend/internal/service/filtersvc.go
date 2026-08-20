package service

import (
	"encoding/json"
	"net/http"

	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	apierrors "github.com/menta2k/siem-v2/backend/internal/errors"
	"github.com/menta2k/siem-v2/backend/internal/ingest/filter"
)

// FilterService manages a tenant's ingest filter rules. Mounted behind
// manage_sources: deciding what is never stored is a data-governance act.
type FilterService struct {
	Repo  *postgres.FilterRepo
	Audit Auditor
}

// Get returns the caller's tenant's rules.
func (s *FilterService) Get(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	rules, err := s.Repo.Get(r.Context(), caller.TenantID)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	if rules == nil {
		rules = []filter.Rule{}
	}
	writeAuthJSON(w, map[string]any{"rules": rules, "max_rules": filter.MaxRules})
}

// Set REPLACES the tenant's rule set. Validation uses the exact compiler the
// ingest path runs, so "it saved" and "it applies" cannot disagree.
func (s *FilterService) Set(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	var req struct {
		Rules []filter.Rule `json:"rules"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeAuthErr(w, apierrors.InvalidInput("The rules could not be read.", err.Error()))
		return
	}
	if _, err := filter.Compile(req.Rules); err != nil {
		writeAuthErr(w, apierrors.InvalidInput(err.Error(), "ingest filter validation"))
		return
	}
	if err := s.Repo.Set(r.Context(), caller.TenantID, req.Rules); err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	// The audit records the FULL rule set: "what were we dropping in March"
	// must be answerable, because the dropped records themselves cannot answer.
	if s.Audit != nil {
		s.Audit.Record(caller.TenantID, caller.ID, "ingest_filters.replaced",
			"tenant:"+caller.TenantID, "", "allowed", map[string]any{"rules": req.Rules, "count": len(req.Rules)})
	}
	writeAuthJSON(w, map[string]any{"rules": req.Rules})
}
