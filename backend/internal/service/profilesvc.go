package service

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	apierrors "github.com/menta2k/siem-v2/backend/internal/errors"
	profiling "github.com/menta2k/siem-v2/backend/internal/profile"
)

// ProfileService serves learned traffic profiles and the per-tenant profiler
// policy. Reads sit behind view_flows; changing what gets analyzed — or
// forgetting what was learned — is data governance and sits behind
// manage_sources, exactly like the ingest filters.
type ProfileService struct {
	Repo  *postgres.ProfileRepo
	Audit Auditor
}

// GetConfig returns the caller's tenant's profiler policy plus the limits the
// editor needs to validate against.
func (s *ProfileService) GetConfig(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	cfg, err := s.Repo.GetConfig(r.Context(), caller.TenantID)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	writeAuthJSON(w, map[string]any{
		"config":    cfg,
		"max_hosts": profiling.MaxHosts, "max_exclude_paths": profiling.MaxExcludePaths,
	})
}

// SetConfig REPLACES the tenant's profiler policy. Validation runs the exact
// checks the profiler applies, so "it saved" and "it applies" cannot disagree.
func (s *ProfileService) SetConfig(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	var req struct {
		Config profiling.TenantConfig `json:"config"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeAuthErr(w, apierrors.InvalidInput("The configuration could not be read.", err.Error()))
		return
	}
	if err := req.Config.Validate(); err != nil {
		writeAuthErr(w, apierrors.InvalidInput(err.Error(), "profiler config validation"))
		return
	}
	if err := s.Repo.SetConfig(r.Context(), caller.TenantID, req.Config); err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	// The audit records the FULL config: "what were we analyzing in March"
	// must be answerable from the trail alone.
	if s.Audit != nil {
		s.Audit.Record(caller.TenantID, caller.ID, "profiler_config.replaced",
			"tenant:"+caller.TenantID, "", "allowed", map[string]any{"config": req.Config})
	}
	writeAuthJSON(w, map[string]any{"config": req.Config})
}

// List returns one page of the tenant's endpoint profiles.
func (s *ProfileService) List(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(q.Get("per_page"))
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}

	// The publish threshold hides one-off scanner noise until it recurs.
	// all=true shows everything — the endpoints are still the tenant's own.
	minObs := 0
	if q.Get("all") != "true" {
		cfg, err := s.Repo.GetConfig(r.Context(), caller.TenantID)
		if err == nil {
			minObs = cfg.MinObservationsToPublish
		}
	}

	eps, total, err := s.Repo.List(r.Context(), caller.TenantID, postgres.ListQuery{
		Host:            q.Get("host"),
		Method:          strings.ToUpper(strings.TrimSpace(q.Get("method"))),
		Search:          q.Get("q"),
		MinObservations: minObs,
		Sort:            q.Get("sort"),
		Ascending:       q.Get("dir") == "asc",
		Limit:           perPage,
		Offset:          (page - 1) * perPage,
	})
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	out := make([]map[string]any, 0, len(eps))
	for _, ep := range eps {
		out = append(out, endpointJSON(ep, caller, false))
	}
	writeAuthJSON(w, map[string]any{
		"endpoints": out, "total": total, "page": page, "per_page": perPage,
	})
}

// Get returns one endpoint with its full parameter set.
func (s *ProfileService) Get(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	ep, err := s.Repo.Get(r.Context(), caller.TenantID, r.PathValue("endpointID"))
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	if ep == nil {
		writeAuthErr(w, apierrors.NotFound("no such endpoint profile"))
		return
	}
	writeAuthJSON(w, map[string]any{"endpoint": endpointJSON(ep, caller, true)})
}

// Hosts returns per-host summaries — the overview strip and the config
// picker's source, so an operator chooses from hosts actually seen instead of
// typing them.
func (s *ProfileService) Hosts(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	hosts, err := s.Repo.Hosts(r.Context(), caller.TenantID)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	if hosts == nil {
		hosts = []postgres.HostStat{}
	}
	writeAuthJSON(w, map[string]any{"hosts": hosts})
}

// Delete forgets one endpoint profile. Active traffic re-learns it; that is
// the point — forgetting resets a baseline that has drifted from reality.
func (s *ProfileService) Delete(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	id := r.PathValue("endpointID")
	deleted, err := s.Repo.DeleteEndpoint(r.Context(), caller.TenantID, id)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	if !deleted {
		writeAuthErr(w, apierrors.NotFound("no such endpoint profile"))
		return
	}
	if s.Audit != nil {
		s.Audit.Record(caller.TenantID, caller.ID, "profile_endpoint.deleted",
			"tenant:"+caller.TenantID, id, "allowed", nil)
	}
	writeAuthJSON(w, map[string]any{"deleted": true})
}

// endpointJSON renders an endpoint for the API. Parameters come sorted (query
// before path, then by name) so the UI needs no client-side ordering logic.
// Cookie NAMES are classified: without view_sensitive the caller sees only
// that cookies exist and how many, never which.
func endpointJSON(ep *profiling.EndpointProfile, caller *tenancy.Principal, includeParams bool) map[string]any {
	out := map[string]any{
		"id":            ep.ID,
		"host":          ep.Host,
		"method":        ep.Method,
		"path_template": ep.PathTemplate,
		"observations":  ep.Observations,
		"first_seen":    ep.FirstSeen,
		"last_seen":     ep.LastSeen,
		"truncated":     ep.Truncated,
		"param_count":   len(ep.Params),
		"providers":     sortedKeys(ep.Providers),
		"status_mix":    ep.StatusMix,
		// nil means NOT MEASURED — the frontend renders "not captured", never 0.
		"max_request_bytes": ep.MaxRequestBytes,
		"max_header_count":  ep.MaxHeaderCount,
		"max_header_bytes":  ep.MaxHeaderBytes,
		"max_cookie_count":  ep.MaxCookieCount,
		"max_param_count":   ep.MaxParamCount,
		"max_value_len":     ep.MaxValueLen,
		"max_path_len":      ep.MaxPathLen,
	}
	if caller.Can(tenancy.PermViewSensitive) {
		out["cookie_names"] = sortedKeys(ep.CookieNames)
	} else {
		out["cookie_names_count"] = len(ep.CookieNames)
	}
	if !includeParams {
		return out
	}
	params := make([]map[string]any, 0, len(ep.Params))
	for _, pp := range ep.Params {
		presence := 0.0
		if pp.Observations > 0 {
			presence = float64(pp.PresentCount) / float64(pp.Observations)
		}
		enum := make([]string, 0, len(pp.EnumValues))
		for v := range pp.EnumValues {
			enum = append(enum, v)
		}
		sort.Strings(enum)
		params = append(params, map[string]any{
			"location":          pp.Location,
			"name":              pp.Name,
			"inferred_type":     pp.Type,
			"observations":      pp.Observations,
			"present_count":     pp.PresentCount,
			"presence":          presence,
			"min_len":           pp.MinLen,
			"max_len":           pp.MaxLen,
			"distinct_estimate": pp.DistinctEstimate,
			"enum_values":       enum,
			"enum_overflowed":   pp.EnumOverflowed,
			"first_seen":        pp.FirstSeen,
			"last_seen":         pp.LastSeen,
		})
	}
	sort.Slice(params, func(i, j int) bool {
		li, lj := params[i]["location"].(profiling.ParamLocation), params[j]["location"].(profiling.ParamLocation)
		if li != lj {
			return li == profiling.LocationQuery
		}
		return params[i]["name"].(string) < params[j]["name"].(string)
	})
	out["params"] = params
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
