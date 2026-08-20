package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/auth"
	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	apierrors "github.com/menta2k/siem-v2/backend/internal/errors"
)

// FeedService manages ingest feeds: per-feed endpoints with per-feed tokens,
// ported from v1's feed model. Every operation is tenant-scoped from the
// caller and mounted behind manage_sources.
type FeedService struct {
	Repo *postgres.FeedRepo
	// Sources receives the matching log_source row when a feed is created: the
	// Sources page tracks health BY FEED ID, and a feed without a source row
	// delivers happily while remaining invisible to silence detection.
	Sources *postgres.SourceRepo
	Audit   Auditor
	Now     func() time.Time
}

func (s *FeedService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

var feedProviders = map[string]bool{
	"cloudflare": true, "datadome": true, "f5asm": true, "nginx": true,
}

func feedJSON(f postgres.FeedRow) map[string]any {
	// The hash never crosses this boundary — the UI gets a boolean world.
	return map[string]any{
		"id": f.ID, "provider": f.Provider, "name": f.Name, "enabled": f.Enabled,
		"created_at": f.CreatedAt, "token_rotated_at": f.TokenRotatedAt,
	}
}

// List renders the caller's tenant's feeds.
func (s *FeedService) List(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	rows, err := s.Repo.ListByTenant(r.Context(), caller.TenantID)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	feeds := make([]map[string]any, 0, len(rows))
	for _, f := range rows {
		feeds = append(feeds, feedJSON(f))
	}
	writeAuthJSON(w, map[string]any{"feeds": feeds})
}

// Create mints a feed and its first token. The token appears in THIS response
// and nowhere else, ever — the row keeps only the hash.
func (s *FeedService) Create(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	var req struct {
		Provider string `json:"provider"`
		Name     string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeAuthErr(w, apierrors.InvalidInput("A provider and name are required.", "malformed feed"))
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if !feedProviders[req.Provider] {
		writeAuthErr(w, apierrors.InvalidInput(
			"Provider must be cloudflare, datadome, f5asm or nginx.", "provider="+req.Provider))
		return
	}
	if req.Name == "" || len(req.Name) > 80 {
		writeAuthErr(w, apierrors.InvalidInput("A name of at most 80 characters is required.", "bad feed name"))
		return
	}

	// The id doubles as a URL path segment and the token's lookup half, so it
	// is derived, readable, and dot-free.
	feedID := fmt.Sprintf("feed-%s-%s-%d", caller.TenantID, req.Provider, s.now().UnixNano())
	tok, err := auth.NewFeedToken(feedID)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	row := postgres.FeedRow{
		ID: feedID, TenantID: caller.TenantID, Provider: req.Provider,
		Name: req.Name, Enabled: true, TokenHash: tok.SecretHash(), CreatedBy: caller.ID,
	}
	if err := s.Repo.Create(r.Context(), row); err != nil {
		if errors.Is(err, postgres.ErrFeedNameTaken) {
			writeAuthErr(w, apierrors.New(apierrors.KindConflict,
				"A feed with that name already exists.", "name="+req.Name))
			return
		}
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	if s.Sources != nil {
		if err := s.Sources.Upsert(r.Context(), caller.TenantID, postgres.SourceRow{
			ID: feedID, Provider: req.Provider, DeliveryMode: "push",
			ExpectedCadenceSeconds: 900, DataClassification: "standard",
			ParserVersion:    req.Provider + "/1.0",
			DetectionPosture: "pipeline.source_silence",
			Enabled:          true, HealthState: "awaiting_first_record",
		}); err != nil {
			writeAuthErr(w, apierrors.Internal(err.Error()))
			return
		}
	}
	s.audit(caller, "feed.created", feedID, map[string]any{"provider": req.Provider, "name": req.Name})
	row.CreatedAt, row.TokenRotatedAt = s.now(), s.now()
	writeAuthJSON(w, map[string]any{"feed": feedJSON(row), "token": tok.Encode()})
}

// Update flips the enabled flag. Disabling takes effect at the ingest cache's
// next refresh; the UI says so.
func (s *FeedService) Update(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	feedID := r.PathValue("feedID")
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || req.Enabled == nil {
		writeAuthErr(w, apierrors.InvalidInput("Provide enabled: true or false.", "malformed feed update"))
		return
	}
	changed, err := s.Repo.SetEnabled(r.Context(), caller.TenantID, feedID, *req.Enabled)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	if !changed {
		writeAuthErr(w, apierrors.NotFound("No such feed in your tenant: "+feedID))
		return
	}
	what := "feed.disabled"
	if *req.Enabled {
		what = "feed.enabled"
	}
	s.audit(caller, what, feedID, nil)
	writeAuthJSON(w, map[string]any{"updated": true})
}

// Rotate replaces the feed's token, v1 semantics kept deliberately: the old
// credential dies the moment this commits. Providers retry refused
// deliveries, so the reconfiguration window loses nothing — while a grace
// period would mean two live credentials with no way to tell which one a
// sender still uses.
func (s *FeedService) Rotate(w http.ResponseWriter, r *http.Request) {
	caller, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeAuthErr(w, apierrors.Unauthorized(err.Error()))
		return
	}
	feedID := r.PathValue("feedID")
	tok, err := auth.NewFeedToken(feedID)
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	changed, err := s.Repo.RotateToken(r.Context(), caller.TenantID, feedID, tok.SecretHash())
	if err != nil {
		writeAuthErr(w, apierrors.Internal(err.Error()))
		return
	}
	if !changed {
		writeAuthErr(w, apierrors.NotFound("No such feed in your tenant: "+feedID))
		return
	}
	// The audit records THAT rotation happened, never the token.
	s.audit(caller, "feed.token_rotated", feedID, nil)
	writeAuthJSON(w, map[string]any{"token": tok.Encode(), "rotated_at": s.now()})
}

func (s *FeedService) audit(caller *tenancy.Principal, action, target string, detail map[string]any) {
	if s.Audit != nil {
		s.Audit.Record(caller.TenantID, caller.ID, action,
			"tenant:"+caller.TenantID, target, "allowed", detail)
	}
}
