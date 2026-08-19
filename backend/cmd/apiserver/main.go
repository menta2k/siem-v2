// Command apiserver is the analysis tier: search, flow retrieval, evaluation and
// health.
//
// It is separate from logproc so that maintenance or failure here never stops
// collection (FR-065, SC-022).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/menta2k/siem-v2/backend/internal/asnowner"
	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
	"github.com/menta2k/siem-v2/backend/internal/biz/source"
	"github.com/menta2k/siem-v2/backend/internal/biz/tenancy"
	"github.com/menta2k/siem-v2/backend/internal/cfrules"
	"github.com/menta2k/siem-v2/backend/internal/conf"
	"github.com/menta2k/siem-v2/backend/internal/data/postgres"
	"github.com/menta2k/siem-v2/backend/internal/data/victorialogs"
	apierrors "github.com/menta2k/siem-v2/backend/internal/errors"
	"github.com/menta2k/siem-v2/backend/internal/observability"
	"github.com/menta2k/siem-v2/backend/internal/owasp"
	"github.com/menta2k/siem-v2/backend/internal/server"
	"github.com/menta2k/siem-v2/backend/internal/service"
	"github.com/menta2k/siem-v2/backend/internal/version"
)

func main() {
	confPath := flag.String("conf", "configs/apiserver.yaml", "path to the configuration file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("starting", "version", version.String())
	if err := run(*confPath, logger); err != nil {
		logger.Error("apiserver exited", "error", err)
		os.Exit(1)
	}
}

type apiServer struct {
	repo       *victorialogs.FlowRepo
	engine     *owasp.Engine
	owaspCfg   owasp.Config
	health     *observability.Registry
	principals *postgres.PrincipalRepo
	audit      *postgres.AuditRepo
	cfRules    *cfrules.Client
	alerts     *postgres.AlertRepo
	sources    *postgres.SourceRepo
	authSvc    *service.AuthService
	feeds      *service.FeedService
	asnNames   *asnowner.Resolver
	vl         *victorialogs.Client
	vlTenant   victorialogs.Tenant
	vlHotURL   string
	vlWarmURL  string
	pool       *pgxpool.Pool
	logger     *slog.Logger
}

// auditAdapter bridges the audit repository to the server middleware's
// interface. Audit failures are logged rather than returned: refusing a request
// because we could not audit it would turn an observability fault into an
// outage, but losing the record silently is equally unacceptable, so it is
// surfaced loudly.
type auditAdapter struct {
	repo   *postgres.AuditRepo
	logger *slog.Logger
}

func (a *auditAdapter) Record(tenantID, principalID, action, scope, target, outcome string, detail map[string]any) {
	if a.repo == nil {
		return
	}
	err := a.repo.Append(context.Background(), postgres.AuditEntry{
		TenantID: tenantID, PrincipalID: principalID, Action: action,
		Scope: scope, TargetRef: target, Outcome: outcome, Detail: detail,
	})
	if err != nil {
		a.logger.Error("AUDIT WRITE FAILED", "action", action,
			"principal", principalID, "error", err)
	}
}

func run(confPath string, logger *slog.Logger) error {
	cfg, err := conf.Load(confPath)
	if err != nil {
		return err
	}

	vl := victorialogs.New(cfg.Storage.VictoriaLogs.Hot, nil)
	if err := vl.Ping(context.Background()); err != nil {
		return fmt.Errorf("victorialogs unreachable: %w", err)
	}
	tenant := victorialogs.Tenant{
		AccountID: cfg.Storage.VictoriaLogs.AccountID,
		ProjectID: cfg.Storage.VictoriaLogs.ProjectID,
	}

	owaspCfg := owasp.Config{
		ParanoiaLevel:           cfg.Evaluation.ParanoiaLevel,
		InboundAnomalyThreshold: cfg.Evaluation.AnomalyThreshold,
		RequestBodyLimit:        cfg.Evaluation.RequestBodyLimit,
	}
	engine, err := owasp.NewEngine(owaspCfg)
	if err != nil {
		return fmt.Errorf("owasp engine: %w", err)
	}
	logger.Info("owasp engine ready", "ruleset", engine.RulesetVersion, "engine", engine.EngineVersion)

	pool, err := postgres.Connect(ctx0(), os.Getenv("SIEM_PG_DSN"), cfg.Storage.Postgres.MaxConns, cfg.Storage.Postgres.MinConns)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx0(), pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	logger.Info("postgres ready")

	s := &apiServer{
		pool:       pool,
		repo:       victorialogs.NewFlowRepo(vl, tenant),
		engine:     engine,
		owaspCfg:   owaspCfg,
		health:     observability.NewRegistry(),
		principals: postgres.NewPrincipalRepo(pool),
		audit:      postgres.NewAuditRepo(pool),
		cfRules:    cfrules.New(cfg.Evaluation.WirefilterURL, cfg.Evaluation.Timeout),
		alerts:     postgres.NewAlertRepo(pool),
		sources:    postgres.NewSourceRepo(pool),
		asnNames:   &asnowner.Resolver{Source: postgres.NewASNOwnerRepo(pool)},
		vl:         vl,
		vlTenant:   tenant,
		vlHotURL:   cfg.Storage.VictoriaLogs.Hot,
		vlWarmURL:  cfg.Storage.VictoriaLogs.Warm,
		logger:     logger,
	}
	authSvc, err := buildAuthService(cfg, pool, logger)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	s.authSvc = authSvc
	s.feeds = &service.FeedService{Repo: postgres.NewFeedRepo(pool)}

	if err := s.seedDev(ctx0()); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	if err := s.bootstrapAdmin(ctx0()); err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}

	srv := &http.Server{
		Addr:         cfg.Server.HTTPAddr,
		Handler:      s.routes(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startASNOwnerWorker(ctx, pool, logger)

	go func() {
		logger.Info("api listening", "addr", cfg.Server.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("api server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func (s *apiServer) routes() http.Handler {
	audit := &auditAdapter{repo: s.audit, logger: s.logger}
	s.authSvc.Audit = audit
	s.feeds.Audit = audit
	auth := &server.Authenticator{Resolve: s.resolvePrincipal, Audit: audit, Logger: s.logger}

	// Authenticated routes. Each carries the permission it requires, so the
	// authorization decision is visible at the routing table rather than buried
	// in a handler.
	api := http.NewServeMux()
	api.HandleFunc("POST /api/v1/flows/search",
		server.RequirePermission(tenancy.PermViewFlows, audit, s.searchFlows))
	api.HandleFunc("GET /api/v1/flows/{flowID}",
		server.RequirePermission(tenancy.PermViewFlows, audit, s.getFlow))
	api.HandleFunc("POST /api/v1/evaluations",
		server.RequirePermission(tenancy.PermRunEvaluation, audit, s.createEvaluation))
	api.HandleFunc("GET /api/v1/health/collection",
		server.RequirePermission(tenancy.PermViewFlows, audit, s.collectionHealth))
	api.HandleFunc("GET /api/v1/alerts",
		server.RequirePermission(tenancy.PermViewFlows, audit, s.listAlerts))
	api.HandleFunc("POST /api/v1/alerts/{alertID}/acknowledge",
		server.RequirePermission(tenancy.PermViewFlows, audit, s.acknowledgeAlert))
	api.HandleFunc("GET /api/v1/sources",
		server.RequirePermission(tenancy.PermViewFlows, audit, s.listSources))
	// The audit trail is admin-only: it names who looked at what, which is itself
	// sensitive and is not something an analyst needs.
	api.HandleFunc("GET /api/v1/audit",
		server.RequirePermission(tenancy.PermViewAudit, audit, s.listAudit))
	api.HandleFunc("GET /api/v1/stats/verdicts",
		server.RequirePermission(tenancy.PermViewFlows, audit, s.verdictStats))
	// Disk topology is operator information, not analyst information (v1
	// decision) — gated on the retention permission, which only admins hold.
	api.HandleFunc("GET /api/v1/stats/storage",
		server.RequirePermission(tenancy.PermManageRetention, audit, s.storageStats))
	// Unmasked viewing is its own permission, and every such view is recorded
	// individually — seeing a classified field is an event, not a mode (FR-056).
	api.HandleFunc("GET /api/v1/flows/{flowID}/sensitive",
		server.RequirePermission(tenancy.PermViewSensitive, audit, s.getFlowSensitive))
	api.HandleFunc("POST /api/v1/flows/{flowID}/export",
		server.RequirePermission(tenancy.PermExport, audit, s.exportFlow))
	api.HandleFunc("POST /api/v1/sources",
		server.RequirePermission(tenancy.PermManageSources, audit, s.upsertSource))
	api.HandleFunc("GET /api/v1/auth/me",
		server.RequirePermission(tenancy.PermViewFlows, audit, s.authSvc.Me))
	api.HandleFunc("POST /api/v1/invites",
		server.RequirePermission(tenancy.PermManageUsers, audit, s.authSvc.CreateInvite(s.principals)))
	api.HandleFunc("GET /api/v1/users",
		server.RequirePermission(tenancy.PermManageUsers, audit, s.authSvc.ListUsers))
	api.HandleFunc("POST /api/v1/users/{principalID}",
		server.RequirePermission(tenancy.PermManageUsers, audit, s.authSvc.UpdateUser))
	api.HandleFunc("GET /api/v1/feeds",
		server.RequirePermission(tenancy.PermManageSources, audit, s.feeds.List))
	api.HandleFunc("POST /api/v1/feeds",
		server.RequirePermission(tenancy.PermManageSources, audit, s.feeds.Create))
	api.HandleFunc("POST /api/v1/feeds/{feedID}",
		server.RequirePermission(tenancy.PermManageSources, audit, s.feeds.Update))
	api.HandleFunc("POST /api/v1/feeds/{feedID}/rotate",
		server.RequirePermission(tenancy.PermManageSources, audit, s.feeds.Rotate))

	// CORS wraps the authenticated API so a preflight is answered before
	// authentication runs — a browser preflight carries no credentials by design.
	cors := &server.CORS{AllowedOrigins: corsOrigins()}

	// Public authentication operations, listed EXPLICITLY — never a prefix.
	// The v1 lesson behind this: a misnamed entry once left Refresh demanding
	// the very access token it exists to reissue, and an explicit set is the
	// only arrangement where that mistake is visible in review.
	public := http.NewServeMux()
	public.HandleFunc("POST /api/v1/auth/login", s.authSvc.Login)
	public.HandleFunc("POST /api/v1/auth/mfa", s.authSvc.VerifyMFA)
	public.HandleFunc("POST /api/v1/auth/refresh", s.authSvc.Refresh)
	public.HandleFunc("POST /api/v1/auth/logout", s.authSvc.Logout)
	public.HandleFunc("GET /api/v1/invites/preview", s.authSvc.PreviewInvite)
	public.HandleFunc("POST /api/v1/invites/redeem", s.authSvc.RedeemInvite)

	mux := http.NewServeMux()
	for _, route := range []string{
		"POST /api/v1/auth/login", "POST /api/v1/auth/mfa",
		"POST /api/v1/auth/refresh", "POST /api/v1/auth/logout",
		"GET /api/v1/invites/preview", "POST /api/v1/invites/redeem",
	} {
		mux.Handle(route, cors.Middleware(public))
	}
	mux.Handle("/api/v1/", cors.Middleware(auth.Middleware(api)))
	// Liveness is deliberately unauthenticated: it exposes no data and is needed
	// by orchestration before any credential exists.
	mux.HandleFunc("GET /health", s.healthz)
	return mux
}

// resolvePrincipal turns a bearer access token into a principal.
//
// The token is parsed and its subject RE-READ from the database on every
// request, so deactivation takes effect immediately rather than at token
// expiry. The tenant comes from the stored record, never from anything the
// caller sent.
//
// SIEM_DEV_IDENTITIES=true restores the identity-string resolver for local
// work. It is a fallback, not a bypass: a valid token always wins, and the
// flag exists so the browser dev identity switcher keeps working while the
// login UI is exercised alongside it.
func (s *apiServer) resolvePrincipal(r *http.Request) (*tenancy.Principal, error) {
	bearer := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if bearer == "" {
		return nil, fmt.Errorf("no credential presented")
	}
	p, err := s.authSvc.ResolveAccess(r.Context(), bearer)
	if err == nil {
		return p, nil
	}
	if os.Getenv("SIEM_DEV_IDENTITIES") == "true" && strings.Contains(bearer, "@") {
		return s.principals.ByIdentity(r.Context(), bearer)
	}
	return nil, err
}

func ctx0() context.Context { return context.Background() }

// corsOrigins reads the browser origins permitted to call this API.
//
// Explicit origins only: this API serves tenant-scoped security data and accepts
// credentials, so a wildcard is both unsafe and non-functional.
func corsOrigins() []string {
	raw := os.Getenv("SIEM_CORS_ORIGINS")
	if raw == "" {
		return nil
	}
	var out []string
	for _, o := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(o); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// tenantOf reads the caller's tenant from the authenticated principal.
//
// There is no path by which a request field can influence this. That is the
// structural half of FR-074b: cross-tenant access is not refused after the fact,
// it is inexpressible.
func tenantOf(r *http.Request) string {
	t, err := tenancy.TenantOf(r.Context())
	if err != nil {
		// Unreachable behind the authentication middleware; an empty tenant is
		// rejected by the query builder, so this fails closed rather than
		// producing an unscoped query.
		return ""
	}
	return t
}

func (s *apiServer) searchFlows(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From              time.Time `json:"from"`
		To                time.Time `json:"to"`
		ClientIP          string    `json:"client_ip"`
		Host              string    `json:"host"`
		PathPrefix        string    `json:"path_prefix"`
		Method            string    `json:"method"`
		Status            int       `json:"status"`
		Action            string    `json:"action"`
		Layer             string    `json:"layer"`
		RuleID            string    `json:"rule_id"`
		Country           string    `json:"country"`
		Provider          string    `json:"provider"`
		Completeness      string    `json:"completeness"`
		UserAgent         string    `json:"user_agent"`
		RayID             string    `json:"ray_id"`
		SupportID         string    `json:"support_id"`
		CorrelationMethod string    `json:"correlation_method"`
		Bridged           *bool     `json:"bridged"`
		ASN               int       `json:"asn"`
		MinLayers         int       `json:"min_layers"`
		MaxLayers         int       `json:"max_layers"`
		QualityFlag       string    `json:"quality_flag"`
		Limit             int       `json:"limit"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, apierrors.InvalidInput("The request body could not be read.", err.Error()))
		return
	}

	// Note what is absent: there is no free-text query field to populate. The
	// search is compiled from these typed parameters only.
	flows, err := s.repo.Search(r.Context(), tenantOf(r), victorialogs.FlowSearch{
		From: req.From, To: req.To, ClientIP: req.ClientIP, Host: req.Host,
		PathPrefix: req.PathPrefix, Method: req.Method, Status: req.Status,
		Action: req.Action, Layer: req.Layer, RuleID: req.RuleID,
		Country: req.Country, Provider: req.Provider,
		Completeness: req.Completeness, UserAgentSub: req.UserAgent,
		RayID: req.RayID, VendorRequestID: req.SupportID,
		CorrelationMethod: req.CorrelationMethod,
		Bridged:           req.Bridged, ASN: req.ASN,
		MinLayers: req.MinLayers, MaxLayers: req.MaxLayers,
		HasQualityFlag: req.QualityFlag,
		Limit:          req.Limit,
	})
	if err != nil {
		var unsafe *victorialogs.ErrUnsafeValue
		if errors.As(err, &unsafe) {
			writeError(w, apierrors.InvalidInput(
				"One or more search values contain unsupported characters.", err.Error()))
			return
		}
		s.logger.Error("flow search failed", "error", err)
		writeError(w, apierrors.Internal(err.Error()))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"flows": flows, "count": len(flows)})
}

func (s *apiServer) getFlow(w http.ResponseWriter, r *http.Request) {
	f, err := s.repo.Get(r.Context(), tenantOf(r), r.PathValue("flowID"))
	if err != nil {
		var unsafe *victorialogs.ErrUnsafeValue
		if errors.As(err, &unsafe) {
			writeError(w, apierrors.InvalidInput("The flow id is not valid.", err.Error()))
			return
		}
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	if f == nil {
		// Not found and out-of-scope are deliberately indistinguishable.
		writeError(w, apierrors.NotFound("flow not present for this tenant"))
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (s *apiServer) createEvaluation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Engine        string            `json:"engine"`
		Method        string            `json:"method"`
		URI           string            `json:"uri"`
		Headers       map[string]string `json:"headers"`
		Body          string            `json:"body"`
		Expression    string            `json:"expression"`
		ClientIP      string            `json:"client_ip"`
		ParanoiaLevel int               `json:"paranoia_level"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&req); err != nil {
		writeError(w, apierrors.InvalidInput("The request body could not be read.", err.Error()))
		return
	}
	if req.Engine == "cf_expression" {
		s.evaluateExpression(w, r, req.Expression, req.Method, req.URI, req.ClientIP, req.Headers)
		return
	}
	if req.Engine != "" && req.Engine != "owasp_crs" {
		writeError(w, apierrors.InvalidInput(
			"Unknown evaluation engine. Use owasp_crs or cf_expression.",
			"engine="+req.Engine))
		return
	}

	cfg := s.owaspCfg
	if req.ParanoiaLevel > 0 {
		cfg.ParanoiaLevel = req.ParanoiaLevel
	}

	result, err := s.engine.Evaluate(r.Context(), owasp.CapturedRequest{
		ClientIP: req.ClientIP, ClientPort: 0,
		Method: req.Method, URI: req.URI, Headers: req.Headers,
		Body: []byte(req.Body),
	}, cfg)
	if err != nil {
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *apiServer) collectionHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"overall": s.health.Overall(),
		"sources": s.health.Sources(),
		"stages":  s.health.Stages(),
	})
}

// evaluateExpression runs a Cloudflare rule expression through the sidecar.
//
// An unavailable sidecar is reported as such rather than as a non-match: "we
// could not ask" and "the rule does not match" must never look the same.
func (s *apiServer) evaluateExpression(w http.ResponseWriter, r *http.Request,
	expression, method, uri, clientIP string, headers map[string]string) {

	if expression == "" {
		writeError(w, apierrors.InvalidInput(
			"An expression is required for cf_expression evaluation.", "empty expression"))
		return
	}

	path, query := uri, ""
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		path, query = uri[:i], uri[i+1:]
	}

	resp, err := s.cfRules.Evaluate(r.Context(), expression, []cfrules.CapturedRequest{{
		Ref: "request",
		Fields: cfrules.FieldsFromFlow(method, headers["Host"], path, query,
			headers["User-Agent"], clientIP),
	}})
	if err != nil {
		if err == cfrules.ErrNotConfigured {
			writeError(w, apierrors.Unavailable(
				"Cloudflare expression evaluation is not configured on this deployment.",
				err.Error()))
			return
		}
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	if resp.Unavailable {
		writeError(w, apierrors.Unavailable(
			"Cloudflare expression evaluation is temporarily unavailable.", resp.Unreachable))
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// getFlowSensitive returns a flow with classified fields unmasked.
//
// Two things make this safe to offer at all: the permission is separate from
// viewing flows, and each use is audited individually with the flow named. A
// principal who can see everything is one thing; a principal who can see
// everything without anyone knowing is another.
func (s *apiServer) getFlowSensitive(w http.ResponseWriter, r *http.Request) {
	p, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeError(w, apierrors.Unauthorized(err.Error()))
		return
	}
	flowID := r.PathValue("flowID")

	f, err := s.repo.Get(r.Context(), p.TenantID, flowID)
	if err != nil {
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	if f == nil {
		writeError(w, apierrors.NotFound("flow not present for this tenant"))
		return
	}

	// Recorded before the response is written, so a crash mid-write still leaves
	// the access on the record.
	if err := s.audit.Append(r.Context(), postgres.AuditEntry{
		TenantID: p.TenantID, PrincipalID: p.ID,
		Action: "flow.view_sensitive", Scope: "tenant:" + p.TenantID,
		TargetRef: flowID, Outcome: "allowed",
		Detail: map[string]any{"masked_field_count": maskedFieldCount(f)},
	}); err != nil {
		// An unmasked view that cannot be audited must not happen: refusing is
		// the safe direction, because the alternative is an invisible access.
		s.logger.Error("AUDIT WRITE FAILED for sensitive view", "principal", p.ID, "error", err)
		writeError(w, apierrors.Unavailable(
			"The request could not be completed.", "sensitive view refused: audit unavailable"))
		return
	}

	writeJSON(w, http.StatusOK, f)
}

func maskedFieldCount(f *flow.Flow) int {
	n := 0
	for _, e := range f.Events {
		n += len(e.MaskedFields)
	}
	return n
}

func (s *apiServer) exportFlow(w http.ResponseWriter, r *http.Request) {
	p, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeError(w, apierrors.Unauthorized(err.Error()))
		return
	}
	flowID := r.PathValue("flowID")

	f, err := s.repo.Get(r.Context(), p.TenantID, flowID)
	if err != nil {
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	if f == nil {
		writeError(w, apierrors.NotFound("flow not present for this tenant"))
		return
	}

	exporter := &flow.Exporter{Raw: s.repo}
	pkg, err := exporter.Export(r.Context(), f, flow.ExportOptions{
		ExportedBy: p.Identity, TenantID: p.TenantID,
		// Unmasked content requires the separate permission, so an export by a
		// principal without it carries the redactions named rather than the values.
		IncludeSensitive: p.Can(tenancy.PermViewSensitive),
	})
	if err != nil {
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, pkg)
}

func (s *apiServer) upsertSource(w http.ResponseWriter, r *http.Request) {
	p, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeError(w, apierrors.Unauthorized(err.Error()))
		return
	}
	var row postgres.SourceRow
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&row); err != nil {
		writeError(w, apierrors.InvalidInput("The request body could not be read.", err.Error()))
		return
	}

	// Onboarding is a gate, not a checklist: each missing piece produces a
	// specific quiet failure later (FR-008).
	if err := source.Validate(source.Source{
		ID: row.ID, TenantID: p.TenantID, Provider: row.Provider,
		DeliveryMode:           source.DeliveryMode(row.DeliveryMode),
		ExpectedCadenceSeconds: row.ExpectedCadenceSeconds,
		DataClassification:     row.DataClassification,
		RetentionPolicyID:      "default",
		ParserVersion:          row.ParserVersion,
		DetectionPosture:       row.DetectionPosture,
		FixtureCount:           1,
	}); err != nil {
		writeError(w, apierrors.InvalidInput(
			"This source cannot be enabled until its configuration is complete.", err.Error()))
		return
	}

	if err := s.sources.Upsert(r.Context(), p.TenantID, row); err != nil {
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, row)
}

func (s *apiServer) listAlerts(w http.ResponseWriter, r *http.Request) {
	onlyOpen := r.URL.Query().Get("acknowledged") == "false"
	rows, err := s.alerts.List(r.Context(), tenantOf(r), onlyOpen, 100)
	if err != nil {
		s.logger.Error("list alerts", "error", err)
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": rows, "count": len(rows)})
}

func (s *apiServer) acknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	p, err := tenancy.FromContext(r.Context())
	if err != nil {
		writeError(w, apierrors.Unauthorized(err.Error()))
		return
	}
	if err := s.alerts.Acknowledge(r.Context(), p.TenantID, r.PathValue("alertID"), p.ID); err != nil {
		writeError(w, apierrors.NotFound(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *apiServer) listSources(w http.ResponseWriter, r *http.Request) {
	rows, err := s.sources.List(r.Context(), tenantOf(r))
	if err != nil {
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": rows, "count": len(rows)})
}

func (s *apiServer) listAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.audit.List(r.Context(), tenantOf(r), 200)
	if err != nil {
		writeError(w, apierrors.Internal(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}

// verdictStats powers the dashboard. It aggregates over flows the caller may
// already see, so it adds no new disclosure — but it is still tenant-scoped by
// the same path as everything else.
func (s *apiServer) verdictStats(w http.ResponseWriter, r *http.Request) {
	flows, err := s.repo.Search(r.Context(), tenantOf(r), victorialogs.FlowSearch{Limit: 1000})
	if err != nil {
		writeError(w, apierrors.Internal(err.Error()))
		return
	}

	byOutcome := map[string]int{}
	byLayer := map[string]int{}
	byCompleteness := map[string]int{}
	byProvider := map[string]int{}
	bridged, heuristic := 0, 0

	for _, f := range flows {
		byOutcome[string(f.EffectiveOutcome)]++
		byCompleteness[string(f.Completeness)]++
		if f.TerminatingLayer != "" {
			byLayer[string(f.TerminatingLayer)]++
		}
		if f.Bridged {
			bridged++
		}
		if string(f.Method) == "heuristic" {
			heuristic++
		}
		for _, e := range f.Events {
			byProvider[string(e.Provider)]++
		}
	}

	exactRatio := 1.0
	if len(flows) > 0 {
		exactRatio = float64(len(flows)-heuristic) / float64(len(flows))
	}

	topSources, topNetworks := s.topPanels(r.Context(), flows)

	writeJSON(w, http.StatusOK, map[string]any{
		"total_flows":          len(flows),
		"top_sources":          topSources,
		"top_networks":         topNetworks,
		"by_outcome":           byOutcome,
		"by_terminating_layer": byLayer,
		"by_completeness":      byCompleteness,
		"by_provider":          byProvider,
		"bridged_flows":        bridged,
		// The exact-join ratio is the number FR-072e exists for: a falling ratio
		// means identifier propagation broke while flows still appear to form.
		"exact_join_ratio": exactRatio,
	})
}

func (s *apiServer) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError sends only the caller-safe message; the detail stays server-side.
func writeError(w http.ResponseWriter, err error) {
	kind := apierrors.KindOf(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(apierrors.HTTPStatus(kind))
	_ = json.NewEncoder(w).Encode(map[string]string{
		"code":    string(kind),
		"message": apierrors.PublicOf(err),
	})
}
