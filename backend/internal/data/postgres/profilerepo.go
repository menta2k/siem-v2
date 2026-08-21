package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/menta2k/siem-v2/backend/internal/profile"
)

// ProfileRepo persists learned endpoint profiles and per-tenant profiler
// policy. The profiler process is the writer; the API server only reads
// (except config and endpoint deletion).
type ProfileRepo struct{ pool *pgxpool.Pool }

func NewProfileRepo(pool *pgxpool.Pool) *ProfileRepo { return &ProfileRepo{pool: pool} }

// endpointColumns is the SELECT list shared by every reader so struct mapping
// lives in exactly one place (scanEndpoint).
const endpointColumns = `id, tenant_id, host, method, path_template, observations,
	first_seen, last_seen, max_request_bytes, max_header_count, max_header_bytes,
	max_cookie_count, max_param_count, max_value_len, max_path_len,
	cookie_names, status_mix, providers, truncated, params`

func scanEndpoint(row pgx.Row) (*profile.EndpointProfile, error) {
	var (
		ep          profile.EndpointProfile
		cookieNames []string
		providers   []string
		statusMix   []byte
		params      []byte
	)
	err := row.Scan(&ep.ID, &ep.Tenant, &ep.Host, &ep.Method, &ep.PathTemplate,
		&ep.Observations, &ep.FirstSeen, &ep.LastSeen,
		&ep.MaxRequestBytes, &ep.MaxHeaderCount, &ep.MaxHeaderBytes,
		&ep.MaxCookieCount, &ep.MaxParamCount, &ep.MaxValueLen, &ep.MaxPathLen,
		&cookieNames, &statusMix, &providers, &ep.Truncated, &params)
	if err != nil {
		return nil, err
	}
	if len(cookieNames) > 0 {
		ep.CookieNames = map[string]bool{}
		for _, n := range cookieNames {
			ep.CookieNames[n] = true
		}
	}
	if len(providers) > 0 {
		ep.Providers = map[string]bool{}
		for _, p := range providers {
			ep.Providers[p] = true
		}
	}
	if len(statusMix) > 0 {
		if err := json.Unmarshal(statusMix, &ep.StatusMix); err != nil {
			return nil, fmt.Errorf("decode status mix for %s: %w", ep.ID, err)
		}
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &ep.Params); err != nil {
			return nil, fmt.Errorf("decode params for %s: %w", ep.ID, err)
		}
	}
	return &ep, nil
}

func setToSlice(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// UpsertEndpoints stores a flush's dirty endpoints in one batch. The in-memory
// aggregator is authoritative, so each row is REPLACED wholesale — merging in
// SQL would be a second implementation of the merge semantics that could
// drift from the real one.
func (r *ProfileRepo) UpsertEndpoints(ctx context.Context, eps []*profile.EndpointProfile) error {
	if len(eps) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, ep := range eps {
		statusMix, err := json.Marshal(ep.StatusMix)
		if err != nil {
			return fmt.Errorf("encode status mix for %s: %w", ep.ID, err)
		}
		params, err := json.Marshal(ep.Params)
		if err != nil {
			return fmt.Errorf("encode params for %s: %w", ep.ID, err)
		}
		batch.Queue(`
			INSERT INTO profile_endpoint (
				id, tenant_id, host, method, path_template, observations,
				first_seen, last_seen, max_request_bytes, max_header_count,
				max_header_bytes, max_cookie_count, max_param_count,
				max_value_len, max_path_len, cookie_names, status_mix,
				providers, truncated, params, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,now())
			ON CONFLICT (id) DO UPDATE SET
				observations = EXCLUDED.observations,
				first_seen = EXCLUDED.first_seen,
				last_seen = EXCLUDED.last_seen,
				max_request_bytes = EXCLUDED.max_request_bytes,
				max_header_count = EXCLUDED.max_header_count,
				max_header_bytes = EXCLUDED.max_header_bytes,
				max_cookie_count = EXCLUDED.max_cookie_count,
				max_param_count = EXCLUDED.max_param_count,
				max_value_len = EXCLUDED.max_value_len,
				max_path_len = EXCLUDED.max_path_len,
				cookie_names = EXCLUDED.cookie_names,
				status_mix = EXCLUDED.status_mix,
				providers = EXCLUDED.providers,
				truncated = EXCLUDED.truncated,
				params = EXCLUDED.params,
				updated_at = now()`,
			ep.ID, ep.Tenant, ep.Host, ep.Method, ep.PathTemplate, ep.Observations,
			ep.FirstSeen, ep.LastSeen, ep.MaxRequestBytes, ep.MaxHeaderCount,
			ep.MaxHeaderBytes, ep.MaxCookieCount, ep.MaxParamCount,
			ep.MaxValueLen, ep.MaxPathLen, setToSlice(ep.CookieNames), statusMix,
			setToSlice(ep.Providers), ep.Truncated, params)
	}
	res := r.pool.SendBatch(ctx, batch)
	defer res.Close()
	for range eps {
		if _, err := res.Exec(); err != nil {
			return fmt.Errorf("upsert endpoint profile: %w", err)
		}
	}
	return nil
}

// DeleteEndpoints removes rows retired by a template merge: their evidence now
// lives in the merged template row, and keeping both would double-count.
func (r *ProfileRepo) DeleteEndpoints(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM profile_endpoint WHERE id = ANY($1)`, ids)
	if err != nil {
		return fmt.Errorf("delete retired endpoint profiles: %w", err)
	}
	return nil
}

// LoadAll returns every stored profile — the profiler's startup seed. Learned
// templates and caps only stay monotonic across restarts because the process
// resumes from what it already knew.
func (r *ProfileRepo) LoadAll(ctx context.Context) ([]*profile.EndpointProfile, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+endpointColumns+` FROM profile_endpoint`)
	if err != nil {
		return nil, fmt.Errorf("load endpoint profiles: %w", err)
	}
	defer rows.Close()
	var out []*profile.EndpointProfile
	for rows.Next() {
		ep, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

// ListQuery filters and pages the endpoint list. Tenant is injected by the
// caller from the authenticated principal, never from client input.
type ListQuery struct {
	Host            string
	Method          string
	Search          string // substring of the path template
	MinObservations int
	Sort            string // observations | last_seen | path
	Ascending       bool
	Limit           int
	Offset          int
}

// List returns one page of a tenant's endpoints plus the total match count.
func (r *ProfileRepo) List(ctx context.Context, tenantID string, q ListQuery) ([]*profile.EndpointProfile, int, error) {
	where := `WHERE tenant_id = $1 AND observations >= $2`
	args := []any{tenantID, q.MinObservations}
	if q.Host != "" {
		args = append(args, q.Host)
		where += fmt.Sprintf(` AND host = $%d`, len(args))
	}
	if q.Method != "" {
		args = append(args, q.Method)
		where += fmt.Sprintf(` AND method = $%d`, len(args))
	}
	if q.Search != "" {
		args = append(args, "%"+q.Search+"%")
		where += fmt.Sprintf(` AND path_template ILIKE $%d`, len(args))
	}

	var total int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM profile_endpoint `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count endpoint profiles: %w", err)
	}

	// The sort column comes from a fixed vocabulary, never from the raw
	// request — string-building an ORDER BY from client input would be an
	// injection surface.
	order := "observations"
	switch q.Sort {
	case "last_seen":
		order = "last_seen"
	case "path":
		order = "path_template"
	}
	dir := "DESC"
	if q.Ascending {
		dir = "ASC"
	}
	limit := q.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args = append(args, limit, q.Offset)
	sql := fmt.Sprintf(`SELECT `+endpointColumns+` FROM profile_endpoint %s
		ORDER BY %s %s, id ASC LIMIT $%d OFFSET $%d`,
		where, order, dir, len(args)-1, len(args))

	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list endpoint profiles: %w", err)
	}
	defer rows.Close()
	var out []*profile.EndpointProfile
	for rows.Next() {
		ep, err := scanEndpoint(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, ep)
	}
	return out, total, rows.Err()
}

// Get returns one endpoint, tenant-checked: asking for another tenant's ID is
// indistinguishable from asking for one that does not exist.
func (r *ProfileRepo) Get(ctx context.Context, tenantID, id string) (*profile.EndpointProfile, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+endpointColumns+` FROM profile_endpoint WHERE tenant_id = $1 AND id = $2`,
		tenantID, id)
	ep, err := scanEndpoint(row)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get endpoint profile: %w", err)
	}
	return ep, nil
}

// DeleteEndpoint forgets one profile on operator request. The profiler will
// re-learn the endpoint from live traffic if it is still active.
func (r *ProfileRepo) DeleteEndpoint(ctx context.Context, tenantID, id string) (bool, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM profile_endpoint WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return false, fmt.Errorf("delete endpoint profile: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// HostStat summarizes one observed host for the overview strip and the config
// picker.
type HostStat struct {
	Host         string    `json:"host"`
	Endpoints    int       `json:"endpoints"`
	Observations int64     `json:"observations"`
	LastSeen     time.Time `json:"last_seen"`
}

// Hosts returns per-host endpoint and observation totals for a tenant.
func (r *ProfileRepo) Hosts(ctx context.Context, tenantID string) ([]HostStat, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT host, count(*), sum(observations), max(last_seen)
		FROM profile_endpoint WHERE tenant_id = $1
		GROUP BY host ORDER BY sum(observations) DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("host stats: %w", err)
	}
	defer rows.Close()
	var out []HostStat
	for rows.Next() {
		var h HostStat
		if err := rows.Scan(&h.Host, &h.Endpoints, &h.Observations, &h.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// GetConfig returns a tenant's profiler policy.
func (r *ProfileRepo) GetConfig(ctx context.Context, tenantID string) (profile.TenantConfig, error) {
	cfg := profile.DefaultTenantConfig()
	var raw []byte
	err := r.pool.QueryRow(ctx,
		`SELECT profiler_config FROM tenant WHERE id = $1`, tenantID).Scan(&raw)
	if err != nil {
		return cfg, fmt.Errorf("load profiler config: %w", err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("decode profiler config: %w", err)
	}
	return cfg, nil
}

// SetConfig REPLACES a tenant's profiler policy (no merge — what the editor
// shows is exactly what applies, the ingest-filter semantics).
func (r *ProfileRepo) SetConfig(ctx context.Context, tenantID string, cfg profile.TenantConfig) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode profiler config: %w", err)
	}
	tag, err := r.pool.Exec(ctx,
		`UPDATE tenant SET profiler_config = $2 WHERE id = $1`, tenantID, raw)
	if err != nil {
		return fmt.Errorf("store profiler config: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("no such tenant %q", tenantID)
	}
	return nil
}

// AllConfigs returns every ENABLED tenant's policy — the profiler cache's
// refresh source. A tenant whose stored JSON does not decode is SKIPPED, which
// for the profiler means "not profiled": unlike ingest filters this cache
// fails CLOSED, because not-analyzing is the safe default for an additive
// feature.
func (r *ProfileRepo) AllConfigs(ctx context.Context) (map[string]profile.TenantConfig, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, profiler_config FROM tenant`)
	if err != nil {
		return nil, fmt.Errorf("list profiler configs: %w", err)
	}
	defer rows.Close()
	out := map[string]profile.TenantConfig{}
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var cfg profile.TenantConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			continue // fail closed: this tenant is simply not profiled
		}
		if cfg.Enabled {
			out[id] = cfg
		}
	}
	return out, rows.Err()
}
