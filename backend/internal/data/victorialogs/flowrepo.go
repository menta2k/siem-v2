package victorialogs

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// FlowRepo stores and retrieves materialized flows.
type FlowRepo struct {
	client *Client
	tenant Tenant
}

func NewFlowRepo(c *Client, t Tenant) *FlowRepo {
	return &FlowRepo{client: c, tenant: t}
}

// Store writes a flow plus its contributing events.
//
// The flow is written as its own document rather than assembled at query time,
// because LogsQL's join buffers the joined side in RAM and cannot serve
// SIEM-scale windows (R5). Reads then become a single-document lookup.
func (r *FlowRepo) Store(ctx context.Context, f *flow.Flow) error {
	docs := []Document{flowDocument(f)}
	for i := range f.Events {
		docs = append(docs, eventDocument(f.Tenant, &f.Events[i], f.FlowID))
	}
	return r.client.Insert(ctx, r.tenant, docs)
}

// StoreFlows persists many flows in one insert per call (the pipeline's bulk
// path). A catch-up burst once produced 200k flow closes in one flush tick;
// per-flow inserts turned that into 200k HTTP round trips.
func (r *FlowRepo) StoreFlows(ctx context.Context, flows []*flow.Flow) error {
	docs := make([]Document, 0, len(flows)*3)
	for _, f := range flows {
		docs = append(docs, flowDocument(f))
		for i := range f.Events {
			docs = append(docs, eventDocument(f.Tenant, &f.Events[i], f.FlowID))
		}
	}
	return r.client.Insert(ctx, r.tenant, docs)
}

// StoreRaw writes the unmodified provider record alongside its normalized form,
// which Constitution Principle II requires for the full retention period.
func (r *FlowRepo) StoreRaw(ctx context.Context, tenant string, provider schema.Provider,
	items []flow.RawItem, receivedAt time.Time) error {
	docs := make([]Document, 0, len(items))
	for _, it := range items {
		docs = append(docs, Document{
			Time: receivedAt,
			Msg:  string(it.Payload),
			Fields: map[string]any{
				"tenant": tenant, "provider": string(provider),
				"dataset": "raw", "record_kind": string(KindRaw),
				"raw_id": it.ID, "received_at": receivedAt.UTC().Format(time.RFC3339Nano),
			},
		})
	}
	return r.client.Insert(ctx, r.tenant, docs)
}

// ProviderEventCounts returns the TRUE per-provider event count over a window
// via a direct stats query — not a flow sample. The dashboard's old
// sample-and-count under-represented whichever provider is spread thinly
// across many flows (Cloudflare: present in nearly every request, yet a
// 1000-flow slice of millions barely showed it).
func (r *FlowRepo) ProviderEventCounts(ctx context.Context, tenant string, from, to time.Time) (map[string]int, error) {
	if !safeValue.MatchString(tenant) || tenant == "" {
		return nil, &ErrUnsafeValue{Field: "tenant", Value: tenant}
	}
	q := fmt.Sprintf(`{tenant=%s,record_kind=%s} _time:[%s, %s] | stats by (provider) count() n`,
		quote(tenant), quote(string(KindEvent)),
		from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	rows, err := r.client.Query(ctx, r.tenant, q, 0)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, row := range rows {
		provider, _ := row["provider"].(string)
		if provider == "" {
			continue
		}
		n, _ := strconv.Atoi(fmt.Sprint(row["n"]))
		out[provider] = n
	}
	return out, nil
}

// Get fetches one flow by id, scoped to the tenant.
func (r *FlowRepo) Get(ctx context.Context, tenant, flowID string) (*flow.Flow, error) {
	q, err := BuildFlowByIDQuery(tenant, flowID)
	if err != nil {
		return nil, err
	}
	rows, err := r.client.Query(ctx, r.tenant, q, 0)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return decodeFlow(rows[0])
}

// Search returns flows matching a typed search.
func (r *FlowRepo) Search(ctx context.Context, tenant string, s FlowSearch) ([]*flow.Flow, error) {
	q, err := BuildFlowQuery(tenant, s)
	if err != nil {
		return nil, err
	}
	// The query's own limit/offset pipes control the page; passing the URL
	// limit parameter as well would truncate AFTER the offset was applied.
	rows, err := r.client.Query(ctx, r.tenant, q, 0)
	if err != nil {
		return nil, err
	}
	out := make([]*flow.Flow, 0, len(rows))
	// An amended flow is a NEW document version under the same flow id (the
	// store is append-only); rows arrive newest-first, so the first version
	// seen per id is the current one and older versions are skipped.
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		f, err := decodeFlow(row)
		if err != nil {
			// One malformed stored document must not fail the whole search; the
			// analyst is better served by the rest of the results plus a gap than
			// by an error page.
			continue
		}
		if seen[f.FlowID] {
			continue
		}
		seen[f.FlowID] = true
		out = append(out, f)
	}
	flow.SortFlows(out)
	return out, nil
}

// flowDocument renders a flow for storage.
//
// Note which fields are stream fields (tenant, provider, dataset, record_kind)
// and which are regular: correlation_key and flow_id are high-cardinality and
// must stay regular fields (R6).
func flowDocument(f *flow.Flow) Document {
	payload, _ := json.Marshal(f)
	return Document{
		Time: f.FirstSeen,
		Msg:  string(payload),
		Fields: map[string]any{
			"tenant": f.Tenant, "provider": "correlated",
			"dataset": "flows", "record_kind": string(KindFlow),

			"flow_id":            f.FlowID,
			"correlation_key":    f.CorrelationKey,
			"completeness":       string(f.Completeness),
			"correlation_method": string(f.Method),
			"confidence":         f.Confidence,
			"bridged":            f.Bridged,
			"effective_outcome":  string(f.EffectiveOutcome),
			"terminating_layer":  string(f.TerminatingLayer),
			"client_ip":          f.Client.IP,
			"country":            f.Client.Country,
			"user_agent":         f.Client.UserAgent,
			"host":               f.Request.Host,
			"path":               f.Request.Path,
			"method":             f.Request.Method,
			"status":             statusOf(f),
			"rule_id":            terminatingRuleID(f),
			"layer_count":        len(f.LayersPresent),
			"amended":            f.Amended,
			"ray_id":             rayIDOf(f),
			// Each provider's own reference, so an investigation that begins in a
			// vendor console can find the flow by the id that console showed.
			"vendor_request_ids": vendorRequestIDsJoined(f),
			// Participating providers, space-joined for word-matching — the
			// record's own "provider" field is the constant "correlated".
			"providers":          providersJoined(f),
			"asn":                f.Client.ASN,
			"data_quality_flags": strings.Join(qualityFlags(f), " "),
		},
	}
}

func eventDocument(tenant string, e *schema.Event, flowID string) Document {
	payload, _ := json.Marshal(e)
	return Document{
		Time: e.EventTime,
		Msg:  string(payload),
		Fields: map[string]any{
			"tenant": tenant, "provider": string(e.Provider),
			"dataset": e.Dataset, "record_kind": string(KindEvent),

			"event_id":          e.EventID,
			"raw_id":            e.RawID,
			"flow_id":           flowID,
			"correlation_key":   e.CorrelationKey,
			"ray_id":            e.RayID,
			"layer":             string(e.Layer),
			"action":            string(e.Verdict.Action),
			"rule_id":           e.Verdict.RuleID,
			"vendor_request_id": e.VendorRequestID,
			"client_ip":         e.Client.IP,
			"host":              e.Request.Host,
			"path":              e.Request.Path,
			"method":            e.Request.Method,
			"status":            e.Response.Status,
		},
	}
}

func decodeFlow(row map[string]any) (*flow.Flow, error) {
	msg, ok := row["_msg"].(string)
	if !ok {
		return nil, fmt.Errorf("stored flow has no _msg payload")
	}
	var f flow.Flow
	if err := json.Unmarshal([]byte(msg), &f); err != nil {
		return nil, fmt.Errorf("decode stored flow: %w", err)
	}
	return &f, nil
}

func statusOf(f *flow.Flow) int {
	for i := len(f.Events) - 1; i >= 0; i-- {
		if f.Events[i].Response.Status > 0 {
			return f.Events[i].Response.Status
		}
	}
	return 0
}

func terminatingRuleID(f *flow.Flow) string {
	for _, e := range f.Events {
		if e.Verdict.Terminating && e.Verdict.RuleID != "" {
			return e.Verdict.RuleID
		}
	}
	return ""
}

// RawForFlow returns the original provider records contributing to a flow.
//
// Raw records are stored separately from the flow rather than embedded, because
// Constitution Principle II requires the unmodified original be retained for the
// full retention period and an amended flow must not duplicate them.
func (r *FlowRepo) RawForFlow(ctx context.Context, tenantID, flowID string) ([]flow.RawRecord, error) {
	f, err := r.Get(ctx, tenantID, flowID)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, nil
	}

	out := make([]flow.RawRecord, 0, len(f.Events))
	for _, e := range f.Events {
		q, err := BuildRawByIDQuery(tenantID, e.RawID)
		if err != nil {
			// A raw id we cannot safely query is skipped rather than failing the
			// whole export: the remaining records are still evidence.
			continue
		}
		rows, err := r.client.Query(ctx, r.tenant, q, 1)
		if err != nil || len(rows) == 0 {
			continue
		}
		payload, _ := rows[0]["_msg"].(string)
		out = append(out, flow.RawRecord{
			RawID:        e.RawID,
			Provider:     e.Provider,
			ReceivedAt:   e.ReceivedAt,
			Payload:      payload,
			MaskedFields: e.MaskedFields,
		})
	}
	return out, nil
}

// rayIDOf returns the flow's ray id, taken from whichever event carries one.
func rayIDOf(f *flow.Flow) string {
	for _, e := range f.Events {
		if e.RayID != "" {
			return e.RayID
		}
	}
	return ""
}

// qualityFlags flattens the flow's data-quality conditions for filtering.
func qualityFlags(f *flow.Flow) []string {
	out := make([]string, 0, len(f.DataQualityFlags))
	for _, flag := range f.DataQualityFlags {
		out = append(out, string(flag))
	}
	return out
}

// vendorRequestIDs collects every provider-specific reference on a flow.
//
// F5's support_id is the important one: it is what an operator reads off the ASM
// console and what they quote to F5 support, and without it an investigation that
// starts there has no way into this system.
//
// Returned SPACE-DELIMITED rather than as an array. VictoriaLogs flattens an
// array to its JSON representation — `["9911..."]` — which no exact-match filter
// can hit. A delimited string keeps each id individually matchable as a word.
func providersJoined(f *flow.Flow) string {
	seen := map[string]bool{}
	var out []string
	for _, e := range f.Events {
		p := string(e.Provider)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

func vendorRequestIDsJoined(f *flow.Flow) string {
	return strings.Join(vendorRequestIDs(f), " ")
}

func vendorRequestIDs(f *flow.Flow) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(f.Events))
	for _, e := range f.Events {
		if e.VendorRequestID == "" || seen[e.VendorRequestID] {
			continue
		}
		seen[e.VendorRequestID] = true
		out = append(out, e.VendorRequestID)
	}
	return out
}
