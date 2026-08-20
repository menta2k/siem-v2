// Package victorialogs writes and reads events and flows.
//
// Two rules govern everything here, both from Phase 0 research:
//
//   - Stream fields must be LOW CARDINALITY. The VictoriaLogs docs are explicit
//     that ip, user_id and trace_id must never be stream fields; doing so
//     degrades ingestion and query performance and inflates disk I/O. The
//     correlation key is therefore a regular field, which costs nothing because
//     all fields are indexed for search regardless of cardinality (R6).
//
//   - Clients never supply query text. VictoriaLogs' tenancy headers are
//     unauthenticated and advisory, so this package is the only place LogsQL is
//     constructed, always from typed parameters with tenant headers injected
//     server-side (R8, FR-074b).
package victorialogs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Tenant identifies a VictoriaLogs tenant. It is resolved server-side from the
// authenticated principal and never read from a request field.
type Tenant struct {
	AccountID uint32
	ProjectID uint32
}

// Client talks to one VictoriaLogs instance (one retention class).
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: httpClient}
}

// RecordKind distinguishes what a stored document represents.
type RecordKind string

const (
	KindRaw        RecordKind = "raw"
	KindEvent      RecordKind = "event"
	KindFlow       RecordKind = "flow"
	KindDeadLetter RecordKind = "dead_letter"
)

// streamFields are the ONLY fields used to partition streams. Adding a
// high-cardinality field here would be the single most damaging change possible
// to this system's storage behaviour.
var streamFields = []string{"tenant", "provider", "dataset", "record_kind"}

// Document is one record written to VictoriaLogs.
type Document struct {
	Time   time.Time      `json:"-"`
	Msg    string         `json:"_msg"`
	Fields map[string]any `json:"-"`
}

// MarshalJSON flattens the document, stamping the time field VictoriaLogs reads.
func (d Document) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, len(d.Fields)+2)
	for k, v := range d.Fields {
		out[k] = v
	}
	out["_msg"] = d.Msg
	out["_time"] = d.Time.UTC().Format(time.RFC3339Nano)
	return json.Marshal(out)
}

// Insert writes documents via the JSON-lines endpoint.
func (c *Client) Insert(ctx context.Context, tenant Tenant, docs []Document) error {
	if len(docs) == 0 {
		return nil
	}

	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, d := range docs {
		if err := enc.Encode(d); err != nil {
			return fmt.Errorf("encode document: %w", err)
		}
	}

	u := c.BaseURL + "/insert/jsonline?" + url.Values{
		"_msg_field":     {"_msg"},
		"_time_field":    {"_time"},
		"_stream_fields": {strings.Join(streamFields, ",")},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/stream+json")
	setTenant(req, tenant)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("victorialogs insert: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("victorialogs insert returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// Query runs a LogsQL query built by this package and decodes the result.
//
// The query argument is unexported-by-convention: it is only ever produced by
// QueryBuilder in this package, never accepted from a caller.
func (c *Client) Query(ctx context.Context, tenant Tenant, logsQL string, limit int) ([]map[string]any, error) {
	form := url.Values{"query": {logsQL}}
	if limit > 0 {
		form.Set("limit", strconv.Itoa(limit))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/select/logsql/query", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setTenant(req, tenant)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("victorialogs query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("victorialogs query returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	// The response is newline-delimited JSON, one object per matching record.
	var out []map[string]any
	dec := json.NewDecoder(resp.Body)
	for {
		var row map[string]any
		if err := dec.Decode(&row); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode query result: %w", err)
		}
		out = append(out, row)
	}
	return out, nil
}

// DeleteByQuery removes every record matching the LogsQL filter. It drives
// scheduled raw-evidence expiry: VictoriaLogs has no per-record TTL, so a
// shorter retention class is enforced by periodically deleting what has aged
// out. Requires the instance to run with -delete.enable (research.md R7).
func (c *Client) DeleteByQuery(ctx context.Context, tenant Tenant, logsQL string) error {
	form := url.Values{"filter": {logsQL}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/delete/run_task", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setTenant(req, tenant)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("victorialogs delete: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("victorialogs delete returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// Ping reports whether the instance is reachable.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/select/logsql/query?query=*&limit=1", nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("victorialogs ping returned %d", resp.StatusCode)
	}
	return nil
}

// setTenant injects the tenancy headers.
//
// These headers are the ONLY thing separating tenants in the store, and
// VictoriaLogs does not authenticate them. That is precisely why they are set
// here from a server-resolved Tenant and why nothing client-supplied reaches
// this function (R8).
func setTenant(req *http.Request, t Tenant) {
	req.Header.Set("AccountID", strconv.FormatUint(uint64(t.AccountID), 10))
	req.Header.Set("ProjectID", strconv.FormatUint(uint64(t.ProjectID), 10))
}
