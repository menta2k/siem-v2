// Package cfrules evaluates Cloudflare rule expressions via the sidecar.
//
// The sidecar is treated as OPTIONAL throughout. It is a separate process
// precisely so its failure cannot take anything else down (research.md R1), and
// a client that turned an unreachable sidecar into a hard error would give back
// the coupling the separation was meant to remove.
package cfrules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client talks to the wirefilter sidecar.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	Timeout time.Duration
}

func New(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: timeout},
		Timeout: timeout,
	}
}

// Configured reports whether an endpoint was supplied at all. A deployment may
// legitimately run without CF expression testing.
func (c *Client) Configured() bool { return c != nil && c.BaseURL != "" }

// CapturedRequest is one request's fields, keyed by Cloudflare field name.
type CapturedRequest struct {
	Ref    string         `json:"ref"`
	Fields map[string]any `json:"fields"`
}

type evaluateRequest struct {
	Expression string            `json:"expression"`
	Requests   []CapturedRequest `json:"requests"`
}

// Result is one request's outcome.
type Result struct {
	Ref     string `json:"ref"`
	Matched bool   `json:"matched"`
	// Caveats state why a result may differ from production — an absent field
	// evaluated as empty, for instance. A "no match" without its caveats would
	// let an operator read uncertainty as safety.
	Caveats []string `json:"caveats,omitempty"`
}

// Response is the sidecar's answer.
type Response struct {
	ExpressionValid bool     `json:"expression_valid"`
	ParseError      string   `json:"parse_error,omitempty"`
	SchemeVersion   string   `json:"scheme_version"`
	EngineVersion   string   `json:"engine_version"`
	FidelityNote    string   `json:"fidelity_note"`
	Results         []Result `json:"results"`
	// Unavailable is set by the client, not the sidecar: it distinguishes "the
	// expression did not match" from "we could not ask".
	Unavailable bool   `json:"unavailable,omitempty"`
	Unreachable string `json:"unreachable_reason,omitempty"`
}

// ErrNotConfigured is returned when no sidecar endpoint is set.
var ErrNotConfigured = fmt.Errorf("cloudflare expression evaluation is not configured")

// Evaluate asks the sidecar to evaluate an expression against captured requests.
//
// An unreachable sidecar returns a Response marked Unavailable rather than an
// error, so a caller rendering results can say "unavailable" without having to
// distinguish transport failures from evaluation outcomes itself.
func (c *Client) Evaluate(ctx context.Context, expression string, requests []CapturedRequest) (*Response, error) {
	if !c.Configured() {
		return nil, ErrNotConfigured
	}

	body, err := json.Marshal(evaluateRequest{Expression: expression, Requests: requests})
	if err != nil {
		return nil, fmt.Errorf("encode evaluation request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return &Response{Unavailable: true, Unreachable: err.Error()}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return &Response{
			Unavailable: true,
			Unreachable: fmt.Sprintf("sidecar returned %d", resp.StatusCode),
		}, nil
	}

	var out Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode evaluation response: %w", err)
	}
	return &out, nil
}

// Health reports the sidecar's state.
func (c *Client) Health(ctx context.Context) error {
	if !c.Configured() {
		return ErrNotConfigured
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("sidecar unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sidecar health returned %d", resp.StatusCode)
	}
	return nil
}

// FieldsFromFlow builds the sidecar's field map from a captured request.
//
// Only fields the capture actually has are included. Sending an empty value for
// a missing field would make it indistinguishable from a genuinely empty one,
// and the sidecar's caveat about absent fields is what tells an operator the
// result is uncertain.
func FieldsFromFlow(method, host, path, query, userAgent, clientIP string) map[string]any {
	fields := map[string]any{}
	put := func(k, v string) {
		if v != "" {
			fields[k] = v
		}
	}
	put("http.request.method", method)
	put("http.host", host)
	put("http.request.uri.path", path)
	put("http.request.uri.query", query)
	put("http.user_agent", userAgent)
	put("ip.src", clientIP)
	if path != "" {
		uri := path
		if query != "" {
			uri += "?" + query
		}
		fields["http.request.uri"] = uri
	}
	return fields
}
