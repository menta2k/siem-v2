package victorialogs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
)

func TestIDLookupWindowsAreNewestFirstAndContiguous(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ws := idLookupWindows(now, time.Time{}, time.Time{})

	if got := ws[0][1]; !got.Equal(now) {
		t.Fatalf("first window must end now, ends %v", got)
	}
	if got := ws[0][0]; !got.Equal(now.Add(-time.Hour)) {
		t.Fatalf("first window must be the last hour, starts %v", got)
	}
	for i := 1; i < len(ws); i++ {
		if !ws[i][1].Equal(ws[i-1][0]) {
			t.Fatalf("window %d does not abut window %d: %v vs %v", i, i-1, ws[i][1], ws[i-1][0])
		}
	}
	if last := ws[len(ws)-1][0]; !last.Equal(epoch) {
		t.Fatalf("unbounded lookup must reach back to the epoch, stops at %v", last)
	}
}

func TestIDLookupWindowsRespectCallerRange(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	from := now.Add(-3 * time.Hour)
	ws := idLookupWindows(now, from, now)

	if len(ws) != 2 {
		t.Fatalf("a 3h range should split into last-hour + remainder, got %v", ws)
	}
	if !ws[1][0].Equal(from) {
		t.Fatalf("the oldest window must stop at the caller's from, got %v", ws[1][0])
	}
}

// timeRange pulls the bounds out of a generated query's _time filter.
var timeRange = regexp.MustCompile(`_time:\[(\S+), (\S+)\]`)

func TestRaySearchStopsAtFirstMatchingWindow(t *testing.T) {
	hit := time.Now().UTC().Add(-3 * time.Hour) // inside the 1h–24h window
	var queries []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.FormValue("query")
		queries = append(queries, q)
		m := timeRange.FindStringSubmatch(q)
		if m == nil {
			t.Errorf("id lookup sent a query with no time bound: %s", q)
			return
		}
		lo, _ := time.Parse(time.RFC3339, m[1])
		hi, _ := time.Parse(time.RFC3339, m[2])
		if hit.Before(lo) || hit.After(hi) {
			return
		}
		payload, _ := json.Marshal(&flow.Flow{FlowID: "f1", FirstSeen: hit})
		_ = json.NewEncoder(w).Encode(map[string]any{"_msg": string(payload)})
	}))
	defer srv.Close()

	repo := NewFlowRepo(New(srv.URL, nil), Tenant{})
	got, err := repo.Search(context.Background(), "default", FlowSearch{RayID: "a2e04931dd48d0d2"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(got) != 1 || got[0].FlowID != "f1" {
		t.Fatalf("want flow f1, got %+v", got)
	}
	// 1h window (miss), 24h window (hit), widened re-run. Never the 7d+ windows.
	if len(queries) != 3 {
		t.Fatalf("want 3 queries (miss, hit, widened), got %d: %v", len(queries), queries)
	}
}

func TestPagedIDSearchKeepsSingleQuery(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { n++ }))
	defer srv.Close()

	repo := NewFlowRepo(New(srv.URL, nil), Tenant{})
	if _, err := repo.Search(context.Background(), "default", FlowSearch{RayID: "x1", Offset: 50}); err != nil {
		t.Fatalf("search: %v", err)
	}
	if n != 1 {
		t.Fatalf("a later page must run one query so offsets stay consistent, ran %d", n)
	}
}

func TestIDLookupOutOfBudgetReportsHowFarItGot(t *testing.T) {
	defer func(b time.Duration) { idLookupBudget = b }(idLookupBudget)
	idLookupBudget = 50 * time.Millisecond

	n := 0
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		n++
		if n > 1 { // first window answers (empty), the next one hangs past the budget
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}
	}))
	defer srv.Close()
	defer close(release)

	repo := NewFlowRepo(New(srv.URL, nil), Tenant{})
	_, err := repo.Search(context.Background(), "default", FlowSearch{RayID: "a2e04931dd48d0d2"})
	var timeout *ErrLookupTimeout
	if !errors.As(err, &timeout) {
		t.Fatalf("want ErrLookupTimeout, got %v", err)
	}
	// Only the last hour was searched before the budget ran out.
	if age := time.Since(timeout.SearchedFrom); age < 59*time.Minute || age > 61*time.Minute {
		t.Fatalf("want SearchedFrom ~1h ago, got %v (%v ago)", timeout.SearchedFrom, age)
	}
}

func TestIDLookupKeepsHitWhenWideningRunsOutOfBudget(t *testing.T) {
	defer func(b time.Duration) { idLookupBudget = b }(idLookupBudget)
	idLookupBudget = 50 * time.Millisecond

	n := 0
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n > 1 { // the widened re-run hangs past the budget
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		payload, _ := json.Marshal(&flow.Flow{FlowID: "f1", FirstSeen: time.Now().UTC()})
		_ = json.NewEncoder(w).Encode(map[string]any{"_msg": string(payload)})
	}))
	defer srv.Close()
	defer close(release)

	repo := NewFlowRepo(New(srv.URL, nil), Tenant{})
	got, err := repo.Search(context.Background(), "default", FlowSearch{RayID: "a2e04931dd48d0d2"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(got) != 1 || got[0].FlowID != "f1" {
		t.Fatalf("want the hit f1 kept, got %+v", got)
	}
}
