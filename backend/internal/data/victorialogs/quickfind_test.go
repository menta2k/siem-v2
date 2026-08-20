package victorialogs

import (
	"strings"
	"testing"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

func TestRayIDsCollectsEverySubrequestRay(t *testing.T) {
	f := &flow.Flow{
		CorrelationKey: "ray:a2e04931dd48d0d2",
		Events: []schema.Event{
			{RayID: "a2e04931dd48d0d2", Identifiers: []string{"ray:a2e04931dd48d0d2"}},
			{RayID: "a2e049317c8ad0d2", Identifiers: []string{"ray:a2e049317c8ad0d2", "dd:x"}},
		},
	}
	got := strings.Join(rayIDs(f), " ")
	for _, want := range []string{"a2e04931dd48d0d2", "a2e049317c8ad0d2"} {
		if !strings.Contains(got, want) {
			t.Errorf("rayIDs %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "dd:x") {
		t.Errorf("rayIDs must not include non-ray identifiers: %q", got)
	}
}

func TestQuickFindMatchesEveryIDSpace(t *testing.T) {
	q, err := BuildFlowQuery("default", FlowSearch{Query: "2773644994071897863"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `(ray_ids:"2773644994071897863" OR vendor_request_ids:"2773644994071897863" OR flow_id:"2773644994071897863")`
	if !strings.Contains(q, want) {
		t.Errorf("query %q missing quick-find clause %q", q, want)
	}
}

func TestRaySearchMatchesRayIDs(t *testing.T) {
	q, err := BuildFlowQuery("default", FlowSearch{RayID: "a2e04931dd48d0d2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(q, `ray_ids:"a2e04931dd48d0d2"`) {
		t.Errorf("ray search should word-match ray_ids, got %q", q)
	}
}
