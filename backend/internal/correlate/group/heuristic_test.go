package group

import (
	"testing"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/correlate/keys"
)

var hbase = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func hrec(id, provider string, at time.Time) HeuristicRecord {
	return HeuristicRecord{
		EventID: id, Provider: provider, ClientIP: "203.0.113.9",
		Host: "shop.example.com", Path: "/cart", Method: "POST", EventTime: at,
	}
}

func TestHeuristicJoinsWithinWindow(t *testing.T) {
	records := []HeuristicRecord{
		hrec("cf-1", "cloudflare", hbase),
		hrec("f5-1", "f5asm", hbase.Add(80*time.Millisecond)),
		hrec("ngx-1", "nginx", hbase.Add(150*time.Millisecond)),
	}
	components, ambiguous := Heuristic(records, HeuristicOptions{Window: time.Second})

	if len(ambiguous) != 0 {
		t.Fatalf("distinct providers within the window are not ambiguous: %v", ambiguous)
	}
	if len(components) != 1 || len(components[0].EventIDs) != 3 {
		t.Fatalf("expected one component of three, got %+v", components)
	}
	if components[0].Key.Tier != keys.TierHeuristic {
		t.Errorf("tier must be heuristic, got %q", components[0].Key.Tier)
	}
}

// TestTwoRecordsFromSameProviderIsAmbiguous is the conservative rule that keeps
// this tier honest: one request cannot produce two records at one layer, so a
// cluster containing two is unresolvable and must not be guessed at.
func TestTwoRecordsFromSameProviderIsAmbiguous(t *testing.T) {
	records := []HeuristicRecord{
		hrec("cf-1", "cloudflare", hbase),
		hrec("cf-2", "cloudflare", hbase.Add(50*time.Millisecond)), // same client, same path, same instant-ish
		hrec("ngx-1", "nginx", hbase.Add(100*time.Millisecond)),
	}
	components, ambiguous := Heuristic(records, HeuristicOptions{Window: time.Second})

	if len(components) != 0 {
		t.Fatalf("an ambiguous cluster must not be joined, got %+v", components)
	}
	if len(ambiguous) != 3 {
		t.Fatalf("all members of the ambiguous cluster should be reported, got %v", ambiguous)
	}
}

func TestRecordsOutsideWindowStaySeparate(t *testing.T) {
	records := []HeuristicRecord{
		hrec("cf-1", "cloudflare", hbase),
		hrec("ngx-1", "nginx", hbase.Add(30*time.Second)),
	}
	components, _ := Heuristic(records, HeuristicOptions{Window: time.Second})
	if len(components) != 0 {
		t.Fatalf("30 seconds apart is a different request, got %+v", components)
	}
}

func TestDifferentAttributesDoNotJoin(t *testing.T) {
	a := hrec("cf-1", "cloudflare", hbase)
	b := hrec("ngx-1", "nginx", hbase.Add(10*time.Millisecond))
	b.Path = "/checkout"

	components, _ := Heuristic([]HeuristicRecord{a, b}, HeuristicOptions{Window: time.Second})
	if len(components) != 0 {
		t.Fatalf("different paths are different requests, got %+v", components)
	}
}

// TestIncompleteAttributesAreNotJoined: a partial key would match far too much.
func TestIncompleteAttributesAreNotJoined(t *testing.T) {
	a := hrec("cf-1", "cloudflare", hbase)
	b := hrec("ngx-1", "nginx", hbase.Add(10*time.Millisecond))
	b.ClientIP = "" // F5 sometimes logs no usable client address

	components, _ := Heuristic([]HeuristicRecord{a, b}, HeuristicOptions{Window: time.Second})
	if len(components) != 0 {
		t.Fatalf("a record missing part of the key must not be joined, got %+v", components)
	}
}

func TestHeuristicIsOrderIndependent(t *testing.T) {
	records := []HeuristicRecord{
		hrec("cf-1", "cloudflare", hbase),
		hrec("f5-1", "f5asm", hbase.Add(80*time.Millisecond)),
		hrec("ngx-1", "nginx", hbase.Add(150*time.Millisecond)),
	}
	reversed := []HeuristicRecord{records[2], records[1], records[0]}

	a, _ := Heuristic(records, HeuristicOptions{Window: time.Second})
	b, _ := Heuristic(reversed, HeuristicOptions{Window: time.Second})

	if len(a) != len(b) || a[0].Key.Value != b[0].Key.Value {
		t.Fatalf("heuristic grouping must be deterministic: %+v vs %+v", a, b)
	}
}

func TestSingleRecordIsNotAComponent(t *testing.T) {
	components, _ := Heuristic([]HeuristicRecord{hrec("cf-1", "cloudflare", hbase)},
		HeuristicOptions{Window: time.Second})
	if len(components) != 0 {
		t.Fatal("one record joined nothing and is not a correlated flow")
	}
}
