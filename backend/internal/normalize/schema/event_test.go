package schema

import "testing"

func TestLayerOrderFollowsTheRequestPath(t *testing.T) {
	// Ordering is the source of truth for flow reconstruction, so the sequence
	// itself is worth asserting rather than assuming.
	path := []Layer{LayerEdge, LayerBotManagement, LayerAppFirewall, LayerOrigin}
	prev := -1
	for _, l := range path {
		got, ok := l.Order()
		if !ok {
			t.Fatalf("layer %q must have a defined position", l)
		}
		if got <= prev {
			t.Fatalf("layer %q (order %d) must come after order %d", l, got, prev)
		}
		prev = got
	}
	if _, ok := Layer("some_future_provider").Order(); ok {
		t.Error("an unknown layer must report no defined position rather than a default one")
	}
}

func TestTerminalActions(t *testing.T) {
	terminal := []Action{ActionBlocked, ActionChallengeFailed, ActionRateLimited}
	for _, a := range terminal {
		if !a.Terminal() {
			t.Errorf("%q ends the request and must be terminal", a)
		}
	}
	nonTerminal := []Action{ActionAllowed, ActionLogged, ActionChallenged, ActionChallengePassed, ActionUnknown}
	for _, a := range nonTerminal {
		if a.Terminal() {
			t.Errorf("%q does not end the request", a)
		}
	}
}

// TestChallengedIsNotTerminal is worth its own test: a challenge is an
// invitation, not an ending. Treating it as terminal would attribute the outcome
// to the challenging layer even when the client passed and was served normally.
func TestChallengedIsNotTerminal(t *testing.T) {
	if ActionChallenged.Terminal() {
		t.Fatal("a challenge does not end the request; the client may still pass it")
	}
	if !ActionChallengeFailed.Terminal() {
		t.Fatal("a failed challenge does end the request")
	}
}

func TestFlagsAreASetNotALog(t *testing.T) {
	e := &Event{}
	e.AddFlag(FlagClockSkew)
	e.AddFlag(FlagClockSkew)
	e.AddFlag(FlagBodyTruncated)

	if len(e.DataQualityFlags) != 2 {
		t.Fatalf("repeating a condition must not inflate the list: %v", e.DataQualityFlags)
	}
	if !e.HasFlag(FlagClockSkew) || !e.HasFlag(FlagBodyTruncated) {
		t.Error("both flags should be present")
	}
	if e.HasFlag(FlagFieldsMasked) {
		t.Error("unset flag reported as present")
	}
}
