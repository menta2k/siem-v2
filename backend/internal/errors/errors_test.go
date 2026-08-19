package errors

import (
	"errors"
	"strings"
	"testing"
)

// TestForbiddenAndNotFoundAreIndistinguishable closes an enumeration channel: if
// the two differed, a caller could probe for another tenant's resources by
// watching which error came back.
func TestForbiddenAndNotFoundAreIndistinguishable(t *testing.T) {
	f := Forbidden("principal acme-1 attempted access to tenant globex flow:123")
	n := NotFound("flow:123 does not exist")

	if f.PublicMessage() != n.PublicMessage() {
		t.Fatalf("public messages must match: %q vs %q", f.PublicMessage(), n.PublicMessage())
	}
	if HTTPStatus(f.Kind) != HTTPStatus(n.Kind) {
		t.Fatalf("status codes must match: %d vs %d", HTTPStatus(f.Kind), HTTPStatus(n.Kind))
	}
}

// TestDetailNeverReachesTheCaller is the whole point of splitting the fields.
func TestDetailNeverReachesTheCaller(t *testing.T) {
	secret := "tenant=globex table=flows_hot query=_stream:{tenant=\"globex\"}"
	e := Forbidden(secret)

	if strings.Contains(e.PublicMessage(), "globex") || strings.Contains(e.PublicMessage(), "_stream") {
		t.Fatalf("internal detail leaked to the caller: %q", e.PublicMessage())
	}
	if !strings.Contains(e.Error(), secret) {
		t.Error("the operator-facing error should retain full context for the server log")
	}
}

func TestForeignErrorsDiscloseNothing(t *testing.T) {
	err := errors.New("pq: relation \"audit_record\" does not exist")
	if got := PublicOf(err); strings.Contains(got, "audit_record") {
		t.Fatalf("a non-typed error must not be echoed to the caller: %q", got)
	}
	if KindOf(err) != KindInternal {
		t.Error("an unclassified error must default to internal, never to something benign")
	}
}

func TestMissingPublicMessageFallsBackSafely(t *testing.T) {
	e := &Error{Kind: KindInternal, Detail: "connection refused to 10.0.0.5:5432"}
	if strings.Contains(e.PublicMessage(), "10.0.0.5") {
		t.Fatal("a forgotten Public field must fall back to a generic message, not to Detail")
	}
}

func TestWrapPreservesChain(t *testing.T) {
	root := errors.New("dial tcp: connection refused")
	e := Wrap(KindUnavailable, "The service is temporarily unavailable.", root)
	if !errors.Is(e, root) {
		t.Error("wrapped errors must remain unwrappable for retry classification")
	}
}

func TestHTTPStatusMapping(t *testing.T) {
	cases := map[Kind]int{
		KindInvalidInput: 400,
		KindUnauthorized: 401,
		KindForbidden:    404, // deliberately the same as not-found
		KindNotFound:     404,
		KindConflict:     409,
		KindUnavailable:  503,
		KindInternal:     500,
	}
	for kind, want := range cases {
		if got := HTTPStatus(kind); got != want {
			t.Errorf("%s: want %d, got %d", kind, want, got)
		}
	}
	// An unrecognised kind must not fall through to something permissive.
	if got := HTTPStatus(Kind("made_up")); got != 500 {
		t.Errorf("an unknown kind must default to 500, got %d", got)
	}
}

func TestConstructors(t *testing.T) {
	if e := InvalidInput("bad", "detail"); e.Kind != KindInvalidInput || e.PublicMessage() != "bad" {
		t.Errorf("InvalidInput: %+v", e)
	}
	if e := Unauthorized("detail"); e.Kind != KindUnauthorized {
		t.Errorf("Unauthorized: %+v", e)
	}
	if e := Unavailable("try later", "detail"); e.Kind != KindUnavailable {
		t.Errorf("Unavailable: %+v", e)
	}
	if e := Internal("stack trace here"); strings.Contains(e.PublicMessage(), "stack") {
		t.Error("internal detail must not reach the caller")
	}
	if e := Errorf(KindInvalidInput, "bad input", "field %s is %d", "limit", 99); !strings.Contains(e.Error(), "limit is 99") {
		t.Errorf("Errorf should format the detail: %v", e)
	}
}

func TestKindOfAndPublicOfOnTypedErrors(t *testing.T) {
	e := Unavailable("The service is temporarily unavailable.", "nats down")
	if KindOf(e) != KindUnavailable {
		t.Errorf("KindOf: got %s", KindOf(e))
	}
	if PublicOf(e) != "The service is temporarily unavailable." {
		t.Errorf("PublicOf: got %q", PublicOf(e))
	}
}

func TestErrorStringPrefersDetail(t *testing.T) {
	withDetail := &Error{Kind: KindInternal, Public: "oops", Detail: "connection refused"}
	if !strings.Contains(withDetail.Error(), "connection refused") {
		t.Error("the operator-facing string should carry the detail")
	}
	withoutDetail := &Error{Kind: KindInternal, Public: "oops"}
	if !strings.Contains(withoutDetail.Error(), "oops") {
		t.Error("with no detail, the public message is the best available")
	}
}
