package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

var abase = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

type fakeReader struct {
	entries []Entry
	err     error
}

func (f *fakeReader) Since(context.Context, string, time.Time, time.Time) ([]Entry, error) {
	return f.entries, f.err
}

type fakeWriter struct {
	key         string
	body        []byte
	retainUntil time.Time
	err         error
}

func (f *fakeWriter) PutLocked(_ context.Context, key string, body []byte, until time.Time) error {
	if f.err != nil {
		return f.err
	}
	f.key, f.body, f.retainUntil = key, body, until
	return nil
}

func exporter(r *fakeReader, w *fakeWriter) *Exporter {
	return &Exporter{Reader: r, Writer: w, Retention: time.Hour, Now: func() time.Time { return abase }}
}

func TestExportWritesLockedObjectWithDigest(t *testing.T) {
	r := &fakeReader{entries: []Entry{
		{TenantID: "acme", PrincipalID: "p1", Action: "flow.view", Outcome: "allowed", OccurredAt: abase},
		{TenantID: "acme", PrincipalID: "p2", Action: "export", Outcome: "denied", OccurredAt: abase},
	}}
	w := &fakeWriter{}

	m, err := exporter(r, w).Export(context.Background(), "acme", abase.Add(-time.Hour), abase)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if m.EntryCount != 2 {
		t.Errorf("entry count: got %d", m.EntryCount)
	}
	// The digest is what makes the export evidence rather than a copy.
	if len(m.SHA256) != 64 {
		t.Errorf("a content digest is required, got %q", m.SHA256)
	}
	if w.retainUntil.IsZero() || !w.retainUntil.After(abase) {
		t.Error("the object must be written under retention, or it is not immutable")
	}
	if w.key == "" {
		t.Error("no key written")
	}
}

// TestEmptyWindowWritesNothing: an empty object would create a gap that looks
// identical to a missing export.
func TestEmptyWindowWritesNothing(t *testing.T) {
	w := &fakeWriter{}
	m, err := exporter(&fakeReader{}, w).Export(context.Background(), "acme", abase.Add(-time.Hour), abase)
	if err != nil {
		t.Fatalf("an empty window is not an error: %v", err)
	}
	if m != nil {
		t.Error("nothing to export means no manifest")
	}
	if w.key != "" {
		t.Error("no object should have been written")
	}
}

func TestDigestChangesWithContent(t *testing.T) {
	a, _ := exporter(&fakeReader{entries: []Entry{{Action: "a"}}}, &fakeWriter{}).
		Export(context.Background(), "acme", abase.Add(-time.Hour), abase)
	b, _ := exporter(&fakeReader{entries: []Entry{{Action: "b"}}}, &fakeWriter{}).
		Export(context.Background(), "acme", abase.Add(-time.Hour), abase)
	if a.SHA256 == b.SHA256 {
		t.Fatal("different content must produce a different digest, or the digest proves nothing")
	}
}

func TestWriteFailureSurfaces(t *testing.T) {
	w := &fakeWriter{err: errors.New("object store down")}
	_, err := exporter(&fakeReader{entries: []Entry{{Action: "a"}}}, w).
		Export(context.Background(), "acme", abase.Add(-time.Hour), abase)
	if err == nil {
		t.Fatal("a failed export must surface; silently skipping it loses the evidence")
	}
}

func TestReadFailureSurfaces(t *testing.T) {
	_, err := exporter(&fakeReader{err: errors.New("db down")}, &fakeWriter{}).
		Export(context.Background(), "acme", abase.Add(-time.Hour), abase)
	if err == nil {
		t.Fatal("an unreadable trail must not be reported as an empty one")
	}
}

func TestInvalidWindowRejected(t *testing.T) {
	_, err := exporter(&fakeReader{}, &fakeWriter{}).
		Export(context.Background(), "acme", abase, abase.Add(-time.Hour))
	if err == nil {
		t.Error("a backwards window must be rejected")
	}
}

func TestDefaultRetentionIsLong(t *testing.T) {
	e := &Exporter{Reader: &fakeReader{}, Writer: &fakeWriter{}}
	// Shortening a retention later is easy; lengthening it retroactively is not.
	if e.retention() < 5*365*24*time.Hour {
		t.Errorf("the default audit retention should be years, got %v", e.retention())
	}
}
