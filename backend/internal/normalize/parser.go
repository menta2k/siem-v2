// Package normalize maps provider records into the common event schema.
package normalize

import (
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// Parser turns one provider's raw record into a normalized event.
//
// Parsers are versioned and fixture-tested (Constitution Principle II). A parser
// never returns a partially-populated event alongside an error: either it
// produces a usable event, or it fails and the record goes to the dead-letter
// store with its original bytes intact (FR-012).
type Parser interface {
	// Provider identifies which source this parser handles.
	Provider() schema.Provider
	// Version identifies the parser itself, stamped onto every event it produces
	// so a record can be re-parsed when a parser bug is fixed.
	Version() string
	// Parse converts one raw record. receivedAt is the time we took delivery,
	// which is recorded separately from the provider's own event time (FR-011).
	Parse(raw []byte, receivedAt time.Time) (*schema.Event, error)
}

// ParseError describes why a record could not be normalized. It carries enough
// context for the dead-letter record to be actionable without the original
// operator having to reproduce the failure.
type ParseError struct {
	Provider schema.Provider
	Version  string
	Reason   string
	Err      error
}

func (e *ParseError) Error() string {
	if e.Err != nil {
		return string(e.Provider) + " parser " + e.Version + ": " + e.Reason + ": " + e.Err.Error()
	}
	return string(e.Provider) + " parser " + e.Version + ": " + e.Reason
}

func (e *ParseError) Unwrap() error { return e.Err }
