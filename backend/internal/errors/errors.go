// Package errors defines the error vocabulary shared across services.
//
// The central rule: an error carries two audiences. The operator needs full
// context in the server log; the caller must learn nothing about internal
// structure, other tenants, or why exactly a lookup failed (FR-058).
package errors

import (
	"errors"
	"fmt"
)

type Kind string

const (
	KindInvalidInput Kind = "invalid_input"
	KindUnauthorized Kind = "unauthorized"
	KindForbidden    Kind = "forbidden"
	KindNotFound     Kind = "not_found"
	KindConflict     Kind = "conflict"
	KindUnavailable  Kind = "unavailable"
	KindInternal     Kind = "internal"
)

// Error carries an operator-facing detail and a caller-facing message. The two
// are separate fields rather than one string so that disclosing the wrong one is
// a visible mistake at the call site rather than an accident.
type Error struct {
	Kind Kind
	// Public is returned to the caller. It must never name internal components,
	// query shapes, or other tenants' data.
	Public string
	// Detail is logged server-side and never sent to the caller.
	Detail string
	Err    error
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return string(e.Kind) + ": " + e.Detail
	}
	return string(e.Kind) + ": " + e.Public
}

func (e *Error) Unwrap() error { return e.Err }

// PublicMessage returns what is safe to send to a caller.
func (e *Error) PublicMessage() string {
	if e.Public != "" {
		return e.Public
	}
	// Defaulting to a generic message rather than to Detail means a forgotten
	// Public field leaks nothing.
	return "The request could not be completed."
}

func New(kind Kind, public, detail string) *Error {
	return &Error{Kind: kind, Public: public, Detail: detail}
}

func Wrap(kind Kind, public string, err error) *Error {
	return &Error{Kind: kind, Public: public, Detail: err.Error(), Err: err}
}

func InvalidInput(public, detail string) *Error { return New(KindInvalidInput, public, detail) }
func Unauthorized(detail string) *Error {
	return New(KindUnauthorized, "Authentication required.", detail)
}

// Forbidden and NotFound return the SAME public message on purpose. If "you may
// not see this" and "this does not exist" were distinguishable, a caller could
// enumerate another tenant's resources by observing which error they got
// (FR-053, FR-074b).
func Forbidden(detail string) *Error {
	return New(KindForbidden, "Not found.", detail)
}
func NotFound(detail string) *Error {
	return New(KindNotFound, "Not found.", detail)
}
func Unavailable(public, detail string) *Error { return New(KindUnavailable, public, detail) }
func Internal(detail string) *Error {
	return New(KindInternal, "An internal error occurred.", detail)
}

// KindOf extracts the kind from an error chain, defaulting to internal so an
// unclassified error is never treated as benign.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindInternal
}

// PublicOf returns the caller-safe message for any error. An error that is not
// one of ours discloses nothing at all.
func PublicOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.PublicMessage()
	}
	return "An internal error occurred."
}

// HTTPStatus maps a kind to a response code.
func HTTPStatus(kind Kind) int {
	switch kind {
	case KindInvalidInput:
		return 400
	case KindUnauthorized:
		return 401
	case KindForbidden, KindNotFound:
		return 404 // deliberately indistinguishable
	case KindConflict:
		return 409
	case KindUnavailable:
		return 503
	default:
		return 500
	}
}

func Errorf(kind Kind, public, format string, args ...any) *Error {
	return New(kind, public, fmt.Sprintf(format, args...))
}
