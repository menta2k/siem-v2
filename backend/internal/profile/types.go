// Package profile learns per-URL behavioural baselines from completed flows.
//
// A profile answers "what does POST /api/orders/{int} normally look like":
// which parameters it accepts, what type each carries, and the structural
// ceilings of the requests that reach it. It is a baseline, not a detection —
// the consumer decides what deviation means.
package profile

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"
	"time"
)

// ValueType is a point in the inference lattice. The recorded type of a
// parameter is the least upper bound of every value observed, so "this is an
// int" degrades honestly to "this is freetext" the first time something else
// shows up — and that transition, not the steady state, is the signal a later
// drift detection will care about.
type ValueType string

const (
	TypeEmpty    ValueType = "empty" // bottom: no value observed yet
	TypeBool     ValueType = "bool"
	TypeInt      ValueType = "int"
	TypeFloat    ValueType = "float"
	TypeUUID     ValueType = "uuid"
	TypeIPv4     ValueType = "ipv4"
	TypeIPv6     ValueType = "ipv6"
	TypeEmail    ValueType = "email"
	TypeDate     ValueType = "date"
	TypeHex      ValueType = "hex"
	TypeJSON     ValueType = "json"
	TypeAlnum    ValueType = "alnum"
	TypeVar      ValueType = "var"      // path-only: collapsed by cardinality, any value
	TypeFreetext ValueType = "freetext" // top
)

var (
	uuidRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	intRe   = regexp.MustCompile(`^-?[0-9]+$`)
	floatRe = regexp.MustCompile(`^-?[0-9]+\.[0-9]+$`)
	hexRe   = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	alnumRe = regexp.MustCompile(`^[0-9a-zA-Z]+$`)
)

// Infer classifies a single observed value. Detection order matters: an
// all-digit string is an int even though it is also valid hex, so the more
// specific claim wins.
func Infer(v string) ValueType {
	switch {
	case v == "":
		return TypeEmpty
	case strings.EqualFold(v, "true") || strings.EqualFold(v, "false"):
		return TypeBool
	case intRe.MatchString(v):
		return TypeInt
	case floatRe.MatchString(v):
		return TypeFloat
	case uuidRe.MatchString(v):
		return TypeUUID
	case isIPv4(v):
		return TypeIPv4
	case isIPv6(v):
		return TypeIPv6
	case emailRe.MatchString(v):
		return TypeEmail
	case isDate(v):
		return TypeDate
	case hexRe.MatchString(v):
		return TypeHex
	case isJSON(v):
		return TypeJSON
	case alnumRe.MatchString(v):
		return TypeAlnum
	default:
		return TypeFreetext
	}
}

func isIPv4(v string) bool {
	if !strings.Contains(v, ".") {
		return false
	}
	ip := net.ParseIP(v)
	return ip != nil && ip.To4() != nil
}

func isIPv6(v string) bool {
	if !strings.Contains(v, ":") {
		return false
	}
	return net.ParseIP(v) != nil
}

func isDate(v string) bool {
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if _, err := time.Parse(layout, v); err == nil {
			return true
		}
	}
	return false
}

func isJSON(v string) bool {
	if len(v) < 2 {
		return false
	}
	if c := v[0]; c != '{' && c != '[' {
		return false
	}
	return json.Valid([]byte(v))
}

// alnumCharset reports whether every value of the type draws from [0-9a-zA-Z]
// only — the classes that can honestly merge into TypeAlnum rather than
// falling all the way to freetext.
func alnumCharset(t ValueType) bool {
	switch t {
	case TypeBool, TypeInt, TypeHex, TypeAlnum:
		return true
	default:
		return false
	}
}

// Join returns the least upper bound of two types.
//
// The special cases keep useful structure as long as it is true: ints widen to
// floats, ints widen to hex (every digit string is valid hex), and anything
// alphanumeric-only merges into alnum. Everything else falls to freetext —
// claiming less is always safe, claiming more never is.
func Join(a, b ValueType) ValueType {
	if a == b {
		return a
	}
	if a == TypeEmpty {
		return b
	}
	if b == TypeEmpty {
		return a
	}
	if a == TypeFreetext || b == TypeFreetext {
		return TypeFreetext
	}
	if (a == TypeInt && b == TypeFloat) || (a == TypeFloat && b == TypeInt) {
		return TypeFloat
	}
	if (a == TypeInt && b == TypeHex) || (a == TypeHex && b == TypeInt) {
		return TypeHex
	}
	if alnumCharset(a) && alnumCharset(b) {
		return TypeAlnum
	}
	return TypeFreetext
}

// promotable lists the types a path segment may be templated to. Deliberately
// narrow: promoting a position to {alnum} would swallow literal routes like
// /job/search, which must stay distinct from /job/{int}.
func promotable(t ValueType) bool {
	switch t {
	case TypeInt, TypeUUID, TypeHex, TypeDate:
		return true
	default:
		return false
	}
}

// Token renders a type as a path-template segment.
func Token(t ValueType) string { return "{" + string(t) + "}" }

// ParseToken reports whether a template segment is a parameter token and, if
// so, which type it carries.
func ParseToken(seg string) (ValueType, bool) {
	if len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}' {
		return ValueType(seg[1 : len(seg)-1]), true
	}
	return "", false
}

// Matches reports whether a concrete segment value belongs under a parameter
// of type t: the value's own type must join into t without widening it. A var
// parameter (cardinality collapse) accepts anything.
func Matches(value string, t ValueType) bool {
	if t == TypeVar {
		return true
	}
	return Join(Infer(value), t) == t
}
