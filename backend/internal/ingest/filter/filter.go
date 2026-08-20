// Package filter drops records at ingest by tenant-defined rules (ported
// from v1). Matched records are never stored ANYWHERE — no raw payload, no
// event, no flow — which is why every failure in this package fails OPEN:
// over-ingesting is recoverable, a dropped record is not.
package filter

import (
	"fmt"
	"strings"
)

// MaxRules bounds a tenant's rule set; past this the set is a program, not
// configuration.
const MaxRules = 64

// Rule drops events where <Field> <Op> any of <Values>. Fields and operators
// are CLOSED sets — no regex, no globs, no negation: every operator here has
// exactly one obvious meaning an operator can predict at 2am.
type Rule struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"`
	Values []string `json:"values"`
}

const (
	FieldHost = "request_host"
	FieldPath = "request_path"
)

var validOps = map[string]bool{"equals": true, "suffix": true, "prefix": true, "contains": true}

// Set is a compiled, immutable rule set.
type Set struct {
	rules []compiled
}

type compiled struct {
	field  string
	op     string
	values []string // lowercased once here, not per match
}

// Compile validates and lowers a rule set. Rejections are deliberate
// footgun-guards: an unknown field or op means a typo that would silently
// never match, and all-blank values under prefix/suffix would drop every
// event the tenant has.
func Compile(rules []Rule) (*Set, error) {
	if len(rules) > MaxRules {
		return nil, fmt.Errorf("filter: %d rules exceeds the maximum of %d", len(rules), MaxRules)
	}
	s := &Set{}
	for i, r := range rules {
		if r.Field != FieldHost && r.Field != FieldPath {
			return nil, fmt.Errorf("filter: rule %d has unknown field %q", i, r.Field)
		}
		if !validOps[r.Op] {
			return nil, fmt.Errorf("filter: rule %d has unknown op %q", i, r.Op)
		}
		values := make([]string, 0, len(r.Values))
		for _, v := range r.Values {
			if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
				values = append(values, v)
			}
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("filter: rule %d has no usable values (blank values under prefix/suffix would drop everything)", i)
		}
		s.rules = append(s.rules, compiled{field: r.Field, op: r.Op, values: values})
	}
	return s, nil
}

// Drops reports whether an event with this host and path must not be ingested.
// Any value of any rule matching drops (OR of OR). Case-insensitive. An empty
// subject never matches: "no host" is missing data, not a matching empty string.
func (s *Set) Drops(host, path string) bool {
	if s == nil || len(s.rules) == 0 {
		return false
	}
	host = strings.ToLower(host)
	path = strings.ToLower(path)
	for _, r := range s.rules {
		subject := host
		if r.field == FieldPath {
			subject = path
		}
		if subject == "" {
			continue
		}
		for _, v := range r.values {
			var hit bool
			switch r.op {
			case "equals":
				hit = subject == v
			case "suffix":
				hit = strings.HasSuffix(subject, v)
			case "prefix":
				hit = strings.HasPrefix(subject, v)
			case "contains":
				hit = strings.Contains(subject, v)
			}
			if hit {
				return true
			}
		}
	}
	return false
}

// Empty reports whether the set drops nothing.
func (s *Set) Empty() bool { return s == nil || len(s.rules) == 0 }
