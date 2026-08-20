package filter

import "testing"

func compile(t *testing.T, rules []Rule) *Set {
	t.Helper()
	s, err := Compile(rules)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return s
}

func TestMatchingSemantics(t *testing.T) {
	s := compile(t, []Rule{
		{Field: "request_host", Op: "suffix", Values: []string{".internal.jobs.bg"}},
		{Field: "request_host", Op: "equals", Values: []string{"health.jobs.bg"}},
		{Field: "request_path", Op: "prefix", Values: []string{"/nginx_status"}},
		{Field: "request_path", Op: "contains", Values: []string{"/.well-known/"}},
		{Field: "request_path", Op: "suffix", Values: []string{".map"}},
	})

	drops := []struct{ host, path string }{
		{"api.internal.jobs.bg", "/x"},
		{"HEALTH.JOBS.BG", "/"},
		{"www.jobs.bg", "/nginx_status"},
		{"www.jobs.bg", "/a/.well-known/b"},
		{"www.jobs.bg", "/app.js.map"},
	}
	for _, d := range drops {
		if !s.Drops(d.host, d.path) {
			t.Errorf("must drop host=%q path=%q", d.host, d.path)
		}
	}
	keeps := []struct{ host, path string }{
		{"www.jobs.bg", "/front_job_search.php"},
		{"internal.jobs.bg.evil.com", "/"},
		{"", ""},
	}
	for _, k := range keeps {
		if s.Drops(k.host, k.path) {
			t.Errorf("must keep host=%q path=%q", k.host, k.path)
		}
	}
}

func TestCompileRejectsFootguns(t *testing.T) {
	bad := [][]Rule{
		{{Field: "user_agent", Op: "equals", Values: []string{"x"}}},
		{{Field: "request_host", Op: "regex", Values: []string{"x"}}},
		{{Field: "request_path", Op: "prefix", Values: []string{""}}},
	}
	for i, rules := range bad {
		if _, err := Compile(rules); err == nil {
			t.Errorf("case %d must be rejected", i)
		}
	}
	many := make([]Rule, MaxRules+1)
	for i := range many {
		many[i] = Rule{Field: "request_host", Op: "equals", Values: []string{"a"}}
	}
	if _, err := Compile(many); err == nil {
		t.Error("more than MaxRules must be rejected")
	}
}

func TestEmptySetKeepsEverything(t *testing.T) {
	s := compile(t, nil)
	if s.Drops("any.host", "/any") {
		t.Fatal("an empty set must never drop — fail-open is the contract")
	}
}
