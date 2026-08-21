package normalize

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// CookieShape reduces a Cookie request-header VALUE to its structure: how many
// cookies, named what. The values themselves never leave this function — that
// is the property that makes shape capture safe to run before the masker.
func CookieShape(header string) (count int, names []string) {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, _, _ := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		count++
		names = append(names, name)
	}
	return count, names
}

// ShapeFromCookieHeader builds the cookie part of a Shape, or returns the
// input unchanged when the header is absent.
func ShapeFromCookieHeader(s *schema.Shape, cookieHeader string) *schema.Shape {
	if strings.TrimSpace(cookieHeader) == "" {
		return s
	}
	count, names := CookieShape(cookieHeader)
	if count == 0 {
		return s
	}
	if s == nil {
		s = &schema.Shape{}
	}
	s.CookieCount = IntPtr(count)
	s.CookieNames = names
	return s
}

// IntPtr and Int64Ptr lift measured values into the Shape's nil-able fields.
func IntPtr(v int) *int       { return &v }
func Int64Ptr(v int64) *int64 { return &v }

// ShapeFromBody records the request body's PARAMETERS (names and
// secret-filtered values) as a form-encoded string on the shape. It handles
// application/x-www-form-urlencoded and application/json (top-level keys); other
// content types are ignored. Values that look like secrets are blanked, so the
// profiler learns a password field as a name without ever keeping the value.
// Runs before the masker, like the rest of shape capture.
func ShapeFromBody(s *schema.Shape, contentType, body string) *schema.Shape {
	ct := strings.ToLower(contentType)
	body = strings.TrimSpace(body)
	if body == "" {
		return s
	}
	out := url.Values{}
	switch {
	case strings.Contains(ct, "application/x-www-form-urlencoded"),
		ct == "" && !strings.HasPrefix(body, "{"):
		parsed, _ := url.ParseQuery(body)
		for name, vals := range parsed {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			for _, v := range vals {
				out.Add(name, safeBodyValue(name, v))
			}
		}
	case strings.Contains(ct, "application/json"), strings.HasPrefix(body, "{"):
		var obj map[string]any
		if json.Unmarshal([]byte(body), &obj) != nil {
			return s
		}
		for name, v := range obj {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			out.Set(name, safeBodyValue(name, scalar(v)))
		}
	default:
		return s
	}
	if len(out) == 0 {
		return s
	}
	if s == nil {
		s = &schema.Shape{}
	}
	s.BodyForm = out.Encode() // sorted, deterministic
	return s
}

// safeBodyValue blanks a body value that is a credential — by its FIELD NAME
// (password, token, cvv, ...) or by looking secret-shaped — keeping only the
// name's evidence. Request bodies carry the passwords query strings rarely do,
// and a plain password like "hunter2" is not secret-SHAPED, so the name check
// is what actually protects it. It never lets a credential reach the shape.
func safeBodyValue(name, v string) string {
	if isSensitiveName(name) || ContainsSecret(v) {
		return ""
	}
	return v
}

// sensitiveField matches a body/query field NAME that conventionally carries a
// credential or other value that must never be stored.
var sensitiveField = []string{
	"password", "passwd", "pwd", "pass", "secret", "token", "auth",
	"apikey", "api_key", "accesskey", "access_key", "sessid", "session",
	"csrf", "xsrf", "cvv", "cvc", "cardnum", "card_number", "cardnumber",
	"ccnum", "ssn", "pin", "otp", "mfa", "private", "credential", "signature",
}

func isSensitiveName(name string) bool {
	n := strings.ToLower(name)
	for _, k := range sensitiveField {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// scalar renders a JSON scalar for type inference; nested objects/arrays are
// recorded as present (empty value) rather than flattened.
func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool, float64, json.Number:
		return fmt.Sprint(t)
	default:
		return ""
	}
}
