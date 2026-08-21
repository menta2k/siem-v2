package normalize

import (
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
