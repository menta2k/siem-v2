package asnowner

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

const sampleTSV = `1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET
1.0.1.0	1.0.3.255	0	None	Not routed
1.0.4.0	1.0.5.255	38803	AU	WPL-AS-AP Wirefreebroadband Pty Ltd
1.0.6.0	1.0.7.255	38803	AU	Some Later Different Name
broken line without tabs
1.1.1.0	1.1.1.255	13335	US	CLOUDFLARENET
2.0.0.0	2.0.0.255	3215	FR	France Telecom - Orange
`

func TestParseIptoasnTSV(t *testing.T) {
	owners, err := Parse(strings.NewReader(sampleTSV))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byASN := map[int]Owner{}
	for _, o := range owners {
		byASN[o.ASN] = o
	}
	if len(byASN) != 3 {
		t.Fatalf("expected 3 distinct ASNs, got %d: %v", len(byASN), byASN)
	}
	if got := byASN[13335]; got.Name != "CLOUDFLARENET" || got.Country != "US" {
		t.Errorf("AS13335 = %+v", got)
	}
	// First description per ASN wins: ranges are sorted and later entries for
	// the same ASN add nothing but churn.
	if got := byASN[38803]; got.Name != "WPL-AS-AP Wirefreebroadband Pty Ltd" {
		t.Errorf("first name must win, got %q", got.Name)
	}
	if _, ok := byASN[0]; ok {
		t.Error("ASN 0 (unrouted space) must be skipped")
	}
}

func TestParseGzipRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(sampleTSV)); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	owners, err := ParseGzip(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parse gzip: %v", err)
	}
	if len(owners) != 3 {
		t.Fatalf("expected 3 owners, got %d", len(owners))
	}
}

func TestParseRefusesOversizedInput(t *testing.T) {
	huge := strings.NewReader(strings.Repeat("x", 10))
	// A tiny cap proves the guard without allocating anything real.
	if _, err := parseBounded(huge, 5); err == nil {
		t.Fatal("input past the cap must be refused, not truncated silently")
	}
}
