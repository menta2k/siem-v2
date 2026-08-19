// Package asnowner maps AS numbers to registry owner names.
//
// Ported from v1. The mapping is DECORATION: it makes "AS13335" readable as
// "CLOUDFLARENET" on dashboards and search results. Every path degrades to an
// empty name — a missing table, a stale snapshot or an unknown ASN never
// breaks a page, it only leaves a number unexplained.
package asnowner

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Owner is one AS number's registry attribution.
type Owner struct {
	ASN     int
	Name    string
	Country string
}

// Size caps for the downloaded snapshot (v1 values). The source file is a few
// tens of MB; anything past these caps is a broken or hostile response.
const (
	MaxCompressedBytes   = 64 << 20
	MaxDecompressedBytes = 512 << 20
)

// Parse reads the iptoasn.com 5-column TSV:
// range_start<TAB>range_end<TAB>as_number<TAB>country<TAB>description.
// Malformed lines are skipped — the file is third-party and one bad line must
// not discard the other million.
func Parse(r io.Reader) ([]Owner, error) {
	return parseBounded(r, MaxDecompressedBytes)
}

// ParseGzip decompresses and parses, bounding both sides.
func ParseGzip(r io.Reader) ([]Owner, error) {
	zr, err := gzip.NewReader(io.LimitReader(r, MaxCompressedBytes))
	if err != nil {
		return nil, fmt.Errorf("asnowner: open gzip: %w", err)
	}
	defer zr.Close()
	return parseBounded(zr, MaxDecompressedBytes)
}

func parseBounded(r io.Reader, maxBytes int64) ([]Owner, error) {
	// LimitReader with one extra byte: reading past the cap is detectable as
	// "limit reached with input remaining" rather than a silent truncation.
	lr := &countingReader{r: io.LimitReader(r, maxBytes+1), max: maxBytes}
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	seen := map[int]bool{}
	var out []Owner
	for sc.Scan() {
		cols := strings.Split(sc.Text(), "\t")
		if len(cols) != 5 {
			continue
		}
		asn, err := strconv.Atoi(cols[2])
		if err != nil || asn <= 0 {
			continue
		}
		name := strings.TrimSpace(cols[4])
		if name == "" || name == "Not routed" {
			continue
		}
		// Ranges are sorted; the first description per ASN wins and the rest
		// are the same organisation's other prefixes.
		if seen[asn] {
			continue
		}
		seen[asn] = true
		out = append(out, Owner{ASN: asn, Name: name, Country: strings.TrimSpace(cols[3])})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("asnowner: scan: %w", err)
	}
	if lr.n > lr.max {
		return nil, fmt.Errorf("asnowner: input exceeds %d bytes", maxBytes)
	}
	return out, nil
}

type countingReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
