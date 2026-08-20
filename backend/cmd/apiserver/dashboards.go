// Dashboard aggregation handlers: top sources, top networks (with ASN owner
// attribution) and storage headroom. Ported from v1's dashboard panels,
// adapted to VictoriaLogs storage.
package main

import (
	"bufio"
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// topN bounds both panels. Ten rows is what a human reads; past that the
// search page is the right tool.
const topN = 10

type sourceCount struct {
	ClientIP string `json:"client_ip"`
	Country  string `json:"country"`
	ASN      int    `json:"asn,omitempty"`
	ASNOwner string `json:"asn_owner,omitempty"`
	Events   int    `json:"events"`
	Blocked  int    `json:"blocked"`
}

type asnCount struct {
	ASN     int    `json:"asn"`
	Owner   string `json:"owner,omitempty"`
	Country string `json:"country"`
	Clients int    `json:"clients"`
	Events  int    `json:"events"`
	Blocked int    `json:"blocked"`
}

// topPanels builds the Top sources and Top networks panels from direct stats
// queries over the window (not a flow sample), then decorates ASNs with owner
// names in one batched lookup.
func (s *apiServer) topPanels(ctx context.Context, tenant string, from, to time.Time) (sources []sourceCount, networks []asnCount) {
	srcRows, err := s.repo.TopSources(ctx, tenant, from, to, topN)
	if err != nil {
		srcRows = nil
	}
	netRows, err := s.repo.TopNetworks(ctx, tenant, from, to, topN)
	if err != nil {
		netRows = nil
	}

	sources = make([]sourceCount, 0, len(srcRows))
	for _, r := range srcRows {
		sources = append(sources, sourceCount{
			ClientIP: r.ClientIP, Country: r.Country, ASN: r.ASN,
			Events: r.Events, Blocked: r.Blocked,
		})
	}
	networks = make([]asnCount, 0, len(netRows))
	for _, r := range netRows {
		networks = append(networks, asnCount{
			ASN: r.ASN, Country: r.Country, Clients: r.Clients,
			Events: r.Events, Blocked: r.Blocked,
		})
	}

	// One batched owner lookup decorates BOTH panels.
	if s.asnNames != nil {
		asns := make([]int, 0, len(sources)+len(networks))
		for _, src := range sources {
			asns = append(asns, src.ASN)
		}
		for _, n := range networks {
			asns = append(asns, n.ASN)
		}
		names := s.asnNames.Resolve(ctx, asns)
		for i := range sources {
			sources[i].ASNOwner = names[sources[i].ASN]
		}
		for i := range networks {
			networks[i].Owner = names[networks[i].ASN]
		}
	}
	return sources, networks
}

// storageClass is one VictoriaLogs instance's disk picture.
type storageClass struct {
	Reachable bool   `json:"reachable"`
	DataBytes int64  `json:"data_bytes"`
	FreeBytes int64  `json:"free_bytes"`
	URL       string `json:"-"`
}

// storageStats answers the Storage headroom card. Admin-gated: disk topology
// is operator information, not analyst information (v1 decision).
func (s *apiServer) storageStats(w http.ResponseWriter, r *http.Request) {
	hot := scrapeVLMetrics(r.Context(), s.vlHotURL)
	warm := scrapeVLMetrics(r.Context(), s.vlWarmURL)

	// Growth is measured from whole days only (v1 rule): today's partial day
	// would understate the rate every morning and overstate headroom.
	rowsPerDay, measuredDays := s.wholeDayRowRate(r.Context())
	totalRows := s.totalRows(r.Context())

	var bytesPerDay float64
	if rowsPerDay > 0 && totalRows > 0 && hot.DataBytes > 0 {
		bytesPerRow := float64(hot.DataBytes) / float64(totalRows)
		bytesPerDay = rowsPerDay * bytesPerRow
	}
	steady := bytesPerDay == 0
	var daysRemaining float64
	if !steady && hot.FreeBytes > 0 {
		daysRemaining = float64(hot.FreeBytes) / bytesPerDay
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"hot":            hot,
		"warm":           warm,
		"bytes_per_day":  int64(bytesPerDay),
		"measured_days":  measuredDays,
		"days_remaining": daysRemaining,
		"steady":         steady,
	})
}

// wholeDayRowRate averages ingested rows over the last 7 whole UTC days.
func (s *apiServer) wholeDayRowRate(ctx context.Context) (float64, int) {
	rows, err := s.vl.Query(ctx, s.vlTenant,
		`_time:8d | stats by (_time:1d) count() rows`, 0)
	if err != nil {
		return 0, 0
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	var total float64
	days := 0
	for _, row := range rows {
		ts, _ := row["_time"].(string)
		day, err := time.Parse(time.RFC3339, ts)
		if err != nil || !day.Before(today) {
			continue // skip today's partial bucket and anything unparsable
		}
		n, _ := strconv.ParseFloat(asString(row["rows"]), 64)
		total += n
		days++
	}
	if days == 0 {
		return 0, 0
	}
	return total / float64(days), days
}

func (s *apiServer) totalRows(ctx context.Context) int64 {
	rows, err := s.vl.Query(ctx, s.vlTenant, `* | stats count() rows`, 0)
	if err != nil || len(rows) == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(asString(rows[0]["rows"]), 10, 64)
	return n
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

// scrapeVLMetrics reads vl_data_size_bytes and vl_free_disk_space_bytes from
// one instance's /metrics. An unreachable instance reports reachable=false
// rather than failing the panel — in this deployment the warm tier may
// legitimately be absent.
func scrapeVLMetrics(ctx context.Context, baseURL string) storageClass {
	out := storageClass{URL: baseURL}
	if baseURL == "" {
		return out
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/metrics", nil)
	if err != nil {
		return out
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "vl_data_size_bytes"):
			out.DataBytes += metricValue(line)
		case strings.HasPrefix(line, "vl_free_disk_space_bytes"):
			out.FreeBytes = metricValue(line)
		}
	}
	out.Reachable = true
	return out
}

func metricValue(line string) int64 {
	idx := strings.LastIndexByte(line, ' ')
	if idx < 0 {
		return 0
	}
	f, err := strconv.ParseFloat(line[idx+1:], 64)
	if err != nil {
		return 0
	}
	return int64(f)
}
