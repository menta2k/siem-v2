// Dashboard aggregation handlers: top sources, top networks (with ASN owner
// attribution) and storage headroom. Ported from v1's dashboard panels,
// adapted to VictoriaLogs storage.
package main

import (
	"bufio"
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/menta2k/siem-v2/backend/internal/biz/flow"
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

// topPanels aggregates the flow set the dashboard already reads — the same
// data the caller may search, so it adds no new disclosure.
func (s *apiServer) topPanels(ctx context.Context, flows []*flow.Flow) (sources []sourceCount, networks []asnCount) {
	type ipAgg struct {
		country string
		asn     int
		events  int
		blocked int
	}
	type asnAgg struct {
		countries map[string]int
		clients   map[string]bool
		events    int
		blocked   int
	}
	byIP := map[string]*ipAgg{}
	byASN := map[int]*asnAgg{}

	for _, f := range flows {
		blocked := f.EffectiveOutcome == "blocked"
		ip := f.Client.IP
		if ip != "" {
			a := byIP[ip]
			if a == nil {
				a = &ipAgg{country: f.Client.Country, asn: f.Client.ASN}
				byIP[ip] = a
			}
			a.events++
			if blocked {
				a.blocked++
			}
		}
		// The ASN panel only counts flows where a vendor actually reported one.
		if f.Client.ASN > 0 {
			a := byASN[f.Client.ASN]
			if a == nil {
				a = &asnAgg{countries: map[string]int{}, clients: map[string]bool{}}
				byASN[f.Client.ASN] = a
			}
			a.events++
			if blocked {
				a.blocked++
			}
			if ip != "" {
				a.clients[ip] = true
			}
			if f.Client.Country != "" {
				a.countries[f.Client.Country]++
			}
		}
	}

	for ip, a := range byIP {
		sources = append(sources, sourceCount{
			ClientIP: ip, Country: a.country, ASN: a.asn,
			Events: a.events, Blocked: a.blocked,
		})
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Events != sources[j].Events {
			return sources[i].Events > sources[j].Events
		}
		return sources[i].ClientIP < sources[j].ClientIP
	})
	if len(sources) > topN {
		sources = sources[:topN]
	}

	for asn, a := range byASN {
		top, topCount := "", 0
		for c, n := range a.countries {
			if n > topCount || (n == topCount && c < top) {
				top, topCount = c, n
			}
		}
		networks = append(networks, asnCount{
			ASN: asn, Country: top, Clients: len(a.clients),
			Events: a.events, Blocked: a.blocked,
		})
	}
	sort.Slice(networks, func(i, j int) bool {
		if networks[i].Events != networks[j].Events {
			return networks[i].Events > networks[j].Events
		}
		return networks[i].ASN < networks[j].ASN
	})
	if len(networks) > topN {
		networks = networks[:topN]
	}

	// One batched owner lookup decorates BOTH panels (v1's nameNetworks).
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
	if sources == nil {
		sources = []sourceCount{}
	}
	if networks == nil {
		networks = []asnCount{}
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
