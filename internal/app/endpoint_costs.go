package app

import (
	"net/http"
	"strconv"
)

// Cost-of-protection reporting: per-endpoint request counts and timings over
// a bounded lookback of the access log. The response deliberately carries
// only counts, timings and matched-rule references — no payloads, headers or
// client addresses — matching the evidence/privacy posture of the log
// surfaces it aggregates.

const (
	endpointCostsDefaultHours = 24
	endpointCostsMaxHours     = 168
	endpointCostsMaxRows      = 256
	endpointCostsTopRules     = 3
)

type endpointCostRule struct {
	RuleID int64  `json:"rule_id"`
	Group  string `json:"group,omitempty"`
	Count  int64  `json:"count"`
}
type endpointCost struct {
	PathClass  string             `json:"path_class"`
	Requests   int64              `json:"requests"`
	Blocked    int64              `json:"blocked"`
	Forwarded  int64              `json:"forwarded"`
	TotalP50MS float64            `json:"total_p50_ms"`
	TotalP95MS float64            `json:"total_p95_ms"`
	AddedP50MS float64            `json:"added_p50_ms"`
	AddedP95MS float64            `json:"added_p95_ms"`
	TopRules   []endpointCostRule `json:"top_rules"`
}
type endpointCostReport struct {
	SiteID    int64          `json:"site_id"`
	Hours     int            `json:"hours"`
	Endpoints []endpointCost `json:"endpoints"`
}

func (a *App) endpointCosts(w http.ResponseWriter, r *http.Request, _ identity) error {
	query := r.URL.Query()
	siteID, e := strconv.ParseInt(query.Get("site_id"), 10, 64)
	if e != nil || siteID < 1 {
		return invalid("site_id must be a positive application id")
	}
	hours := endpointCostsDefaultHours
	if raw := query.Get("hours"); raw != "" {
		hours, e = strconv.Atoi(raw)
		if e != nil || hours < 1 || hours > endpointCostsMaxHours {
			return invalid("hours must be between 1 and 168")
		}
	}
	rows, e := a.db.Query(r.Context(), `SELECT path_class,
count(*),
count(*) FILTER (WHERE blocked),
count(*) FILTER (WHERE response_source='upstream'),
coalesce(percentile_disc(0.5) WITHIN GROUP (ORDER BY duration_ms), 0),
coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY duration_ms), 0),
coalesce(percentile_disc(0.5) WITHIN GROUP (ORDER BY greatest(0, duration_ms*1000-upstream_us)) FILTER (WHERE response_source='upstream' AND upstream_us>0), 0),
coalesce(percentile_disc(0.95) WITHIN GROUP (ORDER BY greatest(0, duration_ms*1000-upstream_us)) FILTER (WHERE response_source='upstream' AND upstream_us>0), 0)
FROM access_logs
WHERE site_id=$1 AND at>now()-($2::int*interval '1 hour') AND path_class<>''
GROUP BY path_class
ORDER BY count(*) DESC
LIMIT $3`, siteID, hours, endpointCostsMaxRows)
	if e != nil {
		return e
	}
	defer rows.Close()
	report := endpointCostReport{SiteID: siteID, Hours: hours, Endpoints: []endpointCost{}}
	classes := []string{}
	for rows.Next() {
		var cost endpointCost
		var totalP50, totalP95, addedP50, addedP95 int64
		if e = rows.Scan(&cost.PathClass, &cost.Requests, &cost.Blocked, &cost.Forwarded, &totalP50, &totalP95, &addedP50, &addedP95); e != nil {
			return e
		}
		cost.TotalP50MS = float64(totalP50)
		cost.TotalP95MS = float64(totalP95)
		cost.AddedP50MS = float64(addedP50) / 1000
		cost.AddedP95MS = float64(addedP95) / 1000
		cost.TopRules = []endpointCostRule{}
		report.Endpoints = append(report.Endpoints, cost)
		classes = append(classes, cost.PathClass)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if len(classes) > 0 {
		if e = a.attachTopRules(r, &report, classes); e != nil {
			return e
		}
	}
	respond(w, 200, report)
	return nil
}

// attachTopRules counts matched custom/community rules per path class over
// the same window, then keeps the most frequent few per class.
func (a *App) attachTopRules(r *http.Request, report *endpointCostReport, classes []string) error {
	rows, e := a.db.Query(r.Context(), `SELECT l.path_class, (elem->>'rule_id')::bigint, coalesce(elem->>'group',''), count(*)
FROM access_logs l, jsonb_array_elements(l.rule_results) elem
WHERE l.site_id=$1 AND l.at>now()-($2::int*interval '1 hour') AND l.path_class=ANY($3) AND elem->>'result'='matched'
GROUP BY 1,2,3
ORDER BY 4 DESC`, report.SiteID, report.Hours, classes)
	if e != nil {
		return e
	}
	defer rows.Close()
	counts := map[string][]endpointCostRule{}
	for rows.Next() {
		var class string
		var rule endpointCostRule
		if e = rows.Scan(&class, &rule.RuleID, &rule.Group, &rule.Count); e != nil {
			return e
		}
		if len(counts[class]) < endpointCostsTopRules {
			counts[class] = append(counts[class], rule)
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	for n := range report.Endpoints {
		if rules := counts[report.Endpoints[n].PathClass]; rules != nil {
			report.Endpoints[n].TopRules = rules
		}
	}
	return nil
}
