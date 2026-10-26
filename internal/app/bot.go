package app

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type botChallengeSettings struct {
	Enabled           bool `json:"enabled"`
	Threshold         int  `json:"score_threshold"`
	ClearanceMinutes  int  `json:"clearance_minutes"`
	RequestsPerSecond int  `json:"risk_requests_per_second"`
	Burst             int  `json:"risk_burst"`
}

func normalizeBotChallenge(s botChallengeSettings) (botChallengeSettings, error) {
	if s.Threshold == 0 {
		s.Threshold = 60
	}
	if s.ClearanceMinutes == 0 {
		s.ClearanceMinutes = 30
	}
	if s.RequestsPerSecond == 0 {
		s.RequestsPerSecond = 25
	}
	if s.Burst == 0 {
		s.Burst = 50
	}
	if s.Threshold < 1 || s.Threshold > 100 || s.ClearanceMinutes < 1 || s.ClearanceMinutes > 120 || s.RequestsPerSecond < 1 || s.RequestsPerSecond > 100000 || s.Burst < s.RequestsPerSecond || s.Burst > 1000000 {
		return s, invalid("provide bot score threshold 1–100, clearance 1–120 minutes, and positive risk rate/burst with burst at least the rate")
	}
	return s, nil
}

type botResult struct {
	StateUnavailable bool     `json:"state_unavailable,omitempty"`
	Score            int      `json:"score"`
	Threshold        int      `json:"threshold"`
	Reasons          []string `json:"reasons,omitempty"`
	Decision         string   `json:"decision,omitempty"`
}
type botRequest struct {
	site                   int64
	scope, binding, bucket string
	secure                 bool
	result                 botResult
}

func (a *App) botContext(p *protectionPolicy, site int64, policyID, revision int64, r *http.Request, ip netip.Addr, secure bool) botRequest {
	// Scope changes invalidate clearance on policy/trust/tuning changes. No visitor
	// data is stored in the clear in the challenge and clearance tables.
	scope := hash(strconv.FormatInt(site, 10) + ":" + requestHost(r.Host) + ":" + strconv.FormatInt(policyID, 10) + ":" + strconv.FormatInt(revision, 10) + ":" + p.botFingerprint)
	return botRequest{site: site, scope: scope, binding: a.botMAC("binding", scope+":"+ip.String()+":"+r.UserAgent()), bucket: a.botMAC("bucket", strconv.FormatInt(site, 10)+":"+ip.String()), secure: secure, result: botResult{Threshold: p.BotChallenge.Threshold}}
}
func (a *App) botScore(p *protectionPolicy, site int64, r *http.Request, ip netip.Addr, now time.Time, profile ...string) botResult {
	result := botResult{Threshold: p.BotChallenge.Threshold, Decision: "allow"}
	add := func(score int, reason string) { result.Score += score; result.Reasons = append(result.Reasons, reason) }
	ua := strings.ToLower(r.UserAgent())
	for _, v := range []string{"sqlmap", "nikto", "nuclei", "masscan", "zgrab"} {
		if strings.Contains(ua, v) {
			add(80, "scanner_user_agent")
			break
		}
	}
	if strings.Contains(ua, "headlesschrome") || strings.Contains(ua, "phantomjs") {
		add(60, "headless_user_agent")
	}
	if ua == "" && p.BlockEmptyUA {
		add(60, "empty_user_agent")
	}
	if (len(profile) == 0 || !(Site{TrafficProfile: profile[0]}).machineEndpoint()) && strings.Contains(ua, "mozilla/") && r.Header.Get("Accept") == "" && r.Header.Get("Accept-Language") == "" {
		add(25, "browser_header_mismatch")
	}
	path := strings.ToLower(r.URL.Path)
	for _, v := range []string{"/.git/", "/.env", "/wp-config.php", "/vendor/phpunit/"} {
		if strings.HasPrefix(path, v) {
			add(35, "sensitive_path_probe")
			break
		}
	}
	key := rateKey{site, "bot:" + strconv.FormatInt(p.budgetScope, 10) + ":" + ip.String()}
	decisions, err := takeRateState(r.Context(), &a.botRates, []rateLimit{{key, p.BotChallenge.RequestsPerSecond, p.BotChallenge.Burst}}, now)
	if err != nil {
		result.StateUnavailable = true
		result.Reasons = append(result.Reasons, "rate_state_unavailable")
	} else if !decisions[0] {
		add(40, "request_frequency")
	}
	result.Score = min(result.Score, 100)
	return result
}
func botSettingsJSON(p *protectionPolicy) string {
	b, _ := json.Marshal(p.BotChallenge)
	return string(b)
}
