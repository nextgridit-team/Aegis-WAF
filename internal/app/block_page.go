package app

import (
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Block page text fields are stored per site as bounded plain text. The caps
// keep the rendered page small; control characters (including NUL, which
// PostgreSQL text columns reject) are refused rather than stored.
const (
	blockTitleMaxChars     = 80
	blockContactMaxChars   = 200
	blockReferenceMaxChars = 80
)

// wantsJSONResponse reports whether the client asked for a machine-readable
// error. API and streaming profiles always qualify; other clients qualify by
// sending Accept: application/json. They keep the JSON error shape and never
// receive the HTML block page.
func wantsJSONResponse(r *http.Request) bool {
	if r == nil {
		return false
	}
	for _, value := range r.Header.Values("Accept") {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]), "application/json") {
				return true
			}
		}
	}
	return false
}

// blockPageHeading keeps the visitor-facing reason coarse: a status class,
// never a rule ID, policy name or upstream detail.
func blockPageHeading(status int) string {
	switch status {
	case http.StatusTooManyRequests:
		return "Too many requests"
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		return "Upstream unavailable"
	case http.StatusServiceUnavailable:
		return "Service unavailable"
	case http.StatusNotFound:
		return "Not found"
	default:
		return "Request blocked"
	}
}

// writeBlockPage renders the default visitor-facing error page: one small
// static HTML document with no external assets and no security detail beyond
// the per-request correlation ID. Site-provided lines are length-capped at
// save time and are HTML-escaped here regardless of what storage returned.
func (s Site) writeBlockPage(w http.ResponseWriter, status int) {
	heading := blockPageHeading(status)
	if s.BlockTitle != "" {
		heading = s.BlockTitle
	}
	requestID := w.Header().Get("X-Request-ID")
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>")
	b.WriteString(html.EscapeString(heading))
	b.WriteString(`</title>
<style>
body{margin:0;font-family:system-ui,sans-serif;background:#f5f6f8;color:#1b2530;display:grid;min-height:100vh;align-items:center}
main{max-width:32rem;margin:auto;padding:2.5rem 1.5rem;background:#fff;border:1px solid #d8dde4;border-radius:10px;text-align:center}
h1{font-size:1.25rem;line-height:1.3;margin:0 0 .75rem}
p{color:#4b5560;line-height:1.5;margin:.4rem 0}
code{font-family:ui-monospace,monospace;font-size:.875rem;word-break:break-all}
</style>
</head>
<body>
<main>
<h1>`)
	b.WriteString(html.EscapeString(heading))
	b.WriteString("</h1>\n<p>The request could not be completed. No further detail is available.</p>\n")
	if requestID != "" {
		b.WriteString("<p>Request ID: <code>")
		b.WriteString(html.EscapeString(requestID))
		b.WriteString("</code></p>\n")
	}
	if s.BlockContact != "" {
		b.WriteString("<p>Contact: ")
		b.WriteString(html.EscapeString(s.BlockContact))
		b.WriteString("</p>\n")
	}
	if s.BlockReference != "" {
		b.WriteString("<p>Reference: ")
		b.WriteString(html.EscapeString(s.BlockReference))
		b.WriteString("</p>\n")
	}
	b.WriteString("</main>\n</body>\n</html>\n")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	io.WriteString(w, b.String())
}

// validateBlockPageText enforces the per-site block page contract: bounded
// plain text with no control characters. NUL is valid UTF-8 and survives JSON
// decoding, but PostgreSQL text columns reject it, so it is refused here
// together with every other control rune.
func validateBlockPageText(field, value string, maxChars int) error {
	if len(value) > maxChars {
		return invalid(field + " must be at most " + strconv.Itoa(maxChars) + " bytes")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return invalid(field + " must be plain text without control characters")
		}
	}
	return nil
}

// normalizeBlockPage validates the per-site block page lines. Empty values
// select the built-in defaults.
func normalizeBlockPage(site *Site) error {
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"block_title", site.BlockTitle, blockTitleMaxChars},
		{"block_contact", site.BlockContact, blockContactMaxChars},
		{"block_reference", site.BlockReference, blockReferenceMaxChars},
	} {
		if e := validateBlockPageText(field.name, field.value, field.max); e != nil {
			return e
		}
	}
	return nil
}
