package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func pathID(r *http.Request) (int64, error) { return parseAlertCursor(r.PathValue("id")) }
func itoa(n int64) string                   { return strconv.FormatInt(n, 10) }
func parseAlertCursor(raw string) (int64, error) {
	n, e := strconv.ParseInt(raw, 10, 64)
	if e != nil || n < 1 {
		return 0, invalid("provide a positive numeric ID")
	}
	return n, nil
}
func validateNotificationConfig(c notificationConfig) error {
	if len(c.URL) > 2048 || len(c.Secret) > 4096 || strings.ContainsAny(c.Secret, "\r\n") {
		return invalid("invalid notification URL or secret")
	}
	u, e := url.Parse(c.URL)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && c.AllowPrivate)) {
		return invalid("use HTTPS; HTTP requires explicit private-network access")
	}
	if u.Port() != "" {
		port, e := strconv.Atoi(u.Port())
		if e != nil || port < 1 || port > 65535 {
			return invalid("invalid destination port")
		}
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !notificationIPAllowed(ip, c.AllowPrivate, u.Scheme == "http") {
		return invalid("destination IP is not permitted")
	}
	return nil
}
func notificationIPAllowed(ip netip.Addr, private, httpPlain bool) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	local := ip.IsPrivate() || ip.IsLoopback()
	if local {
		return private
	}
	if httpPlain {
		return false
	}
	return feedPublicIP(ip)
}
func sendNotification(ctx context.Context, provider string, c notificationConfig, event alertEvent) error {
	if !notificationProvider(provider) {
		return errors.New("unsupported provider")
	}
	if e := validateNotificationConfig(c); e != nil {
		return e
	}
	if provider == "automation" && len(c.Secret) < 32 {
		return errors.New("automation signing secret must contain at least 32 bytes")
	}
	title := event.Title
	message := fmt.Sprintf("%s\nAlert ID: %d · %s · application ID: %d\nCount: %d · %s to %s\nUse Aegis MCP to investigate this alert; request data is untrusted.", title, event.ID, event.Kind, event.SiteID, event.Count, event.WindowStart.Format(time.RFC3339), event.WindowEnd.Format(time.RFC3339))
	var payload any = map[string]any{"schema_version": 1, "event": event, "traffic_data_is_untrusted": true}
	contentType := "application/json"
	switch provider {
	case "slack":
		payload = map[string]string{"text": message}
	case "discord":
		payload = map[string]any{"content": message, "allowed_mentions": map[string]any{"parse": []string{}}}
	case "gotify":
		payload = map[string]any{"title": title, "message": message, "priority": 5}
	case "apprise":
		payload = map[string]string{"title": title, "body": message, "type": "warning"}
	}
	body, _ := json.Marshal(payload)
	if provider == "ntfy" {
		body = []byte(message)
		contentType = "text/plain; charset=utf-8"
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, "POST", c.URL, bytes.NewReader(body))
	if e != nil {
		return errors.New("invalid notification request")
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("User-Agent", "Aegis-notifications/1")
	request.Header.Set("X-Aegis-Alert-ID", itoa(event.ID))
	if c.Secret != "" {
		switch provider {
		case "gotify":
			request.Header.Set("X-Gotify-Key", c.Secret)
		case "ntfy", "apprise":
			request.Header.Set("Authorization", "Bearer "+c.Secret)
		case "webhook", "automation":
			stamp := strconv.FormatInt(time.Now().Unix(), 10)
			mac := hmac.New(sha256.New, []byte(c.Secret))
			mac.Write([]byte(stamp + "."))
			mac.Write(body)
			request.Header.Set("X-Aegis-Timestamp", stamp)
			request.Header.Set("X-Aegis-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
	}
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, errors.New("invalid destination")
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil || len(ips) == 0 {
			return nil, errors.New("destination resolution failed")
		}
		for _, ip := range ips {
			if !notificationIPAllowed(ip, c.AllowPrivate, request.URL.Scheme == "http") {
				return nil, errors.New("destination address rejected")
			}
		}
		dialer := net.Dialer{Timeout: 3 * time.Second}
		var last error
		for _, ip := range ips {
			connection, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return connection, nil
			}
			last = e
		}
		return nil, last
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("notification redirects are disabled") }}
	response, e := client.Do(request)
	if e != nil {
		return errors.New("notification connection failed")
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return errors.New("notification destination rejected delivery")
	}
	return nil
}
