package config

import (
	"net"
)

// CheckIPAllowed checks whether the given client IP is allowed to access
// the specified scope ("admin", "portforward", or "webservice").
//
// Rules are evaluated in creation order. The first enabled rule whose
// Scopes list contains the requested scope wins:
//   - whitelist mode: allow only if the IP is in the combined IP list.
//   - blacklist mode: block if the IP is in the combined IP list.
//
// If no enabled rule covers the scope, the request is allowed.
func (c *Config) CheckIPAllowed(scope, clientIP string) bool {
	c.RLock()
	rules := append([]IPFilterRule{}, c.IPFilter...)
	c.RUnlock()

	ip := net.ParseIP(clientIP)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !scopeMatches(rule.Scopes, scope) {
			continue
		}

		// Build the full IP set for this rule.
		all := make([]string, 0, len(rule.ManualIPs))
		all = append(all, rule.ManualIPs...)
		for _, att := range rule.Attachments {
			all = append(all, att.IPs...)
		}

		matched := ipInList(ip, clientIP, all)

		if rule.Mode == "blacklist" {
			return !matched
		}
		// whitelist
		return matched
	}

	// No rule covers this scope — allow by default.
	return true
}

func scopeMatches(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// ipInList reports whether ip matches any entry in list.
// Each entry can be a plain IP ("1.2.3.4") or a CIDR ("10.0.0.0/8").
func ipInList(ip net.IP, raw string, list []string) bool {
	for _, entry := range list {
		entry = trimSpace(entry)
		if entry == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			if ip != nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if entry == raw {
			return true
		}
		if ip != nil {
			if net.ParseIP(entry) != nil && net.ParseIP(entry).Equal(ip) {
				return true
			}
		}
	}
	return false
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}
