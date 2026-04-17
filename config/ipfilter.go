package config

import (
	"net"
)

// CheckIPAllowed checks whether the given client IP is allowed to access
// the specified scope.
//
// scopeType:  "admin" | "portforward" | "webservice"
// targetID:   the specific portforward rule ID or webservice route ID being
//             accessed; empty string means a global check with no specific target.
//
// Matching logic (rules evaluated in creation order, first match wins):
//   A rule scope entry matches the request when:
//     - scope.Type == scopeType, AND
//     - scope.TargetID is empty (applies to ALL targets of that type), OR
//       scope.TargetID == targetID (applies only to this specific target).
//
//   On match:
//     - whitelist: allow only if the IP is in the combined IP list.
//     - blacklist: block if the IP is in the combined IP list.
//
// If no enabled rule covers the scope, the request is allowed.
func (c *Config) CheckIPAllowed(scopeType, targetID, clientIP string) bool {
	c.RLock()
	rules := append([]IPFilterRule{}, c.IPFilter...)
	c.RUnlock()

	ip := net.ParseIP(clientIP)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !scopeMatches(rule.Scopes, scopeType, targetID) {
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

// scopeMatches returns true if any scope entry in the rule matches the
// requested (scopeType, targetID) pair.
func scopeMatches(scopes []IPFilterScope, scopeType, targetID string) bool {
	for _, s := range scopes {
		if s.Type != scopeType {
			continue
		}
		// An empty TargetID in the rule means "all targets of this type".
		if s.TargetID == "" || s.TargetID == targetID {
			return true
		}
	}
	return false
}

// HasScopeConflict checks whether the given scopes conflict with any existing
// rule (excluding the rule with excludeID).
//
// Conflict means: another enabled rule already covers the exact same
// (Type, TargetID) pair. Returns the conflicting scope description or "".
func HasScopeConflict(rules []IPFilterRule, excludeID string, newScopes []IPFilterScope) string {
	type key struct{ t, id string }
	claimed := make(map[key]bool)
	for _, r := range rules {
		if r.ID == excludeID {
			continue
		}
		for _, s := range r.Scopes {
			claimed[key{s.Type, s.TargetID}] = true
		}
	}
	for _, s := range newScopes {
		if claimed[key{s.Type, s.TargetID}] {
			if s.TargetID == "" {
				return s.Type + " (全局)"
			}
			name := s.TargetName
			if name == "" {
				name = s.TargetID
			}
			return s.Type + ": " + name
		}
	}
	return ""
}

// CleanScopesForDeletedTarget removes scope entries that reference a deleted
// targetID of the given scopeType from all IPFilter rules in-memory.
// Returns the list of rule IDs that were modified.
func (c *Config) CleanScopesForDeletedTarget(scopeType, targetID string) []string {
	c.Lock()
	defer c.Unlock()
	var modified []string
	for i, rule := range c.IPFilter {
		var kept []IPFilterScope
		changed := false
		for _, s := range rule.Scopes {
			if s.Type == scopeType && s.TargetID == targetID {
				changed = true
				continue
			}
			kept = append(kept, s)
		}
		if changed {
			if kept == nil {
				kept = []IPFilterScope{}
			}
			c.IPFilter[i].Scopes = kept
			modified = append(modified, rule.ID)
		}
	}
	return modified
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
