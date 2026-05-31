use crate::config::types::{IpFilterRule, IpFilterScope};
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::str::FromStr;

/// Check whether client_ip is allowed to access scope_type/target_id.
/// Returns true if allowed (no matching rule = allow by default).
pub fn check_ip_allowed(
    rules: &[IpFilterRule],
    scope_type: &str,
    target_id: &str,
    client_ip: &str,
) -> bool {
    let ip = IpAddr::from_str(client_ip).ok();

    for rule in rules {
        if !rule.enabled {
            continue;
        }
        if !scope_matches(&rule.scopes, scope_type, target_id) {
            continue;
        }

        // Combine all IPs in this rule
        let all: Vec<&str> = rule
            .manual_ips
            .iter()
            .map(|s| s.as_str())
            .chain(rule.attachments.iter().flat_map(|a| a.ips.iter().map(|s| s.as_str())))
            .collect();

        let matched = ip_in_list(ip, client_ip, &all);

        return if rule.mode == "blacklist" {
            !matched
        } else {
            matched
        };
    }

    true // no matching rule → allow
}

fn scope_matches(scopes: &[IpFilterScope], scope_type: &str, target_id: &str) -> bool {
    scopes.iter().any(|s| {
        s.scope_type == scope_type && (s.target_id.is_empty() || s.target_id == target_id)
    })
}

fn ip_in_list(ip: Option<IpAddr>, raw: &str, list: &[&str]) -> bool {
    for entry in list {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // Try CIDR first
        if let Ok(network) = IpNetwork::from_str(entry) {
            if let Some(ip) = ip {
                if network.contains(ip) {
                    return true;
                }
            }
            continue;
        }
        // Plain IP or string match
        if entry == raw {
            return true;
        }
        if let (Some(ip), Ok(parsed)) = (ip, IpAddr::from_str(entry)) {
            if parsed == ip {
                return true;
            }
        }
    }
    false
}

/// Check for conflicting scopes across rules (excludes the rule with excludeID).
pub fn has_scope_conflict(
    rules: &[IpFilterRule],
    exclude_id: &str,
    new_scopes: &[IpFilterScope],
) -> Option<String> {
    use std::collections::HashSet;
    let claimed: HashSet<_> = rules
        .iter()
        .filter(|r| r.id != exclude_id)
        .flat_map(|r| r.scopes.iter().map(|s| (s.scope_type.clone(), s.target_id.clone())))
        .collect();

    for s in new_scopes {
        if claimed.contains(&(s.scope_type.clone(), s.target_id.clone())) {
            let desc = if s.target_id.is_empty() {
                format!("{} (全局)", s.scope_type)
            } else {
                let name = if s.target_name.is_empty() { &s.target_id } else { &s.target_name };
                format!("{}: {}", s.scope_type, name)
            };
            return Some(desc);
        }
    }
    None
}
