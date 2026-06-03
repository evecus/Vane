use crate::config::types::{IpFilterRule, IpFilterScope};
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

// ─── 预编译缓存 ───────────────────────────────────────────────────────────────

/// 单条规则预编译后的 IP 集合。
/// 精确 IP 放 HashSet，O(1) 查找；
/// CIDR 网段放 Vec，数量远少于展开后的 IP 数。
#[derive(Debug, Default)]
pub struct CompiledRule {
    pub id: String,
    pub enabled: bool,
    pub mode: String, // "whitelist" | "blacklist"
    pub scopes: Vec<IpFilterScope>,
    pub exact: HashSet<IpAddr>,
    pub cidrs: Vec<IpNetwork>,
}

/// 全部规则的预编译缓存，与 ip_filter 始终保持同步。
#[derive(Debug, Default)]
pub struct IpFilterCache(pub Vec<CompiledRule>);

impl IpFilterCache {
    /// 从原始规则列表全量重建缓存。在任何规则增删改后调用一次。
    pub fn rebuild(rules: &[IpFilterRule]) -> Self {
        let compiled = rules.iter().map(compile_rule).collect();
        IpFilterCache(compiled)
    }

    /// 查询 client_ip 是否被允许访问 scope_type/target_id。
    /// 无匹配规则时默认放行。
    pub fn check_allowed(&self, scope_type: &str, target_id: &str, client_ip: &str) -> bool {
        let ip = IpAddr::from_str(client_ip).ok();

        for rule in &self.0 {
            if !rule.enabled {
                continue;
            }
            if !scope_matches(&rule.scopes, scope_type, target_id) {
                continue;
            }
            let matched = ip_in_compiled(ip, &rule.exact, &rule.cidrs);
            return if rule.mode == "blacklist" { !matched } else { matched };
        }

        true // 无匹配规则 → 放行
    }
}

fn compile_rule(rule: &IpFilterRule) -> CompiledRule {
    let mut exact: HashSet<IpAddr> = HashSet::new();
    let mut cidrs: Vec<IpNetwork> = Vec::new();

    let all_ips = rule
        .manual_ips
        .iter()
        .map(|s| s.as_str())
        .chain(
            rule.attachments
                .iter()
                .flat_map(|a| a.ips.iter().map(|s| s.as_str())),
        );

    for entry in all_ips {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // 优先尝试解析为 CIDR（含 /32、/128 精确掩码）
        if let Ok(network) = IpNetwork::from_str(entry) {
            // /32（IPv4）或 /128（IPv6）等价于单个 IP，放进 HashSet 更快
            if network.prefix() == network.max_prefix() {
                exact.insert(network.network());
            } else {
                cidrs.push(network);
            }
            continue;
        }
        // 纯 IP 地址
        if let Ok(addr) = IpAddr::from_str(entry) {
            exact.insert(addr);
        }
    }

    CompiledRule {
        id: rule.id.clone(),
        enabled: rule.enabled,
        mode: rule.mode.clone(),
        scopes: rule.scopes.clone(),
        exact,
        cidrs,
    }
}

fn ip_in_compiled(ip: Option<IpAddr>, exact: &HashSet<IpAddr>, cidrs: &[IpNetwork]) -> bool {
    let Some(ip) = ip else { return false };
    if exact.contains(&ip) {
        return true;
    }
    cidrs.iter().any(|net| net.contains(ip))
}

// ─── 辅助函数（供 check_ip_allowed 旧接口及其他模块使用）─────────────────────

fn scope_matches(scopes: &[IpFilterScope], scope_type: &str, target_id: &str) -> bool {
    scopes.iter().any(|s| {
        s.scope_type == scope_type && (s.target_id.is_empty() || s.target_id == target_id)
    })
}

/// 不经缓存的原始检查（仅在缓存尚未建立时作为兜底，正常路径不走这里）。
pub fn check_ip_allowed(
    rules: &[IpFilterRule],
    scope_type: &str,
    target_id: &str,
    client_ip: &str,
) -> bool {
    IpFilterCache::rebuild(rules).check_allowed(scope_type, target_id, client_ip)
}

/// 删除目标时清理 scopes，返回被修改的规则 ID 列表。
pub fn clean_scopes_for_deleted_target(
    rules: &mut Vec<IpFilterRule>,
    scope_type: &str,
    target_id: &str,
) -> Vec<String> {
    let mut modified = Vec::new();
    for rule in rules.iter_mut() {
        let before = rule.scopes.len();
        rule.scopes
            .retain(|s| !(s.scope_type == scope_type && s.target_id == target_id));
        if rule.scopes.len() != before {
            modified.push(rule.id.clone());
        }
    }
    modified
}

/// 检查新 scopes 是否与现有规则冲突（排除 exclude_id 自身）。
pub fn has_scope_conflict(
    rules: &[IpFilterRule],
    exclude_id: &str,
    new_scopes: &[IpFilterScope],
) -> Option<String> {
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
                let name = if s.target_name.is_empty() {
                    &s.target_id
                } else {
                    &s.target_name
                };
                format!("{}: {}", s.scope_type, name)
            };
            return Some(desc);
        }
    }
    None
}
