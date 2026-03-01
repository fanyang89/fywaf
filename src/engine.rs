use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use regex::Regex;

use crate::config::{
    Action, AppConfig, ConditionConfig, ConditionOperator, ConditionTarget, ConditionTransform,
    EngineConfig, RuleConfig,
};
use crate::snapshot::{EngineSnapshot, SnapshotProfile};

#[derive(Debug)]
pub struct WafEngine {
    profiles: HashMap<String, CompiledProfile>,
    vm: Arc<dyn RuleVm>,
}

#[derive(Debug)]
struct CompiledProfile {
    default_action: Action,
    rules: Vec<CompiledRule>,
    method_index: HashMap<String, Vec<usize>>,
    any_method_rules: Vec<usize>,
}

#[derive(Debug)]
struct CompiledRule {
    id: String,
    action: Action,
    status_code: u16,
    methods: Vec<String>,
    path_prefixes: Vec<String>,
    ip_cidrs: Vec<Cidr>,
    user_agent_contains: Vec<String>,
    conditions: Vec<CompiledCondition>,
}

#[derive(Debug)]
struct CompiledCondition {
    source: ConditionSource,
    operator: CompiledConditionOperator,
    transforms: Vec<ConditionTransform>,
}

#[derive(Debug)]
enum ConditionSource {
    Method,
    Path,
    Query,
    Body,
    UserAgent,
    Header(String),
    ClientIp,
}

#[derive(Debug)]
enum CompiledConditionOperator {
    Eq(String),
    Contains(String),
    Prefix(String),
    Suffix(String),
    Regex(Regex),
    In(Vec<String>),
    IpMatch(Vec<Cidr>),
}

#[derive(Debug, Clone, Copy)]
enum Cidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub client_ip: IpAddr,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub user_agent: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub profile_id: String,
    pub action: Action,
    pub status_code: u16,
    pub matched_rule_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MatchScore {
    matched_dimensions: u8,
    path_specificity: u16,
    ip_specificity: u8,
    ua_specificity: u16,
    condition_specificity: u16,
}

#[derive(Debug, Clone, Copy)]
struct MatchDetails {
    path_specificity: u16,
    ip_specificity: u8,
    ua_specificity: u16,
    condition_specificity: u16,
}

trait RuleVm: Send + Sync + std::fmt::Debug {
    fn select_best_match(
        &self,
        profile: &CompiledProfile,
        req: &RequestMeta,
        candidate_rule_ids: &[usize],
    ) -> Option<usize>;
}

#[derive(Debug, Default)]
struct NativeVm;

impl WafEngine {
    pub fn from_config(cfg: &AppConfig) -> anyhow::Result<Self> {
        let path = cfg
            .engine
            .snapshot_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("engine.snapshot_path is required"))?;
        Self::from_snapshot_path(path, &cfg.engine)
    }

    pub fn from_snapshot_path(path: impl AsRef<Path>, _cfg: &EngineConfig) -> anyhow::Result<Self> {
        let snapshot = EngineSnapshot::read_from_path(path.as_ref())?;
        Self::from_snapshot(snapshot)
    }

    pub fn from_snapshot(snapshot: EngineSnapshot) -> anyhow::Result<Self> {
        let mut profiles = HashMap::new();
        for profile in &snapshot.profiles {
            let compiled = CompiledProfile::compile_from_snapshot(profile)?;
            profiles.insert(profile.id.clone(), compiled);
        }
        Ok(Self {
            profiles,
            vm: Arc::new(NativeVm),
        })
    }

    pub fn decide(&self, profile_id: &str, req: &RequestMeta) -> anyhow::Result<Decision> {
        let profile = self
            .profiles
            .get(profile_id)
            .ok_or_else(|| anyhow::anyhow!("profile not found: {}", profile_id))?;

        let candidates = profile.candidates_for_method(&req.method);
        if let Some(rule_id) = self.vm.select_best_match(profile, req, &candidates) {
            let rule = &profile.rules[rule_id];
            return Ok(Decision {
                profile_id: profile_id.to_string(),
                action: rule.action,
                status_code: rule.status_code,
                matched_rule_id: Some(rule.id.clone()),
            });
        }

        let (action, status_code) = match profile.default_action {
            Action::Allow => (Action::Allow, 200),
            Action::Block => (Action::Block, 403),
        };
        Ok(Decision {
            profile_id: profile_id.to_string(),
            action,
            status_code,
            matched_rule_id: None,
        })
    }
}

impl RuleVm for NativeVm {
    fn select_best_match(
        &self,
        profile: &CompiledProfile,
        req: &RequestMeta,
        candidate_rule_ids: &[usize],
    ) -> Option<usize> {
        let mut best: Option<(usize, MatchScore)> = None;

        for &rule_id in candidate_rule_ids {
            let rule = &profile.rules[rule_id];
            let Some(details) = rule.match_details(req) else {
                continue;
            };
            let score = rule.score(details);

            match best {
                None => best = Some((rule_id, score)),
                Some((best_id, best_score)) => {
                    if score > best_score || (score == best_score && rule_id < best_id) {
                        best = Some((rule_id, score));
                    }
                }
            }
        }

        best.map(|(rule_id, _)| rule_id)
    }
}

impl CompiledProfile {
    fn compile_from_snapshot(raw: &SnapshotProfile) -> anyhow::Result<Self> {
        let mut rules = Vec::new();
        for rule in &raw.rules {
            if !rule.enabled {
                continue;
            }
            rules.push(CompiledRule::compile(rule).with_context(|| {
                format!("failed to compile rule {} in profile {}", rule.id, raw.id)
            })?);
        }
        Ok(Self::with_indexes(raw.default_action, rules))
    }

    fn with_indexes(default_action: Action, rules: Vec<CompiledRule>) -> Self {
        let mut method_index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut any_method_rules = Vec::new();

        for (rule_id, rule) in rules.iter().enumerate() {
            if rule.methods.is_empty() {
                any_method_rules.push(rule_id);
                continue;
            }
            for method in &rule.methods {
                method_index
                    .entry(method.clone())
                    .or_default()
                    .push(rule_id);
            }
        }

        Self {
            default_action,
            rules,
            method_index,
            any_method_rules,
        }
    }

    fn candidates_for_method(&self, method: &str) -> Vec<usize> {
        let mut candidates = self.any_method_rules.clone();
        let method_upper = method.to_ascii_uppercase();
        if let Some(ids) = self.method_index.get(&method_upper) {
            candidates.extend_from_slice(ids);
        }
        candidates
    }
}

impl CompiledRule {
    fn compile(raw: &RuleConfig) -> anyhow::Result<Self> {
        let ip_cidrs = raw
            .ip_cidrs
            .iter()
            .map(|cidr| Cidr::parse(cidr).with_context(|| format!("rule {}", raw.id)))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let methods = raw
            .methods
            .iter()
            .map(|m| m.trim().to_ascii_uppercase())
            .collect::<Vec<_>>();

        let path_prefixes = raw.path_prefixes.clone();
        let user_agent_contains = raw
            .user_agent_contains
            .iter()
            .map(|ua| ua.to_ascii_lowercase())
            .collect::<Vec<_>>();

        let conditions = raw
            .conditions
            .iter()
            .map(|cond| CompiledCondition::compile(cond, &raw.id))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let status_code = raw.status_code.unwrap_or(403);
        if raw.action == Action::Allow && raw.status_code.is_some() {
            bail!(
                "rule {}: status_code is only valid for block action",
                raw.id
            );
        }

        Ok(Self {
            id: raw.id.clone(),
            action: raw.action,
            status_code,
            methods,
            path_prefixes,
            ip_cidrs,
            user_agent_contains,
            conditions,
        })
    }

    fn match_details(&self, req: &RequestMeta) -> Option<MatchDetails> {
        if !self.methods.is_empty() {
            let method = req.method.to_ascii_uppercase();
            if !self.methods.iter().any(|m| m == &method) {
                return None;
            }
        }

        let mut path_specificity: u16 = 0;
        if !self.path_prefixes.is_empty() {
            let mut best = 0usize;
            for prefix in &self.path_prefixes {
                if req.path.starts_with(prefix) && prefix.len() > best {
                    best = prefix.len();
                }
            }
            if best == 0 {
                return None;
            }
            path_specificity = best.min(u16::MAX as usize) as u16;
        }

        let mut ip_specificity: u8 = 0;
        if !self.ip_cidrs.is_empty() {
            let mut best: Option<u8> = None;
            for cidr in &self.ip_cidrs {
                if let Some(prefix) = cidr.match_prefix(req.client_ip) {
                    best = Some(best.map_or(prefix, |old| old.max(prefix)));
                }
            }
            let Some(prefix) = best else {
                return None;
            };
            ip_specificity = prefix;
        }

        let mut ua_specificity: u16 = 0;
        if !self.user_agent_contains.is_empty() {
            let ua = req.user_agent.as_deref().unwrap_or("").to_ascii_lowercase();
            let mut best = 0usize;
            for needle in &self.user_agent_contains {
                if ua.contains(needle) && needle.len() > best {
                    best = needle.len();
                }
            }
            if best == 0 {
                return None;
            }
            ua_specificity = best.min(u16::MAX as usize) as u16;
        }

        let mut condition_specificity: u16 = 0;
        if !self.conditions.is_empty() {
            for condition in &self.conditions {
                let Some(specificity) = condition.match_specificity(req) else {
                    return None;
                };
                condition_specificity = condition_specificity.saturating_add(specificity);
            }
        }

        Some(MatchDetails {
            path_specificity,
            ip_specificity,
            ua_specificity,
            condition_specificity,
        })
    }

    fn score(&self, details: MatchDetails) -> MatchScore {
        let mut matched_dimensions = 0u8;
        if !self.methods.is_empty() {
            matched_dimensions += 1;
        }
        if !self.path_prefixes.is_empty() {
            matched_dimensions += 1;
        }
        if !self.ip_cidrs.is_empty() {
            matched_dimensions += 1;
        }
        if !self.user_agent_contains.is_empty() {
            matched_dimensions += 1;
        }
        if !self.conditions.is_empty() {
            matched_dimensions += 1;
        }

        MatchScore {
            matched_dimensions,
            path_specificity: details.path_specificity,
            ip_specificity: details.ip_specificity,
            ua_specificity: details.ua_specificity,
            condition_specificity: details.condition_specificity,
        }
    }
}

impl CompiledCondition {
    fn compile(raw: &ConditionConfig, rule_id: &str) -> anyhow::Result<Self> {
        let source = match &raw.target {
            ConditionTarget::Method => ConditionSource::Method,
            ConditionTarget::Path => ConditionSource::Path,
            ConditionTarget::Query => ConditionSource::Query,
            ConditionTarget::Body => ConditionSource::Body,
            ConditionTarget::UserAgent => ConditionSource::UserAgent,
            ConditionTarget::Header { name } => {
                if name.trim().is_empty() {
                    bail!("rule {}: condition header name must not be empty", rule_id);
                }
                ConditionSource::Header(name.to_ascii_lowercase())
            }
            ConditionTarget::ClientIp => ConditionSource::ClientIp,
        };

        let operator = match raw.operator {
            ConditionOperator::Eq => {
                let value = required_single_value(raw, rule_id, "eq")?;
                CompiledConditionOperator::Eq(value)
            }
            ConditionOperator::Contains => {
                let value = required_single_value(raw, rule_id, "contains")?;
                CompiledConditionOperator::Contains(value)
            }
            ConditionOperator::Prefix => {
                let value = required_single_value(raw, rule_id, "prefix")?;
                CompiledConditionOperator::Prefix(value)
            }
            ConditionOperator::Suffix => {
                let value = required_single_value(raw, rule_id, "suffix")?;
                CompiledConditionOperator::Suffix(value)
            }
            ConditionOperator::Regex => {
                let pattern = required_single_value(raw, rule_id, "regex")?;
                let regex = Regex::new(&pattern)
                    .with_context(|| format!("rule {}: invalid regex {}", rule_id, pattern))?;
                CompiledConditionOperator::Regex(regex)
            }
            ConditionOperator::In => {
                let values = required_list_values(raw, rule_id, "in")?;
                CompiledConditionOperator::In(values)
            }
            ConditionOperator::IpMatch => {
                let values = required_list_values(raw, rule_id, "ip_match")?;
                let cidrs = values
                    .iter()
                    .map(|cidr| Cidr::parse(cidr).with_context(|| format!("rule {}", rule_id)))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                CompiledConditionOperator::IpMatch(cidrs)
            }
        };

        match (&source, &operator) {
            (ConditionSource::ClientIp, CompiledConditionOperator::IpMatch(_)) => {}
            (ConditionSource::ClientIp, _) => {
                bail!(
                    "rule {}: client_ip target only supports ip_match operator",
                    rule_id
                )
            }
            (_, CompiledConditionOperator::IpMatch(_)) => {
                bail!(
                    "rule {}: ip_match operator only supports client_ip target",
                    rule_id
                )
            }
            _ => {}
        }

        let transforms = normalize_transforms(&raw.transforms, rule_id)?;

        Ok(Self {
            source,
            operator,
            transforms,
        })
    }

    fn match_specificity(&self, req: &RequestMeta) -> Option<u16> {
        match (&self.source, &self.operator) {
            (ConditionSource::ClientIp, CompiledConditionOperator::IpMatch(cidrs)) => {
                let mut best: Option<u8> = None;
                for cidr in cidrs {
                    if let Some(prefix) = cidr.match_prefix(req.client_ip) {
                        best = Some(best.map_or(prefix, |old| old.max(prefix)));
                    }
                }
                best.map(u16::from)
            }
            _ => {
                let candidate = self.read_source_value(req)?;
                let transformed = self.apply_transforms(candidate);
                match &self.operator {
                    CompiledConditionOperator::Eq(expected) => (transformed == *expected)
                        .then_some(expected.len().min(u16::MAX as usize) as u16),
                    CompiledConditionOperator::Contains(needle) => transformed
                        .contains(needle)
                        .then_some(needle.len().min(u16::MAX as usize) as u16),
                    CompiledConditionOperator::Prefix(prefix) => transformed
                        .starts_with(prefix)
                        .then_some(prefix.len().min(u16::MAX as usize) as u16),
                    CompiledConditionOperator::Suffix(suffix) => transformed
                        .ends_with(suffix)
                        .then_some(suffix.len().min(u16::MAX as usize) as u16),
                    CompiledConditionOperator::Regex(regex) => regex
                        .find(&transformed)
                        .map(|m| m.as_str().len().min(u16::MAX as usize) as u16),
                    CompiledConditionOperator::In(values) => values
                        .iter()
                        .filter(|v| transformed == v.as_str())
                        .map(|v| v.len().min(u16::MAX as usize) as u16)
                        .max(),
                    CompiledConditionOperator::IpMatch(_) => None,
                }
            }
        }
    }

    fn apply_transforms(&self, input: &str) -> String {
        let mut out = input.to_string();
        for transform in &self.transforms {
            match transform {
                ConditionTransform::None => {}
                ConditionTransform::Lowercase => out = out.to_ascii_lowercase(),
                ConditionTransform::UrlDecode => out = url_decode(&out),
                ConditionTransform::CompressWhitespace => {
                    out = out.split_whitespace().collect::<Vec<_>>().join(" ");
                }
                ConditionTransform::RemoveNulls => out.retain(|ch| ch != '\0'),
            }
        }
        out
    }

    fn read_source_value<'a>(&self, req: &'a RequestMeta) -> Option<&'a str> {
        match &self.source {
            ConditionSource::Method => Some(req.method.as_str()),
            ConditionSource::Path => Some(req.path.as_str()),
            ConditionSource::Query => req.query.as_deref(),
            ConditionSource::Body => req.body.as_deref(),
            ConditionSource::UserAgent => req.user_agent.as_deref(),
            ConditionSource::Header(name) => req.headers.get(name).map(String::as_str),
            ConditionSource::ClientIp => None,
        }
    }
}

fn normalize_transforms(
    transforms: &[ConditionTransform],
    rule_id: &str,
) -> anyhow::Result<Vec<ConditionTransform>> {
    if transforms.is_empty() {
        return Ok(Vec::new());
    }
    if transforms.len() > 1 && transforms.contains(&ConditionTransform::None) {
        bail!(
            "rule {}: transform none cannot be combined with other transforms",
            rule_id
        );
    }

    if transforms.contains(&ConditionTransform::None) {
        return Ok(Vec::new());
    }

    Ok(transforms.to_vec())
}

fn url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;

    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h1), Some(h2)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push((h1 << 4) | h2);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            _ => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

fn required_single_value(
    raw: &ConditionConfig,
    rule_id: &str,
    op_name: &str,
) -> anyhow::Result<String> {
    if !raw.values.is_empty() {
        bail!(
            "rule {}: operator {} requires value, not values",
            rule_id,
            op_name
        );
    }
    let value = raw
        .value
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("rule {}: operator {} requires value", rule_id, op_name))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!(
            "rule {}: operator {} value must not be empty",
            rule_id,
            op_name
        );
    }
    Ok(trimmed.to_string())
}

fn required_list_values(
    raw: &ConditionConfig,
    rule_id: &str,
    op_name: &str,
) -> anyhow::Result<Vec<String>> {
    if raw.value.is_some() {
        bail!(
            "rule {}: operator {} requires values, not value",
            rule_id,
            op_name
        );
    }
    if raw.values.is_empty() {
        bail!(
            "rule {}: operator {} requires non-empty values",
            rule_id,
            op_name
        );
    }
    let mut out = Vec::with_capacity(raw.values.len());
    for value in &raw.values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            bail!(
                "rule {}: operator {} values must not contain empty entries",
                rule_id,
                op_name
            );
        }
        out.push(trimmed.to_string());
    }
    Ok(out)
}

impl Cidr {
    fn parse(input: &str) -> anyhow::Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("CIDR must not be empty");
        }

        let (ip_str, prefix_str) = match trimmed.split_once('/') {
            Some(parts) => parts,
            None => {
                let ip: IpAddr = trimmed.parse()?;
                return Ok(match ip {
                    IpAddr::V4(v4) => Cidr::V4 {
                        network: u32::from(v4),
                        prefix: 32,
                    },
                    IpAddr::V6(v6) => Cidr::V6 {
                        network: u128::from(v6),
                        prefix: 128,
                    },
                });
            }
        };

        let ip: IpAddr = ip_str.parse()?;
        let prefix: u8 = prefix_str.parse()?;

        match ip {
            IpAddr::V4(addr) => {
                if prefix > 32 {
                    bail!("invalid IPv4 prefix length {}", prefix);
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                let network = u32::from(addr) & mask;
                Ok(Cidr::V4 { network, prefix })
            }
            IpAddr::V6(addr) => {
                if prefix > 128 {
                    bail!("invalid IPv6 prefix length {}", prefix);
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                let network = u128::from(addr) & mask;
                Ok(Cidr::V6 { network, prefix })
            }
        }
    }

    fn match_prefix(self, ip: IpAddr) -> Option<u8> {
        match (self, ip) {
            (Cidr::V4 { network, prefix }, IpAddr::V4(addr)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                ((u32::from(addr) & mask) == network).then_some(prefix)
            }
            (Cidr::V6 { network, prefix }, IpAddr::V6(addr)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                ((u128::from(addr) & mask) == network).then_some(prefix)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Action, AppConfig, ConditionConfig, ConditionOperator, ConditionTarget, ConditionTransform,
        ProfileConfig, RuleConfig, SiteConfig, UpstreamConfig,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_req(ip: IpAddr, method: &str, path: &str, ua: Option<&str>) -> RequestMeta {
        let (path_only, query) = match path.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (path.to_string(), None),
        };
        RequestMeta {
            client_ip: ip,
            method: method.to_string(),
            path: path_only,
            query,
            user_agent: ua.map(ToString::to_string),
            headers: std::collections::HashMap::new(),
            body: None,
        }
    }

    fn base_cfg(profiles: Vec<ProfileConfig>) -> AppConfig {
        AppConfig {
            sites: vec![SiteConfig {
                id: "s1".to_string(),
                listen: "127.0.0.1:8080".to_string(),
                upstream: UpstreamConfig {
                    url: "http://127.0.0.1:9000".to_string(),
                },
                profile: "p1".to_string(),
            }],
            profiles,
            engine: Default::default(),
        }
    }

    #[test]
    fn cidr_ipv4_matches() {
        let cidr = Cidr::parse("10.0.0.0/8").unwrap();
        assert_eq!(
            cidr.match_prefix(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            Some(8)
        );
        assert_eq!(
            cidr.match_prefix(IpAddr::V4(Ipv4Addr::new(11, 1, 2, 3))),
            None
        );
    }

    #[test]
    fn cidr_ipv6_matches() {
        let cidr = Cidr::parse("2001:db8::/32").unwrap();
        assert_eq!(
            cidr.match_prefix(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())),
            Some(32)
        );
        assert_eq!(
            cidr.match_prefix(IpAddr::V6("2001:db9::1".parse::<Ipv6Addr>().unwrap())),
            None
        );
    }

    #[test]
    fn default_action_by_profile() {
        let cfg = base_cfg(vec![
            ProfileConfig {
                id: "p1".to_string(),
                default_action: Action::Allow,
                rules: vec![],
            },
            ProfileConfig {
                id: "p2".to_string(),
                default_action: Action::Block,
                rules: vec![],
            },
        ]);
        let snapshot = EngineSnapshot::from_app_config(&cfg);
        let engine = WafEngine::from_snapshot(snapshot).unwrap();

        assert_eq!(
            engine
                .decide(
                    "p1",
                    &test_req(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "GET", "/", None)
                )
                .unwrap()
                .action,
            Action::Allow
        );
        assert_eq!(
            engine
                .decide(
                    "p2",
                    &test_req(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "GET", "/", None)
                )
                .unwrap()
                .action,
            Action::Block
        );
    }

    #[test]
    fn best_match_picks_more_specific_rule() {
        let cfg = base_cfg(vec![ProfileConfig {
            id: "p1".to_string(),
            default_action: Action::Allow,
            rules: vec![
                RuleConfig {
                    id: "generic-admin".to_string(),
                    enabled: true,
                    action: Action::Block,
                    status_code: Some(403),
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/admin".to_string()],
                    ip_cidrs: vec![],
                    user_agent_contains: vec![],
                    conditions: vec![],
                },
                RuleConfig {
                    id: "specific-admin".to_string(),
                    enabled: true,
                    action: Action::Block,
                    status_code: Some(403),
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/admin/secure".to_string()],
                    ip_cidrs: vec![],
                    user_agent_contains: vec![],
                    conditions: vec![],
                },
            ],
        }]);
        let snapshot = EngineSnapshot::from_app_config(&cfg);
        let engine = WafEngine::from_snapshot(snapshot).unwrap();
        let decision = engine
            .decide(
                "p1",
                &test_req(
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    "GET",
                    "/admin/secure/panel",
                    None,
                ),
            )
            .unwrap();
        assert_eq!(decision.matched_rule_id.as_deref(), Some("specific-admin"));
    }

    #[test]
    fn snapshot_roundtrip_decision() {
        let cfg = base_cfg(vec![ProfileConfig {
            id: "p1".to_string(),
            default_action: Action::Allow,
            rules: vec![RuleConfig {
                id: "block-curl".to_string(),
                enabled: true,
                action: Action::Block,
                status_code: Some(403),
                methods: vec![],
                path_prefixes: vec![],
                ip_cidrs: vec![],
                user_agent_contains: vec!["curl".to_string()],
                conditions: vec![],
            }],
        }]);
        let snapshot = EngineSnapshot::from_app_config(&cfg);
        let engine = WafEngine::from_snapshot(snapshot).unwrap();
        let decision = engine
            .decide(
                "p1",
                &test_req(
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    "GET",
                    "/",
                    Some("curl/8.0"),
                ),
            )
            .unwrap();
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn condition_header_contains_matches() {
        let cfg = base_cfg(vec![ProfileConfig {
            id: "p1".to_string(),
            default_action: Action::Allow,
            rules: vec![RuleConfig {
                id: "block-bad-header".to_string(),
                enabled: true,
                action: Action::Block,
                status_code: Some(403),
                methods: vec![],
                path_prefixes: vec![],
                ip_cidrs: vec![],
                user_agent_contains: vec![],
                conditions: vec![ConditionConfig {
                    target: ConditionTarget::Header {
                        name: "x-risk".to_string(),
                    },
                    operator: ConditionOperator::Contains,
                    value: Some("bot".to_string()),
                    values: vec![],
                    transforms: vec![],
                }],
            }],
        }]);

        let snapshot = EngineSnapshot::from_app_config(&cfg);
        let engine = WafEngine::from_snapshot(snapshot).unwrap();
        let decision = engine
            .decide(
                "p1",
                &RequestMeta {
                    client_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    query: None,
                    user_agent: None,
                    headers: std::collections::HashMap::from([(
                        "x-risk".to_string(),
                        "known-bot".to_string(),
                    )]),
                    body: None,
                },
            )
            .unwrap();

        assert_eq!(decision.action, Action::Block);
        assert_eq!(
            decision.matched_rule_id.as_deref(),
            Some("block-bad-header")
        );
    }

    #[test]
    fn condition_query_regex_matches() {
        let cfg = base_cfg(vec![ProfileConfig {
            id: "p1".to_string(),
            default_action: Action::Allow,
            rules: vec![RuleConfig {
                id: "block-union".to_string(),
                enabled: true,
                action: Action::Block,
                status_code: Some(403),
                methods: vec![],
                path_prefixes: vec![],
                ip_cidrs: vec![],
                user_agent_contains: vec![],
                conditions: vec![ConditionConfig {
                    target: ConditionTarget::Query,
                    operator: ConditionOperator::Regex,
                    value: Some("(?i)union\\+select".to_string()),
                    values: vec![],
                    transforms: vec![],
                }],
            }],
        }]);

        let snapshot = EngineSnapshot::from_app_config(&cfg);
        let engine = WafEngine::from_snapshot(snapshot).unwrap();
        let decision = engine
            .decide(
                "p1",
                &RequestMeta {
                    client_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    method: "GET".to_string(),
                    path: "/search".to_string(),
                    query: Some("q=1+UNION+SELECT+2".to_string()),
                    user_agent: None,
                    headers: std::collections::HashMap::new(),
                    body: None,
                },
            )
            .unwrap();

        assert_eq!(decision.action, Action::Block);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("block-union"));
    }

    #[test]
    fn condition_body_contains_matches() {
        let cfg = base_cfg(vec![ProfileConfig {
            id: "p1".to_string(),
            default_action: Action::Allow,
            rules: vec![RuleConfig {
                id: "block-body-token".to_string(),
                enabled: true,
                action: Action::Block,
                status_code: Some(403),
                methods: vec![],
                path_prefixes: vec![],
                ip_cidrs: vec![],
                user_agent_contains: vec![],
                conditions: vec![ConditionConfig {
                    target: ConditionTarget::Body,
                    operator: ConditionOperator::Contains,
                    value: Some("drop table".to_string()),
                    values: vec![],
                    transforms: vec![],
                }],
            }],
        }]);

        let snapshot = EngineSnapshot::from_app_config(&cfg);
        let engine = WafEngine::from_snapshot(snapshot).unwrap();
        let decision = engine
            .decide(
                "p1",
                &RequestMeta {
                    client_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    method: "POST".to_string(),
                    path: "/submit".to_string(),
                    query: None,
                    user_agent: None,
                    headers: std::collections::HashMap::new(),
                    body: Some("name=x;drop table users".to_string()),
                },
            )
            .unwrap();

        assert_eq!(decision.action, Action::Block);
        assert_eq!(
            decision.matched_rule_id.as_deref(),
            Some("block-body-token")
        );
    }

    #[test]
    fn condition_transform_lowercase_and_url_decode_matches() {
        let cfg = base_cfg(vec![ProfileConfig {
            id: "p1".to_string(),
            default_action: Action::Allow,
            rules: vec![RuleConfig {
                id: "block-union-decoded".to_string(),
                enabled: true,
                action: Action::Block,
                status_code: Some(403),
                methods: vec![],
                path_prefixes: vec![],
                ip_cidrs: vec![],
                user_agent_contains: vec![],
                conditions: vec![ConditionConfig {
                    target: ConditionTarget::Query,
                    operator: ConditionOperator::Contains,
                    value: Some("union select".to_string()),
                    values: vec![],
                    transforms: vec![ConditionTransform::UrlDecode, ConditionTransform::Lowercase],
                }],
            }],
        }]);

        let snapshot = EngineSnapshot::from_app_config(&cfg);
        let engine = WafEngine::from_snapshot(snapshot).unwrap();
        let decision = engine
            .decide(
                "p1",
                &RequestMeta {
                    client_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    method: "GET".to_string(),
                    path: "/search".to_string(),
                    query: Some("q=UNIOn%20SELECT%201".to_string()),
                    user_agent: None,
                    headers: std::collections::HashMap::new(),
                    body: None,
                },
            )
            .unwrap();

        assert_eq!(decision.action, Action::Block);
        assert_eq!(
            decision.matched_rule_id.as_deref(),
            Some("block-union-decoded")
        );
    }

    #[test]
    fn condition_transform_compress_whitespace_matches() {
        let cfg = base_cfg(vec![ProfileConfig {
            id: "p1".to_string(),
            default_action: Action::Allow,
            rules: vec![RuleConfig {
                id: "block-spaced-pattern".to_string(),
                enabled: true,
                action: Action::Block,
                status_code: Some(403),
                methods: vec![],
                path_prefixes: vec![],
                ip_cidrs: vec![],
                user_agent_contains: vec![],
                conditions: vec![ConditionConfig {
                    target: ConditionTarget::Body,
                    operator: ConditionOperator::Contains,
                    value: Some("select from users".to_string()),
                    values: vec![],
                    transforms: vec![ConditionTransform::CompressWhitespace],
                }],
            }],
        }]);

        let snapshot = EngineSnapshot::from_app_config(&cfg);
        let engine = WafEngine::from_snapshot(snapshot).unwrap();
        let decision = engine
            .decide(
                "p1",
                &RequestMeta {
                    client_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    method: "POST".to_string(),
                    path: "/submit".to_string(),
                    query: None,
                    user_agent: None,
                    headers: std::collections::HashMap::new(),
                    body: Some("select   from\nusers".to_string()),
                },
            )
            .unwrap();

        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn condition_transform_none_cannot_mix_with_others() {
        let cfg = base_cfg(vec![ProfileConfig {
            id: "p1".to_string(),
            default_action: Action::Allow,
            rules: vec![RuleConfig {
                id: "bad-transform-rule".to_string(),
                enabled: true,
                action: Action::Block,
                status_code: Some(403),
                methods: vec![],
                path_prefixes: vec![],
                ip_cidrs: vec![],
                user_agent_contains: vec![],
                conditions: vec![ConditionConfig {
                    target: ConditionTarget::Path,
                    operator: ConditionOperator::Contains,
                    value: Some("admin".to_string()),
                    values: vec![],
                    transforms: vec![ConditionTransform::None, ConditionTransform::Lowercase],
                }],
            }],
        }]);

        let snapshot = EngineSnapshot::from_app_config(&cfg);
        assert!(WafEngine::from_snapshot(snapshot).is_err());
    }
}
