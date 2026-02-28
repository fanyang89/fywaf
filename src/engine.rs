use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, bail};

use crate::config::{Action, RuleConfig, WafConfig};

#[derive(Debug)]
pub struct WafEngine {
    default_action: Action,
    rules: Vec<CompiledRule>,
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
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub status_code: u16,
    pub matched_rule_id: Option<String>,
}

impl WafEngine {
    pub fn from_config(cfg: &WafConfig) -> anyhow::Result<Self> {
        let mut rules = Vec::new();

        for raw in &cfg.rules {
            if !raw.enabled {
                continue;
            }
            rules.push(CompiledRule::compile(raw)?);
        }

        Ok(Self {
            default_action: cfg.default_action,
            rules,
        })
    }

    pub fn decide(&self, req: &RequestMeta) -> Decision {
        for rule in &self.rules {
            if rule.matches(req) {
                return Decision {
                    action: rule.action,
                    status_code: rule.status_code,
                    matched_rule_id: Some(rule.id.clone()),
                };
            }
        }

        match self.default_action {
            Action::Allow => Decision {
                action: Action::Allow,
                status_code: 200,
                matched_rule_id: None,
            },
            Action::Block => Decision {
                action: Action::Block,
                status_code: 403,
                matched_rule_id: None,
            },
        }
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

        let status_code = raw.status_code.unwrap_or(403);
        if raw.action == Action::Allow && raw.status_code.is_some() {
            bail!("rule {}: status_code is only valid for block action", raw.id);
        }

        Ok(Self {
            id: raw.id.clone(),
            action: raw.action,
            status_code,
            methods,
            path_prefixes,
            ip_cidrs,
            user_agent_contains,
        })
    }

    fn matches(&self, req: &RequestMeta) -> bool {
        if !self.methods.is_empty() {
            let method = req.method.to_ascii_uppercase();
            if !self.methods.iter().any(|m| m == &method) {
                return false;
            }
        }

        if !self.path_prefixes.is_empty()
            && !self.path_prefixes.iter().any(|p| req.path.starts_with(p))
        {
            return false;
        }

        if !self.ip_cidrs.is_empty() && !self.ip_cidrs.iter().any(|cidr| cidr.contains(req.client_ip))
        {
            return false;
        }

        if !self.user_agent_contains.is_empty() {
            let ua = req.user_agent.as_deref().unwrap_or("").to_ascii_lowercase();
            if !self.user_agent_contains.iter().any(|needle| ua.contains(needle)) {
                return false;
            }
        }

        true
    }
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

    fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { network, prefix }, IpAddr::V4(addr)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (u32::from(addr) & mask) == network
            }
            (Cidr::V6 { network, prefix }, IpAddr::V6(addr)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                (u128::from(addr) & mask) == network
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Action, RuleConfig, WafConfig};

    fn test_req(ip: IpAddr, method: &str, path: &str, ua: Option<&str>) -> RequestMeta {
        RequestMeta {
            client_ip: ip,
            method: method.to_string(),
            path: path.to_string(),
            user_agent: ua.map(ToString::to_string),
        }
    }

    #[test]
    fn cidr_ipv4_contains() {
        let cidr = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!cidr.contains(IpAddr::V4(Ipv4Addr::new(11, 1, 2, 3))));
    }

    #[test]
    fn cidr_ipv6_contains() {
        let cidr = Cidr::parse("2001:db8::/32").unwrap();
        assert!(cidr.contains(IpAddr::V6(
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!cidr.contains(IpAddr::V6(
            "2001:db9::1".parse::<Ipv6Addr>().unwrap()
        )));
    }

    #[test]
    fn match_first_rule() {
        let cfg = WafConfig {
            default_action: Action::Allow,
            rules: vec![
                RuleConfig {
                    id: "block-admin".to_string(),
                    enabled: true,
                    action: Action::Block,
                    status_code: Some(403),
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/admin".to_string()],
                    ip_cidrs: vec![],
                    user_agent_contains: vec![],
                },
                RuleConfig {
                    id: "allow-all".to_string(),
                    enabled: true,
                    action: Action::Allow,
                    status_code: None,
                    methods: vec![],
                    path_prefixes: vec![],
                    ip_cidrs: vec![],
                    user_agent_contains: vec![],
                },
            ],
        };

        let engine = WafEngine::from_config(&cfg).unwrap();
        let decision = engine.decide(&test_req(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            "GET",
            "/admin/dashboard",
            Some("curl"),
        ));
        assert_eq!(decision.action, Action::Block);
        assert_eq!(decision.status_code, 403);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("block-admin"));
    }

    #[test]
    fn default_allow_when_no_match() {
        let cfg = WafConfig {
            default_action: Action::Allow,
            rules: vec![RuleConfig {
                id: "only-post".to_string(),
                enabled: true,
                action: Action::Block,
                status_code: Some(403),
                methods: vec!["POST".to_string()],
                path_prefixes: vec!["/admin".to_string()],
                ip_cidrs: vec![],
                user_agent_contains: vec![],
            }],
        };

        let engine = WafEngine::from_config(&cfg).unwrap();
        let decision = engine.decide(&test_req(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            "GET",
            "/",
            None,
        ));
        assert_eq!(decision.action, Action::Allow);
        assert!(decision.matched_rule_id.is_none());
    }
}
