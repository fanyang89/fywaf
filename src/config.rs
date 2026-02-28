use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub sites: Vec<SiteConfig>,
    pub profiles: Vec<ProfileConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SiteConfig {
    pub id: String,
    pub listen: String,
    pub upstream: UpstreamConfig,
    pub profile: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProfileConfig {
    pub id: String,
    pub default_action: Action,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Block,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub action: Action,
    pub status_code: Option<u16>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    #[serde(default)]
    pub user_agent_contains: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

impl AppConfig {
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config: AppConfig = serde_yaml::from_str(&raw)
            .with_context(|| format!("invalid yaml in {}", path.display()))?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.sites.is_empty() {
            bail!("sites must not be empty");
        }
        if self.profiles.is_empty() {
            bail!("profiles must not be empty");
        }

        let mut profile_ids = HashSet::new();
        for profile in &self.profiles {
            if profile.id.trim().is_empty() {
                bail!("profile.id must not be empty");
            }
            if !profile_ids.insert(profile.id.clone()) {
                bail!("duplicate profile.id found: {}", profile.id);
            }

            let mut rule_ids = HashSet::new();
            for rule in &profile.rules {
                if rule.id.trim().is_empty() {
                    bail!("rule.id must not be empty in profile {}", profile.id);
                }
                if !rule_ids.insert(rule.id.clone()) {
                    bail!(
                        "duplicate rule.id found in profile {}: {}",
                        profile.id,
                        rule.id
                    );
                }
                if let Some(status) = rule.status_code {
                    if !(100..=599).contains(&status) {
                        bail!(
                            "profile {} rule {} has invalid status_code {}",
                            profile.id,
                            rule.id,
                            status
                        );
                    }
                }
            }
        }

        let profile_lookup: HashMap<&str, ()> = self
            .profiles
            .iter()
            .map(|profile| (profile.id.as_str(), ()))
            .collect();

        let mut site_ids = HashSet::new();
        let mut listen_addrs = HashSet::new();
        for site in &self.sites {
            if site.id.trim().is_empty() {
                bail!("site.id must not be empty");
            }
            if !site_ids.insert(site.id.clone()) {
                bail!("duplicate site.id found: {}", site.id);
            }
            if site.listen.trim().is_empty() {
                bail!("site {} listen must not be empty", site.id);
            }
            if !listen_addrs.insert(site.listen.clone()) {
                bail!("duplicate site.listen found: {}", site.listen);
            }
            if site.upstream.url.trim().is_empty() {
                bail!("site {} upstream.url must not be empty", site.id);
            }
            if !site.upstream.url.starts_with("http://") {
                bail!(
                    "site {} upstream.url must start with http:// for MVP",
                    site.id
                );
            }
            if !profile_lookup.contains_key(site.profile.as_str()) {
                bail!(
                    "site {} references missing profile {}",
                    site.id,
                    site.profile
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> AppConfig {
        AppConfig {
            sites: vec![SiteConfig {
                id: "site-a".to_string(),
                listen: "127.0.0.1:8080".to_string(),
                upstream: UpstreamConfig {
                    url: "http://127.0.0.1:9000".to_string(),
                },
                profile: "public".to_string(),
            }],
            profiles: vec![ProfileConfig {
                id: "public".to_string(),
                default_action: Action::Allow,
                rules: vec![],
            }],
        }
    }

    #[test]
    fn validate_ok() {
        let cfg = valid_config();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_fails_missing_profile_reference() {
        let mut cfg = valid_config();
        cfg.sites[0].profile = "missing".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_fails_duplicate_listen() {
        let mut cfg = valid_config();
        cfg.sites.push(SiteConfig {
            id: "site-b".to_string(),
            listen: "127.0.0.1:8080".to_string(),
            upstream: UpstreamConfig {
                url: "http://127.0.0.1:9001".to_string(),
            },
            profile: "public".to_string(),
        });
        assert!(cfg.validate().is_err());
    }
}
