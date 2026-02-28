use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub waf: WafConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WafConfig {
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
        if self.server.listen.trim().is_empty() {
            bail!("server.listen must not be empty");
        }
        if self.upstream.url.trim().is_empty() {
            bail!("upstream.url must not be empty");
        }
        if !self.upstream.url.starts_with("http://") {
            bail!("upstream.url must start with http:// for MVP");
        }

        let mut ids = HashSet::new();
        for rule in &self.waf.rules {
            if rule.id.trim().is_empty() {
                bail!("rule.id must not be empty");
            }
            if !ids.insert(rule.id.clone()) {
                bail!("duplicate rule.id found: {}", rule.id);
            }
            if let Some(status) = rule.status_code {
                if !(100..=599).contains(&status) {
                    bail!("rule {} has invalid status_code {}", rule.id, status);
                }
            }
        }

        Ok(())
    }
}
