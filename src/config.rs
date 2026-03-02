use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{bail, Context};
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
    pub wasm_path: String,
    /// Optional key-value parameters forwarded to the WASM module in each
    /// request JSON (e.g. `paranoia_level`, `anomaly_threshold`).
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
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
            if profile.wasm_path.trim().is_empty() {
                bail!("profile {} wasm_path must not be empty", profile.id);
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
                wasm_path: "wasm/public.wasm".to_string(),
                params: HashMap::new(),
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

    #[test]
    fn validate_fails_empty_wasm_path() {
        let mut cfg = valid_config();
        cfg.profiles[0].wasm_path = "  ".to_string();
        assert!(cfg.validate().is_err());
    }
}
