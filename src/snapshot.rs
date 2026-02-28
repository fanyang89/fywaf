use std::fs;
use std::path::Path;

use anyhow::{Context, bail};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize, rancor::Error};

use crate::config::{Action, AppConfig, RuleConfig};

const SNAPSHOT_MAGIC: [u8; 8] = *b"FYWAFBIN";
const SNAPSHOT_VERSION: u32 = 1;
const HEADER_LEN: usize = 20;

#[derive(Debug, Clone, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct EngineSnapshot {
    pub profiles: Vec<SnapshotProfile>,
}

#[derive(Debug, Clone, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct SnapshotProfile {
    pub id: String,
    pub default_action: Action,
    pub rules: Vec<RuleConfig>,
}

impl EngineSnapshot {
    pub fn from_app_config(cfg: &AppConfig) -> Self {
        let profiles = cfg
            .profiles
            .iter()
            .map(|profile| SnapshotProfile {
                id: profile.id.clone(),
                default_action: profile.default_action,
                rules: profile.rules.clone(),
            })
            .collect();
        Self { profiles }
    }

    pub fn read_from_path(path: &Path) -> anyhow::Result<Self> {
        let data = fs::read(path)
            .with_context(|| format!("failed to read snapshot {}", path.display()))?;

        if data.len() < HEADER_LEN {
            bail!("invalid snapshot {}: too short", path.display());
        }

        let magic = &data[0..8];
        if magic != SNAPSHOT_MAGIC {
            bail!("invalid snapshot {}: bad magic header", path.display());
        }

        let version = u32::from_le_bytes(data[8..12].try_into().expect("header slice len"));
        if version != SNAPSHOT_VERSION {
            bail!(
                "unsupported snapshot {}: version {} (expected {})",
                path.display(),
                version,
                SNAPSHOT_VERSION
            );
        }

        let payload_len =
            u32::from_le_bytes(data[12..16].try_into().expect("header slice len")) as usize;
        let checksum = u32::from_le_bytes(data[16..20].try_into().expect("header slice len"));
        let payload = &data[20..];

        if payload.len() != payload_len {
            bail!(
                "invalid snapshot {}: payload size mismatch (header {}, actual {})",
                path.display(),
                payload_len,
                payload.len()
            );
        }

        let actual_checksum = crc32fast::hash(payload);
        if actual_checksum != checksum {
            bail!("invalid snapshot {}: checksum mismatch", path.display());
        }

        let snapshot = rkyv::from_bytes::<EngineSnapshot, Error>(payload)
            .with_context(|| format!("invalid snapshot {} payload", path.display()))?;
        Ok(snapshot)
    }

    pub fn write_to_path(&self, path: &Path) -> anyhow::Result<()> {
        let payload =
            rkyv::to_bytes::<Error>(self).context("failed to serialize snapshot payload")?;
        let checksum = crc32fast::hash(&payload);

        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(&SNAPSHOT_MAGIC);
        out.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&checksum.to_le_bytes());
        out.extend_from_slice(&payload);

        fs::write(path, out).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    pub fn version() -> u32 {
        SNAPSHOT_VERSION
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::config::{EngineConfig, ProfileConfig, SiteConfig, UpstreamConfig};

    fn test_config() -> AppConfig {
        AppConfig {
            sites: vec![SiteConfig {
                id: "site-a".to_string(),
                listen: "127.0.0.1:8080".to_string(),
                upstream: UpstreamConfig {
                    url: "http://127.0.0.1:9000".to_string(),
                },
                profile: "p1".to_string(),
            }],
            profiles: vec![ProfileConfig {
                id: "p1".to_string(),
                default_action: Action::Allow,
                rules: vec![RuleConfig {
                    id: "r1".to_string(),
                    enabled: true,
                    action: Action::Block,
                    status_code: Some(403),
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/admin".to_string()],
                    ip_cidrs: vec![],
                    user_agent_contains: vec!["curl".to_string()],
                    conditions: vec![],
                }],
            }],
            engine: EngineConfig {
                snapshot_path: Some("examples/rules.snapshot.bin".to_string()),
            },
        }
    }

    fn temp_snapshot_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("fywaf-{name}-{nanos}.bin"))
    }

    #[test]
    fn snapshot_roundtrip_binary() {
        let cfg = test_config();
        let snapshot = EngineSnapshot::from_app_config(&cfg);
        let path = temp_snapshot_path("roundtrip");

        snapshot.write_to_path(&path).unwrap();
        let loaded = EngineSnapshot::read_from_path(&path).unwrap();

        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profiles[0].id, "p1");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn snapshot_detects_corruption() {
        let cfg = test_config();
        let snapshot = EngineSnapshot::from_app_config(&cfg);
        let path = temp_snapshot_path("corrupt");

        snapshot.write_to_path(&path).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let tail = bytes.len() - 1;
        bytes[tail] ^= 0xFF;
        fs::write(&path, bytes).unwrap();

        assert!(EngineSnapshot::read_from_path(&path).is_err());
        let _ = fs::remove_file(path);
    }
}
