use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, bail};
use fory::{Fory, ForyObject};

use crate::config::{Action, AppConfig, RuleConfig};

const SNAPSHOT_MAGIC: &[u8; 8] = b"FYWAF-FY";
const SNAPSHOT_VERSION: u32 = 2;
const HEADER_SIZE: usize = 20;

#[derive(Debug, Clone, ForyObject)]
pub struct SnapshotProfile {
    pub id: String,
    pub default_action: Action,
    pub rules: Vec<RuleConfig>,
}

pub struct EngineSnapshot {
    pub profiles: Vec<SnapshotProfile>,
}

struct ProfileIndex {
    offset: u64,
    size: u64,
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
        let mut file = File::open(path)
            .with_context(|| format!("failed to open snapshot {}", path.display()))?;

        let mut header_buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf)
            .with_context(|| format!("failed to read snapshot header {}", path.display()))?;

        if &header_buf[0..8] != SNAPSHOT_MAGIC {
            bail!("invalid snapshot {}: bad magic header", path.display());
        }

        let version = u32::from_le_bytes(header_buf[8..12].try_into().expect("header slice"));
        if version != SNAPSHOT_VERSION {
            bail!(
                "unsupported snapshot {}: version {} (expected {})",
                path.display(),
                version,
                SNAPSHOT_VERSION
            );
        }

        let profile_count =
            u32::from_le_bytes(header_buf[12..16].try_into().expect("header slice"));

        let index_size = profile_count as usize * 16;
        let mut index_buf = vec![0u8; index_size];
        file.read_exact(&mut index_buf)
            .with_context(|| format!("failed to read snapshot index {}", path.display()))?;

        let indices: Vec<ProfileIndex> = (0..profile_count)
            .map(|i| {
                let offset = i as usize * 16;
                ProfileIndex {
                    offset: u64::from_le_bytes(index_buf[offset..offset + 8].try_into().unwrap()),
                    size: u64::from_le_bytes(
                        index_buf[offset + 8..offset + 16].try_into().unwrap(),
                    ),
                }
            })
            .collect();

        let mut fory = Fory::default();
        fory.register::<SnapshotProfile>(1)?;
        fory.register::<RuleConfig>(2)?;
        fory.register::<crate::config::Action>(3)?;
        fory.register::<crate::config::ConditionConfig>(4)?;
        fory.register::<crate::config::ConditionTarget>(5)?;
        fory.register::<crate::config::ConditionOperator>(6)?;
        fory.register::<crate::config::ConditionTransform>(7)?;

        let mut profiles = Vec::with_capacity(profile_count as usize);
        for (i, idx) in indices.iter().enumerate() {
            file.seek(SeekFrom::Start(idx.offset)).with_context(|| {
                format!("failed to seek to profile {} in {}", i, path.display())
            })?;

            let mut payload = vec![0u8; idx.size as usize];
            file.read_exact(&mut payload)
                .with_context(|| format!("failed to read profile {} in {}", i, path.display()))?;

            let profile: SnapshotProfile = fory.deserialize(&payload).with_context(|| {
                format!("failed to deserialize profile {} in {}", i, path.display())
            })?;
            profiles.push(profile);
        }

        Ok(Self { profiles })
    }

    pub fn write_to_path(&self, path: &Path) -> anyhow::Result<()> {
        let mut file = File::create(path)
            .with_context(|| format!("failed to create snapshot {}", path.display()))?;

        let mut fory = Fory::default();
        fory.register::<SnapshotProfile>(1)?;
        fory.register::<RuleConfig>(2)?;
        fory.register::<crate::config::Action>(3)?;
        fory.register::<crate::config::ConditionConfig>(4)?;
        fory.register::<crate::config::ConditionTarget>(5)?;
        fory.register::<crate::config::ConditionOperator>(6)?;
        fory.register::<crate::config::ConditionTransform>(7)?;

        let payloads: Vec<Vec<u8>> = self
            .profiles
            .iter()
            .map(|p| fory.serialize(p).context("failed to serialize profile"))
            .collect::<Result<_, anyhow::Error>>()?;

        let data_start = HEADER_SIZE + payloads.len() * 16;

        file.write_all(SNAPSHOT_MAGIC)
            .with_context(|| format!("failed to write magic to {}", path.display()))?;
        file.write_all(&SNAPSHOT_VERSION.to_le_bytes())
            .with_context(|| format!("failed to write version to {}", path.display()))?;
        file.write_all(&(payloads.len() as u32).to_le_bytes())
            .with_context(|| format!("failed to write count to {}", path.display()))?;
        file.write_all(&[0u8; 4])
            .with_context(|| format!("failed to write padding to {}", path.display()))?;

        let mut current_offset = data_start as u64;
        for payload in &payloads {
            file.write_all(&current_offset.to_le_bytes())
                .with_context(|| format!("failed to write offset to {}", path.display()))?;
            file.write_all(&(payload.len() as u64).to_le_bytes())
                .with_context(|| format!("failed to write size to {}", path.display()))?;
            current_offset += payload.len() as u64;
        }

        for payload in &payloads {
            file.write_all(payload)
                .with_context(|| format!("failed to write payload to {}", path.display()))?;
        }

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
