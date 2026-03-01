use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use serde::Serialize;

use crate::secrule_parser::{
    collect_conf_files, join_continued_lines, parse_action_id, parse_quoted_pair, split_actions,
    split_first_token,
};

use crate::config::{
    Action, ConditionConfig, ConditionOperator, ConditionTarget, ConditionTransform,
};

#[derive(Debug, Clone)]
pub struct ImportCrsOptions {
    pub rules_dir: PathBuf,
    pub out: PathBuf,
    pub profile_id: String,
    pub default_action: String,
    pub report_out: PathBuf,
}

#[derive(Debug, Serialize)]
struct ImportOutput {
    profiles: Vec<ImportedProfile>,
}

#[derive(Debug, Serialize)]
struct ImportedProfile {
    id: String,
    default_action: Action,
    rules: Vec<ImportedRule>,
}

#[derive(Debug, Serialize, Clone)]
struct ImportedRule {
    id: String,
    enabled: bool,
    action: Action,
    status_code: Option<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    methods: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    path_prefixes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ip_cidrs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_agent_contains: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    conditions: Vec<ConditionConfig>,
}

#[derive(Debug)]
struct ParseResult {
    rule_id: String,
    status: ImportStatus,
    reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportStatus {
    Imported,
    Skipped,
}

#[derive(Debug)]
struct ParsedSecRule {
    target: String,
    operator: String,
    actions_raw: String,
    action: Action,
    status_code: Option<u16>,
    rule_id: String,
    transforms: Vec<ConditionTransform>,
}

pub fn run(options: ImportCrsOptions) -> anyhow::Result<()> {
    let default_action = parse_default_action(&options.default_action)?;

    let mut files = Vec::new();
    collect_conf_files(&options.rules_dir, &mut files)?;
    files.sort();

    let mut imported_rules = Vec::new();
    let mut parse_results = Vec::new();

    for file in &files {
        let (mut rules, mut results) = import_file(file)?;
        imported_rules.append(&mut rules);
        parse_results.append(&mut results);
    }

    let output = ImportOutput {
        profiles: vec![ImportedProfile {
            id: options.profile_id,
            default_action,
            rules: imported_rules,
        }],
    };

    let yaml = serde_yaml::to_string(&output).context("failed to render import YAML")?;
    fs::write(&options.out, yaml)
        .with_context(|| format!("failed to write import output {}", options.out.display()))?;

    let report = render_report(&files, &parse_results);
    fs::write(&options.report_out, report)
        .with_context(|| format!("failed to write report {}", options.report_out.display()))?;

    println!("imported profile written to {}", options.out.display());
    println!("report written to {}", options.report_out.display());
    Ok(())
}

fn parse_default_action(input: &str) -> anyhow::Result<Action> {
    match input.trim().to_ascii_lowercase().as_str() {
        "allow" => Ok(Action::Allow),
        "block" => Ok(Action::Block),
        other => bail!("invalid --default-action {}, expected allow|block", other),
    }
}

fn import_file(path: &Path) -> anyhow::Result<(Vec<ImportedRule>, Vec<ParseResult>)> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read rule file {}", path.display()))?;
    let statements = join_continued_lines(&raw);
    let mut rules = Vec::new();
    let mut results = Vec::new();

    for statement in statements {
        let Some(body) = statement.trim_start().strip_prefix("SecRule ") else {
            continue;
        };
        let Some((target, tail)) = split_first_token(body) else {
            continue;
        };
        let Some((operator, actions)) = parse_quoted_pair(tail) else {
            continue;
        };

        let parsed = match parse_secrule(target, operator, actions) {
            Ok(parsed) => parsed,
            Err(err) => {
                results.push(ParseResult {
                    rule_id: "(no-id)".to_string(),
                    status: ImportStatus::Skipped,
                    reason: format!("parse_error: {}", err),
                });
                continue;
            }
        };

        match map_rule(&parsed, path.parent()) {
            Ok(mapped) => {
                for rule in mapped {
                    rules.push(rule);
                }
                results.push(ParseResult {
                    rule_id: parsed.rule_id,
                    status: ImportStatus::Imported,
                    reason: "ok".to_string(),
                });
            }
            Err(err) => {
                results.push(ParseResult {
                    rule_id: parsed.rule_id,
                    status: ImportStatus::Skipped,
                    reason: err.to_string(),
                });
            }
        }
    }

    Ok((rules, results))
}

fn parse_secrule(target: &str, operator: &str, actions: &str) -> anyhow::Result<ParsedSecRule> {
    let action_list = split_actions(actions);
    let action = parse_action(&action_list)?;
    let status_code = parse_status_code(&action_list)?;
    let rule_id = parse_action_id(actions).unwrap_or_else(|| "(no-id)".to_string());
    let transforms = parse_transforms(&action_list)?;

    Ok(ParsedSecRule {
        target: target.to_string(),
        operator: operator.to_string(),
        actions_raw: actions.to_string(),
        action,
        status_code,
        rule_id,
        transforms,
    })
}

fn parse_action(actions: &[String]) -> anyhow::Result<Action> {
    let mut has_block = false;
    let mut has_allow = false;
    for action in actions {
        let normalized = action.trim().to_ascii_lowercase();
        if normalized == "block" || normalized == "deny" {
            has_block = true;
        }
        if normalized == "allow" || normalized == "pass" {
            has_allow = true;
        }
    }
    match (has_block, has_allow) {
        (true, false) => Ok(Action::Block),
        (false, true) => Ok(Action::Allow),
        (false, false) => bail!("missing action (block/deny/pass/allow)"),
        (true, true) => bail!("conflicting actions"),
    }
}

fn parse_status_code(actions: &[String]) -> anyhow::Result<Option<u16>> {
    let status = actions
        .iter()
        .find_map(|a| a.trim().strip_prefix("status:"))
        .map(str::trim);
    let Some(raw) = status else {
        return Ok(None);
    };
    let code = raw.parse::<u16>()?;
    if !(100..=599).contains(&code) {
        bail!("invalid status code {}", code);
    }
    Ok(Some(code))
}

fn parse_transforms(actions: &[String]) -> anyhow::Result<Vec<ConditionTransform>> {
    let mut transforms = Vec::new();
    for action in actions {
        let trimmed = action.trim();
        let Some(raw) = trimmed.strip_prefix("t:") else {
            continue;
        };
        let transform = match raw.trim().to_ascii_lowercase().as_str() {
            "none" => ConditionTransform::None,
            "lowercase" => ConditionTransform::Lowercase,
            "urldecode" | "urldecodeuni" => ConditionTransform::UrlDecode,
            "compresswhitespace" => ConditionTransform::CompressWhitespace,
            "removenulls" => ConditionTransform::RemoveNulls,
            other => bail!("unsupported transform {}", other),
        };
        transforms.push(transform);
    }
    Ok(transforms)
}

fn map_rule(parsed: &ParsedSecRule, base_dir: Option<&Path>) -> anyhow::Result<Vec<ImportedRule>> {
    let (operator, operand) = parse_operator(&parsed.operator)?;

    if parsed.actions_raw.contains("chain") {
        bail!("unsupported chained rule");
    }

    if parsed.target == "REQUEST_HEADERS:User-Agent"
        && (operator == "@pm" || operator == "@pmFromFile")
    {
        let needles = if operator == "@pmFromFile" {
            let file = operand.ok_or_else(|| anyhow::anyhow!("pmFromFile missing operand"))?;
            load_phrase_file(file, base_dir)?
        } else {
            split_pm_values(operand.ok_or_else(|| anyhow::anyhow!("pm missing operand"))?)
        };

        if needles.is_empty() {
            bail!("empty phrase list");
        }

        return Ok(vec![ImportedRule {
            id: format!("crs-{}", parsed.rule_id),
            enabled: true,
            action: parsed.action,
            status_code: parsed.status_code,
            methods: Vec::new(),
            path_prefixes: Vec::new(),
            ip_cidrs: Vec::new(),
            user_agent_contains: needles,
            conditions: Vec::new(),
        }]);
    }

    let target = map_target(&parsed.target)?;
    map_generic_condition(parsed, target, operator, operand, base_dir)
}

fn parse_operator(raw: &str) -> anyhow::Result<(&str, Option<&str>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("empty operator");
    }
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let op = parts.next().unwrap_or("");
    let operand = parts.next().map(str::trim).filter(|s| !s.is_empty());
    Ok((op, operand))
}

fn map_target(raw: &str) -> anyhow::Result<ConditionTarget> {
    match raw {
        "REQUEST_METHOD" => Ok(ConditionTarget::Method),
        "REQUEST_URI" => Ok(ConditionTarget::Path),
        "QUERY_STRING" => Ok(ConditionTarget::Query),
        "REQUEST_BODY" => Ok(ConditionTarget::Body),
        "REQUEST_HEADERS:User-Agent" => Ok(ConditionTarget::UserAgent),
        "REMOTE_ADDR" => Ok(ConditionTarget::ClientIp),
        _ => {
            if let Some(name) = raw.strip_prefix("REQUEST_HEADERS:") {
                return Ok(ConditionTarget::Header {
                    name: name.to_ascii_lowercase(),
                });
            }
            bail!("unsupported target {}", raw)
        }
    }
}

fn map_generic_condition(
    parsed: &ParsedSecRule,
    target: ConditionTarget,
    operator: &str,
    operand: Option<&str>,
    base_dir: Option<&Path>,
) -> anyhow::Result<Vec<ImportedRule>> {
    let mk_rule = |rule_id: String, condition: ConditionConfig| ImportedRule {
        id: rule_id,
        enabled: true,
        action: parsed.action,
        status_code: parsed.status_code,
        methods: Vec::new(),
        path_prefixes: Vec::new(),
        ip_cidrs: Vec::new(),
        user_agent_contains: Vec::new(),
        conditions: vec![condition],
    };

    match operator {
        "@streq" => {
            let value = required_operand(operand, operator)?;
            Ok(vec![mk_rule(
                format!("crs-{}", parsed.rule_id),
                ConditionConfig {
                    target,
                    operator: ConditionOperator::Eq,
                    value: Some(value.to_string()),
                    values: Vec::new(),
                    transforms: parsed.transforms.clone(),
                },
            )])
        }
        "@contains" => {
            let value = required_operand(operand, operator)?;
            Ok(vec![mk_rule(
                format!("crs-{}", parsed.rule_id),
                ConditionConfig {
                    target,
                    operator: ConditionOperator::Contains,
                    value: Some(value.to_string()),
                    values: Vec::new(),
                    transforms: parsed.transforms.clone(),
                },
            )])
        }
        "@beginsWith" => {
            let value = required_operand(operand, operator)?;
            Ok(vec![mk_rule(
                format!("crs-{}", parsed.rule_id),
                ConditionConfig {
                    target,
                    operator: ConditionOperator::Prefix,
                    value: Some(value.to_string()),
                    values: Vec::new(),
                    transforms: parsed.transforms.clone(),
                },
            )])
        }
        "@endsWith" => {
            let value = required_operand(operand, operator)?;
            Ok(vec![mk_rule(
                format!("crs-{}", parsed.rule_id),
                ConditionConfig {
                    target,
                    operator: ConditionOperator::Suffix,
                    value: Some(value.to_string()),
                    values: Vec::new(),
                    transforms: parsed.transforms.clone(),
                },
            )])
        }
        "@rx" => {
            let value = required_operand(operand, operator)?;
            Ok(vec![mk_rule(
                format!("crs-{}", parsed.rule_id),
                ConditionConfig {
                    target,
                    operator: ConditionOperator::Regex,
                    value: Some(value.to_string()),
                    values: Vec::new(),
                    transforms: parsed.transforms.clone(),
                },
            )])
        }
        "@ipMatch" => {
            if !matches!(target, ConditionTarget::ClientIp) {
                bail!("@ipMatch only supports REMOTE_ADDR target");
            }
            let values = split_pm_values(required_operand(operand, operator)?);
            Ok(vec![mk_rule(
                format!("crs-{}", parsed.rule_id),
                ConditionConfig {
                    target,
                    operator: ConditionOperator::IpMatch,
                    value: None,
                    values,
                    transforms: Vec::new(),
                },
            )])
        }
        "@pm" | "@pmFromFile" => {
            let phrases = if operator == "@pmFromFile" {
                let file = required_operand(operand, operator)?;
                load_phrase_file(file, base_dir)?
            } else {
                split_pm_values(required_operand(operand, operator)?)
            };
            if phrases.is_empty() {
                bail!("empty phrase list");
            }
            let mut out = Vec::with_capacity(phrases.len());
            for (idx, phrase) in phrases.into_iter().enumerate() {
                out.push(mk_rule(
                    format!("crs-{}-{}", parsed.rule_id, idx + 1),
                    ConditionConfig {
                        target: target.clone(),
                        operator: ConditionOperator::Contains,
                        value: Some(phrase),
                        values: Vec::new(),
                        transforms: parsed.transforms.clone(),
                    },
                ));
            }
            Ok(out)
        }
        other => bail!("unsupported operator {}", other),
    }
}

fn required_operand<'a>(operand: Option<&'a str>, operator: &str) -> anyhow::Result<&'a str> {
    let value = operand.ok_or_else(|| anyhow::anyhow!("{} missing operand", operator))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{} operand is empty", operator);
    }
    Ok(trimmed)
}

fn split_pm_values(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn load_phrase_file(file_name: &str, base_dir: Option<&Path>) -> anyhow::Result<Vec<String>> {
    let path = resolve_data_file(file_name, base_dir)?;
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read phrase file {}", path.display()))?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        out.push(trimmed.to_string());
    }
    Ok(out)
}

fn resolve_data_file(file_name: &str, base_dir: Option<&Path>) -> anyhow::Result<PathBuf> {
    let direct = PathBuf::from(file_name);
    if direct.exists() {
        return Ok(direct);
    }

    if let Some(dir) = base_dir {
        let same_dir = dir.join(file_name);
        if same_dir.exists() {
            return Ok(same_dir);
        }
        if let Some(parent) = dir.parent() {
            let data_dir = parent.join("data").join(file_name);
            if data_dir.exists() {
                return Ok(data_dir);
            }
        }
    }

    bail!("unable to resolve data file {}", file_name)
}

fn render_report(files: &[PathBuf], results: &[ParseResult]) -> String {
    let mut reason_counts = BTreeMap::new();
    let imported = results
        .iter()
        .filter(|r| r.status == ImportStatus::Imported)
        .count();
    let skipped = results.len().saturating_sub(imported);

    for result in results {
        if result.status == ImportStatus::Skipped {
            *reason_counts.entry(result.reason.clone()).or_insert(0usize) += 1;
        }
    }

    let mut out = String::new();
    out.push_str("CRS Import Report\n");
    out.push_str(&format!("files_scanned: {}\n", files.len()));
    out.push_str(&format!("rules_seen: {}\n", results.len()));
    out.push_str(&format!("rules_imported: {}\n", imported));
    out.push_str(&format!("rules_skipped: {}\n", skipped));
    out.push_str("skip_reasons:\n");
    if reason_counts.is_empty() {
        out.push_str("  - none\n");
    } else {
        for (reason, count) in reason_counts {
            out.push_str(&format!("  - {}: {}\n", reason, count));
        }
    }

    out.push_str("sample_skipped:\n");
    let mut printed = 0usize;
    for item in results
        .iter()
        .filter(|r| r.status == ImportStatus::Skipped)
        .take(20)
    {
        out.push_str(&format!("  - {} {}\n", item.rule_id, item.reason));
        printed += 1;
    }
    if printed == 0 {
        out.push_str("  - none\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::config::{
        AppConfig, EngineConfig, ProfileConfig, RuleConfig, SiteConfig, UpstreamConfig,
    };
    use crate::engine::{RequestMeta, WafEngine};
    use crate::snapshot::EngineSnapshot;

    #[test]
    fn split_actions_keeps_quoted_commas() {
        let parts = split_actions("id:1,msg:'a,b',t:none,block");
        assert_eq!(parts, vec!["id:1", "msg:'a,b'", "t:none", "block"]);
    }

    #[test]
    fn parse_operator_handles_operand() {
        let (op, value) = parse_operator("@rx (?i)union\\s+select").unwrap();
        assert_eq!(op, "@rx");
        assert_eq!(value, Some("(?i)union\\s+select"));
    }

    #[test]
    fn map_pm_user_agent_into_single_rule() {
        let parsed = ParsedSecRule {
            target: "REQUEST_HEADERS:User-Agent".to_string(),
            operator: "@pm sqlmap nmap".to_string(),
            actions_raw: "id:913100,block".to_string(),
            action: Action::Block,
            status_code: Some(403),
            rule_id: "913100".to_string(),
            transforms: vec![],
        };

        let mapped = map_rule(&parsed, None).unwrap();
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].user_agent_contains, vec!["sqlmap", "nmap"]);

        let decision = decide_with_mapped_rule(
            &mapped[0],
            RequestMeta {
                client_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                method: "GET".to_string(),
                path: "/".to_string(),
                query: None,
                user_agent: Some("sqlmap/1.0".to_string()),
                headers: HashMap::new(),
                body: None,
            },
        );
        assert_eq!(decision.action, Action::Block);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("crs-913100"));
    }

    #[test]
    fn map_pm_from_file_works() {
        let temp_root = std::env::temp_dir().join(format!(
            "fywaf-import-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        ));
        let rules_dir = temp_root.join("rules");
        let data_dir = temp_root.join("data");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::create_dir_all(&data_dir).unwrap();
        fs::write(data_dir.join("scanner.data"), "# comment\nsqlmap\n\nnmap\n").unwrap();

        let parsed = ParsedSecRule {
            target: "REQUEST_HEADERS:User-Agent".to_string(),
            operator: "@pmFromFile scanner.data".to_string(),
            actions_raw: "id:913101,block".to_string(),
            action: Action::Block,
            status_code: Some(403),
            rule_id: "913101".to_string(),
            transforms: vec![],
        };

        let mapped = map_rule(&parsed, Some(&rules_dir)).unwrap();
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].user_agent_contains, vec!["sqlmap", "nmap"]);

        let _ = fs::remove_dir_all(temp_root);
    }

    #[test]
    fn map_regex_condition_effective() {
        let parsed = ParsedSecRule {
            target: "QUERY_STRING".to_string(),
            operator: "@rx (?i)union\\+select".to_string(),
            actions_raw: "id:942100,block,t:none".to_string(),
            action: Action::Block,
            status_code: Some(403),
            rule_id: "942100".to_string(),
            transforms: vec![ConditionTransform::None],
        };

        let mapped = map_rule(&parsed, None).unwrap();
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].conditions.len(), 1);

        let decision = decide_with_mapped_rule(
            &mapped[0],
            RequestMeta {
                client_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                method: "GET".to_string(),
                path: "/search".to_string(),
                query: Some("q=1+UNION+SELECT+2".to_string()),
                user_agent: None,
                headers: HashMap::new(),
                body: None,
            },
        );
        assert_eq!(decision.action, Action::Block);
        assert_eq!(decision.matched_rule_id.as_deref(), Some("crs-942100"));
    }

    fn decide_with_mapped_rule(rule: &ImportedRule, req: RequestMeta) -> crate::engine::Decision {
        let cfg = AppConfig {
            sites: vec![SiteConfig {
                id: "s1".to_string(),
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
                    id: rule.id.clone(),
                    enabled: rule.enabled,
                    action: rule.action,
                    status_code: rule.status_code,
                    methods: rule.methods.clone(),
                    path_prefixes: rule.path_prefixes.clone(),
                    ip_cidrs: rule.ip_cidrs.clone(),
                    user_agent_contains: rule.user_agent_contains.clone(),
                    conditions: rule.conditions.clone(),
                }],
            }],
            engine: EngineConfig {
                snapshot_path: Some("examples/rules.snapshot.bin".to_string()),
            },
        };

        let snapshot = EngineSnapshot::from_app_config(&cfg);
        let engine = WafEngine::from_snapshot(snapshot).unwrap();
        engine.decide("p1", &req).unwrap()
    }
}
