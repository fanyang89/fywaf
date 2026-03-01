use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::Parser;

#[path = "../secrule_parser.rs"]
mod secrule_parser;
use secrule_parser::{
    collect_conf_files, join_continued_lines, parse_action_id, parse_quoted_pair, split_actions,
    split_first_token,
};

#[derive(Parser, Debug)]
#[command(name = "fywaf-compat")]
#[command(about = "Report compatibility of CRS-style SecRule files")]
struct Args {
    #[arg(long, short, default_value = "rules")]
    rules_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleStatus {
    Supported,
    Partial,
    Unsupported,
}

#[derive(Debug)]
struct RuleReport {
    file: PathBuf,
    rule_id: String,
    status: RuleStatus,
    reasons: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut files = Vec::new();
    collect_conf_files(&args.rules_dir, &mut files)?;
    files.sort();

    let mut reports = Vec::new();
    for file in files {
        let mut file_reports = analyze_file(&file)?;
        reports.append(&mut file_reports);
    }

    print_report(&reports);
    Ok(())
}

fn analyze_file(path: &Path) -> anyhow::Result<Vec<RuleReport>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read rule file {}", path.display()))?;
    let statements = join_continued_lines(&raw);
    let mut reports = Vec::new();

    for stmt in statements {
        let Some(body) = stmt.trim_start().strip_prefix("SecRule ") else {
            continue;
        };
        let Some((target, tail)) = split_first_token(body) else {
            continue;
        };
        let Some((operator, actions)) = parse_quoted_pair(tail) else {
            continue;
        };

        let (status, reasons) = evaluate_rule(target, operator, actions);
        let rule_id = parse_action_id(actions).unwrap_or_else(|| "(no-id)".to_string());
        reports.push(RuleReport {
            file: path.to_path_buf(),
            rule_id,
            status,
            reasons,
        });
    }

    Ok(reports)
}

fn evaluate_rule(target: &str, operator: &str, actions: &str) -> (RuleStatus, Vec<String>) {
    let mut unsupported = BTreeSet::new();
    let mut partial = BTreeSet::new();

    evaluate_target(target, &mut unsupported, &mut partial);
    evaluate_operator(operator, &mut unsupported, &mut partial);
    evaluate_actions(actions, &mut unsupported, &mut partial);

    let status = if !unsupported.is_empty() {
        RuleStatus::Unsupported
    } else if !partial.is_empty() {
        RuleStatus::Partial
    } else {
        RuleStatus::Supported
    };

    let mut reasons = Vec::new();
    reasons.extend(unsupported);
    reasons.extend(partial);
    (status, reasons)
}

fn evaluate_target(
    target: &str,
    unsupported: &mut BTreeSet<String>,
    partial: &mut BTreeSet<String>,
) {
    if target.contains('|') || target.contains('&') {
        unsupported.insert("multi-target".to_string());
        return;
    }

    if target == "REQUEST_METHOD"
        || target == "REQUEST_URI"
        || target == "REQUEST_BODY"
        || target == "REMOTE_ADDR"
        || target == "QUERY_STRING"
    {
        return;
    }

    if target.starts_with("REQUEST_HEADERS:") {
        return;
    }
    if target == "REQUEST_HEADERS" {
        partial.insert("header-collection".to_string());
        return;
    }
    if target.starts_with("ARGS") {
        partial.insert("args-target".to_string());
        return;
    }

    unsupported.insert(format!("target:{}", target));
}

fn evaluate_operator(
    operator: &str,
    unsupported: &mut BTreeSet<String>,
    partial: &mut BTreeSet<String>,
) {
    let op = operator.trim();
    let name = op.split_whitespace().next().unwrap_or(op);

    match name {
        "@streq" | "@contains" | "@beginsWith" | "@endsWith" | "@rx" | "@pm" | "@ipMatch" => {}
        "@pmFromFile" => {
            partial.insert("operator:pm_from_file".to_string());
        }
        _ => {
            unsupported.insert(format!("operator:{}", name));
        }
    };
}

fn evaluate_actions(
    actions: &str,
    unsupported: &mut BTreeSet<String>,
    partial: &mut BTreeSet<String>,
) {
    for action in split_actions(actions) {
        let a = action.trim();
        if a.is_empty() {
            continue;
        }

        if let Some(transform) = a.strip_prefix("t:") {
            match transform.to_ascii_lowercase().as_str() {
                "none" | "lowercase" | "urldecode" | "compresswhitespace" | "removenulls" => {}
                "urldecodeuni" => {
                    partial.insert("transform:url_decode_uni".to_string());
                }
                other => {
                    unsupported.insert(format!("transform:{}", other));
                }
            }
            continue;
        }

        if a.starts_with("setvar:") || a == "capture" {
            partial.insert("stateful-actions".to_string());
            continue;
        }

        if a == "chain" {
            partial.insert("chain".to_string());
            continue;
        }

        if a.starts_with("phase:") {
            partial.insert("phase-control".to_string());
            continue;
        }

        if a.starts_with("ctl:") || a.starts_with("skipAfter:") {
            unsupported.insert("control-flow-actions".to_string());
        }
    }
}

fn print_report(reports: &[RuleReport]) {
    let mut supported = 0usize;
    let mut partial = 0usize;
    let mut unsupported = 0usize;
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();

    for report in reports {
        match report.status {
            RuleStatus::Supported => supported += 1,
            RuleStatus::Partial => partial += 1,
            RuleStatus::Unsupported => unsupported += 1,
        }
        for reason in &report.reasons {
            *reasons.entry(reason.clone()).or_insert(0) += 1;
        }
    }

    println!("Compatibility report");
    println!("- total_rules: {}", reports.len());
    println!("- supported: {}", supported);
    println!("- partial: {}", partial);
    println!("- unsupported: {}", unsupported);

    if !reasons.is_empty() {
        println!("- reasons:");
        for (reason, count) in reasons {
            println!("  - {}: {}", reason, count);
        }
    }

    println!("- sample_non_supported:");
    for report in reports
        .iter()
        .filter(|r| r.status != RuleStatus::Supported)
        .take(20)
    {
        println!(
            "  - {} {} [{}] {}",
            report.file.display(),
            report.rule_id,
            match report.status {
                RuleStatus::Supported => "supported",
                RuleStatus::Partial => "partial",
                RuleStatus::Unsupported => "unsupported",
            },
            report.reasons.join(",")
        );
    }
}
