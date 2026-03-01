use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;

pub fn collect_conf_files(root: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    if root.is_file() {
        if root.extension().and_then(|x| x.to_str()) == Some("conf") {
            out.push(root.to_path_buf());
        }
        return Ok(());
    }

    let entries = fs::read_dir(root)
        .with_context(|| format!("failed to read directory {}", root.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_conf_files(&path, out)?;
        } else if path.extension().and_then(|x| x.to_str()) == Some("conf") {
            out.push(path);
        }
    }
    Ok(())
}

pub fn join_continued_lines(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();

    for line in raw.lines() {
        let trimmed = line.trim_end();
        if current.is_empty() {
            current.push_str(trimmed);
        } else {
            current.push(' ');
            current.push_str(trimmed);
        }

        if trimmed.ends_with('\\') {
            current.pop();
        } else {
            out.push(current.clone());
            current.clear();
        }
    }

    if !current.is_empty() {
        out.push(current);
    }

    out
}

pub fn split_first_token(input: &str) -> Option<(&str, &str)> {
    let mut parts = input.splitn(2, char::is_whitespace);
    let first = parts.next()?.trim();
    let rest = parts.next()?.trim_start();
    Some((first, rest))
}

pub fn parse_quoted_pair(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    if !input.starts_with('"') {
        return None;
    }
    let (first, rest) = extract_quoted(input)?;
    let rest = rest.trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let (second, _) = extract_quoted(rest)?;
    Some((first, second))
}

pub fn extract_quoted(input: &str) -> Option<(&str, &str)> {
    let bytes = input.as_bytes();
    if bytes.first().copied()? != b'"' {
        return None;
    }
    let mut i = 1usize;
    let mut escaped = false;
    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if b == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            let value = &input[1..i];
            let rest = &input[i + 1..];
            return Some((value, rest));
        }
        i += 1;
    }
    None
}

pub fn split_actions(actions: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;

    for ch in actions.chars() {
        match ch {
            '\'' => {
                in_single = !in_single;
                cur.push(ch);
            }
            ',' if !in_single => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }

    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

pub fn parse_action_id(actions: &str) -> Option<String> {
    split_actions(actions).into_iter().find_map(|a| {
        let trimmed = a.trim();
        trimmed
            .strip_prefix("id:")
            .map(|x| x.trim_matches('\'').to_string())
    })
}
