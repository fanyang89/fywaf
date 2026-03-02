//! Operator evaluation for SecRule conditions.
//!
//! Each function takes the *transformed* value string and returns `true` when
//! the operator matches (i.e. the condition is satisfied).

extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crs_parser::Operator;
use regex::Regex;

/// Evaluate `operator` against `value`.  Returns `true` on match.
///
/// `data_files_dir` is the path to the directory containing `.data` files
/// used by `@pmFromFile`.  In the WASM build this is embedded at compile time
/// (handled by the build script); at test time it can be a real path.
pub fn matches(operator: &Operator, value: &str) -> bool {
    match operator {
        Operator::Rx(pattern) => rx_match(pattern, value),
        Operator::Pm(words) => pm_match(words, value),
        Operator::PmFromFile(phrases) => pm_match_phrases(phrases, value),
        Operator::Contains(s) => value.to_lowercase().contains(s.to_lowercase().as_str()),
        Operator::BeginsWith(s) => value.to_lowercase().starts_with(s.to_lowercase().as_str()),
        Operator::EndsWith(s) => value.to_lowercase().ends_with(s.to_lowercase().as_str()),
        Operator::Streq(s) => value == s.as_str(),
        Operator::Lt(n) => parse_i64(value).map(|v| v < *n).unwrap_or(false),
        Operator::Le(n) => parse_i64(value).map(|v| v <= *n).unwrap_or(false),
        Operator::Ge(n) => parse_i64(value).map(|v| v >= *n).unwrap_or(false),
        Operator::Gt(n) => parse_i64(value).map(|v| v > *n).unwrap_or(false),
        Operator::Within(list) => {
            let v = value.to_lowercase();
            list.iter().any(|w| w.to_lowercase() == v)
        }
        Operator::ValidateByteRange(ranges) => validate_byte_range(value, ranges),
        // libinjection operators: not supported at runtime — always pass (no match)
        Operator::DetectXss | Operator::DetectSqli => false,
        Operator::Negated(inner) => !matches(inner, value),
        Operator::Pass => false,
        Operator::Unsupported(_) => false,
    }
}

// ---------------------------------------------------------------------------
// @rx — regular expression
// ---------------------------------------------------------------------------

fn rx_match(pattern: &str, value: &str) -> bool {
    // Build the regex. CRS patterns often use (?i) inline flags; the `regex`
    // crate supports those natively.
    match Regex::new(pattern) {
        Ok(re) => re.is_match(value),
        // Unparseable pattern — fail safe (no match).
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// @pm — Aho-Corasick multi-pattern phrase match (case-insensitive)
// ---------------------------------------------------------------------------

fn pm_match(words: &[String], value: &str) -> bool {
    // words were already lowercased by the parser
    let lower = value.to_lowercase();
    words.iter().any(|w| lower.contains(w.as_str()))
}

/// @pmFromFile — the `phrases` field in PmFromFile contains the pre-loaded
/// newline-separated phrases embedded by `build.rs`.  Each line is a phrase;
/// empty lines and `#` comments are skipped.
fn pm_match_phrases(phrases: &str, value: &str) -> bool {
    let lower = value.to_lowercase();
    for line in phrases.lines() {
        let phrase = line.trim();
        if phrase.is_empty() || phrase.starts_with('#') {
            continue;
        }
        if lower.contains(&phrase.to_lowercase() as &str) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// @validateByteRange — all bytes in `value` must fall in specified ranges
// ---------------------------------------------------------------------------

/// Ranges string format: `9-13,32-126` (like ModSecurity).
/// Returns `true` when ALL bytes are within the specified ranges (i.e. the
/// value is *valid*).  The operator is typically negated (`!@validateByteRange`)
/// to detect out-of-range bytes.
fn validate_byte_range(value: &str, ranges: &str) -> bool {
    let parsed = parse_byte_ranges(ranges);
    if parsed.is_empty() {
        return true; // no ranges → vacuously valid
    }
    for b in value.bytes() {
        if !parsed.iter().any(|(lo, hi)| b >= *lo && b <= *hi) {
            return false;
        }
    }
    true
}

fn parse_byte_ranges(ranges: &str) -> Vec<(u8, u8)> {
    let mut result = Vec::new();
    for part in ranges.split(',') {
        let part = part.trim();
        if let Some((lo, hi)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (lo.trim().parse::<u8>(), hi.trim().parse::<u8>()) {
                result.push((a, b));
            }
        } else if let Ok(n) = part.parse::<u8>() {
            result.push((n, n));
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Numeric helper
// ---------------------------------------------------------------------------

fn parse_i64(s: &str) -> Option<i64> {
    s.trim().parse().ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rx_basic() {
        assert!(matches(&Operator::Rx("(?i)select".to_string()), "SELECT 1"));
        assert!(!matches(
            &Operator::Rx("(?i)select".to_string()),
            "hello world"
        ));
    }

    #[test]
    fn pm_basic() {
        let op = Operator::Pm(alloc::vec!["union".to_string(), "select".to_string()]);
        assert!(matches(&op, "UNION ALL SELECT 1"));
        assert!(!matches(&op, "hello world"));
    }

    #[test]
    fn contains_case_insensitive() {
        assert!(matches(
            &Operator::Contains("script".to_string()),
            "<SCRIPT>"
        ));
    }

    #[test]
    fn begins_ends_with() {
        assert!(matches(&Operator::BeginsWith("hel".to_string()), "hello"));
        assert!(matches(&Operator::EndsWith("rld".to_string()), "world"));
    }

    #[test]
    fn numeric_ops() {
        assert!(matches(&Operator::Lt(5), "3"));
        assert!(!matches(&Operator::Lt(5), "5"));
        assert!(matches(&Operator::Ge(3), "3"));
        assert!(matches(&Operator::Gt(2), "3"));
    }

    #[test]
    fn negated() {
        let inner = Operator::Rx("sql".to_string());
        let op = Operator::Negated(alloc::boxed::Box::new(inner));
        assert!(matches(&op, "hello"));
        assert!(!matches(&op, "sql injection"));
    }

    #[test]
    fn detect_xss_sqli_always_false() {
        assert!(!matches(&Operator::DetectXss, "<script>alert(1)</script>"));
        assert!(!matches(&Operator::DetectSqli, "' OR 1=1--"));
    }

    #[test]
    fn validate_byte_range_valid() {
        // All ASCII printable — should be valid for range 32-126
        assert!(validate_byte_range("hello", "32-126"));
    }

    #[test]
    fn validate_byte_range_invalid() {
        // Null byte — not in 32-126
        assert!(!validate_byte_range("hel\x00lo", "32-126"));
    }
}
