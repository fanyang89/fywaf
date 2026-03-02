//! Core rule evaluation engine.
//!
//! The `evaluate` function iterates through the embedded CRS rules and
//! implements:
//!
//! - Paranoia level filtering
//! - Variable resolution (extracting values from the request)
//! - Transform pipeline application
//! - Operator matching
//! - Chained rule support (all chain links must match)
//! - `skipAfter` jump logic (pass rules that skip to a SecMarker)
//! - Anomaly score accumulation and threshold comparison
//!
//! Returns `Some((rule_id, message))` when the anomaly score crosses the
//! threshold, `None` to allow the request.

extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use crs_parser::{Operator, Rule, Variable};

use crate::operators;
use crate::transforms::apply_transforms;

/// Evaluate all `rules` against the incoming request.
///
/// Returns the first `(rule_id, msg)` that causes the anomaly score to reach
/// or exceed `anomaly_threshold`, or `None` to allow the request.
pub fn evaluate(
    rules: &[Rule],
    method: &str,
    path: &str,
    query: Option<&str>,
    user_agent: Option<&str>,
    headers: &BTreeMap<&str, &str>,
    body: Option<&str>,
    paranoia_level: u8,
    anomaly_threshold: u32,
) -> Option<(u32, String)> {
    let mut anomaly_score: u32 = 0;
    let mut skip_until: Option<String> = None;
    let mut blocking_rule: Option<(u32, String)> = None;

    // Build a simple request context struct for variable resolution.
    let ctx = RequestContext {
        method,
        path,
        query,
        user_agent,
        headers,
        body,
    };

    let mut i = 0;
    while i < rules.len() {
        let rule = &rules[i];
        i += 1;

        // ── skipAfter jump logic ────────────────────────────────────────────
        // A SecMarker has id=0 and skip_after = Some(marker_name).
        if rule.id == 0 {
            // This is a SecMarker.
            if let Some(ref target) = skip_until {
                if rule.skip_after.as_deref() == Some(target.as_str()) {
                    skip_until = None;
                }
            }
            continue;
        }

        // While skipping, ignore all non-marker rules.
        if skip_until.is_some() {
            continue;
        }

        // ── Paranoia level filter ───────────────────────────────────────────
        // Rules with paranoia_level == 0 belong to no specific level (e.g.
        // anomaly scoring rules) and are always evaluated.
        if rule.paranoia_level > 0 && rule.paranoia_level > paranoia_level {
            continue;
        }

        // ── Rule match ─────────────────────────────────────────────────────
        let matched = rule_matches(rule, &ctx);

        if !matched {
            continue;
        }

        // ── Action on match ────────────────────────────────────────────────
        match rule.action {
            crs_parser::Action::Pass => {
                // A passing rule may carry a skipAfter directive.
                if let Some(ref marker) = rule.skip_after {
                    skip_until = Some(marker.clone());
                }
                // Pass rules never accumulate score.
                continue;
            }
            crs_parser::Action::Block => {
                // Accumulate anomaly score.
                let score = rule.anomaly_score.unwrap_or(5); // default CRITICAL
                anomaly_score = anomaly_score.saturating_add(score);

                if blocking_rule.is_none() {
                    let msg = rule
                        .msg
                        .clone()
                        .unwrap_or_else(|| alloc::format!("Rule {} matched", rule.id));
                    blocking_rule = Some((rule.id, msg));
                }

                if anomaly_score >= anomaly_threshold {
                    return blocking_rule;
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Rule matching
// ---------------------------------------------------------------------------

/// Returns `true` if the rule (including all chained links) matches the
/// request.
fn rule_matches(rule: &Rule, ctx: &RequestContext<'_>) -> bool {
    // Evaluate the primary rule condition.
    if !condition_matches(&rule.variables, &rule.operator, &rule.transforms, ctx) {
        return false;
    }

    // All chained rules must also match.
    for chained in &rule.chained {
        if !condition_matches(
            &chained.variables,
            &chained.operator,
            &chained.transforms,
            ctx,
        ) {
            return false;
        }
    }

    true
}

/// Returns `true` when any value resolved from `variables` — after applying
/// `transforms` — matches `operator`.
fn condition_matches(
    variables: &[Variable],
    operator: &Operator,
    transforms: &[crs_parser::Transform],
    ctx: &RequestContext<'_>,
) -> bool {
    // Resolve all values from the variable list.
    let values = resolve_variables(variables, ctx);

    // Apply transforms and test the operator against each value.
    for raw_value in &values {
        let transformed = apply_transforms(raw_value, transforms);
        if operators::matches(operator, &transformed) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Variable resolution
// ---------------------------------------------------------------------------

struct RequestContext<'a> {
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    user_agent: Option<&'a str>,
    headers: &'a BTreeMap<&'a str, &'a str>,
    body: Option<&'a str>,
}

/// Resolve a list of variables to a flat list of string values from the
/// request.  Duplicates are possible but harmless.
fn resolve_variables<'a>(vars: &[Variable], ctx: &'a RequestContext<'_>) -> Vec<String> {
    let mut values: Vec<String> = Vec::new();
    // Track header names that should be excluded (from RequestHeaderExclude).
    let mut exclude_headers: Vec<String> = Vec::new();

    // First pass: collect exclusions.
    for var in vars {
        if let Variable::RequestHeaderExclude(name) = var {
            exclude_headers.push(name.to_lowercase());
        }
    }

    for var in vars {
        match var {
            Variable::Args => {
                // Query string params and body params.
                if let Some(q) = ctx.query {
                    values.extend(parse_urlencoded_values(q));
                }
                if let Some(b) = ctx.body {
                    values.extend(parse_urlencoded_values(b));
                }
            }
            Variable::ArgsNames => {
                if let Some(q) = ctx.query {
                    values.extend(parse_urlencoded_names(q));
                }
                if let Some(b) = ctx.body {
                    values.extend(parse_urlencoded_names(b));
                }
            }
            Variable::RequestCookies => {
                if let Some(cookie_hdr) = ctx
                    .headers
                    .get("cookie")
                    .or_else(|| ctx.headers.get("Cookie"))
                {
                    values.extend(parse_cookie_values(cookie_hdr));
                }
            }
            Variable::RequestCookiesNames => {
                if let Some(cookie_hdr) = ctx
                    .headers
                    .get("cookie")
                    .or_else(|| ctx.headers.get("Cookie"))
                {
                    values.extend(parse_cookie_names(cookie_hdr));
                }
            }
            Variable::RequestFilename => {
                values.push(ctx.path.to_string());
            }
            Variable::RequestHeaders => {
                for (name, val) in ctx.headers.iter() {
                    let name_lc = name.to_lowercase();
                    if !exclude_headers.contains(&name_lc) {
                        values.push(val.to_string());
                    }
                }
            }
            Variable::RequestHeader(name) => {
                let name_lc = name.to_lowercase();
                for (hname, hval) in ctx.headers.iter() {
                    if hname.to_lowercase() == name_lc {
                        values.push(hval.to_string());
                    }
                }
                // Also check user_agent shortcut
                if name_lc == "user-agent" {
                    if let Some(ua) = ctx.user_agent {
                        // Only add if not already added from headers map
                        if ctx.headers.get("user-agent").is_none()
                            && ctx.headers.get("User-Agent").is_none()
                        {
                            values.push(ua.to_string());
                        }
                    }
                }
            }
            Variable::RequestHeaderExclude(_) => {
                // Already handled above — skip here.
            }
            Variable::RequestMethod => {
                values.push(ctx.method.to_string());
            }
            Variable::RequestUri => {
                let uri = match ctx.query {
                    Some(q) => alloc::format!("{}?{}", ctx.path, q),
                    None => ctx.path.to_string(),
                };
                values.push(uri);
            }
            Variable::RequestBody => {
                if let Some(b) = ctx.body {
                    values.push(b.to_string());
                }
            }
            Variable::Tx(_) => {
                // Transaction variables are not tracked at runtime in this
                // simplified engine — return empty string so numeric
                // comparisons (e.g. @lt 1) treat them as 0.
                values.push(String::new());
            }
            Variable::Xml => {
                // XML inspection not supported — skip.
            }
        }
    }

    values
}

// ---------------------------------------------------------------------------
// URL-encoded parameter helpers
// ---------------------------------------------------------------------------

/// Parse `key=value&key2=value2` and return values.
fn parse_urlencoded_values(s: &str) -> Vec<String> {
    s.split('&')
        .filter_map(|pair| {
            if pair.is_empty() {
                return None;
            }
            match pair.split_once('=') {
                Some((_, v)) => Some(url_decode_simple(v)),
                None => Some(url_decode_simple(pair)),
            }
        })
        .collect()
}

/// Parse `key=value&key2=value2` and return names.
fn parse_urlencoded_names(s: &str) -> Vec<String> {
    s.split('&')
        .filter_map(|pair| {
            if pair.is_empty() {
                return None;
            }
            match pair.split_once('=') {
                Some((k, _)) => Some(url_decode_simple(k)),
                None => None,
            }
        })
        .collect()
}

/// Parse `name=value; name2=value2` cookie header and return values.
fn parse_cookie_values(s: &str) -> Vec<String> {
    s.split(';')
        .filter_map(|pair| {
            let pair = pair.trim();
            if pair.is_empty() {
                return None;
            }
            match pair.split_once('=') {
                Some((_, v)) => Some(v.trim().to_string()),
                None => Some(pair.to_string()),
            }
        })
        .collect()
}

/// Parse `name=value; name2=value2` cookie header and return names.
fn parse_cookie_names(s: &str) -> Vec<String> {
    s.split(';')
        .filter_map(|pair| {
            let pair = pair.trim();
            if pair.is_empty() {
                return None;
            }
            match pair.split_once('=') {
                Some((k, _)) => Some(k.trim().to_string()),
                None => None,
            }
        })
        .collect()
}

/// Minimal `%XX` URL decoding (+ → space).
fn url_decode_simple(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            result.push(' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                result.push((hi << 4 | lo) as char);
                i += 3;
                continue;
            }
            result.push(bytes[i] as char);
            i += 1;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use crs_parser::{Action, ChainedRule, Operator, Phase, Rule, Transform, Variable};

    fn make_rule(id: u32, vars: Vec<Variable>, op: Operator, action: Action) -> Rule {
        Rule {
            id,
            phase: Phase::Two,
            variables: vars,
            operator: op,
            transforms: vec![Transform::Lowercase],
            action,
            msg: Some("test".to_string()),
            tags: vec![],
            severity: None,
            chained: vec![],
            skip_after: None,
            anomaly_score: Some(5),
            paranoia_level: 1,
        }
    }

    fn empty_headers() -> BTreeMap<&'static str, &'static str> {
        BTreeMap::new()
    }

    #[test]
    fn blocks_sqli_in_args() {
        let rules = alloc::vec![make_rule(
            942100,
            alloc::vec![Variable::Args],
            Operator::Pm(alloc::vec!["union".to_string(), "select".to_string()]),
            Action::Block,
        )];
        let hdrs = empty_headers();
        let result = evaluate(
            &rules,
            "GET",
            "/",
            Some("q=UNION+SELECT+1"),
            None,
            &hdrs,
            None,
            1,
            5,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, 942100);
    }

    #[test]
    fn allows_clean_request() {
        let rules = alloc::vec![make_rule(
            942100,
            alloc::vec![Variable::Args],
            Operator::Pm(alloc::vec!["union".to_string()]),
            Action::Block,
        )];
        let hdrs = empty_headers();
        let result = evaluate(
            &rules,
            "GET",
            "/",
            Some("q=hello+world"),
            None,
            &hdrs,
            None,
            1,
            5,
        );
        assert!(result.is_none());
    }

    #[test]
    fn paranoia_level_filters_high_pl_rules() {
        let mut rule = make_rule(
            942999,
            alloc::vec![Variable::Args],
            Operator::Pm(alloc::vec!["select".to_string()]),
            Action::Block,
        );
        rule.paranoia_level = 3; // only active at PL3+
        let rules = alloc::vec![rule];
        let hdrs = empty_headers();
        // With PL=1 the rule should be skipped → allow
        let result = evaluate(
            &rules,
            "GET",
            "/",
            Some("q=SELECT+1"),
            None,
            &hdrs,
            None,
            1,
            5,
        );
        assert!(result.is_none());
        // With PL=3 the rule fires → block
        let result2 = evaluate(
            &rules,
            "GET",
            "/",
            Some("q=SELECT+1"),
            None,
            &hdrs,
            None,
            3,
            5,
        );
        assert!(result2.is_some());
    }

    #[test]
    fn skip_after_skips_rules() {
        // Rule A has pass + skipAfter=MARKER
        let mut rule_a = make_rule(
            941011,
            alloc::vec![Variable::Tx("detection_paranoia_level".to_string())],
            Operator::Lt(1),
            Action::Pass,
        );
        rule_a.skip_after = Some("END-MARKER".to_string());
        rule_a.anomaly_score = None;

        // Rule B would block if evaluated
        let rule_b = make_rule(
            941100,
            alloc::vec![Variable::Args],
            Operator::Rx("(?i)script".to_string()),
            Action::Block,
        );

        // SecMarker
        let marker = Rule {
            id: 0,
            phase: Phase::Two,
            variables: vec![],
            operator: Operator::Pass,
            transforms: vec![],
            action: Action::Pass,
            msg: None,
            tags: vec![],
            severity: None,
            chained: vec![],
            skip_after: Some("END-MARKER".to_string()),
            anomaly_score: None,
            paranoia_level: 0,
        };

        let rules = alloc::vec![rule_a, rule_b, marker];
        let hdrs = empty_headers();
        // TX is empty string → @lt 1 → empty.parse::<i64>() = None → false
        // Wait: TX returns empty string, parse_i64("") = None → false
        // So rule_a does NOT fire (tx="" doesn't match @lt 1)
        // rule_b should fire
        let result = evaluate(
            &rules,
            "GET",
            "/",
            Some("foo=<script>"),
            None,
            &hdrs,
            None,
            1,
            5,
        );
        assert!(result.is_some());
    }

    #[test]
    fn chained_rule_requires_both_match() {
        let chained = ChainedRule {
            variables: alloc::vec![Variable::RequestMethod],
            operator: Operator::Streq("POST".to_string()),
            transforms: vec![],
        };
        let mut rule = make_rule(
            942200,
            alloc::vec![Variable::Args],
            Operator::Pm(alloc::vec!["union".to_string()]),
            Action::Block,
        );
        rule.chained = alloc::vec![chained];
        rule.transforms = vec![]; // no transforms for primary

        let hdrs = empty_headers();
        let rules = alloc::vec![rule];

        // GET request: chain fails (method != POST) → allow
        let result = evaluate(&rules, "GET", "/", Some("x=union"), None, &hdrs, None, 1, 5);
        assert!(result.is_none());

        // POST request: both match → block
        let result2 = evaluate(
            &rules,
            "POST",
            "/",
            Some("x=union"),
            None,
            &hdrs,
            None,
            1,
            5,
        );
        assert!(result2.is_some());
    }
}
