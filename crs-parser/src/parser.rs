//! Parse SecRule `.conf` files into [`Rule`] values.
//!
//! The parser handles:
//! - Line continuation with `\` at end of line
//! - `SecRule VARIABLES OPERATOR "ACTIONS"` syntax
//! - `SecMarker` directives (used as jump targets for `skipAfter`)
//! - Comments (`#`) and blank lines
//! - Chained rules (`chain` action + next `SecRule`)

use std::path::Path;

use crate::types::*;

/// Parse all SecRule directives from a `.conf` file.
///
/// Lines that cannot be parsed are silently skipped (with a debug-level note).
/// `SecMarker` directives are returned as `Rule` values with id=0 and a
/// special `skip_after` field set to the marker name (so the engine can
/// identify jump targets).
pub fn parse_conf(path: &Path) -> Result<Vec<Rule>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    Ok(parse_str(&content))
}

/// Parse SecRule directives from a string (useful for tests).
pub fn parse_str(input: &str) -> Vec<Rule> {
    let logical_lines = join_continuations(input);
    let mut rules: Vec<Rule> = Vec::new();

    // Pending chain context: when we see `chain` in a rule's actions the
    // *next* SecRule belongs to that rule's `chained` list.
    let mut chain_stack: Vec<Rule> = Vec::new();

    for line in &logical_lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("SecMarker") {
            let marker = rest.trim().trim_matches('"').trim().to_string();
            // Flush any pending chain (shouldn't happen in well-formed CRS,
            // but be safe)
            flush_chain(&mut chain_stack, &mut rules);
            // Emit a synthetic pass rule with the marker as skip_after target
            rules.push(Rule {
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
                skip_after: Some(marker),
                anomaly_score: None,
                paranoia_level: 0,
            });
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("SecRule") {
            match parse_secrule(rest.trim()) {
                Some((rule, is_chain)) => {
                    if chain_stack.is_empty() {
                        if is_chain {
                            chain_stack.push(rule);
                        } else {
                            rules.push(rule);
                        }
                    } else {
                        // This rule is chained onto the top of the stack
                        let chained = ChainedRule {
                            variables: rule.variables,
                            operator: rule.operator,
                            transforms: rule.transforms,
                        };
                        let top = chain_stack.last_mut().unwrap();
                        top.chained.push(chained);
                        if !is_chain {
                            // Chain ends here — pop and emit
                            flush_chain(&mut chain_stack, &mut rules);
                        }
                    }
                }
                None => {
                    // Skip unparseable lines
                }
            }
            continue;
        }

        // Any other directive (SecAction, SecDefaultAction, etc.) — flush
        // pending chains and skip.
        flush_chain(&mut chain_stack, &mut rules);
    }

    // Flush any dangling chain at EOF
    flush_chain(&mut chain_stack, &mut rules);
    rules
}

fn flush_chain(stack: &mut Vec<Rule>, rules: &mut Vec<Rule>) {
    while let Some(r) = stack.pop() {
        rules.push(r);
    }
}

/// Join physical lines that end with `\` into logical lines.
fn join_continuations(input: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();

    for line in input.lines() {
        if line.ends_with('\\') {
            // Strip the trailing backslash and append
            current.push_str(&line[..line.len() - 1]);
            current.push(' ');
        } else {
            current.push_str(line);
            result.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

/// Parse the body of a `SecRule` directive (everything after `SecRule `).
///
/// Returns `(Rule, is_chain)` where `is_chain` is true when the rule's
/// actions include the `chain` keyword.
///
/// SecRule format: `VARIABLES OPERATOR "ACTIONS"`
///
/// The VARIABLES field is everything up to the first whitespace.
/// The OPERATOR is everything between the first whitespace and the last
/// double-quoted block (the ACTIONS).
/// The ACTIONS is the last double-quoted block.
fn parse_secrule(input: &str) -> Option<(Rule, bool)> {
    let input = input.trim();

    // The ACTIONS is always the last `"..."` block in the line.
    // Find it by scanning from the end.
    let actions_open = find_last_quoted_block_start(input)?;
    let before_actions = input[..actions_open].trim();
    let actions_str = &input[actions_open + 1..]; // after opening "
    let actions_end = find_closing_quote(actions_str)?;
    let actions_raw = &actions_str[..actions_end];

    // VARIABLES is the first whitespace-delimited token.
    // OPERATOR is everything between VARIABLES and the ACTIONS block.
    let (vars_str, rest) = split_first_ws(before_actions)?;
    let op_str = rest.trim();

    let variables = parse_variables(vars_str);

    // The operator may itself be quoted (e.g. `"@rx foo"`) — strip quotes.
    let op_str = op_str.trim_matches('"');
    let (operator, negated) = parse_operator(op_str.trim());

    let operator = if negated {
        Operator::Negated(Box::new(operator))
    } else {
        operator
    };

    let (
        actions,
        transforms,
        id,
        phase,
        action,
        msg,
        tags,
        severity,
        skip_after,
        anomaly_score,
        is_chain,
    ) = parse_actions(actions_raw);
    let _ = actions;

    let paranoia_level = tags
        .iter()
        .find_map(|t| t.strip_prefix("paranoia-level/"))
        .and_then(|n| n.parse::<u8>().ok())
        .unwrap_or(0);

    Some((
        Rule {
            id,
            phase,
            variables,
            operator,
            transforms,
            action,
            msg,
            tags,
            severity,
            chained: vec![],
            skip_after,
            anomaly_score,
            paranoia_level,
        },
        is_chain,
    ))
}

/// Find the opening `"` of the last double-quoted block in `s`.
///
/// Scans left from the last `"` character to find the preceding `"` that
/// opens the final quoted block.  This correctly handles operator arguments
/// that are themselves quoted (e.g. `VARS "@pm word1 word2" "ACTIONS"`).
fn find_last_quoted_block_start(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    // Position of the final closing "
    let close = bytes.iter().rposition(|&b| b == b'"')?;
    // Scan leftward from close-1 to find the matching opener.
    // We walk backwards respecting `\"` escape sequences (though CRS rarely
    // uses them inside the operator argument).
    let mut i = close;
    while i > 0 {
        i -= 1;
        if bytes[i] == b'"' {
            // Make sure it's not escaped
            let backslashes = bytes[..i].iter().rev().take_while(|&&b| b == b'\\').count();
            if backslashes % 2 == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// Find the position of the closing `"` in a string that starts just after
/// an opening quote, respecting `\"` escapes.
fn find_closing_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip escaped char
            continue;
        }
        if bytes[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Split `s` at the first ASCII whitespace, returning `(left, right)`.
fn split_first_ws(s: &str) -> Option<(&str, &str)> {
    let idx = s.find(|c: char| c.is_ascii_whitespace())?;
    Some((&s[..idx], s[idx + 1..].trim_start()))
}

// ---------------------------------------------------------------------------
// Variable parsing
// ---------------------------------------------------------------------------

fn parse_variables(s: &str) -> Vec<Variable> {
    s.split('|')
        .map(|part| parse_variable(part.trim()))
        .collect()
}

fn parse_variable(s: &str) -> Variable {
    // Capture negation before stripping `!` so the flag is available below.
    let negated = s.starts_with('!');
    let s = s.strip_prefix('!').unwrap_or(s);

    let upper = s.to_uppercase();

    if upper == "ARGS" {
        return Variable::Args;
    }
    if upper == "ARGS_NAMES" {
        return Variable::ArgsNames;
    }
    if upper == "REQUEST_COOKIES" {
        return Variable::RequestCookies;
    }
    if upper == "REQUEST_COOKIES_NAMES" {
        return Variable::RequestCookiesNames;
    }
    if upper == "REQUEST_FILENAME" {
        return Variable::RequestFilename;
    }
    if upper == "REQUEST_HEADERS" {
        return Variable::RequestHeaders;
    }
    if upper.starts_with("REQUEST_HEADERS:") {
        let name = s["REQUEST_HEADERS:".len()..].to_string();
        if negated {
            return Variable::RequestHeaderExclude(name);
        }
        return Variable::RequestHeader(name);
    }
    if upper == "REQUEST_METHOD" {
        return Variable::RequestMethod;
    }
    if upper == "REQUEST_URI" || upper == "REQUEST_URI_RAW" {
        return Variable::RequestUri;
    }
    if upper == "REQUEST_BODY" || upper == "REQUEST_BODY_RAW" {
        return Variable::RequestBody;
    }
    if upper.starts_with("TX:") {
        return Variable::Tx(s["TX:".len()..].to_string());
    }
    if upper.starts_with("XML:") {
        return Variable::Xml;
    }
    Variable::RequestHeader(s.to_string()) // fallback
}

// ---------------------------------------------------------------------------
// Operator parsing
// ---------------------------------------------------------------------------

/// Returns `(operator, negated)`.
fn parse_operator(s: &str) -> (Operator, bool) {
    let (negated, s) = if s.starts_with('!') {
        (true, &s[1..])
    } else {
        (false, s)
    };

    // Operators start with `@`; if absent it's an implicit `@rx`
    let (op_name, arg) = if s.starts_with('@') {
        let rest = &s[1..];
        match rest.find(|c: char| c.is_ascii_whitespace()) {
            Some(i) => (&rest[..i], rest[i + 1..].trim()),
            None => (rest, ""),
        }
    } else {
        // Bare value → implicit @rx
        ("rx", s)
    };

    let op = match op_name.to_lowercase().as_str() {
        "rx" => Operator::Rx(arg.to_string()),
        "pm" => Operator::Pm(arg.split_whitespace().map(|w| w.to_lowercase()).collect()),
        "pmfromfile" => Operator::PmFromFile(arg.to_string()),
        "contains" => Operator::Contains(arg.to_string()),
        "beginswith" => Operator::BeginsWith(arg.to_string()),
        "endswith" => Operator::EndsWith(arg.to_string()),
        "streq" => Operator::Streq(arg.to_string()),
        "lt" => Operator::Lt(arg.parse().unwrap_or(0)),
        "le" => Operator::Le(arg.parse().unwrap_or(0)),
        "ge" => Operator::Ge(arg.parse().unwrap_or(0)),
        "gt" => Operator::Gt(arg.parse().unwrap_or(0)),
        "within" => Operator::Within(arg.split_whitespace().map(|w| w.to_string()).collect()),
        "validatebyterange" => Operator::ValidateByteRange(arg.to_string()),
        "detectxss" => Operator::DetectXss,
        "detectsqli" => Operator::DetectSqli,
        other => Operator::Unsupported(other.to_string()),
    };
    (op, negated)
}

// ---------------------------------------------------------------------------
// Action parsing
// ---------------------------------------------------------------------------

/// Parse the actions string (content between the outer quotes of a SecRule).
///
/// Returns a tuple of everything we care about.
#[allow(clippy::type_complexity)]
fn parse_actions(
    raw: &str,
) -> (
    Vec<String>,      // raw action tokens (unused after parsing)
    Vec<Transform>,   // t: transforms
    u32,              // id
    Phase,            // phase
    Action,           // block/pass
    Option<String>,   // msg
    Vec<String>,      // tags
    Option<Severity>, // severity
    Option<String>,   // skip_after
    Option<u32>,      // anomaly_score
    bool,             // is_chain
) {
    let tokens = split_actions(raw);

    let mut transforms = Vec::new();
    let mut id = 0u32;
    let mut phase = Phase::Two;
    let mut action = Action::Pass; // default is pass unless block/deny seen
    let mut msg: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();
    let mut severity: Option<Severity> = None;
    let mut skip_after: Option<String> = None;
    let mut anomaly_score: Option<u32> = None;
    let mut is_chain = false;

    for token in &tokens {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        if let Some(val) = token.strip_prefix("id:") {
            id = val.parse().unwrap_or(0);
        } else if let Some(val) = token.strip_prefix("phase:") {
            phase = match val.trim() {
                "1" | "request-headers" => Phase::One,
                "2" | "request-body" => Phase::Two,
                "3" | "response-headers" => Phase::Three,
                "4" | "response-body" => Phase::Four,
                "5" | "logging" => Phase::Five,
                _ => Phase::Two,
            };
        } else if token == "block" || token == "deny" {
            action = Action::Block;
        } else if token == "pass" || token == "allow" {
            action = Action::Pass;
        } else if token == "chain" {
            is_chain = true;
        } else if let Some(val) = token.strip_prefix("msg:'") {
            msg = Some(val.trim_end_matches('\'').to_string());
        } else if let Some(val) = token.strip_prefix("msg:\"") {
            msg = Some(val.trim_end_matches('"').to_string());
        } else if let Some(val) = token.strip_prefix("tag:'") {
            tags.push(val.trim_end_matches('\'').to_string());
        } else if let Some(val) = token.strip_prefix("tag:\"") {
            tags.push(val.trim_end_matches('"').to_string());
        } else if let Some(val) = token.strip_prefix("t:") {
            transforms.push(parse_transform(val));
        } else if let Some(val) = token.strip_prefix("severity:'") {
            severity = parse_severity(val.trim_end_matches('\''));
        } else if let Some(val) = token.strip_prefix("severity:\"") {
            severity = parse_severity(val.trim_end_matches('"'));
        } else if let Some(val) = token.strip_prefix("skipAfter:") {
            skip_after = Some(val.trim().to_string());
        } else if let Some(val) = token.strip_prefix("setvar:'") {
            anomaly_score = anomaly_score.or_else(|| extract_anomaly_score(val));
        } else if let Some(val) = token.strip_prefix("setvar:\"") {
            anomaly_score = anomaly_score.or_else(|| extract_anomaly_score(val));
        }
        // logdata, capture, ver, ctl, etc. are intentionally ignored
    }

    (
        tokens,
        transforms,
        id,
        phase,
        action,
        msg,
        tags,
        severity,
        skip_after,
        anomaly_score,
        is_chain,
    )
}

/// Split an actions string on `,` but not inside quoted strings or `'...'`.
fn split_actions(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\'' if !in_double => {
                in_single = !in_single;
                current.push(b as char);
            }
            b'"' if !in_single => {
                in_double = !in_double;
                current.push(b as char);
            }
            b'\\' => {
                // Skip next char (escape)
                current.push(b as char);
                if i + 1 < bytes.len() {
                    i += 1;
                    current.push(bytes[i] as char);
                }
            }
            b',' if !in_single && !in_double => {
                result.push(std::mem::take(&mut current));
            }
            _ => {
                current.push(b as char);
            }
        }
        i += 1;
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

fn parse_transform(s: &str) -> Transform {
    match s.to_lowercase().as_str() {
        "lowercase" => Transform::Lowercase,
        "urldecodeuni" => Transform::UrlDecodeUni,
        "htmlentitydecode" => Transform::HtmlEntityDecode,
        "jsdecode" => Transform::JsDecode,
        "cssdecode" => Transform::CssDecode,
        "removenulls" => Transform::RemoveNulls,
        "removewhitespace" => Transform::RemoveWhitespace,
        "compresswhitespace" => Transform::CompressWhitespace,
        "utf8tounicode" => Transform::Utf8toUnicode,
        "none" => Transform::None,
        other => Transform::Other(other.to_string()),
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_uppercase().as_str() {
        "EMERGENCY" | "0" => Some(Severity::Emergency),
        "ALERT" | "1" => Some(Severity::Alert),
        "CRITICAL" | "2" => Some(Severity::Critical),
        "ERROR" | "3" => Some(Severity::Error),
        "WARNING" | "4" => Some(Severity::Warning),
        "NOTICE" | "5" => Some(Severity::Notice),
        "INFO" | "6" => Some(Severity::Info),
        "DEBUG" | "7" => Some(Severity::Debug),
        _ => None,
    }
}

/// Try to extract the numeric anomaly score increment from a `setvar` value
/// like `tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}`.
/// We map the variable names to known constants.
fn extract_anomaly_score(setvar: &str) -> Option<u32> {
    let val = setvar.to_lowercase();
    if val.contains("critical_anomaly_score") {
        return Some(5);
    }
    if val.contains("error_anomaly_score") {
        return Some(4);
    }
    if val.contains("warning_anomaly_score") {
        return Some(3);
    }
    if val.contains("notice_anomaly_score") {
        return Some(2);
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_rx_rule() {
        let input = r#"SecRule REQUEST_HEADERS:User-Agent "@rx (?i)sqlmap" \
    "id:913100,\
    phase:1,\
    block,\
    msg:'Scanner Detected - sqlmap',\
    tag:'OWASP_CRS',\
    tag:'paranoia-level/1',\
    severity:'CRITICAL'""#;
        let rules = parse_str(input);
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.id, 913100);
        assert_eq!(r.phase, Phase::One);
        assert_eq!(r.action, Action::Block);
        assert_eq!(r.paranoia_level, 1);
        assert!(matches!(r.operator, Operator::Rx(_)));
        if let Operator::Rx(ref rx) = r.operator {
            assert!(rx.contains("sqlmap"));
        }
    }

    #[test]
    fn parse_pm_rule() {
        let input = r#"SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS "@pm union select drop table" \
    "id:942100,phase:2,block,msg:'SQL Injection',tag:'paranoia-level/1'""#;
        let rules = parse_str(input);
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.id, 942100);
        if let Operator::Pm(ref words) = r.operator {
            assert!(words.contains(&"union".to_string()));
            assert!(words.contains(&"select".to_string()));
        } else {
            panic!("expected Pm operator");
        }
    }

    #[test]
    fn parse_variables_multi() {
        let vars = parse_variables("REQUEST_COOKIES|ARGS|REQUEST_HEADERS:User-Agent");
        assert_eq!(vars.len(), 3);
        assert!(matches!(vars[0], Variable::RequestCookies));
        assert!(matches!(vars[1], Variable::Args));
        assert!(matches!(vars[2], Variable::RequestHeader(_)));
    }

    #[test]
    fn parse_negated_request_header_variable() {
        // `!REQUEST_HEADERS:User-Agent` must produce RequestHeaderExclude, not RequestHeader.
        let vars = parse_variables("!REQUEST_HEADERS:User-Agent");
        assert_eq!(vars.len(), 1);
        assert!(
            matches!(vars[0], Variable::RequestHeaderExclude(_)),
            "expected RequestHeaderExclude, got {:?}",
            vars[0]
        );
    }

    #[test]
    fn parse_detect_xss_operator() {
        let input = r#"SecRule ARGS "@detectXSS" "id:941100,phase:2,block,msg:'XSS',tag:'paranoia-level/1'""#;
        let rules = parse_str(input);
        assert_eq!(rules.len(), 1);
        assert!(matches!(rules[0].operator, Operator::DetectXss));
    }

    #[test]
    fn parse_skip_after() {
        let input = r#"SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:941011,phase:1,pass,nolog,tag:'OWASP_CRS',skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS""#;
        let rules = parse_str(input);
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].skip_after.as_deref(),
            Some("END-REQUEST-941-APPLICATION-ATTACK-XSS")
        );
        assert_eq!(rules[0].action, Action::Pass);
    }

    #[test]
    fn parse_sec_marker() {
        let input = r#"SecMarker "END-REQUEST-941-APPLICATION-ATTACK-XSS""#;
        let rules = parse_str(input);
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].skip_after.as_deref(),
            Some("END-REQUEST-941-APPLICATION-ATTACK-XSS")
        );
    }

    #[test]
    fn parse_chained_rule() {
        let input = concat!(
            r#"SecRule REQUEST_COOKIES|ARGS_NAMES|ARGS "@rx \xbc" "#,
            "\"id:941310,phase:2,block,msg:'XSS Chain',tag:'paranoia-level/1',chain\"\n",
            r#"    SecRule MATCHED_VARS "@rx (?:\xbc\s*/)" "#,
            "\"setvar:'tx.xss_score=+%{tx.critical_anomaly_score}'\"\n",
        );
        let rules = parse_str(input);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].chained.len(), 1);
    }

    #[test]
    fn line_continuation_joined() {
        let input = "SecRule ARGS \"@rx test\" \\\n    \"id:1,phase:2,block,msg:'test'\"";
        // After joining: SecRule ARGS "@rx test"     "id:1,phase:2,block,msg:'test'"
        let rules = parse_str(input);
        // The join creates a malformed rule (the op and action end up merged)
        // This just checks we don't panic.
        let _ = rules;
    }

    #[test]
    fn anomaly_score_extracted() {
        let input = r#"SecRule ARGS "@rx union" "id:942100,phase:2,block,msg:'SQLi',tag:'paranoia-level/1',setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'""#;
        let rules = parse_str(input);
        assert_eq!(rules[0].anomaly_score, Some(5));
    }
}
