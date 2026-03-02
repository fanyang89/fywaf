//! Data types produced by the SecRule parser.

use serde::{Deserialize, Serialize};

/// A single SecRule directive, potentially with chained follow-on rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: u32,
    pub phase: Phase,
    pub variables: Vec<Variable>,
    pub operator: Operator,
    /// Transformation pipeline applied to the matched value before the operator runs.
    pub transforms: Vec<Transform>,
    pub action: Action,
    pub msg: Option<String>,
    pub tags: Vec<String>,
    /// Numeric severity level derived from the `severity` action keyword.
    pub severity: Option<Severity>,
    /// Rules chained after this one (all must match for the action to trigger).
    pub chained: Vec<ChainedRule>,
    /// `skipAfter` target marker name.
    pub skip_after: Option<String>,
    /// Anomaly score increment extracted from `setvar:tx.inbound_anomaly_score_plN=+%{...}`.
    pub anomaly_score: Option<u32>,
    /// Paranoia level this rule belongs to (extracted from `paranoia-level/N` tag).
    pub paranoia_level: u8,
}

/// A chained rule node (no id, inherits parent's action on final match).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedRule {
    pub variables: Vec<Variable>,
    pub operator: Operator,
    pub transforms: Vec<Transform>,
}

/// Request/response variables that can be inspected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Variable {
    /// `ARGS` — all query-string + body parameters combined
    Args,
    /// `ARGS_NAMES` — parameter names only
    ArgsNames,
    /// `REQUEST_COOKIES` — all cookies
    RequestCookies,
    /// `REQUEST_COOKIES_NAMES`
    RequestCookiesNames,
    /// `REQUEST_FILENAME` — path portion of the URL
    RequestFilename,
    /// `REQUEST_HEADERS` — all headers
    RequestHeaders,
    /// `REQUEST_HEADERS:<Name>` — a specific header value
    RequestHeader(String),
    /// `!REQUEST_HEADERS:<Name>` — negated (exclude) header
    RequestHeaderExclude(String),
    /// `REQUEST_METHOD`
    RequestMethod,
    /// `REQUEST_URI` — full URI including query string
    RequestUri,
    /// `REQUEST_BODY` / `REQUEST_BODY_RAW`
    RequestBody,
    /// `TX:<name>` — transaction variable
    Tx(String),
    /// `XML:/*` (not evaluated — treated as unsupported)
    Xml,
}

/// The matching operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operator {
    /// `@rx <regex>` — regular expression match
    Rx(String),
    /// `@pm <word1> <word2> ...` — multi-pattern phrase match (case-insensitive)
    Pm(Vec<String>),
    /// `@pmFromFile <filename>` — phrase list loaded from a `.data` file
    PmFromFile(String),
    /// `@contains <string>` — substring match
    Contains(String),
    /// `@beginsWith <string>`
    BeginsWith(String),
    /// `@endsWith <string>`
    EndsWith(String),
    /// `@streq <string>` — exact string equality
    Streq(String),
    /// `@lt <n>` — numeric less-than
    Lt(i64),
    /// `@le <n>` — numeric less-than-or-equal
    Le(i64),
    /// `@ge <n>` — numeric greater-than-or-equal
    Ge(i64),
    /// `@gt <n>` — numeric greater-than
    Gt(i64),
    /// `@within <list>` — value is within a whitespace-separated list
    Within(Vec<String>),
    /// `@validateByteRange <ranges>` — byte range validation
    ValidateByteRange(String),
    /// `@detectXSS` — libinjection XSS detection (unsupported at runtime, treated as pass)
    DetectXss,
    /// `@detectSQLi` — libinjection SQLi detection (unsupported at runtime, treated as pass)
    DetectSqli,
    /// Negated operator `!@op` — matches when the inner operator does NOT match
    Negated(Box<Operator>),
    /// Synthetic "always pass" operator used by SecMarker pseudo-rules
    Pass,
    /// Any other operator we don't handle yet
    Unsupported(String),
}

/// Rule action: what to do when all conditions match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Block the request (deny / block).
    Block,
    /// Allow the request to continue (pass / allow).
    Pass,
}

/// Request processing phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    One = 1,
    Two = 2,
    Three = 3,
    Four = 4,
    Five = 5,
}

/// Transform applied to a variable value before matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transform {
    Lowercase,
    UrlDecodeUni,
    HtmlEntityDecode,
    JsDecode,
    CssDecode,
    RemoveNulls,
    RemoveWhitespace,
    CompressWhitespace,
    Utf8toUnicode,
    None,
    /// Any other transform we don't need to support.
    Other(String),
}

/// Severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}
