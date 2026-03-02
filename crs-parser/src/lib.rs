//! SecRule parser for OWASP CRS `.conf` files.
//!
//! Parses ModSecurity `SecRule` directives into structured [`Rule`] values.
//! Only the subset of the SecRule language used by CRS is supported.
//!
//! Unsupported operators (e.g. `@detectXSS`, `@detectSQLi`) produce
//! [`Operator::Unsupported`] — the engine will treat them as a non-match
//! (pass-through) at runtime.

pub mod parser;
pub mod types;

pub use parser::parse_conf;
pub use types::{Action, ChainedRule, Operator, Phase, Rule, Transform, Variable};
