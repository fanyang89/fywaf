//! SecRule parser for OWASP CRS `.conf` files.
//!
//! Parses ModSecurity `SecRule` directives into structured [`Rule`] values.
//! Only the subset of the SecRule language used by CRS is supported.
//!
//! Operators that are not explicitly supported by this crate produce
//! [`Operator::Unsupported`], which the engine will treat as a non-match
//! (pass-through) at runtime. `@detectXSS` and `@detectSQLi` are parsed into
//! [`Operator::DetectXss`] and [`Operator::DetectSqli`] respectively.

pub mod parser;
pub mod types;

pub use parser::parse_conf;
pub use types::{Action, ChainedRule, Operator, Phase, Rule, Transform, Variable};
