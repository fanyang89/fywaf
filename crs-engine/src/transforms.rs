//! Value transformation pipeline for SecRule `t:` actions.
//!
//! Each transform takes a `&str` and returns an owned `String`.
//! Transforms are applied in order before the operator evaluates the value.

extern crate alloc;
use alloc::string::{String, ToString};

use crs_parser::Transform;

/// Apply a slice of transforms to a value in order.
pub fn apply_transforms(value: &str, transforms: &[Transform]) -> String {
    let mut s: String = value.to_string();
    for t in transforms {
        s = apply_one(&s, t);
    }
    s
}

fn apply_one(s: &str, t: &Transform) -> String {
    match t {
        Transform::Lowercase => s.to_lowercase(),
        Transform::RemoveNulls => s.replace('\0', ""),
        Transform::RemoveWhitespace => s.chars().filter(|c| !c.is_ascii_whitespace()).collect(),
        Transform::CompressWhitespace => compress_whitespace(s),
        // The transforms below require Unicode/HTML awareness.
        // We provide best-effort implementations that cover the common cases
        // seen in CRS rule payloads.
        Transform::UrlDecodeUni => url_decode_uni(s),
        Transform::HtmlEntityDecode => html_entity_decode(s),
        Transform::JsDecode => js_decode(s),
        Transform::Utf8toUnicode => utf8_to_unicode_escape(s),
        Transform::CssDecode => css_decode(s),
        Transform::None => s.to_string(),
        Transform::Other(_) => s.to_string(),
    }
}

fn compress_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut prev_ws = false;
    for c in s.chars() {
        if c.is_ascii_whitespace() {
            if !prev_ws {
                result.push(' ');
            }
            prev_ws = true;
        } else {
            result.push(c);
            prev_ws = false;
        }
    }
    result
}

/// Decode `%XX` and `%uXXXX` percent-encoding sequences.
fn url_decode_uni(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // %uXXXX unicode escape
            if i + 5 < bytes.len() && (bytes[i + 1] == b'u' || bytes[i + 1] == b'U') {
                if let Some(cp) = hex4(&bytes[i + 2..i + 6]).and_then(char::from_u32) {
                    result.push(cp);
                    i += 6;
                    continue;
                }
            }
            // %XX byte
            if i + 2 < bytes.len() {
                if let Some(b) = hex2(bytes[i + 1], bytes[i + 2]) {
                    result.push(b as char);
                    i += 3;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn hex4(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    let h = [
        hex_digit(b[0])?,
        hex_digit(b[1])?,
        hex_digit(b[2])?,
        hex_digit(b[3])?,
    ];
    Some((h[0] as u32) << 12 | (h[1] as u32) << 8 | (h[2] as u32) << 4 | h[3] as u32)
}

fn hex2(a: u8, b: u8) -> Option<u8> {
    Some(hex_digit(a)? << 4 | hex_digit(b)?)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode common HTML entities: `&lt;` `&gt;` `&amp;` `&quot;` `&#NNN;` `&#xHH;`.
fn html_entity_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        result.push_str(&rest[..amp]);
        rest = &rest[amp..];
        if rest.starts_with("&lt;") {
            result.push('<');
            rest = &rest[4..];
        } else if rest.starts_with("&gt;") {
            result.push('>');
            rest = &rest[4..];
        } else if rest.starts_with("&amp;") {
            result.push('&');
            rest = &rest[5..];
        } else if rest.starts_with("&quot;") {
            result.push('"');
            rest = &rest[6..];
        } else if rest.starts_with("&apos;") {
            result.push('\'');
            rest = &rest[6..];
        } else if rest.starts_with("&#x") || rest.starts_with("&#X") {
            if let Some(semi) = rest[3..].find(';') {
                if let Ok(n) = u32::from_str_radix(&rest[3..3 + semi], 16) {
                    if let Some(c) = char::from_u32(n) {
                        result.push(c);
                        rest = &rest[4 + semi..];
                        continue;
                    }
                }
            }
            result.push('&');
            rest = &rest[1..];
        } else if rest.starts_with("&#") {
            if let Some(semi) = rest[2..].find(';') {
                if let Ok(n) = rest[2..2 + semi].parse::<u32>() {
                    if let Some(c) = char::from_u32(n) {
                        result.push(c);
                        rest = &rest[3 + semi..];
                        continue;
                    }
                }
            }
            result.push('&');
            rest = &rest[1..];
        } else {
            result.push('&');
            rest = &rest[1..];
        }
    }
    result.push_str(rest);
    result
}

/// Decode `\uXXXX` and `\xHH` JavaScript escape sequences.
fn js_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'u' | b'U' if i + 5 < bytes.len() => {
                    if let Some(cp) = hex4(&bytes[i + 2..i + 6]).and_then(char::from_u32) {
                        result.push(cp);
                        i += 6;
                        continue;
                    }
                }
                b'x' | b'X' if i + 3 < bytes.len() => {
                    if let Some(b) = hex2(bytes[i + 2], bytes[i + 3]) {
                        result.push(b as char);
                        i += 4;
                        continue;
                    }
                }
                b'n' => {
                    result.push('\n');
                    i += 2;
                    continue;
                }
                b'r' => {
                    result.push('\r');
                    i += 2;
                    continue;
                }
                b't' => {
                    result.push('\t');
                    i += 2;
                    continue;
                }
                _ => {
                    result.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

/// Convert UTF-8 non-ASCII characters to `\uXXXX` escape sequences.
/// (ModSecurity's `utf8toUnicode` transform.)
fn utf8_to_unicode_escape(s: &str) -> String {
    use alloc::format;
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            result.push(c);
        } else {
            result.push_str(&format!("\\u{:04X}", c as u32));
        }
    }
    result
}

/// Decode `\XX` CSS hex escape sequences.
fn css_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            // CSS allows `\XXXXXX` (1-6 hex digits followed by optional space)
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && end - start < 6 && hex_digit(bytes[end]).is_some() {
                end += 1;
            }
            if end > start {
                if end < bytes.len() && bytes[end] == b' ' {
                    end += 1; // consume trailing space
                }
                if let Ok(hex_str) = core::str::from_utf8(&bytes[start..end.min(start + 6)]) {
                    if let Ok(n) = u32::from_str_radix(hex_str.trim_end(), 16) {
                        if let Some(c) = char::from_u32(n) {
                            result.push(c);
                            i = end;
                            continue;
                        }
                    }
                }
            }
            // Not a valid escape — output as-is
            result.push(bytes[i] as char);
            i += 1;
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_basic() {
        assert_eq!(url_decode_uni("%3Cscript%3E"), "<script>");
    }

    #[test]
    fn url_decode_unicode() {
        assert_eq!(url_decode_uni("%u003C"), "<");
    }

    #[test]
    fn html_entity_decode_lt_gt() {
        assert_eq!(html_entity_decode("&lt;script&gt;"), "<script>");
    }

    #[test]
    fn html_entity_decode_numeric() {
        assert_eq!(html_entity_decode("&#60;"), "<");
        assert_eq!(html_entity_decode("&#x3C;"), "<");
    }

    #[test]
    fn js_decode_unicode() {
        assert_eq!(js_decode(r"\u003Cscript\u003E"), "<script>");
    }

    #[test]
    fn compress_whitespace_collapses() {
        assert_eq!(compress_whitespace("a   b\t\tc"), "a b c");
    }

    #[test]
    fn apply_transforms_chain() {
        let t = [Transform::UrlDecodeUni, Transform::Lowercase];
        assert_eq!(apply_transforms("%3CSCRIPT%3E", &t), "<script>");
    }
}
