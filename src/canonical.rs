//! RFC 8785 (JSON Canonicalization Scheme) for the subset of JSON
//! that broadside records use: objects, arrays, strings, booleans,
//! null, and integers. Non-integer numbers are refused outright —
//! canonicalization of floats is where implementations diverge, and
//! broadside records never carry them, so the honest move is to
//! fail closed rather than approximate.
//!
//! Object keys sort by UTF-16 code units (the RFC's rule; for the
//! ASCII keys broadside uses this coincides with byte order).
//! Strings escape only what the RFC requires: quotation mark,
//! reverse solidus, and control characters (\b \t \n \f \r or
//! \u00XX). Everything else is emitted as UTF-8 as-is.

use serde_json::Value;

/// Serialize `value` in canonical form. Errors on non-integer
/// numbers and on strings containing unpaired surrogates (which
/// serde_json cannot represent anyway).
pub fn canonicalize(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err(format!(
                    "non-integer number {n} is outside the canonical subset"
                ));
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by_key(|a| utf16_key(a));
            out.push('{');
            for (idx, key) in keys.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[*key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn utf16_key(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_compacts() {
        let v = json!({"b": 1, "a": [true, null, "x"], "c": {"z": 2, "y": 3}});
        assert_eq!(
            canonicalize(&v).expect("canonical"),
            "{\"a\":[true,null,\"x\"],\"b\":1,\"c\":{\"y\":3,\"z\":2}}"
        );
    }

    #[test]
    fn escapes_only_what_the_rfc_requires() {
        let v = json!({"s": "a\"b\\c\u{0001}d\u{00e9}"});
        assert_eq!(
            canonicalize(&v).expect("canonical"),
            "{\"s\":\"a\\\"b\\\\c\\u0001d\u{e9}\"}"
        );
    }

    #[test]
    fn rejects_floats_fail_closed() {
        // Adversarial: floats and float-valued integers outside the
        // integer path must not silently canonicalize.
        assert!(canonicalize(&json!({"x": 1.5})).is_err());
        assert!(canonicalize(&json!([0.1])).is_err());
    }

    #[test]
    fn integer_edges() {
        assert_eq!(canonicalize(&json!(-42)).expect("neg"), "-42");
        assert_eq!(
            canonicalize(&json!(18446744073709551615u64)).expect("u64 max"),
            "18446744073709551615"
        );
    }
}
