// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(feature = "mock_salts"))]
use crate::utils::generate_salt;
#[cfg(feature = "mock_salts")]
use crate::utils::generate_salt_mock;
use crate::utils::{base64_hash, base64url_encode};
use serde_json::Value;

#[derive(Debug)]
pub(crate) struct SDJWTDisclosure {
    pub raw_b64: String,
    pub hash: String,
}

impl SDJWTDisclosure {
    pub(crate) fn new<V>(key: Option<String>, value: V) -> Self
    where
        V: ToString,
    {
        #[cfg(not(feature = "mock_salts"))]
        let salt = generate_salt();
        let mut value_str = value.to_string();

        #[cfg(feature = "mock_salts")]
        let python_spacing = *crate::utils::MOCK_DISCLOSURE_PYTHON_SPACING.lock().unwrap();
        #[cfg(not(feature = "mock_salts"))]
        let python_spacing = true;

        #[cfg(feature = "mock_salts")]
        let salt = {
            if python_spacing {
                value_str = value_str
                    .replace(":[", ": [")
                    .replace(',', ", ")
                    .replace("\":", "\": ")
                    .replace("\":  ", "\": ");
            }
            generate_salt_mock()
        };

        if !value_str.is_ascii() {
            value_str = escape_unicode_chars(&value_str);
        }

        // The outer [salt, key, value] separators are independent of
        // value_str's own (possibly re-spaced above) formatting: production
        // use and the Python-reference interop always match sd-jwt-python's
        // `json.dumps` separators (", " / ": "); the JS-reference interop
        // needs `JSON.stringify`'s fully compact separators instead.
        let data = match (&key, python_spacing) {
            (Some(key), true) => format!(r#"["{}", {}, {}]"#, salt, escape_json(key), value_str),
            (Some(key), false) => format!(r#"["{}",{},{}]"#, salt, escape_json(key), value_str),
            (None, true) => format!(r#"["{}", {}]"#, salt, value_str),
            (None, false) => format!(r#"["{}",{}]"#, salt, value_str),
        };

        let raw_b64 = base64url_encode(data.as_bytes());
        let hash = base64_hash(raw_b64.as_bytes());

        Self { raw_b64, hash }
    }
}

fn escape_unicode_chars(s: &str) -> String {
    let mut result = String::new();

    for c in s.chars() {
        if c.is_ascii() {
            result.push(c);
        } else {
            let esc_c = c.escape_unicode().to_string();

            let esc_c_new = match esc_c.chars().count() {
                6 => esc_c.replace("\\u{", "\\u00").replace('}', ""), // example: \u{de}
                7 => esc_c.replace("\\u{", "\\u0").replace('}', ""),  // example: \u{980}
                8 => esc_c.replace("\\u{", "\\u").replace('}', ""),   // example: \u{23f0}
                _ => {
                    panic!("unexpected value")
                }
            };

            result.push_str(&esc_c_new);
        }
    }

    result
}

fn escape_json(s: &str) -> String {
    Value::String(String::from(s)).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::base64url_decode;
    use regex::Regex;

    #[test]
    fn test_sdjwt_disclosure_when_key_is_none() {
        let sdjwt_disclosure = SDJWTDisclosure::new(None, "test");
        let decoded_disclosure: String =
            String::from_utf8(base64url_decode(&sdjwt_disclosure.raw_b64).unwrap()).unwrap();

        let re = Regex::new(r#"\[".*", test]"#).unwrap();
        assert!(re.is_match(&decoded_disclosure));
    }

    #[test]
    fn test_sdjwt_disclosure_when_key_is_present() {
        let sdjwt_disclosure = SDJWTDisclosure::new(Some("key".to_string()), "test");
        let decoded =
            String::from_utf8(base64url_decode(&sdjwt_disclosure.raw_b64).unwrap()).unwrap();

        let re = Regex::new(r#"\[".*", "key", test]"#).unwrap();
        assert!(re.is_match(&decoded));
    }
}
