use crate::utils::{base64_hash, base64url_encode, generate_salt};

#[derive(Debug)]
pub(crate) struct SDJWTDisclosure {
    pub raw_b64: String,
    pub hash: String,
}

impl SDJWTDisclosure  {
    pub(crate) fn new<V>(key: Option<String>, value: V) -> Self where V: ToString {
        let salt = generate_salt(key.clone());
        let mut value_str = value.to_string();
        value_str = value_str.replace(":[", ": [").replace(',', ", ");
        let (_data, raw_b64) = if let Some(key) = &key { //TODO remove data?
            let data = format!(r#"["{}", "{}", {}]"#, salt, key, value_str);
            let raw_b64 = base64url_encode(data.as_bytes());
            (data, raw_b64)
        } else {
            let data = format!(r#"["{}", {}]"#, salt, value_str);
            let raw_b64 = base64url_encode(data.as_bytes());
            (data, raw_b64)
        };

        let hash = base64_hash(raw_b64.as_bytes());

        Self {
            raw_b64,
            hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::base64url_decode;
    use regex::Regex;


    #[test]
    fn test_sdjwt_disclosure_when_key_is_none() {
        let sdjwt_disclosure = SDJWTDisclosure::new(None, "test");
        let decoded_disclosure: String = String::from_utf8(base64url_decode(&sdjwt_disclosure.raw_b64).unwrap()).unwrap();

        let re = Regex::new(r#"\[".*", test]"#).unwrap();
        assert!(re.is_match(&decoded_disclosure));
    }

    #[test]
    fn test_sdjwt_disclosure_when_key_is_present() {
        let sdjwt_disclosure = SDJWTDisclosure::new(Some("key".to_string()), "test");
        let decoded = String::from_utf8(base64url_decode(&sdjwt_disclosure.raw_b64).unwrap()).unwrap();

        let re = Regex::new(r#"\[".*", "key", test]"#).unwrap();
        assert!(re.is_match(&decoded));    }
}
