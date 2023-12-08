use crate::SDJWTCommon;

#[derive(Debug)]
pub(crate) struct SDJWTDisclosure {
    pub raw_b64: String,
    pub hash: String,
}

impl SDJWTDisclosure  {
    pub(crate) fn new<V>(key: Option<String>, value: V, inner: &SDJWTCommon) -> Self where V: ToString {
        let salt = SDJWTCommon::generate_salt(key.clone());
        let mut value_str = value.to_string();
        value_str = value_str.replace(":[", ": [").replace(',', ", ");
        let (_data, raw_b64) = if let Some(key) = &key { //TODO remove data?
            let data = format!(r#"["{}", "{}", {}]"#, salt, key, value_str);
            let raw_b64 = SDJWTCommon::base64url_encode(data.as_bytes());
            (data, raw_b64)
        } else {
            let data = format!("[{}, {}]", salt, value_str);
            let raw_b64 = SDJWTCommon::base64url_encode(data.as_bytes());
            (data, raw_b64)
        };

        let hash = inner.b64hash(raw_b64.as_bytes());

        Self {
            raw_b64,
            hash,
        }
    }
}
