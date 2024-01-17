use crate::error;
use crate::error::Error;
use crate::error::Error::DeserializationError;

use base64::engine::general_purpose;
use base64::Engine;
use error::Result;
#[cfg(feature = "mock_salts")]
use lazy_static::lazy_static;
use rand::prelude::ThreadRng;
use rand::RngCore;
use serde_json::Value;
use sha2::Digest;
#[cfg(feature = "mock_salts")]
use std::{collections::HashMap, sync::Mutex};

#[cfg(feature = "mock_salts")]
lazy_static! {
    pub static ref SALTS: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

pub(crate) fn base64_hash(data: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

pub(crate) fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub(crate) fn base64url_decode(b64data: &str) -> Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(b64data)
        .map_err(|e| Error::DeserializationError(e.to_string()))
}

pub(crate) fn generate_salt(_key_for_predefined_salt: Option<String>) -> String {

    #[cfg(feature = "mock_salts")]
    {
        let map = SALTS.lock().unwrap();
        if let Some(salt) = _key_for_predefined_salt.and_then(|key| map.get(&key)) {
            //FIXME better mock approach
            return salt.clone()
        }
    }

    let mut buf = [0u8; 16];
    ThreadRng::default().fill_bytes(&mut buf);
    base64url_encode(&buf)
}

pub(crate) fn jwt_payload_decode(b64data: &str) -> Result<serde_json::Map<String, Value>> {
    serde_json::from_str(
        &String::from_utf8(
            base64url_decode(b64data).map_err(|e| DeserializationError(e.to_string()))?,
        )
            .map_err(|e| DeserializationError(e.to_string()))?,
    )
        .map_err(|e| DeserializationError(e.to_string()))
}
