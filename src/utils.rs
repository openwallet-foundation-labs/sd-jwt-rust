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
use std::{collections::VecDeque, sync::Mutex};

#[cfg(feature = "mock_salts")]
lazy_static! {
    pub static ref SALTS: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
}

#[doc(hidden)]
pub fn base64_hash(data: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

pub(crate) fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[doc(hidden)]
pub fn base64url_decode(b64data: &str) -> Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(b64data)
        .map_err(|e| Error::DeserializationError(e.to_string()))
}

pub(crate) fn generate_salt() -> String {
    let mut buf = [0u8; 16];
    ThreadRng::default().fill_bytes(&mut buf);
    base64url_encode(&buf)
}

#[cfg(feature = "mock_salts")]
pub(crate) fn generate_salt_mock() -> String {
    let mut salts = SALTS.lock().unwrap();
    return salts.pop_front().expect("SALTS is empty");
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
