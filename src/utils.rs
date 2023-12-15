use crate::error;
use crate::error::Error;
use crate::error::Error::DeserializationError;
use crate::SALTS;
use base64::engine::general_purpose;
use base64::Engine;
use error::Result;
use rand::prelude::ThreadRng;
use rand::RngCore;
use serde_json::Value;
use sha2::Digest;

pub(crate) fn base64_hash(data: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    general_purpose::URL_SAFE_NO_PAD.encode(&hash)
}

pub(crate) fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub(crate) fn base64url_decode(b64data: &str) -> Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(b64data)
        .map_err(|e| Error::DeserializationError(e.to_string()))
}

pub(crate) fn generate_salt(key_for_predefined_salt: Option<String>) -> String {
    let map = SALTS.lock().unwrap();

    if let Some(salt) = key_for_predefined_salt.and_then(|key| map.get(&key)) {
        //FIXME better mock approach
        salt.clone()
    } else {
        let mut buf = [0u8; 16];
        ThreadRng::default().fill_bytes(&mut buf);
        base64url_encode(&buf)
    }
}

pub(crate) fn jwt_payload_decode(b64data: &str) -> Result<serde_json::Map<String, Value>> {
    Ok(serde_json::from_str(
        &String::from_utf8(
            base64url_decode(b64data).map_err(|e| DeserializationError(e.to_string()))?,
        )
            .map_err(|e| DeserializationError(e.to_string()))?,
    )
        .map_err(|e| DeserializationError(e.to_string()))?)
}
