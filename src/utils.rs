use base64::Engine;
use base64::engine::general_purpose;
use rand::prelude::ThreadRng;
use rand::RngCore;
use serde_json::Value;
use sha2::Digest;
use crate::{SALTS, SDJWTHasSDClaimException};

pub(crate) fn base64_hash(data: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    general_purpose::URL_SAFE_NO_PAD.encode(&hash)
}

pub(crate) fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub(crate) fn base64url_decode(b64data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(b64data)
}

pub(crate) fn generate_salt(key_for_predefined_salt: Option<String>) -> String {
    let map = SALTS.lock().unwrap();

    if let Some(salt) = key_for_predefined_salt.and_then(|key| map.get(&key)) { //FIXME better mock approach
        salt.clone()
    } else {
        let mut buf = [0u8; 16];
        ThreadRng::default().fill_bytes(&mut buf);
        base64url_encode(&buf)
    }
}

pub(crate) fn jwt_payload_decode(b64data: &str) -> Result<serde_json::Map<String, Value>, SDJWTHasSDClaimException> {
    Ok(serde_json::from_str(&String::from_utf8(base64url_decode(b64data).unwrap()).unwrap()).unwrap())
}
