use base64::Engine;
use base64::engine::general_purpose;
use sha2::Digest;

pub fn create_base64_encoded_hash(data: String) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    general_purpose::URL_SAFE_NO_PAD.encode(&hash)
}