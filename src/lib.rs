use std::collections::HashMap;
use base64::{engine::general_purpose, Engine};
use lazy_static::lazy_static;
use rand::prelude::ThreadRng;
use rand::RngCore;
use serde_json::{Map, Value};
use sha2::Digest;
use std::sync::Mutex;
pub use {holder::SDJWTHolder, issuer::SDJWTIssuer, verifier::SDJWTVerifier};
mod disclosure;
pub mod holder;
pub mod issuer;
pub mod verifier;

pub const DEFAULT_SIGNING_ALG: &str = "ES256";
const SD_DIGESTS_KEY: &str = "_sd";
const DIGEST_ALG_KEY: &str = "_sd_alg";
pub const DEFAULT_DIGEST_ALG: &str = "sha-256";
const SD_LIST_PREFIX: &str = "...";
const _SD_JWT_TYP_HEADER: &str = "sd+jwt";
const KB_JWT_TYP_HEADER: &str = "kb+jwt";
const JWS_KEY_DISCLOSURES: &str = "disclosures";
const JWS_KEY_KB_JWT: &str = "kb_jwt";
pub const COMBINED_SERIALIZATION_FORMAT_SEPARATOR: &str = "~";
const JWT_SEPARATOR: &str = ".";

#[derive(Debug)]
pub(crate) struct SDJWTHasSDClaimException(String);

impl SDJWTHasSDClaimException {}

#[derive(Default)]
pub(crate) struct SDJWTCommon {
    typ: Option<String>,
    serialization_format: String,
    unverified_input_key_binding_jwt: Option<String>,
    unverified_sd_jwt: Option<String>,
    unverified_input_sd_jwt_payload: Option<Map<String, Value>>,
    hash_to_decoded_disclosure: HashMap<String, Value>,
    hash_to_disclosure: HashMap<String, String>,
    input_disclosures: Vec<String>,
}

// Define the SDJWTCommon struct to hold common properties.
impl SDJWTCommon {
    fn b64hash(&self, data: &[u8]) -> String {
        let mut hasher = sha2::Sha256::new(); // TODO dynamic type
        hasher.update(data);
        let hash = hasher.finalize();
        SDJWTCommon::base64url_encode(&hash)
    }

    fn create_hash_mappings(&mut self) -> Result<(), String> {
        self.hash_to_decoded_disclosure = HashMap::new();
        self.hash_to_disclosure = HashMap::new();

        for disclosure in &self.input_disclosures {
            let decoded_disclosure = SDJWTCommon::base64url_decode(disclosure).map_err(
                |err| format!("Error decoding disclosure {}: {}", disclosure, err)
            )?;
            let decoded_disclosure: Value = serde_json::from_slice(&decoded_disclosure).map_err(
                |err| format!("Error parsing disclosure {}: {}", disclosure, err)
            )?;

            let hash = self.b64hash(disclosure.as_bytes());
            if self.hash_to_decoded_disclosure.contains_key(&hash) {
                return Err(format!("Duplicate disclosure hash {} for disclosure {:?}", hash, decoded_disclosure));
            }
            self.hash_to_decoded_disclosure.insert(hash.clone(), decoded_disclosure);
            self.hash_to_disclosure.insert(hash.clone(), disclosure.to_owned());
        }

        Ok(())
    }

    fn check_for_sd_claim(the_object: &Value) -> Result<(), SDJWTHasSDClaimException> {
        match the_object {
            Value::Object(obj) => {
                for (key, value) in obj.iter() {
                    if key == SD_DIGESTS_KEY {
                        let str_err = serde_json::to_string(obj).unwrap();
                        return Err(SDJWTHasSDClaimException(str_err));
                    } else {
                        Self::check_for_sd_claim(value)?;
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    Self::check_for_sd_claim(item)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn parse_sd_jwt(&mut self, sd_jwt_with_disclosures: String) -> Result<(), String> {
        if self.get_serialization_format() == "compact" {
            let parts: Vec<&str> = sd_jwt_with_disclosures.split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR).collect();
            if parts.len() < 3 {
                unimplemented!()
            }
            let mut parts = parts.into_iter();
            let sd_jwt = parts.next().unwrap();
            self.unverified_input_key_binding_jwt = Some(parts.next_back().unwrap().to_owned());
            self.input_disclosures = parts.map(str::to_owned).collect();
            self.unverified_sd_jwt = Some(sd_jwt.to_owned());

            let mut sd_jwt = sd_jwt.split(JWT_SEPARATOR);
            sd_jwt.next();
            let jwt_body = sd_jwt.next().unwrap();
            self.unverified_input_sd_jwt_payload = Some(SDJWTCommon::jwt_payload_decode(jwt_body).unwrap());
            Ok(())
        } else {
            // If the SD-JWT is in JSON format, parse the JSON and extract the disclosures.
            let unverified_input_sd_jwt_parsed: Value = serde_json::from_str(&sd_jwt_with_disclosures).unwrap();
            self.unverified_input_key_binding_jwt = unverified_input_sd_jwt_parsed.get(JWS_KEY_KB_JWT).map(Value::to_string);
            self.input_disclosures = unverified_input_sd_jwt_parsed[JWS_KEY_DISCLOSURES].as_array().unwrap().iter().map(Value::to_string).collect();
            let payload = unverified_input_sd_jwt_parsed["payload"].as_str().unwrap();
            self.unverified_input_sd_jwt_payload = Some(SDJWTCommon::jwt_payload_decode(payload).unwrap());
            Ok(())
        }
    }

    fn get_serialization_format(&self) -> &str {
        &self.serialization_format
    }

    fn base64url_encode(data: &[u8]) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    fn base64url_decode(b64data: &str) -> Result<Vec<u8>, base64::DecodeError> {
        general_purpose::URL_SAFE_NO_PAD.decode(b64data)
    }

    fn jwt_payload_decode(b64data: &str) -> Result<serde_json::Map<String, Value>, SDJWTHasSDClaimException> {
        Ok(serde_json::from_str(&String::from_utf8(Self::base64url_decode(b64data).unwrap()).unwrap()).unwrap())
    }


    fn generate_salt(key_for_predefined_salt: Option<String>) -> String {
        let map = SALTS.lock().unwrap();

        if let Some(salt) = key_for_predefined_salt.and_then(|key|map.get(&key)) { //FIXME better mock approach
            salt.clone()
        } else {
            let mut buf = [0u8; 16];
            ThreadRng::default().fill_bytes(&mut buf);
            Self::base64url_encode(&buf)
        }
    }
}

lazy_static! {
    pub static ref SALTS: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

#[cfg(test)]
mod tests {
    //FIXME add tests
}
