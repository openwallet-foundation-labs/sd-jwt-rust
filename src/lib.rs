// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::utils::{base64_hash, base64url_decode, jwt_payload_decode};

use error::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use strum::Display;
use std::collections::HashMap;
pub use {holder::SDJWTHolder, issuer::SDJWTIssuer, issuer::ClaimsForSelectiveDisclosureStrategy, verifier::SDJWTVerifier};

mod disclosure;
pub mod error;
pub mod holder;
pub mod issuer;
pub mod utils;
pub mod verifier;

pub const DEFAULT_SIGNING_ALG: &str = "ES256";
const SD_DIGESTS_KEY: &str = "_sd";
const DIGEST_ALG_KEY: &str = "_sd_alg";
pub const DEFAULT_DIGEST_ALG: &str = "sha-256";
const SD_LIST_PREFIX: &str = "...";
const _SD_JWT_TYP_HEADER: &str = "sd+jwt";
const KB_JWT_TYP_HEADER: &str = "kb+jwt";
const KB_DIGEST_KEY: &str = "sd_hash";
pub const COMBINED_SERIALIZATION_FORMAT_SEPARATOR: &str = "~";
const JWT_SEPARATOR: &str = ".";
const CNF_KEY: &str = "cnf";
const JWK_KEY: &str = "jwk";

#[derive(Debug)]
pub(crate) struct SDJWTHasSDClaimException(String);

impl SDJWTHasSDClaimException {}

/// SDJWTSerializationFormat is used to determine how an SD-JWT is serialized to String
#[derive(Default, Clone, PartialEq, Debug, Display)]
pub enum SDJWTSerializationFormat {
    /// JSON-encoded representation
    #[default]
    JSON,
    /// Base64-encoded representation
    Compact,
}

#[derive(Default)]
pub(crate) struct SDJWTCommon {
    typ: Option<String>,
    serialization_format: SDJWTSerializationFormat,
    unverified_input_key_binding_jwt: Option<String>,
    unverified_sd_jwt: Option<String>,
    unverified_sd_jwt_json: Option<SDJWTJson>,
    unverified_input_sd_jwt_payload: Option<Map<String, Value>>,
    hash_to_decoded_disclosure: HashMap<String, Value>,
    hash_to_disclosure: HashMap<String, String>,
    input_disclosures: Vec<String>,
    sign_alg: Option<String>,
}

#[derive(Default, Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct SDJWTJson {
    protected: String,
    payload: String,
    signature: String,
    pub disclosures: Vec<String>,
    pub kb_jwt: Option<String>,
}

// Define the SDJWTCommon struct to hold common properties.
impl SDJWTCommon {
    fn create_hash_mappings(&mut self) -> Result<()> {
        self.hash_to_decoded_disclosure = HashMap::new();
        self.hash_to_disclosure = HashMap::new();

        for disclosure in &self.input_disclosures {
            let decoded_disclosure = base64url_decode(disclosure).map_err(|err| {
                Error::InvalidDisclosure(format!(
                    "Error decoding disclosure {}: {}",
                    disclosure, err
                ))
            })?;
            let decoded_disclosure: Value =
                serde_json::from_slice(&decoded_disclosure).map_err(|err| {
                    Error::InvalidDisclosure(format!(
                        "Error parsing disclosure {}: {}",
                        disclosure, err
                    ))
                })?;

            let hash = base64_hash(disclosure.as_bytes());
            if self.hash_to_decoded_disclosure.contains_key(&hash) {
                return Err(Error::DuplicateDigestError(hash));
            }
            self.hash_to_decoded_disclosure
                .insert(hash.clone(), decoded_disclosure);
            self.hash_to_disclosure
                .insert(hash.clone(), disclosure.to_owned());
        }

        Ok(())
    }

    fn check_for_sd_claim(the_object: &Value) -> Result<()> {
        match the_object {
            Value::Object(obj) => {
                for (key, value) in obj.iter() {
                    if key == SD_DIGESTS_KEY {
                        return Err(Error::DataFieldMismatch(format!(
                            "Claim object cannot have `{}` field",
                            SD_DIGESTS_KEY
                        )));
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

    fn parse_compact_sd_jwt(&mut self, sd_jwt_with_disclosures: String) -> Result<()> {
        let parts: Vec<&str> = sd_jwt_with_disclosures
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        if parts.len() < 2 { // minimal number of SD-JWT parts according to the standard
            return Err(Error::InvalidInput(format!(
                "Invalid SD-JWT length: {}",
                parts.len()
            )));
        }
        let idx = parts.len();
        let mut parts = parts.into_iter();
        let sd_jwt = parts.next().ok_or(Error::IndexOutOfBounds {
            idx: 0,
            length: parts.len(),
            msg: format!("Invalid SD-JWT: {}", sd_jwt_with_disclosures),
        })?;
        self.sign_alg = Self::decode_header_and_get_sign_algorithm(sd_jwt);
        self.unverified_input_key_binding_jwt = Some(
            parts
                .next_back()
                .ok_or(Error::IndexOutOfBounds {
                    idx: idx - 1,
                    length: idx,
                    msg: format!(
                        "Invalid SD-JWT. Key binding not found: {}",
                        sd_jwt_with_disclosures
                    ),
                })?
                .to_owned(),
        );
        self.input_disclosures = parts.map(str::to_owned).collect();
        self.unverified_sd_jwt = Some(sd_jwt.to_owned());

        let mut sd_jwt = sd_jwt.split(JWT_SEPARATOR);
        sd_jwt.next();
        let jwt_body = sd_jwt.next().ok_or(Error::IndexOutOfBounds {
            idx: 1,
            length: 3,
            msg: format!(
                "Invalid JWT: Cannot extract JWT payload: {}",
                self.unverified_sd_jwt.to_owned().unwrap_or("".to_string())
            ),
        })?;
        self.unverified_input_sd_jwt_payload = Some(jwt_payload_decode(jwt_body)?);
        Ok(())
    }

    fn parse_json_sd_jwt(&mut self, sd_jwt_with_disclosures: String) -> Result<()> {
        let parsed_sd_jwt_json: SDJWTJson = serde_json::from_str(&sd_jwt_with_disclosures)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        self.unverified_sd_jwt_json = Some(parsed_sd_jwt_json.clone());
        self.unverified_input_key_binding_jwt = parsed_sd_jwt_json.kb_jwt;
        self.input_disclosures = parsed_sd_jwt_json.disclosures;
        self.unverified_input_sd_jwt_payload =
            Some(jwt_payload_decode(&parsed_sd_jwt_json.payload)?);
        let sd_jwt = format!(
            "{}.{}.{}",
            parsed_sd_jwt_json.protected,
            parsed_sd_jwt_json.payload,
            parsed_sd_jwt_json.signature
        );    
        self.unverified_sd_jwt = Some(sd_jwt.clone());
        self.sign_alg = Self::decode_header_and_get_sign_algorithm(&sd_jwt);    
        Ok(())
    }

    fn parse_sd_jwt(&mut self, sd_jwt_with_disclosures: String) -> Result<()> {
        match self.serialization_format {
            SDJWTSerializationFormat::Compact => {
                self.parse_compact_sd_jwt(sd_jwt_with_disclosures)
            }
            SDJWTSerializationFormat::JSON => {
                self.parse_json_sd_jwt(sd_jwt_with_disclosures)
            }
        }
    }
    /// Decodes a header jwt string and extracts the "alg" field from the JSON object.
    /// # Arguments
    /// * `sd_jwt` - jwt format string.
    /// # Returns
    /// * `Option<String>` - The result containing the algorithm String e.g ES256 or on failure None.
    fn decode_header_and_get_sign_algorithm(sd_jwt: &str) -> Option<String> {
        let parts: Vec<&str> = sd_jwt.split('.').collect();
        if parts.len() < 2 {
            return None;
        }
        let jwt_header = parts[0];
        let decoded = base64url_decode(jwt_header).ok()?;
        let decoded_str = std::str::from_utf8(&decoded).ok()?;
        let json_sign_alg: Value = serde_json::from_str(decoded_str).ok()?;
        let sign_alg = json_sign_alg.get("alg")
            .and_then(Value::as_str)
            .map(String::from);
        sign_alg
    }
}

#[cfg(test)]
mod tests {
    use crate::{utils, SDJWTCommon};


    #[test]
    fn test_parse_compact_sd_jwt(){
        let mut sdjwt = SDJWTCommon::default();
        let encoded_empty_object = utils::base64url_encode("{}".as_bytes());
        sdjwt.parse_compact_sd_jwt(format!("jwt1.{encoded_empty_object}.jwt3~disc1~disc2~kbjwt")).unwrap();
        assert_eq!(sdjwt.unverified_sd_jwt.unwrap(), format!("jwt1.{encoded_empty_object}.jwt3"));
        assert_eq!(sdjwt.unverified_input_key_binding_jwt.unwrap(), "kbjwt");
        assert_eq!(sdjwt.input_disclosures, vec!["disc1".to_string(), "disc2".to_string()]);
    }

    #[test]
    fn test_parse_json_sd_jwt() {
        let mut sdjwt = SDJWTCommon::default();
        let encoded_empty_object = utils::base64url_encode("{}".as_bytes());
        sdjwt.parse_json_sd_jwt(format!(
            "{{\"protected\":\"jwt1\",\"payload\":\"{encoded_empty_object}\",\"signature\":\"jwt3\",\"disclosures\":[\"disc1\",\"disc2\"],\"kb_jwt\":\"kbjwt\"}}"
        )).unwrap();
        assert_eq!(sdjwt.unverified_sd_jwt.unwrap(), format!("jwt1.{encoded_empty_object}.jwt3"));
        assert_eq!(sdjwt.unverified_input_key_binding_jwt.unwrap(), "kbjwt");
        assert_eq!(sdjwt.input_disclosures, vec!["disc1".to_string(), "disc2".to_string()]);
    }
}
