use std::collections::HashMap;
use std::option::Option;
use std::string::String;
use std::vec::Vec;

use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use log::debug;
use serde_json::{Map, Value};

use crate::{DEFAULT_DIGEST_ALG, DEFAULT_SIGNING_ALG, DIGEST_ALG_KEY, SD_DIGESTS_KEY, SDJWTCommon};

type KeyResolver = dyn Fn(&str, &Header) -> DecodingKey;

pub struct SDJWTVerifier {
    sd_jwt_engine: SDJWTCommon,

    sd_jwt_payload: Map<String, Value>,
    _holder_public_key_payload: Option<HashMap<String, Value>>,
    duplicate_hash_check: Vec<String>,
    verified_claims: Value,

    cb_get_issuer_key: Box<KeyResolver>,
}

impl SDJWTVerifier {
    pub fn new(
        sd_jwt_presentation: String,
        cb_get_issuer_key: Box<KeyResolver>,
        expected_aud: Option<String>,
        expected_nonce: Option<String>,
        serialization_format: String,
    ) -> Result<Self, String> {
        let mut verifier = SDJWTVerifier {
            sd_jwt_payload: serde_json::Map::new(),
            _holder_public_key_payload: None,
            duplicate_hash_check: Vec::new(),
            cb_get_issuer_key,
            sd_jwt_engine: SDJWTCommon {
                serialization_format,
                ..Default::default()
            },
            verified_claims: Value::Null,
        };

        verifier.sd_jwt_engine.parse_sd_jwt(sd_jwt_presentation)?;
        verifier.sd_jwt_engine.create_hash_mappings()?;
        verifier.verify_sd_jwt(Some(DEFAULT_SIGNING_ALG.to_owned()))?;
        verifier.verified_claims = verifier.extract_sd_claims()?;

        if expected_aud.is_some() && expected_nonce.is_some() {
            verifier.verify_key_binding_jwt(expected_aud.unwrap(), expected_nonce.unwrap(), Some(DEFAULT_SIGNING_ALG))?;
        } else if expected_aud.is_some() || expected_nonce.is_some() {
            return Err("Either both expected_aud and expected_nonce must be provided or both must be None".to_string());
        }

        Ok(verifier)
    }

    fn verify_sd_jwt(&mut self, sign_alg: Option<String>) -> Result<(), String> {
        let sd_jwt = self.sd_jwt_engine.unverified_sd_jwt.as_ref().unwrap();
        let parsed_header_sd_jwt = jsonwebtoken::decode_header(sd_jwt).map_err(|err| {
            err.to_string()
        })?;

        let unverified_issuer = self.sd_jwt_engine.unverified_input_sd_jwt_payload.as_ref().unwrap()["iss"].as_str().unwrap();
        let issuer_public_key = (self.cb_get_issuer_key)(unverified_issuer, &parsed_header_sd_jwt);

        let claims = jsonwebtoken::decode(sd_jwt,
                                          &issuer_public_key,
                                          &Validation::new(Algorithm::ES256)).unwrap().claims;

        let _ = sign_alg; //FIXME check algo

        self.sd_jwt_payload = claims;

        Ok(())
    }

    fn verify_key_binding_jwt(&mut self, expected_aud: String, expected_nonce: String, sign_alg: Option<&str>) -> Result<(), String> {
        let (_, _, _) = (expected_aud, expected_nonce, sign_alg);
        unimplemented!("JWT KB");
    }

    fn extract_sd_claims(&mut self) -> Result<Value, String> {
        if self.sd_jwt_payload.contains_key(DIGEST_ALG_KEY) && self.sd_jwt_payload[DIGEST_ALG_KEY] != DEFAULT_DIGEST_ALG {
            return Err(format!("Invalid hash algorithm {}", self.sd_jwt_payload[DIGEST_ALG_KEY]));
        }

        self.duplicate_hash_check = Vec::new();
        let claims: Value = self.sd_jwt_payload.clone().into_iter().collect();
        Ok(self.unpack_disclosed_claims(&claims).unwrap())
    }

    fn unpack_disclosed_claims(&mut self, sd_jwt_claims: &Value) -> Result<Value, String> {
        let nested_sd_jwt_claims = match sd_jwt_claims {
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                return Ok(sd_jwt_claims.to_owned());
            }
            Value::Array(arr) => {
                if arr.is_empty() {
                    return Err("Array of disclosed claims cannot be empty".to_string());
                }

                let mut claims = vec![];
                for value in arr {
                    let claim = self.unpack_disclosed_claims(value).unwrap();
                    claims.push(claim);
                }
                return Ok(serde_json::to_value(claims).unwrap());
            }
            Value::Object(obj) => { obj }
        };

        let mut disclosed_claims: Map<String, Value> = serde_json::Map::new();

        for (key, value) in nested_sd_jwt_claims {
            if key != SD_DIGESTS_KEY && key != DIGEST_ALG_KEY {
                disclosed_claims.insert(key.to_owned(),
                                        self.unpack_disclosed_claims(value).unwrap());
            }
        }

        if let Some(Value::Array(digest_of_disclosures)) = nested_sd_jwt_claims.get(SD_DIGESTS_KEY) {
            self.unpack_from_digests(&mut disclosed_claims, digest_of_disclosures)?;
        }

        Ok(Value::Object(disclosed_claims))
    }

    fn unpack_from_digests(&mut self,  pre_output: &mut Map<String, Value>, digests_of_disclosures: &Vec<Value>) -> Result<(), String> {
        for digest in digests_of_disclosures {
            let digest = digest.as_str().unwrap();
            if self.duplicate_hash_check.contains(&digest.to_string()) {
                return Err("Duplicate hash found in SD-JWT".to_string());
            }
            self.duplicate_hash_check.push(digest.to_string());

            if let Some(value_for_digest) = self.sd_jwt_engine.hash_to_decoded_disclosure.get(digest) {
                let disclosure = value_for_digest.as_array().unwrap();
                let key = disclosure[1].as_str().unwrap().to_owned();
                let value = disclosure[2].clone();
                if pre_output.contains_key(&key) {
                    return Err(format!(
                        "Duplicate key found when unpacking disclosed claim: '{}' in {:?}. This is not allowed.",
                        key,
                        pre_output
                    ));
                }
                let unpacked_value = self.unpack_disclosed_claims(&value)?;
                pre_output.insert(key, unpacked_value);
            } else {
                debug!("Digest {:?} skipped as decoy", digest)
            }
        }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use jsonwebtoken::{DecodingKey, EncodingKey};
    use serde_json::{json, Value};
    use crate::issuer::SDJWTClaimsStrategy;
    use crate::{SDJWTHolder, SDJWTIssuer, SDJWTVerifier};

    const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
    const PUBLIC_ISSUER_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";


    #[test]
    fn verify_full_presentation() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        });
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::issue_sd_jwt(user_claims.clone(), SDJWTClaimsStrategy::Full, issuer_key, None, None, false, "compact".to_owned());
        let presentation = SDJWTHolder::new(sd_jwt.serialized_sd_jwt.clone(), "compact".to_owned()).create_presentation(user_claims.as_object().unwrap().clone(), None, None, None, None);
        assert_eq!(sd_jwt.serialized_sd_jwt, presentation);
        let verified_claims = SDJWTVerifier::new(presentation,Box::new(|_, _| {
            let public_issuer_bytes= PUBLIC_ISSUER_PEM.as_bytes();
            DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
        }), None, None, "compact".to_owned()).unwrap().verified_claims;
        assert_eq!(user_claims, verified_claims);
    }

    #[test]
    fn verify_arrayed_presentation() {
        let user_claims = json!(
            {
              "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
              "name": "Bois",
              "iss": "https://example.com/issuer",
              "iat": 1683000000,
              "exp": 1883000000,
              "addresses": [
                {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
                },
                {
                "street_address": "456 Main St",
                "locality": "Anytown",
                "region": "NY",
                "country": "US"
                }
              ],
              "nationalities": [
                "US",
                "CA"
              ]
            }
        );
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let strategy = SDJWTClaimsStrategy::Partial(vec!["$.name", "$.addresses[1]", "$.addresses[1].country", "$.nationalities[0]"]);
        let sd_jwt = SDJWTIssuer::issue_sd_jwt(user_claims.clone(), strategy, issuer_key, None, None, false, "compact".to_owned());

        let mut claims_to_disclose = user_claims.clone();
        claims_to_disclose["addresses"] = Value::Array(vec![Value::Bool(true), Value::Bool(true)]);
        claims_to_disclose["nationalities"] = Value::Array(vec![Value::Bool(true), Value::Bool(true)]);
        let presentation = SDJWTHolder::new(sd_jwt.serialized_sd_jwt.clone(), "compact".to_owned()).create_presentation(claims_to_disclose.as_object().unwrap().clone(), None, None, None, None);

        let verified_claims = SDJWTVerifier::new(presentation.clone(), Box::new(|_, _| {
            let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
            DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
        }), None, None, "compact".to_owned()).unwrap().verified_claims;

        assert_eq!(verified_claims["addresses"][0].to_owned(), user_claims["addresses"][0].to_owned());
        assert!(!verified_claims["addresses"][1].to_owned().get("...").unwrap().to_string().is_empty());
    }
}