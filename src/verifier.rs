// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::SDJWTSerializationFormat;
use crate::error::Error;
use crate::error::Result;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use log::debug;
use serde_json::{Map, Value};
use std::ops::Add;
use std::option::Option;
use std::str::FromStr;
use std::string::String;
use std::vec::Vec;

use crate::utils::base64_hash;
use crate::{
    SDJWTCommon, CNF_KEY, COMBINED_SERIALIZATION_FORMAT_SEPARATOR, DEFAULT_DIGEST_ALG,
    DEFAULT_SIGNING_ALG, DIGEST_ALG_KEY, JWK_KEY, KB_DIGEST_KEY, KB_JWT_TYP_HEADER, SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
};

type KeyResolver = dyn Fn(&str, &Header) -> DecodingKey;

pub struct SDJWTVerifier {
    sd_jwt_engine: SDJWTCommon,

    sd_jwt_payload: Map<String, Value>,
    _holder_public_key_payload: Option<Map<String, Value>>,
    duplicate_hash_check: Vec<String>,
    pub verified_claims: Value,

    cb_get_issuer_key: Box<KeyResolver>,
}

impl SDJWTVerifier {
    /// Create a new SDJWTVerifier instance.
    ///
    /// # Arguments
    /// * `sd_jwt_presentation` - The SD-JWT presentation to verify.
    /// * `cb_get_issuer_key` - A callback function that takes the issuer and the header of the SD-JWT and returns the public key of the issuer.
    /// * `expected_aud` - The expected audience of the SD-JWT.
    /// * `expected_nonce` - The expected nonce of the SD-JWT.
    /// * `serialization_format` - The serialization format of the SD-JWT, see [SDJWTSerializationFormat].
    ///
    /// # Returns
    /// * `SDJWTVerifier` - The SDJWTVerifier instance. The verified claims can be accessed via the `verified_claims` property.
    pub fn new(
        sd_jwt_presentation: String,
        cb_get_issuer_key: Box<KeyResolver>,
        expected_aud: Option<String>,
        expected_nonce: Option<String>,
        serialization_format: SDJWTSerializationFormat,
    ) -> Result<Self> {
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
        let sign_alg = verifier.sd_jwt_engine.sign_alg.clone();
        verifier.verify_sd_jwt(sign_alg.clone())?;
        verifier.verified_claims = verifier.extract_sd_claims()?;

        if let (Some(expected_aud), Some(expected_nonce)) = (&expected_aud, &expected_nonce) {
            let sign_alg = verifier.sd_jwt_engine.unverified_input_key_binding_jwt
                .as_ref()
                .and_then(|value| {
                    SDJWTCommon::decode_header_and_get_sign_algorithm(value)
                });

            verifier.verify_key_binding_jwt(
                expected_aud.to_owned(),
                expected_nonce.to_owned(),
                sign_alg.as_deref(),
            )?;
        } else if expected_aud.is_some() || expected_nonce.is_some() {
            return Err(Error::InvalidInput(
                "Either both expected_aud and expected_nonce must be provided or both must be None"
                    .to_string(),
            ));
        }

        Ok(verifier)
    }

    fn verify_sd_jwt(&mut self, sign_alg: Option<String>) -> Result<()> {
        let sd_jwt = self
            .sd_jwt_engine
            .unverified_sd_jwt
            .as_ref()
            .ok_or(Error::ConversionError("reference".to_string()))?;
        let parsed_header_sd_jwt = jsonwebtoken::decode_header(sd_jwt)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;

        let unverified_issuer = self
            .sd_jwt_engine
            .unverified_input_sd_jwt_payload
            .as_ref()
            .ok_or(Error::ConversionError("reference".to_string()))?["iss"]
            .as_str()
            .ok_or(Error::ConversionError("str".to_string()))?;
        let issuer_public_key = (self.cb_get_issuer_key)(unverified_issuer, &parsed_header_sd_jwt);
        let algorithm: Algorithm = match sign_alg {
            Some(alg_str) => Algorithm::from_str(&alg_str)
                .map_err(|e| Error::DeserializationError(e.to_string()))?,
            None => Algorithm::ES256, // Default or handle as needed
        };
        let mut validation = Validation::new(algorithm);
        // RFC 9901 §4.1: `exp` is not mandated, so don't require it. `validate_exp`
        // stays true, so a present `exp` is still checked for expiry.
        validation.required_spec_claims.remove("exp");
        let claims = jsonwebtoken::decode(
            sd_jwt,
            &issuer_public_key,
            &validation,
        )
            .map_err(|e| Error::DeserializationError(format!("Cannot decode jwt: {}", e)))?
            .claims;

        let _ = sign_alg; //FIXME check algo

        self.sd_jwt_payload = claims;
        self._holder_public_key_payload = self
            .sd_jwt_payload
            .get(CNF_KEY)
            .and_then(Value::as_object)
            .cloned();

        Ok(())
    }

    fn verify_key_binding_jwt(
        &mut self,
        expected_aud: String,
        expected_nonce: String,
        sign_alg: Option<&str>,
    ) -> Result<()> {
        let sign_alg = sign_alg.unwrap_or(DEFAULT_SIGNING_ALG);
        let holder_public_key_payload_jwk = match &self._holder_public_key_payload {
            None => {
                return Err(Error::KeyNotFound(
                    "No holder public key in SD-JWT".to_string(),
                ));
            }
            Some(payload) => {
                if let Some(jwk) = payload.get(JWK_KEY) {
                    jwk.clone()
                } else {
                    return Err(Error::InvalidInput("The holder_public_key_payload is malformed. It doesn't contain the claim jwk".to_string()));
                }
            }
        };
        let pubkey: DecodingKey = match serde_json::from_value::<Jwk>(holder_public_key_payload_jwk)
        {
            Ok(jwk) => {
                if let Ok(pubkey) = DecodingKey::from_jwk(&jwk) {
                    pubkey
                } else {
                    return Err(Error::DeserializationError(
                        "Cannot parse DecodingKey from json".to_string(),
                    ));
                }
            }
            Err(_) => {
                return Err(Error::DeserializationError(
                    "Cannot parse JWK from json".to_string(),
                ));
            }
        };
        let key_binding_jwt = match &self.sd_jwt_engine.unverified_input_key_binding_jwt {
            Some(payload) => {
                let mut validation = Validation::new(
                    Algorithm::from_str(sign_alg)
                        .map_err(|e| Error::DeserializationError(e.to_string()))?,
                );
                validation.set_audience(&[&expected_aud]);
                validation.set_required_spec_claims(&["aud"]);

                jsonwebtoken::decode::<Map<String, Value>>(&payload, &pubkey, &validation)
                    .map_err(|e| Error::DeserializationError(e.to_string()))?
            }
            None => {
                return Err(Error::InvalidState(
                    "Cannot take Key Binding JWK from String".to_string(),
                ));
            }
        };
        if key_binding_jwt.header.typ != Some(KB_JWT_TYP_HEADER.to_string()) {
            return Err(Error::InvalidInput("Invalid header type".to_string()));
        }
        if key_binding_jwt.claims.get("nonce") != Some(&Value::String(expected_nonce)) {
            return Err(Error::InvalidInput("Invalid nonce".to_string()));
        }
        if !key_binding_jwt.claims.contains_key("iat") {
            return Err(Error::InvalidInput("Missing required `iat` claim in KB-JWT".to_string()));
        }
        let sd_hash = self._get_key_binding_digest_hash()?;
        if key_binding_jwt.claims.get(KB_DIGEST_KEY) != Some(&Value::String(sd_hash)) {
            return Err(Error::InvalidInput("Invalid digest in KB-JWT".to_string()));
        }

        Ok(())
    }

    fn _get_key_binding_digest_hash(&mut self) -> Result<String> {
        let mut combined: Vec<&str> =
            Vec::with_capacity(self.sd_jwt_engine.input_disclosures.len() + 1);
        combined.push(
            self.sd_jwt_engine
                .unverified_sd_jwt
                .as_ref()
                .ok_or(Error::ConversionError("reference".to_string()))?
        );
        combined.extend(
            self.sd_jwt_engine
                .input_disclosures
                .iter()
                .map(|s| s.as_str()),
        );
        let combined = combined
            .join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .add(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);

        Ok(base64_hash(combined.as_bytes()))
    }

    fn extract_sd_claims(&mut self) -> Result<Value> {
        if self.sd_jwt_payload.contains_key(DIGEST_ALG_KEY)
            && self.sd_jwt_payload[DIGEST_ALG_KEY] != DEFAULT_DIGEST_ALG
        {
            return Err(Error::DeserializationError(format!(
                "Invalid hash algorithm {}",
                self.sd_jwt_payload[DIGEST_ALG_KEY]
            )));
        }

        for (key, value) in self.sd_jwt_payload.iter() {
            if key == DIGEST_ALG_KEY {
                continue;
            }
            Self::reject_nested_sd_alg(value)?;
        }

        self.duplicate_hash_check = Vec::new();
        let claims: Value = self.sd_jwt_payload.clone().into_iter().collect();
        let unpacked = self.unpack_disclosed_claims(&claims)?;

        // Draft-07 section 8.1 step 5: if any presented Disclosure was not
        // referenced by digest value in the Issuer-signed JWT (directly or
        // recursively via other Disclosures), the SD-JWT MUST be rejected.
        // `duplicate_hash_check` accumulates every digest encountered during
        // the recursive unpack, so any disclosure whose hash is absent from
        // that list is unreferenced.
        for disclosure_hash in self.sd_jwt_engine.hash_to_decoded_disclosure.keys() {
            if !self.duplicate_hash_check.contains(disclosure_hash) {
                return Err(Error::InvalidDisclosure(format!(
                    "Disclosure was not referenced by any digest in the SD-JWT: {}",
                    disclosure_hash
                )));
            }
        }

        Ok(unpacked)
    }

    fn reject_nested_sd_alg(value: &Value) -> Result<()> {
        match value {
            Value::Object(obj) => {
                if obj.contains_key(DIGEST_ALG_KEY) {
                    return Err(Error::DataFieldMismatch(format!(
                        "`{}` is only allowed at the top level of the SD-JWT payload",
                        DIGEST_ALG_KEY
                    )));
                }
                obj.values().try_for_each(Self::reject_nested_sd_alg)
            }
            Value::Array(arr) => arr.iter().try_for_each(Self::reject_nested_sd_alg),
            _ => Ok(()),
        }
    }

    fn unpack_disclosed_claims(&mut self, sd_jwt_claims: &Value) -> Result<Value> {
        match sd_jwt_claims {
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                Ok(sd_jwt_claims.to_owned())
            }
            Value::Array(arr) => {
                self.unpack_disclosed_claims_in_array(arr)
            }
            Value::Object(obj) => {
                self.unpack_disclosed_claims_in_object(obj)
            }
        }
    }

    fn unpack_disclosed_claims_in_array(&mut self, arr: &Vec<Value>) -> Result<Value> {
        if arr.is_empty() {
            return Err(Error::InvalidArrayDisclosureObject(
                "Array of disclosed claims cannot be empty".to_string(),
            ));
        }

        let mut claims = vec![];
        for value in arr {

            match value {
                // case for SD objects in arrays
                Value::Object(obj) if obj.contains_key(SD_LIST_PREFIX) => {
                    if obj.len() > 1 {
                        return Err(Error::InvalidDisclosure(
                            "Disclosed claim object in an array maust contain only one key".to_string(),
                        ));
                    }

                    let digest = obj.get(SD_LIST_PREFIX).unwrap();
                    let disclosed_claim = self.unpack_from_digest(digest)?;
                    if let Some(disclosed_claim) = disclosed_claim {
                        claims.push(disclosed_claim);
                    }
                },
                _ => {
                    let claim = self.unpack_disclosed_claims(value)?;
                    claims.push(claim);
                },
            }
        }
        Ok(Value::Array(claims))
    }

    fn unpack_disclosed_claims_in_object(&mut self, nested_sd_jwt_claims: &Map<String, Value>) -> Result<Value> {
        let mut disclosed_claims: Map<String, Value> = serde_json::Map::new();

        for (key, value) in nested_sd_jwt_claims {
            if key != SD_DIGESTS_KEY && key != DIGEST_ALG_KEY {
                disclosed_claims.insert(key.to_owned(), self.unpack_disclosed_claims(value)?);
            }
        }

        if let Some(Value::Array(digest_of_disclosures)) = nested_sd_jwt_claims.get(SD_DIGESTS_KEY)
        {
            self.unpack_from_digests(&mut disclosed_claims, digest_of_disclosures)?;
        }

        Ok(Value::Object(disclosed_claims))
    }

    fn unpack_from_digests(
        &mut self,
        pre_output: &mut Map<String, Value>,
        digests_of_disclosures: &Vec<Value>,
    ) -> Result<()> {
        for digest in digests_of_disclosures {
            let digest = digest
                .as_str()
                .ok_or(Error::ConversionError("str".to_string()))?;
            if self.duplicate_hash_check.contains(&digest.to_string()) {
                return Err(Error::DuplicateDigestError(digest.to_string()));
            }
            self.duplicate_hash_check.push(digest.to_string());

            if let Some(value_for_digest) =
                self.sd_jwt_engine.hash_to_decoded_disclosure.get(digest)
            {
                let disclosure =
                    value_for_digest
                        .as_array()
                        .ok_or(Error::InvalidArrayDisclosureObject(
                            value_for_digest.to_string(),
                        ))?;
                if disclosure.len() != 3 {
                    return Err(Error::InvalidDisclosure(format!(
                        "Object-property Disclosure must be a 3-element array [salt, name, value]: {}",
                        value_for_digest
                    )));
                }
                let key = disclosure[1]
                    .as_str()
                    .ok_or(Error::ConversionError("str".to_string()))?
                    .to_owned();
                if key == SD_DIGESTS_KEY || key == SD_LIST_PREFIX {
                    return Err(Error::InvalidDisclosure(format!(
                        "Disclosure claim name must not be `_sd` or `...`: {}",
                        key
                    )));
                }
                let value = disclosure[2].clone();
                if pre_output.contains_key(&key) {
                    return Err(Error::DuplicateKeyError(key.to_string()));
                }
                let unpacked_value = self.unpack_disclosed_claims(&value)?;
                pre_output.insert(key, unpacked_value);
            } else {
                debug!("Digest {:?} skipped as decoy", digest)
            }
        }

        Ok(())
    }

    fn unpack_from_digest(
        &mut self,
        digest: &Value,
    ) -> Result<Option<Value>> {
        let digest = digest
            .as_str()
            .ok_or(Error::ConversionError("str".to_string()))?;
        if self.duplicate_hash_check.contains(&digest.to_string()) {
            return Err(Error::DuplicateDigestError(digest.to_string()));
        }
        self.duplicate_hash_check.push(digest.to_string());

        if let Some(value_for_digest) =
            self.sd_jwt_engine.hash_to_decoded_disclosure.get(digest)
        {
            let disclosure =
                value_for_digest
                    .as_array()
                    .ok_or(Error::InvalidArrayDisclosureObject(
                        value_for_digest.to_string(),
                    ))?;
            if disclosure.len() != 2 {
                return Err(Error::InvalidArrayDisclosureObject(format!(
                    "Array-element Disclosure must be a 2-element array [salt, value]: {}",
                    value_for_digest
                )));
            }

            let value = disclosure[1].clone();
            let unpacked_value = self.unpack_disclosed_claims(&value)?;
            return Ok(Some(unpacked_value));
        } else {
            debug!("Digest {:?} skipped as decoy", digest)
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use crate::issuer::ClaimsForSelectiveDisclosureStrategy;
    use crate::utils::{base64url_decode, base64url_encode};
    use crate::{SDJWTHolder, SDJWTIssuer, SDJWTFlattenedJson, SDJWTGeneralJson, SDJWTVerifier, SDJWTSerializationFormat, COMBINED_SERIALIZATION_FORMAT_SEPARATOR};
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
    use rstest::rstest;
    use serde_json::{json, Map, Value};

    const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
    const PUBLIC_ISSUER_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";
    const PRIVATE_ISSUER_ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMFECAQEwBQYDK2VwBCIEIF93k6rxZ8W38cm0rOwfGdH+YY3k10hP+7gd0falPLg0\ngSEAdW31QyWzfed4EPcw1rYuUa1QU+fXEL0HhdAfYZRkihc=\n-----END PRIVATE KEY-----\n";
    const PUBLIC_ISSUER_ED25519_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAdW31QyWzfed4EPcw1rYuUa1QU+fXEL0HhdAfYZRkihc=\n-----END PUBLIC KEY-----\n";

    // EdDSA (Ed25519)
    const HOLDER_KEY_ED25519: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIOeIDnHHMoPCUTiq206gR+FdCdNtc31SzF1nKX31hvhd\n-----END PRIVATE KEY-----";

    const HOLDER_JWK_KEY_ED25519: &str = r#"{
        "alg": "EdDSA",
        "crv": "Ed25519",
        "kid": "52128f2e-900e-414e-81c3-0b5f86f0f7b3",
        "kty": "OKP",
        "x": "24QLWXJ18wtbg3k_MDGhGM17Xh39UftuxbwJZzRLzkA"
    }"#;

    #[test]
    fn reject_sd_jwt_with_nested_sd_alg() {
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "_sd_alg": "sha-256",
            "address": { "_sd_alg": "sha-256" }
        });
        let header = Header::new(Algorithm::ES256);
        let signed = jsonwebtoken::encode(&header, &payload, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );

        assert!(result.is_err(), "verifier accepted a nested `_sd_alg`");
        let err = format!("{}", result.err().unwrap());
        assert!(
            err.contains("only allowed at the top level"),
            "wrong error: {err}"
        );
    }

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
        let sd_jwt = SDJWTIssuer::new(issuer_key, None).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
            .unwrap();
        let presentation = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(sd_jwt, presentation);
        let verified_claims = SDJWTVerifier::new(
            presentation,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        )
            .unwrap()
            .verified_claims;
        assert_eq!(user_claims, verified_claims);
    }

    #[test]
    fn verify_noclaim_presentation() {
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
        let sd_jwt = SDJWTIssuer::new(issuer_key, None).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
            .unwrap();

        let presentation = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(sd_jwt, presentation);
        let verified_claims = SDJWTVerifier::new(
            presentation,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        )
            .unwrap()
            .verified_claims;
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
        let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
            "$.name",
            "$.addresses[1]",
            "$.addresses[1].country",
            "$.nationalities[0]",
        ]);
        let sd_jwt = SDJWTIssuer::new(issuer_key, None).issue_sd_jwt(
            user_claims.clone(),
            strategy,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
            .unwrap();

        let mut claims_to_disclose = user_claims.clone();
        claims_to_disclose["addresses"] = Value::Array(vec![Value::Bool(true), Value::Bool(true)]);
        claims_to_disclose["nationalities"] =
            Value::Array(vec![Value::Bool(true), Value::Bool(true)]);
        let presentation = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(
                claims_to_disclose.as_object().unwrap().clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let verified_claims = SDJWTVerifier::new(
            presentation.clone(),
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        )
            .unwrap()
            .verified_claims;

        let expected_verified_claims = json!(
            {
                "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
                "addresses": [
                    {
                        "street_address": "Schulstr. 12",
                        "locality": "Schulpforta",
                        "region": "Sachsen-Anhalt",
                        "country": "DE",
                    },
                    {
                        "street_address": "456 Main St",
                        "locality": "Anytown",
                        "region": "NY",
                    },
                ],
                "nationalities": [
                    "US",
                    "CA",
                ],
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "exp": 1883000000,
                "name": "Bois"
            }
        );

        assert_eq!(verified_claims, expected_verified_claims);
    }

    #[test]
    fn verify_arrayed_no_sd_presentation() {
        let user_claims = json!(
            {
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "exp": 1883000000,
                "array_with_recursive_sd": [
                    "boring",
                    {
                        "foo": "bar",
                        "baz": {
                            "qux": "quux"
                        }
                    },
                    ["foo", "bar"]
                ],
                "test2": ["foo", "bar"]
            }
        );
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
            "$.array_with_recursive_sd[1]",
            "$.array_with_recursive_sd[1].baz",
            "$.array_with_recursive_sd[2][0]",
            "$.array_with_recursive_sd[2][1]",
            "$.test2[0]",
            "$.test2[1]",
        ]);
        let sd_jwt = SDJWTIssuer::new(issuer_key, None).issue_sd_jwt(
            user_claims.clone(),
            strategy,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
            .unwrap();

        let claims_to_disclose = json!({});

        let presentation = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(
                claims_to_disclose.as_object().unwrap().clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let verified_claims = SDJWTVerifier::new(
            presentation.clone(),
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        )
            .unwrap()
            .verified_claims;

        let expected_verified_claims = json!(
            {
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "exp": 1883000000,
                "array_with_recursive_sd":  [
                    "boring",
                    [],
                ],
                "test2": [],
            }
        );

        assert_eq!(verified_claims, expected_verified_claims);
    }

    #[test]
    fn verify_full_presentation_to_allow_other_algorithms() {

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
        let private_issuer_bytes = PRIVATE_ISSUER_ED25519_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ed_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_key, Some("EdDSA".to_string())).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
        )
            .unwrap();
       
        let presentation = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::FlattenedJson) // Changed to Flattened Json format
            .unwrap()
            .create_presentation(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None,
                None
            )
            .unwrap();
        assert_eq!(sd_jwt, presentation);
        let verified_claims = SDJWTVerifier::new(
            presentation,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_ED25519_PEM.as_bytes();
                DecodingKey::from_ed_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
        )
            .unwrap()
            .verified_claims;
        assert_eq!(user_claims, verified_claims);
    }
    #[test]
    fn verify_presentation_when_sd_jwt_uses_es256_and_key_binding_uses_eddsa() {

        let user_claims = json!({
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            },
            "exp": 1883000000,
            "iat": 1683000000,
            "iss": "https://example.com/issuer",
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",

        });

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();

        let mut issuer = SDJWTIssuer::new(issuer_key, Some("ES256".to_string()));

        let sd_jwt = issuer.issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
            false,
            SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
        ).unwrap();

        let private_holder_bytes = HOLDER_KEY_ED25519.as_bytes();
        let holder_key = EncodingKey::from_ed_pem(private_holder_bytes).unwrap();

        let nonce = Some(String::from("testNonce"));
        let aud = Some(String::from("testAud"));

        let mut holder = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::FlattenedJson).unwrap(); // Changed to Flattened Json format
        let presentation = holder.create_presentation(
                user_claims.as_object().unwrap().clone(),
                nonce.clone(),
                aud.clone(),
                Some(holder_key),
                Some("EdDSA".to_string())
            )
            .unwrap();
        let verified_claims = SDJWTVerifier::new(
            presentation,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            aud.clone(),
            nonce.clone(),
            SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
        )
            .unwrap()
            .verified_claims;

        let claims_to_check = json!({
            "iss": user_claims["iss"].clone(),
            "iat": user_claims["iat"].clone(),
            "exp": user_claims["exp"].clone(),
            "cnf": {
                "jwk": serde_json::from_str::<Value>(HOLDER_JWK_KEY_ED25519).unwrap(),
            },
            "sub": user_claims["sub"].clone(),
            "address": user_claims["address"].clone(),
        });

        assert_eq!(claims_to_check, verified_claims);
    }

    #[rstest]
    #[case::flattened(SDJWTSerializationFormat::FlattenedJson)]
    #[case::general(SDJWTSerializationFormat::GeneralJson)]
    #[case::compact(SDJWTSerializationFormat::Compact)]
    fn reject_tampered_presentation_with_injected_disclosure(
        #[case] format: SDJWTSerializationFormat,
    ) {
        let user_claims = json!({
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            },
            "exp": 1883000000,
            "iat": 1683000000,
            "iss": "https://example.com/issuer",
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        });

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();

        let sd_jwt = SDJWTIssuer::new(issuer_key, Some("ES256".to_string())).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
            false,
            format.clone(),
        ).unwrap();

        let private_holder_bytes = HOLDER_KEY_ED25519.as_bytes();
        let holder_key = EncodingKey::from_ed_pem(private_holder_bytes).unwrap();
        let nonce = Some(String::from("testNonce"));
        let aud = Some(String::from("testAud"));

        let presentation = SDJWTHolder::new(sd_jwt, format.clone())
            .unwrap()
            .create_presentation(
                user_claims.as_object().unwrap().clone(),
                nonce.clone(),
                aud.clone(),
                Some(holder_key),
                Some("EdDSA".to_string()),
            )
            .unwrap();

        // Tamper: inject a syntactically-valid extra disclosure into the presentation.
        // The KB-JWT's sd_hash was computed by the holder over the original disclosure
        // list, so the verifier MUST detect the mismatch. Where the disclosure goes
        // differs by format: a `~`-separated segment before the KB-JWT (Compact §4),
        // a top-level `header` member (Flattened §8.2), or the first signature's
        // header (General §8.3).
        let injected_disclosure =
            base64url_encode(br#"["injectedsalt", "injected_claim", "value"]"#);
        let tampered = match format {
            SDJWTSerializationFormat::FlattenedJson => {
                let mut json: SDJWTFlattenedJson = serde_json::from_str(&presentation).unwrap();
                json.header.disclosures.push(injected_disclosure);
                serde_json::to_string(&json).unwrap()
            }
            SDJWTSerializationFormat::GeneralJson => {
                let mut json: SDJWTGeneralJson = serde_json::from_str(&presentation).unwrap();
                json.signatures[0].header.disclosures.push(injected_disclosure);
                serde_json::to_string(&json).unwrap()
            }
            SDJWTSerializationFormat::Compact => {
                // presentation = "<jwt>~<disclosures…>~<kb_jwt>"; splice the extra
                // disclosure in just before the trailing KB-JWT segment.
                let mut parts: Vec<&str> =
                    presentation.split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR).collect();
                parts.insert(parts.len() - 1, &injected_disclosure);
                parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            }
        };

        let result = SDJWTVerifier::new(
            tampered,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            aud,
            nonce,
            format.clone(),
        );

        assert!(
            result.is_err(),
            "Verifier accepted {format:?} presentation with tampered disclosure list",
        );
    }

    #[test]
    fn reject_general_json_with_multiple_signatures() {
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        });

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();

        let sd_jwt = SDJWTIssuer::new(issuer_key, Some("ES256".to_string()))
            .issue_sd_jwt(
                user_claims,
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::GeneralJson,
            )
            .unwrap();

        let mut json: SDJWTGeneralJson = serde_json::from_str(&sd_jwt).unwrap();
        let duplicated = json.signatures[0].clone();
        json.signatures.push(duplicated);
        let tampered = serde_json::to_string(&json).unwrap();

        let result = SDJWTVerifier::new(
            tampered,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::GeneralJson,
        );

        assert!(
            result.is_err(),
            "Verifier accepted a General JSON SD-JWT with multiple signatures",
        );
    }

    #[test]
    fn reject_kb_jwt_missing_iat_claim() {
        let user_claims = json!({
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            },
            "exp": 1883000000,
            "iat": 1683000000,
            "iss": "https://example.com/issuer",
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        });

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_key, Some("ES256".to_string())).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
            false,
            SDJWTSerializationFormat::FlattenedJson,
        ).unwrap();

        let private_holder_bytes = HOLDER_KEY_ED25519.as_bytes();
        let holder_key = EncodingKey::from_ed_pem(private_holder_bytes).unwrap();
        let nonce = Some(String::from("testNonce"));
        let aud = Some(String::from("testAud"));

        let presentation = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::FlattenedJson)
            .unwrap()
            .create_presentation(
                user_claims.as_object().unwrap().clone(),
                nonce.clone(),
                aud.clone(),
                Some(holder_key),
                Some("EdDSA".to_string()),
            )
            .unwrap();

        // Tamper: re-sign the KB-JWT with the `iat` claim stripped from the
        // payload. The KB-JWT remains validly signed by the holder key, so
        // signature verification will pass — but the spec requires `iat` to
        // be present, and the verifier must reject this presentation.
        let mut json: SDJWTFlattenedJson = serde_json::from_str(&presentation).unwrap();
        let original_kb_jwt = json.header.kb_jwt.clone().unwrap();
        let kb_parts: Vec<&str> = original_kb_jwt.split('.').collect();
        let payload_bytes = base64url_decode(kb_parts[1]).unwrap();
        let mut kb_payload: Map<String, Value> =
            serde_json::from_slice(&payload_bytes).unwrap();
        kb_payload.remove("iat");

        let resign_key =
            EncodingKey::from_ed_pem(HOLDER_KEY_ED25519.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(crate::KB_JWT_TYP_HEADER.to_string());
        let tampered_kb_jwt =
            jsonwebtoken::encode(&header, &kb_payload, &resign_key).unwrap();

        json.header.kb_jwt = Some(tampered_kb_jwt);
        let tampered_presentation = serde_json::to_string(&json).unwrap();

        let result = SDJWTVerifier::new(
            tampered_presentation,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            aud,
            nonce,
            SDJWTSerializationFormat::FlattenedJson,
        );

        assert!(
            result.is_err(),
            "Verifier accepted KB-JWT presentation missing required `iat` claim",
        );
    }

    #[test]
    fn reject_presentation_with_unreferenced_disclosure() {
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
        let sd_jwt = SDJWTIssuer::new(issuer_key, None).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
            .unwrap();
        let presentation = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // Append a syntactically-valid but unreferenced disclosure. The
        // legitimate disclosures still hash and unpack normally; only the
        // injected disclosure is not referenced by any digest in the
        // Issuer-signed JWT, so the verifier must reject per draft-07 §8.1.
        let injected = base64url_encode(
            br#"["unreferencedsalt", "unreferenced_claim", "value"]"#,
        );
        let presentation = presentation.trim_end_matches(
            COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
        );
        let tampered = format!(
            "{}{}{}{}",
            presentation,
            COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
            injected,
            COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
        );

        let result = SDJWTVerifier::new(
            tampered,
            Box::new(|_, _| {
                let public_issuer_bytes = PUBLIC_ISSUER_PEM.as_bytes();
                DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
            }),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );

        assert!(
            result.is_err(),
            "Verifier accepted presentation with unreferenced disclosure",
        );
    }

    #[test]
    fn verify_presentation_without_exp() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_key, None)
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let presentation = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let result = SDJWTVerifier::new(
            presentation,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        assert!(result.is_ok(), "verifier rejected `exp`-less SD-JWT");
    }

    #[test]
    fn reject_disclosure_with_reserved_claim_name() {
        use crate::utils::base64_hash;
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        for reserved in ["_sd", "..."] {
            // A well-formed (3-element) Disclosure that discloses a claim named
            // `_sd` or `...`; §7.1 requires the Verifier to reject it.
            let disclosure =
                base64url_encode(format!(r#"["salt", "{reserved}", "value"]"#).as_bytes());
            let digest = base64_hash(disclosure.as_bytes());
            let payload = json!({
                "iss": "https://example.com/issuer",
                "iat": 1683000000,
                "_sd": [digest],
                "_sd_alg": "sha-256",
            });
            let signed =
                jsonwebtoken::encode(&Header::new(Algorithm::ES256), &payload, &issuer_key)
                    .unwrap();
            let sd_jwt = format!("{signed}~{disclosure}~");

            let result = SDJWTVerifier::new(
                sd_jwt,
                Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
                None,
                None,
                SDJWTSerializationFormat::Compact,
            );
            assert!(
                result.is_err(),
                "verifier accepted a Disclosure with reserved claim name `{reserved}`",
            );
        }
    }

    #[test]
    fn reject_presentation_with_expired_exp() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1683000300,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_key, None)
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        match result {
            Ok(_) => panic!("verifier accepted a presentation with an expired `exp`"),
            Err(err) => assert!(
                err.to_string().contains("ExpiredSignature"),
                "expected an expiry failure, got: {err}"
            ),
        }
    }

    #[test]
    fn reject_object_property_disclosure_with_wrong_element_count() {
        use crate::utils::base64_hash;
        // A conforming object-property Disclosure is a 3-element array
        // [salt, claim name, claim value]. Craft a malformed 2-element one
        // and reference its digest from the signed `_sd` array.
        let malformed = base64url_encode(br#"["salt", "valuewithoutname"]"#);
        let digest = base64_hash(malformed.as_bytes());
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "_sd": [digest],
            "_sd_alg": "sha-256",
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &payload, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~{malformed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        assert!(
            result.is_err(),
            "verifier accepted a malformed (non-3-element) object-property Disclosure",
        );
    }

    #[test]
    fn reject_array_element_disclosure_with_wrong_element_count() {
        use crate::utils::base64_hash;
        // A conforming array-element Disclosure is a 2-element array
        // [salt, value]. Craft a malformed 3-element one and reference it
        // via {"...": digest}.
        let malformed = base64url_encode(br#"["salt", "claimname", "value"]"#);
        let digest = base64_hash(malformed.as_bytes());
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "arr": [ { "...": digest } ],
            "_sd_alg": "sha-256",
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &payload, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~{malformed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        assert!(
            result.is_err(),
            "verifier accepted a malformed (non-2-element) array-element Disclosure",
        );
    }
}
