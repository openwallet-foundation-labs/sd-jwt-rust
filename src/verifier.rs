// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::error::Result;
use crate::SDJWTSerializationFormat;
use log::debug;
use serde_json::{Map, Value};
use std::ops::Add;
use std::option::Option;
use std::string::String;
use std::vec::Vec;

use crate::crypto_provider::{KeyRequest, SDJWTCryptoProvider, SignatureRole};
use crate::utils::{base64_hash, now_seconds};
use crate::{
    SDJWTCommon, CNF_KEY, COMBINED_SERIALIZATION_FORMAT_SEPARATOR, DEFAULT_DIGEST_ALG,
    DIGEST_ALG_KEY, JWK_KEY, KB_DIGEST_KEY, KB_JWT_TYP_HEADER, SD_DIGESTS_KEY, SD_LIST_PREFIX,
};

/// RFC 7519 `aud` matching: the token's `aud` may be a single string or an
/// array of strings, and matches when `expected` is that string or a member.
fn aud_matches(aud: Option<&Value>, expected: &str) -> bool {
    match aud {
        Some(Value::String(s)) => s == expected,
        Some(Value::Array(items)) => items.iter().any(|item| item.as_str() == Some(expected)),
        _ => false,
    }
}

pub struct SDJWTVerifier {
    sd_jwt_engine: SDJWTCommon,

    sd_jwt_payload: Map<String, Value>,
    _holder_public_key_payload: Option<Map<String, Value>>,
    duplicate_hash_check: Vec<String>,
    pub verified_claims: Value,

    crypto_provider: Box<dyn SDJWTCryptoProvider>,
}

impl SDJWTVerifier {
    /// Create a new SDJWTVerifier instance.
    ///
    /// # Arguments
    /// * `sd_jwt_presentation` - The SD-JWT presentation to verify.
    /// * `crypto_provider` - A crypto provider that verifies signatures; key selection and trust are its responsibility, see [KeyRequest].
    /// * `expected_aud` - The expected audience of the SD-JWT.
    /// * `expected_nonce` - The expected nonce of the SD-JWT.
    /// * `serialization_format` - The serialization format of the SD-JWT, see [SDJWTSerializationFormat].
    ///
    /// # Returns
    /// * `SDJWTVerifier` - The SDJWTVerifier instance. The verified claims can be accessed via the `verified_claims` property.
    pub fn new(
        sd_jwt_presentation: String,
        crypto_provider: Box<dyn SDJWTCryptoProvider>,
        expected_aud: Option<String>,
        expected_nonce: Option<String>,
        serialization_format: SDJWTSerializationFormat,
    ) -> Result<Self> {
        let mut verifier = SDJWTVerifier {
            sd_jwt_payload: serde_json::Map::new(),
            _holder_public_key_payload: None,
            duplicate_hash_check: Vec::new(),
            crypto_provider,
            sd_jwt_engine: SDJWTCommon {
                serialization_format,
                ..Default::default()
            },
            verified_claims: Value::Null,
        };

        verifier.sd_jwt_engine.parse_sd_jwt(sd_jwt_presentation)?;
        verifier.sd_jwt_engine.create_hash_mappings()?;
        verifier.verify_sd_jwt()?;
        verifier.verified_claims = verifier.extract_sd_claims()?;

        if let (Some(expected_aud), Some(expected_nonce)) = (&expected_aud, &expected_nonce) {
            verifier.verify_key_binding_jwt(expected_aud.to_owned(), expected_nonce.to_owned())?;
        } else if expected_aud.is_some() || expected_nonce.is_some() {
            return Err(Error::InvalidInput(
                "Either both expected_aud and expected_nonce must be provided or both must be None"
                    .to_string(),
            ));
        }

        Ok(verifier)
    }

    fn verify_sd_jwt(&mut self) -> Result<()> {
        self.sd_jwt_payload = self
            .sd_jwt_engine
            .process_issuer_jwt(Some(self.crypto_provider.as_ref()))?;
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
    ) -> Result<()> {
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
        let jwk_json = serde_json::to_string(&holder_public_key_payload_jwk)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        let key_binding_jwt = self
            .sd_jwt_engine
            .unverified_input_key_binding_jwt
            .as_ref()
            .ok_or(Error::InvalidState(
                "Cannot take Key Binding JWK from String".to_string(),
            ))?;
        let header = SDJWTCommon::parse_protected_header(key_binding_jwt)?;
        if header.typ.as_deref() != Some(KB_JWT_TYP_HEADER) {
            return Err(Error::InvalidInput("Invalid header type".to_string()));
        }
        let request = KeyRequest {
            role: SignatureRole::KeyBindingJwt,
            iss: None,
            kid: header.kid,
            alg: header.alg,
            x5c: header.x5c,
            jwk: Some(jwk_json),
        };
        let claims = SDJWTCommon::verify_compact_jws(
            key_binding_jwt,
            &request,
            self.crypto_provider.as_ref(),
        )?;
        SDJWTCommon::validate_temporal(&claims)?;
        if claims.get("nonce") != Some(&Value::String(expected_nonce)) {
            return Err(Error::InvalidInput("Invalid nonce".to_string()));
        }
        if !aud_matches(claims.get("aud"), &expected_aud) {
            return Err(Error::InvalidInput(
                "Invalid audience in KB-JWT".to_string(),
            ));
        }
        // The KB-JWT `iat` must be present, numeric, and not in the future; a
        // past-side max-age window is left to the application.
        const IAT_LEEWAY_SECONDS: u64 = 60;
        let iat = SDJWTCommon::numeric_date(&claims, "iat")?.ok_or_else(|| {
            Error::InvalidInput("Missing required `iat` claim in KB-JWT".to_string())
        })?;
        if iat > now_seconds()?.saturating_add(IAT_LEEWAY_SECONDS) as f64 {
            return Err(Error::InvalidInput(
                "Key Binding JWT `iat` is in the future".to_string(),
            ));
        }
        let sd_hash = self._get_key_binding_digest_hash()?;
        if claims.get(KB_DIGEST_KEY) != Some(&Value::String(sd_hash)) {
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
                .ok_or(Error::ConversionError("reference".to_string()))?,
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
            Value::Array(arr) => self.unpack_disclosed_claims_in_array(arr),
            Value::Object(obj) => self.unpack_disclosed_claims_in_object(obj),
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
                            "Disclosed claim object in an array maust contain only one key"
                                .to_string(),
                        ));
                    }

                    let digest = obj.get(SD_LIST_PREFIX).unwrap();
                    let disclosed_claim = self.unpack_from_digest(digest)?;
                    if let Some(disclosed_claim) = disclosed_claim {
                        claims.push(disclosed_claim);
                    }
                }
                _ => {
                    let claim = self.unpack_disclosed_claims(value)?;
                    claims.push(claim);
                }
            }
        }
        Ok(Value::Array(claims))
    }

    fn unpack_disclosed_claims_in_object(
        &mut self,
        nested_sd_jwt_claims: &Map<String, Value>,
    ) -> Result<Value> {
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

    fn unpack_from_digest(&mut self, digest: &Value) -> Result<Option<Value>> {
        let digest = digest
            .as_str()
            .ok_or(Error::ConversionError("str".to_string()))?;
        if self.duplicate_hash_check.contains(&digest.to_string()) {
            return Err(Error::DuplicateDigestError(digest.to_string()));
        }
        self.duplicate_hash_check.push(digest.to_string());

        if let Some(value_for_digest) = self.sd_jwt_engine.hash_to_decoded_disclosure.get(digest) {
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
    use crate::{
        SDJWTFlattenedJson, SDJWTGeneralJson, SDJWTHolder, SDJWTIssuer, SDJWTSerializationFormat,
        SDJWTVerifier, COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
    };
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
    fn aud_matches_accepts_string_and_array_forms() {
        use super::aud_matches;
        assert!(aud_matches(
            Some(&json!("https://verifier.example")),
            "https://verifier.example"
        ));
        // RFC 7519 array form containing the expected audience.
        assert!(aud_matches(
            Some(&json!(["https://other", "https://verifier.example"])),
            "https://verifier.example"
        ));
        assert!(!aud_matches(
            Some(&json!("https://other")),
            "https://verifier.example"
        ));
        assert!(!aud_matches(Some(&json!([])), "https://verifier.example"));
        assert!(!aud_matches(None, "https://verifier.example"));
    }

    fn issuer_crypto_provider(
        key: EncodingKey,
        alg: Option<&str>,
    ) -> Box<dyn crate::SDJWTCryptoProvider> {
        Box::new(
            crate::SDJWTCryptoProviderBuiltin::new()
                .with_signing_key(key, alg.unwrap_or(crate::DEFAULT_SIGNING_ALG)),
        )
    }

    fn verifier_crypto_provider(alg: &str) -> Box<dyn crate::SDJWTCryptoProvider> {
        Box::new(crate::SDJWTCryptoProviderBuiltin::new().with_verifying_key(
            DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap(),
            alg,
        ))
    }

    /// Provider for a Holder in these tests: verifies the (ES256) Issuer
    /// signature and signs the Key Binding JWT with `holder_key` (EdDSA).
    fn holder_crypto_provider(holder_key: EncodingKey) -> Box<dyn crate::SDJWTCryptoProvider> {
        Box::new(
            crate::SDJWTCryptoProviderBuiltin::new()
                .with_verifying_key(
                    DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap(),
                    "ES256",
                )
                .with_signing_key(holder_key, "EdDSA"),
        )
    }

    /// Crypto provider whose `verify` always fails, for exercising error
    /// propagation from a Verifier's crypto provider.
    struct ErroringCryptoProvider;
    impl crate::SDJWTCryptoProvider for ErroringCryptoProvider {
        fn verify(&self, _: &[u8], _: &[u8], _: &crate::KeyRequest) -> crate::error::Result<()> {
            Err(crate::error::Error::KeyNotFound(
                "unknown issuer".to_string(),
            ))
        }
        fn allowed_verifying_algs(
            &self,
            _: crate::SignatureRole,
        ) -> crate::error::Result<Vec<String>> {
            Ok(vec![crate::DEFAULT_SIGNING_ALG.to_string()])
        }
        fn sign(&self, _: &[u8], _: crate::SignatureRole) -> crate::error::Result<Vec<u8>> {
            Err(crate::error::Error::KeyNotFound(
                "no signing key configured".to_string(),
            ))
        }
        fn signing_alg(&self, _: crate::SignatureRole) -> crate::error::Result<String> {
            Err(crate::error::Error::KeyNotFound(
                "no signing key configured".to_string(),
            ))
        }
    }

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
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();
        let presentation = SDJWTHolder::new(
            sd_jwt.clone(),
            SDJWTSerializationFormat::Compact,
            verifier_crypto_provider("ES256"),
        )
        .unwrap()
        .create_presentation(user_claims.as_object().unwrap().clone(), None, None)
        .unwrap();
        assert_eq!(sd_jwt, presentation);
        let verified_claims = SDJWTVerifier::new(
            presentation,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let presentation =
            SDJWTHolder::new_unverified(sd_jwt.clone(), SDJWTSerializationFormat::Compact)
                .unwrap()
                .create_presentation(user_claims.as_object().unwrap().clone(), None, None)
                .unwrap();
        assert_eq!(sd_jwt, presentation);
        let verified_claims = SDJWTVerifier::new(
            presentation,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
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
        let presentation = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(claims_to_disclose.as_object().unwrap().clone(), None, None)
            .unwrap();

        let verified_claims = SDJWTVerifier::new(
            presentation.clone(),
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims.clone(),
                strategy,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let claims_to_disclose = json!({});

        let presentation = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(claims_to_disclose.as_object().unwrap().clone(), None, None)
            .unwrap();

        let verified_claims = SDJWTVerifier::new(
            presentation.clone(),
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, Some("EdDSA")))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
            )
            .unwrap();

        let presentation = SDJWTHolder::new(
            sd_jwt.clone(),
            SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
            Box::new(crate::SDJWTCryptoProviderBuiltin::new().with_verifying_key(
                DecodingKey::from_ed_pem(PUBLIC_ISSUER_ED25519_PEM.as_bytes()).unwrap(),
                "EdDSA",
            )),
        )
        .unwrap()
        .create_presentation(user_claims.as_object().unwrap().clone(), None, None)
        .unwrap();
        assert_eq!(sd_jwt, presentation);
        let verified_claims = SDJWTVerifier::new(
            presentation,
            Box::new(crate::SDJWTCryptoProviderBuiltin::new().with_verifying_key(
                DecodingKey::from_ed_pem(PUBLIC_ISSUER_ED25519_PEM.as_bytes()).unwrap(),
                "EdDSA",
            )),
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

        let mut issuer = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, Some("ES256")));

        let sd_jwt = issuer
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
                false,
                SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
            )
            .unwrap();

        let private_holder_bytes = HOLDER_KEY_ED25519.as_bytes();
        let holder_key = EncodingKey::from_ed_pem(private_holder_bytes).unwrap();

        let nonce = Some(String::from("testNonce"));
        let aud = Some(String::from("testAud"));

        let mut holder = SDJWTHolder::new(
            sd_jwt.clone(),
            SDJWTSerializationFormat::FlattenedJson, // Changed to Flattened Json format
            holder_crypto_provider(holder_key),
        )
        .unwrap();
        let presentation = holder
            .create_presentation(
                user_claims.as_object().unwrap().clone(),
                nonce.clone(),
                aud.clone(),
            )
            .unwrap();
        let verified_claims = SDJWTVerifier::new(
            presentation,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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

        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, Some("ES256")))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
                false,
                format.clone(),
            )
            .unwrap();

        let private_holder_bytes = HOLDER_KEY_ED25519.as_bytes();
        let holder_key = EncodingKey::from_ed_pem(private_holder_bytes).unwrap();
        let nonce = Some(String::from("testNonce"));
        let aud = Some(String::from("testAud"));

        let presentation =
            SDJWTHolder::new(sd_jwt, format.clone(), holder_crypto_provider(holder_key))
                .unwrap()
                .create_presentation(
                    user_claims.as_object().unwrap().clone(),
                    nonce.clone(),
                    aud.clone(),
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
                json.signatures[0]
                    .header
                    .disclosures
                    .push(injected_disclosure);
                serde_json::to_string(&json).unwrap()
            }
            SDJWTSerializationFormat::Compact => {
                // presentation = "<jwt>~<disclosures…>~<kb_jwt>"; splice the extra
                // disclosure in just before the trailing KB-JWT segment.
                let mut parts: Vec<&str> = presentation
                    .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
                    .collect();
                parts.insert(parts.len() - 1, &injected_disclosure);
                parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            }
        };

        let result = SDJWTVerifier::new(
            tampered,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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

        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, Some("ES256")))
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
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, Some("ES256")))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
                false,
                SDJWTSerializationFormat::FlattenedJson,
            )
            .unwrap();

        let private_holder_bytes = HOLDER_KEY_ED25519.as_bytes();
        let holder_key = EncodingKey::from_ed_pem(private_holder_bytes).unwrap();
        let nonce = Some(String::from("testNonce"));
        let aud = Some(String::from("testAud"));

        let presentation = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::FlattenedJson,
            holder_crypto_provider(holder_key),
        )
        .unwrap()
        .create_presentation(
            user_claims.as_object().unwrap().clone(),
            nonce.clone(),
            aud.clone(),
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
        let mut kb_payload: Map<String, Value> = serde_json::from_slice(&payload_bytes).unwrap();
        kb_payload.remove("iat");

        let resign_key = EncodingKey::from_ed_pem(HOLDER_KEY_ED25519.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(crate::KB_JWT_TYP_HEADER.to_string());
        let tampered_kb_jwt = jsonwebtoken::encode(&header, &kb_payload, &resign_key).unwrap();

        json.header.kb_jwt = Some(tampered_kb_jwt);
        let tampered_presentation = serde_json::to_string(&json).unwrap();

        let result = SDJWTVerifier::new(
            tampered_presentation,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
    fn reject_kb_jwt_with_future_iat() {
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
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, Some("ES256")))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
                false,
                SDJWTSerializationFormat::FlattenedJson,
            )
            .unwrap();

        let private_holder_bytes = HOLDER_KEY_ED25519.as_bytes();
        let holder_key = EncodingKey::from_ed_pem(private_holder_bytes).unwrap();
        let nonce = Some(String::from("testNonce"));
        let aud = Some(String::from("testAud"));

        let presentation = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::FlattenedJson,
            holder_crypto_provider(holder_key),
        )
        .unwrap()
        .create_presentation(
            user_claims.as_object().unwrap().clone(),
            nonce.clone(),
            aud.clone(),
        )
        .unwrap();

        // Tamper: re-sign the KB-JWT with a far-future `iat`. The signature is
        // valid, but §7.3 requires the creation time to be within an acceptable
        // window, so the verifier must reject it.
        let mut json: SDJWTFlattenedJson = serde_json::from_str(&presentation).unwrap();
        let original_kb_jwt = json.header.kb_jwt.clone().unwrap();
        let kb_parts: Vec<&str> = original_kb_jwt.split('.').collect();
        let payload_bytes = base64url_decode(kb_parts[1]).unwrap();
        let mut kb_payload: Map<String, Value> = serde_json::from_slice(&payload_bytes).unwrap();
        kb_payload.insert("iat".to_string(), Value::from(9999999999u64));

        let resign_key = EncodingKey::from_ed_pem(HOLDER_KEY_ED25519.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(crate::KB_JWT_TYP_HEADER.to_string());
        let tampered_kb_jwt = jsonwebtoken::encode(&header, &kb_payload, &resign_key).unwrap();

        json.header.kb_jwt = Some(tampered_kb_jwt);
        let tampered_presentation = serde_json::to_string(&json).unwrap();

        let result = SDJWTVerifier::new(
            tampered_presentation,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
            aud,
            nonce,
            SDJWTSerializationFormat::FlattenedJson,
        );

        assert!(
            result.is_err(),
            "Verifier accepted KB-JWT presentation with a future `iat`",
        );
    }

    #[test]
    fn reject_forged_hs256_key_binding_jwt() {
        // Algorithm-confusion regression test: an attacker who never sees the
        // holder's private key should not be able to rebind a stolen
        // presentation to an audience/nonce of their choosing. Before the
        // fix, `SDJWTCryptoProviderBuiltin::verify` took `alg` from the
        // (attacker-controlled) KB-JWT header at face value and passed it to
        // `jsonwebtoken::crypto::verify`, which — unlike `jsonwebtoken::decode`
        // — does not check that the key family matches `alg`. An EC/OKP `cnf`
        // key parsed via `DecodingKey::from_jwk` exposes its PUBLIC key bytes
        // via `as_bytes()`, so an attacker can compute a valid "HS256
        // signature" by HMAC-ing the signing input with those public bytes as
        // the secret.
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": { "country": "DE" },
        });

        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, Some("ES256")))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        // The legitimate holder builds one presentation for verifier A. The
        // attacker below never touches the holder's private key: they only
        // read the public presentation this produces.
        let holder_key = EncodingKey::from_ed_pem(HOLDER_KEY_ED25519.as_bytes()).unwrap();
        let legit_presentation = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            holder_crypto_provider(holder_key),
        )
        .unwrap()
        .create_presentation(
            user_claims.as_object().unwrap().clone(),
            Some("nonceA".to_string()),
            Some("https://verifierA.example.com".to_string()),
        )
        .unwrap();

        // Attacker: reuse the real (public) `sd_hash` from the legitimate
        // presentation, but forge a brand-new KB-JWT for a different
        // audience/nonce, "signed" with HS256 using the holder's PUBLIC cnf
        // key bytes as the HMAC secret.
        let parts: Vec<&str> = legit_presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        let real_kb = parts.last().unwrap();
        let kb_payload_b64 = real_kb.split('.').nth(1).unwrap();
        let kb_payload: Map<String, Value> =
            serde_json::from_slice(&base64url_decode(kb_payload_b64).unwrap()).unwrap();
        let sd_hash = kb_payload.get("sd_hash").unwrap().clone();

        let attacker_aud = "https://verifierB.example.com";
        let attacker_nonce = "nonceB";
        let forged_header = json!({ "alg": "HS256", "typ": "kb+jwt" });
        let forged_payload = json!({
            "nonce": attacker_nonce,
            "aud": attacker_aud,
            "iat": 1683000001,
            "sd_hash": sd_hash,
        });
        let signing_input = format!(
            "{}.{}",
            base64url_encode(&serde_json::to_vec(&forged_header).unwrap()),
            base64url_encode(&serde_json::to_vec(&forged_payload).unwrap()),
        );

        // Same raw bytes as the `x` coordinate in HOLDER_JWK_KEY_ED25519 — the
        // holder's PUBLIC key, never the private key.
        let public_key_bytes =
            base64url_decode("24QLWXJ18wtbg3k_MDGhGM17Xh39UftuxbwJZzRLzkA").unwrap();
        let forged_signature = jsonwebtoken::crypto::sign(
            signing_input.as_bytes(),
            &EncodingKey::from_secret(&public_key_bytes),
            Algorithm::HS256,
        )
        .unwrap();
        let forged_kb_jwt = format!("{signing_input}.{forged_signature}");

        let mut forged_parts = parts.clone();
        *forged_parts.last_mut().unwrap() = &forged_kb_jwt;
        let forged_presentation = forged_parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);

        let result = SDJWTVerifier::new(
            forged_presentation,
            verifier_crypto_provider("ES256"),
            Some(attacker_aud.to_string()),
            Some(attacker_nonce.to_string()),
            SDJWTSerializationFormat::Compact,
        );

        assert!(
            result.is_err(),
            "Verifier accepted a forged HS256 Key Binding JWT signed with the \
             holder's PUBLIC cnf key bytes as the HMAC secret",
        );
    }

    #[test]
    fn reject_sd_jwt_with_future_nbf() {
        // An SD-JWT whose `nbf` is in the future is not yet valid.
        let payload = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "nbf": 1883000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &payload, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        match result {
            Ok(_) => panic!("verifier accepted a presentation with a future `nbf`"),
            Err(err) => assert!(
                err.to_string().contains("not yet valid"),
                "expected an immature-signature failure, got: {err}"
            ),
        }
    }

    #[test]
    fn verify_presentation_with_past_nbf() {
        // A present `nbf` already in the past must not block verification.
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "nbf": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &user_claims, &issuer_key)
                .unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        assert!(
            result.is_ok(),
            "verifier rejected an SD-JWT with a past `nbf`"
        );
    }

    #[test]
    fn verify_presentation_without_iss() {
        // `iss` is optional in the Issuer-signed JWT; a pinned-key provider
        // does not need it.
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iat": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &user_claims, &issuer_key)
                .unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        assert!(
            result.is_ok(),
            "verifier rejected a validly-signed SD-JWT without `iss`: {:?}",
            result.err()
        );
    }

    #[test]
    fn verify_presentation_with_issuer_aud() {
        // An `aud` in the Issuer-signed JWT must not be rejected outright:
        // `expected_aud` applies to the Key Binding JWT, not to this claim.
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "aud": "https://verifier.example.com",
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &user_claims, &issuer_key)
                .unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        assert!(
            result.is_ok(),
            "verifier rejected a validly-signed SD-JWT whose Issuer JWT carries `aud`: {:?}",
            result.err()
        );
    }

    #[test]
    fn verify_propagates_provider_error() {
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &user_claims, &issuer_key)
                .unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(ErroringCryptoProvider),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        match result {
            Ok(_) => panic!("verifier accepted an SD-JWT its crypto provider rejected"),
            Err(err) => assert!(
                err.to_string().contains("unknown issuer"),
                "expected the provider's error, got: {err}"
            ),
        }
    }

    #[test]
    fn reject_issuer_jwt_without_alg_header() {
        // The former silent ES256 fallback is gone: a protected header without
        // `alg` is an error, never an assumption.
        let header = base64url_encode(b"{\"typ\":\"JWT\"}");
        let payload = base64url_encode(
            json!({"iss": "https://example.com/issuer"})
                .to_string()
                .as_bytes(),
        );
        let sd_jwt = format!("{header}.{payload}.AAAA~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        match result {
            Ok(_) => panic!("verifier accepted an Issuer JWT without `alg`"),
            Err(err) => assert!(
                err.to_string().contains("missing the `alg`"),
                "expected a missing-`alg` rejection, got: {err}"
            ),
        }
    }

    /// Provider whose allowlist admits only ES384 and whose `verify` must
    /// never be reached — proves the library checks the allowlist first.
    struct Es384OnlyProvider;
    impl crate::SDJWTCryptoProvider for Es384OnlyProvider {
        fn verify(&self, _: &[u8], _: &[u8], _: &crate::KeyRequest) -> crate::error::Result<()> {
            panic!("verify must not be called for a non-allowlisted alg")
        }
        fn allowed_verifying_algs(
            &self,
            _: crate::SignatureRole,
        ) -> crate::error::Result<Vec<String>> {
            Ok(vec!["ES384".to_string()])
        }
        fn sign(&self, _: &[u8], _: crate::SignatureRole) -> crate::error::Result<Vec<u8>> {
            Err(crate::error::Error::KeyNotFound(
                "no signing key configured".to_string(),
            ))
        }
        fn signing_alg(&self, _: crate::SignatureRole) -> crate::error::Result<String> {
            Err(crate::error::Error::KeyNotFound(
                "no signing key configured".to_string(),
            ))
        }
    }

    #[test]
    fn reject_issuer_jwt_with_alg_outside_provider_allowlist() {
        // The header `alg` (ES256) is one the library supports, but the
        // provider's allowlist admits only ES384: the library must reject the
        // JWT before the provider's `verify` runs.
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &user_claims, &issuer_key)
                .unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTVerifier::new(
            sd_jwt,
            Box::new(Es384OnlyProvider),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        match result {
            Ok(_) => panic!("verifier accepted an `alg` outside the provider's allowlist"),
            Err(err) => assert!(
                err.to_string()
                    .contains("not an allowed verification algorithm for the Issuer-signed JWT"),
                "expected an allowlist rejection, got: {err}"
            ),
        }
    }

    #[test]
    fn reject_kb_jwt_with_alg_outside_provider_allowlist() {
        // A Verifier may restrict which algorithms it accepts for the Key
        // Binding JWT independently of the Issuer JWT: the holder's EdDSA
        // KB-JWT is validly signed, but the provider allows only ES256 there.
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "address": { "country": "DE" },
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, Some("ES256")))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                Some(serde_json::from_str(HOLDER_JWK_KEY_ED25519).unwrap()),
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let holder_key = EncodingKey::from_ed_pem(HOLDER_KEY_ED25519.as_bytes()).unwrap();
        let presentation = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            holder_crypto_provider(holder_key),
        )
        .unwrap()
        .create_presentation(
            user_claims.as_object().unwrap().clone(),
            Some("testNonce".to_string()),
            Some("testAud".to_string()),
        )
        .unwrap();

        let result = SDJWTVerifier::new(
            presentation,
            Box::new(
                crate::SDJWTCryptoProviderBuiltin::new()
                    .with_verifying_key(
                        DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap(),
                        "ES256",
                    )
                    .with_allowed_key_binding_algs(&["ES256"]),
            ),
            Some("testAud".to_string()),
            Some("testNonce".to_string()),
            SDJWTSerializationFormat::Compact,
        );
        match result {
            Ok(_) => panic!("verifier accepted a KB-JWT `alg` outside the provider's allowlist"),
            Err(err) => assert!(
                err.to_string()
                    .contains("not an allowed verification algorithm for the Key Binding JWT"),
                "expected a KB allowlist rejection, got: {err}"
            ),
        }
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
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();
        let presentation = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(user_claims.as_object().unwrap().clone(), None, None)
            .unwrap();

        // Append a syntactically-valid but unreferenced disclosure. The
        // legitimate disclosures still hash and unpack normally; only the
        // injected disclosure is not referenced by any digest in the
        // Issuer-signed JWT, so the verifier must reject per draft-07 §8.1.
        let injected = base64url_encode(br#"["unreferencedsalt", "unreferenced_claim", "value"]"#);
        let presentation = presentation.trim_end_matches(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
        let tampered = format!(
            "{}{}{}{}",
            presentation,
            COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
            injected,
            COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
        );

        let result = SDJWTVerifier::new(
            tampered,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let presentation = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(user_claims.as_object().unwrap().clone(), None, None)
            .unwrap();
        let result = SDJWTVerifier::new(
            presentation,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
                verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
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
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
            None,
            None,
            SDJWTSerializationFormat::Compact,
        );
        match result {
            Ok(_) => panic!("verifier accepted a presentation with an expired `exp`"),
            Err(err) => assert!(
                err.to_string().contains("expired"),
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
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
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
