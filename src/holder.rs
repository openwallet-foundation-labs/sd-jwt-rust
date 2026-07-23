// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::{
    error, SDJWTFlattenedJson, SDJWTGeneralJson, SDJWTGeneralJsonSignature,
    SDJWTSerializationFormat, SDJWTUnprotectedHeader,
};
use error::{Error, Result};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::ops::Add;

use crate::crypto_provider::{encode_jws, SDJWTCryptoProvider, SignatureRole};
use crate::utils::{base64_hash, now_seconds};
use crate::SDJWTCommon;
use crate::{
    COMBINED_SERIALIZATION_FORMAT_SEPARATOR, KB_DIGEST_KEY, KB_JWT_TYP_HEADER, SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
};

pub struct SDJWTHolder {
    sd_jwt_engine: SDJWTCommon,
    crypto_provider: Option<Box<dyn SDJWTCryptoProvider>>,
    hs_disclosures: Vec<String>,
    key_binding_jwt_payload: HashMap<String, Value>,
    serialized_key_binding_jwt: String,
    sd_jwt_payload: Map<String, Value>,
    serialized_sd_jwt: String,
}

impl SDJWTHolder {
    /// Build an instance of holder to create one or more presentations based on SD JWT provided by issuer.
    ///
    /// # Arguments
    /// * `sd_jwt_with_disclosures` - SD JWT with disclosures in the format specified by `serialization_format`
    /// * `serialization_format` - Serialization format of the SD JWT, see [SDJWTSerializationFormat].
    /// * `crypto_provider` - Crypto provider that verifies the Issuer signature and signs the Key Binding JWT. Use [`SDJWTHolder::new_unverified`] to skip Issuer-signature verification.
    ///
    /// # Returns
    /// * `SDJWTHolder` - Instance of SDJWTHolder
    ///
    /// # Errors
    /// * `InvalidInput` - If the serialization format is not supported
    /// * `InvalidState` - If the SD JWT data is not valid
    /// * `DeserializationError` - If the SD JWT serialization is not valid
    pub fn new(
        sd_jwt_with_disclosures: String,
        serialization_format: SDJWTSerializationFormat,
        crypto_provider: Box<dyn SDJWTCryptoProvider>,
    ) -> Result<Self> {
        Self::build(
            sd_jwt_with_disclosures,
            serialization_format,
            Some(crypto_provider),
        )
    }

    /// Like [`SDJWTHolder::new`], but skips the cryptographic Issuer-signature
    /// check — for inputs already verified out of band or for test fixtures.
    /// The keyless checks (header `alg` sanity, `exp`/`nbf` validation) still
    /// run. No crypto provider is attached, so `create_presentation` cannot
    /// create a Key Binding JWT.
    ///
    /// # Arguments
    /// * `sd_jwt_with_disclosures` - SD JWT with disclosures in the format specified by `serialization_format`
    /// * `serialization_format` - Serialization format of the SD JWT, see [SDJWTSerializationFormat].
    ///
    /// # Returns
    /// * `SDJWTHolder` - Instance of SDJWTHolder
    ///
    /// # Errors
    /// * `InvalidInput` - If the serialization format is not supported
    /// * `InvalidState` - If the SD JWT data is not valid
    /// * `DeserializationError` - If the SD JWT serialization is not valid
    pub fn new_unverified(
        sd_jwt_with_disclosures: String,
        serialization_format: SDJWTSerializationFormat,
    ) -> Result<Self> {
        Self::build(sd_jwt_with_disclosures, serialization_format, None)
    }

    fn build(
        sd_jwt_with_disclosures: String,
        serialization_format: SDJWTSerializationFormat,
        crypto_provider: Option<Box<dyn SDJWTCryptoProvider>>,
    ) -> Result<Self> {
        let mut holder = SDJWTHolder {
            sd_jwt_engine: SDJWTCommon {
                serialization_format,
                ..Default::default()
            },
            crypto_provider,
            hs_disclosures: Vec::new(),
            key_binding_jwt_payload: HashMap::new(),
            serialized_key_binding_jwt: "".to_string(),
            sd_jwt_payload: Map::new(),
            serialized_sd_jwt: "".to_string(),
        };

        holder
            .sd_jwt_engine
            .parse_sd_jwt(sd_jwt_with_disclosures.clone())?;

        if holder
            .sd_jwt_engine
            .unverified_input_key_binding_jwt
            .is_some()
        {
            return Err(Error::InvalidInput(
                "Holder received an SD-JWT+KB; a Key Binding JWT must not be present".to_string(),
            ));
        }

        holder.sd_jwt_payload = holder
            .sd_jwt_engine
            .process_issuer_jwt(holder.crypto_provider.as_deref())?;
        holder.serialized_sd_jwt = holder
            .sd_jwt_engine
            .unverified_sd_jwt
            .take()
            .ok_or(Error::InvalidState("Cannot take jwt".to_string()))?;

        holder.sd_jwt_engine.create_hash_mappings()?;

        Ok(holder)
    }

    /// Create a presentation based on the SD JWT provided by issuer.
    ///
    /// # Arguments
    /// * `claims_to_disclose` - Claims to disclose in the presentation
    /// * `nonce` - Nonce to be used in the key-binding JWT
    /// * `aud` - Audience to be used in the key-binding JWT
    ///
    /// # Returns
    /// * `String` - Presentation in the format specified by `serialization_format` in the constructor. It can be either compact or json.
    pub fn create_presentation(
        &mut self,
        claims_to_disclose: Map<String, Value>,
        nonce: Option<String>,
        aud: Option<String>,
    ) -> Result<String> {
        self.key_binding_jwt_payload = Default::default();
        self.serialized_key_binding_jwt = Default::default();
        self.hs_disclosures = self.select_disclosures(&self.sd_jwt_payload, claims_to_disclose)?;

        match (nonce, aud) {
            (Some(nonce), Some(aud)) => self.create_key_binding_jwt(nonce, aud)?,
            (None, None) => {}
            _ => {
                return Err(Error::InvalidInput(
                    "Inconsistency in parameters to determine JWT KB by holder".to_string(),
                ));
            }
        }

        let sd_jwt_presentation = match self.sd_jwt_engine.serialization_format {
            SDJWTSerializationFormat::Compact => {
                let mut combined: Vec<&str> = Vec::with_capacity(self.hs_disclosures.len() + 2);
                combined.push(&self.serialized_sd_jwt);
                combined.extend(self.hs_disclosures.iter().map(|s| s.as_str()));
                combined.push(&self.serialized_key_binding_jwt);
                combined.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            }
            SDJWTSerializationFormat::FlattenedJson => {
                let (protected, payload, signature) =
                    SDJWTCommon::split_jwt(&self.serialized_sd_jwt)?;
                let header = SDJWTUnprotectedHeader {
                    disclosures: self.hs_disclosures.clone(),
                    kb_jwt: (!self.serialized_key_binding_jwt.is_empty())
                        .then(|| self.serialized_key_binding_jwt.clone()),
                };
                serde_json::to_string(&SDJWTFlattenedJson {
                    protected,
                    payload,
                    signature,
                    header,
                })
                .map_err(|e| Error::DeserializationError(e.to_string()))?
            }
            SDJWTSerializationFormat::GeneralJson => {
                let (protected, payload, signature) =
                    SDJWTCommon::split_jwt(&self.serialized_sd_jwt)?;
                let header = SDJWTUnprotectedHeader {
                    disclosures: self.hs_disclosures.clone(),
                    kb_jwt: (!self.serialized_key_binding_jwt.is_empty())
                        .then(|| self.serialized_key_binding_jwt.clone()),
                };
                serde_json::to_string(&SDJWTGeneralJson {
                    payload,
                    signatures: vec![SDJWTGeneralJsonSignature {
                        protected,
                        signature,
                        header,
                    }],
                })
                .map_err(|e| Error::DeserializationError(e.to_string()))?
            }
        };

        Ok(sd_jwt_presentation)
    }

    fn select_disclosures(
        &self,
        sd_jwt_claims: &Map<String, Value>,
        claims_to_disclose: Map<String, Value>,
    ) -> Result<Vec<String>> {
        let mut hash_to_disclosure = Vec::new();
        let default_list = Vec::new();
        let sd_map: HashMap<&str, (&Value, &str)> = sd_jwt_claims
            .get(SD_DIGESTS_KEY)
            .and_then(Value::as_array)
            .unwrap_or(&default_list)
            .iter()
            .filter_map(|digest| {
                let digest = digest.as_str()?;
                let disclosure = self.sd_jwt_engine.hash_to_decoded_disclosure.get(digest)?;
                let key = disclosure[1].as_str()?;
                Some((key, (&disclosure[2], digest)))
            })
            .collect(); //TODO split to 2 maps
        for (key_to_disclose, value_to_disclose) in claims_to_disclose {
            match value_to_disclose {
                Value::Bool(true) | Value::Number(_) | Value::String(_) => {
                    /* disclose without children */
                }
                Value::Array(claims_to_disclose) => {
                    if let Some(sd_jwt_claims) = sd_jwt_claims
                        .get(&key_to_disclose)
                        .and_then(Value::as_array)
                    {
                        hash_to_disclosure.append(
                            &mut self.select_disclosures_from_disclosed_list(
                                sd_jwt_claims,
                                &claims_to_disclose,
                            )?,
                        )
                    } else if let Some(sd_jwt_claims) = sd_map
                        .get(key_to_disclose.as_str())
                        .and_then(|(sd, _)| sd.as_array())
                    {
                        hash_to_disclosure.append(
                            &mut self.select_disclosures_from_disclosed_list(
                                sd_jwt_claims,
                                &claims_to_disclose,
                            )?,
                        )
                    }
                }
                Value::Object(claims_to_disclose) if (!claims_to_disclose.is_empty()) => {
                    let sd_jwt_claims = if let Some(next) = sd_jwt_claims
                        .get(&key_to_disclose)
                        .and_then(Value::as_object)
                    {
                        next
                    } else {
                        sd_map[key_to_disclose.as_str()]
                            .0
                            .as_object()
                            .ok_or(Error::ConversionError("json object".to_string()))?
                    };
                    hash_to_disclosure
                        .append(&mut self.select_disclosures(sd_jwt_claims, claims_to_disclose)?);
                }
                Value::Object(_) => { /* disclose without children */ }
                Value::Bool(false) | Value::Null => {
                    // skip unrevealed
                    continue;
                }
            }
            if sd_jwt_claims.contains_key(&key_to_disclose) {
                continue;
            } else if let Some((_, digest)) = sd_map.get(key_to_disclose.as_str()) {
                hash_to_disclosure.push(self.sd_jwt_engine.hash_to_disclosure[*digest].to_owned());
            } else {
                return Err(Error::InvalidState(
                    "Requested claim doesn't exist".to_string(),
                ));
            }
        }

        Ok(hash_to_disclosure)
    }

    fn select_disclosures_from_disclosed_list(
        &self,
        sd_jwt_claims: &[Value],
        claims_to_disclose: &[Value],
    ) -> Result<Vec<String>> {
        let mut hash_to_disclosure: Vec<String> = Vec::new();
        for (claim_to_disclose, sd_jwt_claims) in claims_to_disclose.iter().zip(sd_jwt_claims) {
            match (claim_to_disclose, sd_jwt_claims) {
                (Value::Bool(true), Value::Object(sd_jwt_claims)) => {
                    if let Some(Value::String(digest)) = sd_jwt_claims.get(SD_LIST_PREFIX) {
                        hash_to_disclosure
                            .push(self.sd_jwt_engine.hash_to_disclosure[digest].to_owned());
                    }
                }
                (claim_to_disclose, Value::Object(sd_jwt_claims)) => {
                    if let Some(Value::String(digest)) = sd_jwt_claims.get(SD_LIST_PREFIX) {
                        let disclosure = self.sd_jwt_engine.hash_to_decoded_disclosure[digest]
                            .as_array()
                            .ok_or(Error::ConversionError("json array".to_string()))?;
                        match (claim_to_disclose, disclosure.get(1)) {
                            (
                                Value::Array(claim_to_disclose),
                                Some(Value::Array(sd_jwt_claims)),
                            ) => {
                                hash_to_disclosure
                                    .push(self.sd_jwt_engine.hash_to_disclosure[digest].clone());
                                hash_to_disclosure.append(
                                    &mut self.select_disclosures_from_disclosed_list(
                                        sd_jwt_claims,
                                        claim_to_disclose,
                                    )?,
                                );
                            }
                            (
                                Value::Object(claim_to_disclose),
                                Some(Value::Object(sd_jwt_claims)),
                            ) => {
                                hash_to_disclosure
                                    .push(self.sd_jwt_engine.hash_to_disclosure[digest].to_owned());
                                hash_to_disclosure.append(&mut self.select_disclosures(
                                    sd_jwt_claims,
                                    claim_to_disclose.to_owned(),
                                )?);
                            }
                            _ => {}
                        }
                    } else if let Some(claim_to_disclose) = claim_to_disclose.as_object() {
                        hash_to_disclosure.append(
                            &mut self
                                .select_disclosures(sd_jwt_claims, claim_to_disclose.to_owned())?,
                        );
                    }
                }
                (Value::Array(claim_to_disclose), Value::Array(sd_jwt_claims)) => {
                    hash_to_disclosure.append(&mut self.select_disclosures_from_disclosed_list(
                        sd_jwt_claims,
                        claim_to_disclose,
                    )?);
                }
                _ => {}
            }
        }

        Ok(hash_to_disclosure)
    }
    fn create_key_binding_jwt(&mut self, nonce: String, aud: String) -> Result<()> {
        self.key_binding_jwt_payload
            .insert("nonce".to_string(), nonce.into());
        self.key_binding_jwt_payload
            .insert("aud".to_string(), aud.into());
        self.key_binding_jwt_payload
            .insert("iat".to_string(), now_seconds()?.into());
        self.set_key_binding_digest_key()?;
        let crypto_provider = self.crypto_provider.as_ref().ok_or_else(|| {
            Error::InvalidInput("Key Binding requires a crypto provider".to_string())
        })?;
        let mut header = Map::new();
        header.insert(
            "alg".to_string(),
            crypto_provider
                .signing_alg(SignatureRole::KeyBindingJwt)?
                .into(),
        );
        header.insert("typ".to_string(), KB_JWT_TYP_HEADER.into());
        self.serialized_key_binding_jwt = encode_jws(
            &header,
            &self.key_binding_jwt_payload,
            crypto_provider.as_ref(),
            SignatureRole::KeyBindingJwt,
        )?;
        Ok(())
    }

    fn set_key_binding_digest_key(&mut self) -> Result<()> {
        let mut combined: Vec<&str> = Vec::with_capacity(self.hs_disclosures.len() + 1);
        combined.push(&self.serialized_sd_jwt);
        combined.extend(self.hs_disclosures.iter().map(|s| s.as_str()));
        let combined = combined
            .join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .add(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);

        let sd_hash = base64_hash(combined.as_bytes());
        self.key_binding_jwt_payload
            .insert(KB_DIGEST_KEY.to_owned(), Value::String(sd_hash));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::issuer::ClaimsForSelectiveDisclosureStrategy;
    use crate::{
        SDJWTHolder, SDJWTIssuer, SDJWTSerializationFormat, COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
    };
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
    use serde_json::{json, Map, Value};
    use std::collections::HashSet;

    const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
    const PUBLIC_ISSUER_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";

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

    struct CheckingCryptoProvider<
        F: Fn(&crate::KeyRequest) -> crate::error::Result<()> + Send + Sync,
    > {
        check: F,
    }
    impl<F: Fn(&crate::KeyRequest) -> crate::error::Result<()> + Send + Sync>
        crate::SDJWTCryptoProvider for CheckingCryptoProvider<F>
    {
        fn verify(
            &self,
            message: &[u8],
            signature: &[u8],
            request: &crate::KeyRequest,
        ) -> crate::error::Result<()> {
            (self.check)(request)?;
            crate::SDJWTCryptoProviderBuiltin::new()
                .with_verifying_key(
                    DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap(),
                    &request.alg,
                )
                .verify(message, signature, request)
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
    fn new_unverified_still_rejects_expired_issuer_jwt() {
        // `new_unverified` skips only the signature check; the keyless temporal
        // check still runs, so an expired Issuer JWT is rejected.
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims,
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();
        let err = match SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact) {
            Ok(_) => panic!("new_unverified must still reject an expired Issuer JWT"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("expired"),
            "new_unverified must still reject an expired Issuer JWT: {err}"
        );
    }

    #[test]
    fn new_accepts_valid_signature() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
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

        let holder = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
        );
        assert!(holder.is_ok());
    }

    #[test]
    fn new_rejects_tampered_signature() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims,
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        // Corrupt the first character of the JWT signature segment. A leading
        // base64url character maps to full signature bytes, so this yields a
        // well-formed but cryptographically invalid signature and exercises the
        // ECDSA rejection path — unlike flipping the trailing character, whose
        // spare bits can fail base64 decoding before verification is reached.
        let parts: Vec<&str> = sd_jwt.split('~').collect();
        let jwt_pieces: Vec<&str> = parts[0].split('.').collect();
        let mut sig: Vec<char> = jwt_pieces[2].chars().collect();
        sig[0] = if sig[0] == 'A' { 'B' } else { 'A' };
        let sig: String = sig.into_iter().collect();
        let tampered_jwt = format!("{}.{}.{}", jwt_pieces[0], jwt_pieces[1], sig);
        let tampered = std::iter::once(tampered_jwt.as_str())
            .chain(parts.iter().skip(1).copied())
            .collect::<Vec<_>>()
            .join("~");

        let result = SDJWTHolder::new(
            tampered,
            SDJWTSerializationFormat::Compact,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
        );
        assert!(result.is_err());
    }

    #[test]
    fn new_unverified_accepts_tampered_signature() {
        // `new_unverified` is the explicit opt-out of Issuer-signature
        // verification, for inputs already verified out of band or for test
        // fixtures: an SD-JWT whose signature would not verify is accepted.
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims,
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let parts: Vec<&str> = sd_jwt.split('~').collect();
        let jwt_pieces: Vec<&str> = parts[0].split('.').collect();
        let mut sig: Vec<char> = jwt_pieces[2].chars().collect();
        sig[0] = if sig[0] == 'A' { 'B' } else { 'A' };
        let sig: String = sig.into_iter().collect();
        let tampered_jwt = format!("{}.{}.{}", jwt_pieces[0], jwt_pieces[1], sig);
        let tampered = std::iter::once(tampered_jwt.as_str())
            .chain(parts.iter().skip(1).copied())
            .collect::<Vec<_>>()
            .join("~");

        let result = SDJWTHolder::new_unverified(tampered, SDJWTSerializationFormat::Compact);
        assert!(
            result.is_ok(),
            "new_unverified must accept an SD-JWT without verifying its signature",
        );
    }

    #[test]
    fn new_accepts_issuer_jwt_with_aud() {
        // An Issuer-signed JWT may legitimately carry an `aud` claim; the Holder's
        // signature check must accept it rather than reject it for lack of an
        // expected audience. NoSDClaims keeps `aud` as a plaintext top-level claim.
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "aud": "https://verifier.example.com",
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims,
                ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let holder = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
        );
        assert!(
            holder.is_ok(),
            "Holder rejected a validly-signed Issuer JWT carrying an `aud` claim",
        );
    }

    #[test]
    fn new_rejects_issuer_jwt_with_future_nbf() {
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

        let result = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
        );
        match result {
            Ok(_) => panic!("holder accepted an SD-JWT with a future `nbf`"),
            Err(err) => assert!(
                err.to_string().contains("not yet valid"),
                "expected an immature-signature failure, got: {err}"
            ),
        }
    }

    #[test]
    fn new_accepts_issuer_jwt_without_iss() {
        // `iss` is optional in the Issuer-signed JWT; a pinned-key provider
        // does not need it.
        let payload = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iat": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let signed =
            jsonwebtoken::encode(&Header::new(Algorithm::ES256), &payload, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~");

        let holder = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
        );
        assert!(
            holder.is_ok(),
            "Holder rejected a validly-signed SD-JWT without `iss`: {:?}",
            holder.err()
        );
    }

    #[test]
    fn new_propagates_provider_error() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims,
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let result = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            Box::new(CheckingCryptoProvider {
                check: |_| {
                    Err(crate::error::Error::KeyNotFound(
                        "unknown issuer".to_string(),
                    ))
                },
            }),
        );
        match result {
            Ok(_) => panic!("holder accepted an SD-JWT its crypto provider rejected"),
            Err(err) => assert!(
                err.to_string().contains("unknown issuer"),
                "expected the provider's error, got: {err}"
            ),
        }
    }

    #[test]
    fn provider_receives_kid_from_header() {
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("issuer-key-1".to_string());
        let signed = jsonwebtoken::encode(&header, &user_claims, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            Box::new(CheckingCryptoProvider {
                check: |req| {
                    assert_eq!(req.kid.as_deref(), Some("issuer-key-1"));
                    assert_eq!(req.iss.as_deref(), Some("https://example.com/issuer"));
                    Ok(())
                },
            }),
        );
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn provider_receives_decoded_x5c() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let der = b"dummy-der-certificate".to_vec();
        let mut header = Header::new(Algorithm::ES256);
        header.x5c = Some(vec![STANDARD.encode(&der)]);
        let signed = jsonwebtoken::encode(&header, &user_claims, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            Box::new(CheckingCryptoProvider {
                check: move |req| {
                    assert_eq!(req.x5c.as_deref(), Some(&[der.clone()][..]));
                    Ok(())
                },
            }),
        );
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn new_rejects_corrupted_x5c() {
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.x5c = Some(vec!["!!!not-base64!!!".to_string()]);
        let signed = jsonwebtoken::encode(&header, &user_claims, &issuer_key).unwrap();
        let sd_jwt = format!("{signed}~");

        let result = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
        );
        match result {
            Ok(_) => panic!("holder accepted an SD-JWT with corrupted `x5c`"),
            Err(err) => assert!(
                err.to_string().contains("x5c"),
                "expected an `x5c` failure, got: {err}"
            ),
        }
    }

    #[test]
    fn new_rejects_alg_none() {
        let header = crate::utils::base64url_encode(b"{\"alg\":\"none\"}");
        let payload = crate::utils::base64url_encode(
            json!({"iss": "https://example.com/issuer"})
                .to_string()
                .as_bytes(),
        );
        let sd_jwt = format!("{header}.{payload}.~");

        let result = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
        );
        match result {
            Ok(_) => panic!("holder accepted an SD-JWT signed with `alg: none`"),
            Err(err) => assert!(
                err.to_string().contains("not acceptable"),
                "expected an alg-none rejection, got: {err}"
            ),
        }
    }

    #[test]
    fn new_unverified_rejects_alg_none() {
        // The opt-out skips only the cryptographic signature check; the header
        // `alg` checks still run, so `alg: none` is rejected without a provider.
        let header = crate::utils::base64url_encode(b"{\"alg\":\"none\"}");
        let payload = crate::utils::base64url_encode(
            json!({"iss": "https://example.com/issuer"})
                .to_string()
                .as_bytes(),
        );
        let sd_jwt = format!("{header}.{payload}.~");

        let result = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact);
        match result {
            Ok(_) => panic!("new_unverified accepted an SD-JWT signed with `alg: none`"),
            Err(err) => assert!(
                err.to_string().contains("not acceptable"),
                "expected an alg-none rejection, got: {err}"
            ),
        }
    }

    #[test]
    fn new_rejects_sd_jwt_with_key_binding() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims,
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        // An issued SD-JWT ends with a trailing `~` and carries no Key Binding
        // JWT. Append a (dummy) Key Binding JWT segment to make it an SD-JWT+KB.
        assert!(sd_jwt.ends_with(COMBINED_SERIALIZATION_FORMAT_SEPARATOR));
        let sd_jwt_kb = format!("{sd_jwt}fakekbjwt");

        let result = SDJWTHolder::new_unverified(sd_jwt_kb, SDJWTSerializationFormat::Compact);
        assert!(
            result.is_err(),
            "Holder accepted an SD-JWT that already carried a Key Binding JWT",
        );
    }

    /// Crypto provider that verifies like the builtin but whose `sign` fails, for
    /// exercising error propagation from Key Binding JWT signing.
    struct KbSignFailingProvider;
    impl crate::SDJWTCryptoProvider for KbSignFailingProvider {
        fn verify(
            &self,
            message: &[u8],
            signature: &[u8],
            request: &crate::KeyRequest,
        ) -> crate::error::Result<()> {
            crate::SDJWTCryptoProviderBuiltin::new()
                .with_verifying_key(
                    DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap(),
                    &request.alg,
                )
                .verify(message, signature, request)
        }
        fn allowed_verifying_algs(
            &self,
            _: crate::SignatureRole,
        ) -> crate::error::Result<Vec<String>> {
            Ok(vec![crate::DEFAULT_SIGNING_ALG.to_string()])
        }
        fn sign(&self, _: &[u8], _: crate::SignatureRole) -> crate::error::Result<Vec<u8>> {
            Err(crate::error::Error::KeyNotFound(
                "keystore unavailable".to_string(),
            ))
        }
        fn signing_alg(&self, _: crate::SignatureRole) -> crate::error::Result<String> {
            Ok(crate::DEFAULT_SIGNING_ALG.to_string())
        }
    }

    #[test]
    fn create_presentation_propagates_kb_sign_error() {
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let err = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            Box::new(KbSignFailingProvider),
        )
        .unwrap()
        .create_presentation(
            user_claims.as_object().unwrap().clone(),
            Some("nonce".to_string()),
            Some("aud".to_string()),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("keystore unavailable"),
            "got: {err}"
        );
    }

    #[test]
    fn create_presentation_requires_crypto_provider_for_key_binding() {
        let user_claims = json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "address": { "country": "DE" }
        });
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims.clone(),
                ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();

        let err = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(
                user_claims.as_object().unwrap().clone(),
                Some("nonce".to_string()),
                Some("aud".to_string()),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("requires a crypto provider"),
            "expected a missing-crypto-provider error, got: {err}"
        );
    }

    #[test]
    fn create_full_presentation() {
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
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
        )
        .unwrap()
        .create_presentation(user_claims.as_object().unwrap().clone(), None, None)
        .unwrap();
        assert_eq!(sd_jwt, presentation);
    }
    #[test]
    fn create_presentation_empty_object_as_disclosure_value() {
        let mut user_claims = json!({
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
        let issued = sd_jwt.clone();
        user_claims["address"] = Value::Object(Map::new());
        let presentation = SDJWTHolder::new(
            sd_jwt,
            SDJWTSerializationFormat::Compact,
            verifier_crypto_provider(crate::DEFAULT_SIGNING_ALG),
        )
        .unwrap()
        .create_presentation(user_claims.as_object().unwrap().clone(), None, None)
        .unwrap();

        let mut parts: Vec<&str> = issued
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        parts.remove(5);
        parts.remove(4);
        parts.remove(3);
        parts.remove(2);
        let expected = parts.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
        assert_eq!(expected, presentation);
    }

    #[test]
    fn create_presentation_for_arrayed_disclosures() {
        let mut user_claims = json!(
            {
              "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
              "name": "Bois",
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
        let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
            "$.name",
            "$.addresses[1]",
            "$.addresses[1].country",
            "$.nationalities[0]",
        ]);

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None))
            .issue_sd_jwt(
                user_claims.clone(),
                strategy,
                None,
                false,
                SDJWTSerializationFormat::Compact,
            )
            .unwrap();
        // Choose what to reveal
        user_claims["addresses"] = Value::Array(vec![Value::Bool(true), Value::Bool(false)]);
        user_claims["nationalities"] = Value::Array(vec![Value::Bool(true), Value::Bool(true)]);

        let issued = sd_jwt.clone();
        println!("{}", issued);
        let presentation = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(user_claims.as_object().unwrap().clone(), None, None)
            .unwrap();
        println!("{}", presentation);
        let mut issued_parts: HashSet<&str> = issued
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        issued_parts.remove("");

        let mut revealed_parts: HashSet<&str> = presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        revealed_parts.remove("");

        let union: HashSet<_> = issued_parts.intersection(&revealed_parts).collect();
        assert_eq!(union.len(), 3);
    }

    #[test]
    fn create_presentation_for_recursive_disclosures() {
        // Input data used to create the SD-JWT and presentation fixtures,
        // can be used to debug in case the test fails:

        // let mut user_claims = json!(
        //     {
        //         "foo": ["one", "two"],
        //         "bar": {
        //           "red": 1,
        //           "green": 2
        //         },
        //         "qux": [
        //           ["blue", "yellow"]
        //         ],
        //         "baz": [
        //           ["orange", "purple"],
        //           ["black", "white"]
        //         ],
        //         "animals": {
        //           "snake": {
        //             "name": "python",
        //             "age": 10
        //           },
        //           "bird": {
        //             "name": "eagle",
        //             "age": 20
        //           }
        //         }
        //       }
        // );
        // let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
        //     "$.foo[0]",
        //     "$.foo[1]",
        //     "$.bar.red",
        //     "$.bar.green",
        //     "$.qux[0]",
        //     "$.qux[0][0]",
        //     "$.qux[0][1]",
        //     "$.baz[0]",
        //     "$.baz[0][0]",
        //     "$.baz[0][1]",
        //     "$.baz[1]",
        //     "$.baz[1][0]",
        //     "$.baz[1][1]",
        //     "$.animals.snake",
        //     "$.animals.snake.name",
        //     "$.animals.snake.age",
        //     "$.animals.bird",
        //     "$.animals.bird.name",
        //     "$.animals.bird.age",
        // ]);

        // let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        // let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        // let sd_jwt = SDJWTIssuer::new(issuer_crypto_provider(issuer_key, None)).issue_sd_jwt(
        //     user_claims.clone(),
        //     strategy,
        //     None,
        //     false,
        //     SDJWTSerializationFormat::Compact,
        // )
        //     .unwrap();

        let sd_jwt = String::from("eyJhbGciOiJFUzI1NiJ9.eyJmb28iOlt7Ii4uLiI6Ii1XMWROTk0tNUI3WlpxR3R4MkF6RTA3X0hpRUpOZVJtNGtEQ1VORTVDNFUifSx7Ii4uLiI6ImpuUURqUEFoclY1bjMtRW5PVEZHWTcwMkd0T3FhN3hua3pVM0E4aElSX3cifV0sImJhciI6eyJfc2QiOlsiX25yZUxad2xVYlp1SmtqS1RVdHR5YkhqUTNrY2J4cnZab1dxUmVBbG4tcyIsImhGcjdBRElQbjZvQ3lSckNBN0VtNldLaGk1UjdXMWJjYWFZUFFrelpGMXciXX0sInF1eCI6W3siLi4uIjoieHl6MkRSSDRTSkpjdFFtMDEtSzROVVllMTMzMWh6U3VkTXd3MENDODEyUSJ9XSwiYmF6IjpbeyIuLi4iOiJRMGcyVmYzNnl6TnNvUkdNb0dsODZnZ2QyWGFVTmg5bGN6STFfbmFZYUhnIn0seyIuLi4iOiJZcGpMNTJKd1BfYmFFS21OaHFLazE3TWFrMl9fSWJCNmctY0haSHd6dmwwIn1dLCJhbmltYWxzIjp7Il9zZCI6WyJyQ19LNzlObG95SkFPWXRCOW9ITFlsTVJSS1V4UTNnaTZ0Wld0Zm90TWRjIiwidjUyd3d6bzB5Ymw2U2V1MjZWYklUODh5bHk1LXVMZkdlYTdkWnMxSHBwMCJdfSwiX3NkX2FsZyI6InNoYS0yNTYifQ.piidRp0pHJYmtExCJnLExaaWMTBX50mLwM6gFVYnD72DszyjpKbAoZhyAXT-I4CqqSpiHZg-2w8s26XBraqX6w~WyJCQ2k5UXlsWVVqVEpXWWVfbzRzOWxnIiwgIm9uZSJd~WyJSLXZ0bDBmbWF6N01zR1ZWRFh3T3BnIiwgInR3byJd~WyJXNWlOQ1Z1Qlo4OW9aV2dIUkxzRWJBIiwgInJlZCIsIDFd~WyJTQW5hNUJnaHJxUXJ0amR5SGxiejJBIiwgImdyZWVuIiwgMl0~WyJENVJrNVlIUkdJVXM5enp6OFUtOTVnIiwgImJsdWUiXQ~WyI0Y2tnSjJuWVhhV21jM3pVQ253d3N3IiwgInllbGxvdyJd~WyJ2Ml8tRG5JN0lEZ1loYVMzTG9Kb013IiwgW3siLi4uIjogIkhqMUQtZE1SNXR0YmpLcl9DUENETzRuVGlkTWR1YVNpMnlnYlhtcmR4MGcifSwgeyIuLi4iOiAiUl9Sb253SFY3bzR6Y0o3TV9jcTlobVpLZ2o2RkMtdmNXTko4bzNkeTg2MCJ9XV0~WyJwRHQtcEtfaklUYXhCVENJRFNvUnhBIiwgIm9yYW5nZSJd~WyJ1b3FDS0lpZGJzQmxhczhUaU5Kakh3IiwgInB1cnBsZSJd~WyJJWWFXMzVPNzBoUWg4OGlqWVBUVXZRIiwgW3siLi4uIjogIjlWdnFSbjk1ZUN6QnVkNkhYOG1faVRNMERZSVVxN0ZheFFtanowV1llbUkifSwgeyIuLi4iOiAiTmFOeXozWEJRZVc4Z1JRd28ySlN5NmhtbnJZT1JxRjMxeUhfWkhqbkRxNCJ9XV0~WyI4cFNkNHl0TWlPdnVGaFhQSXBPbW5BIiwgImJsYWNrIl0~WyJxLWR0QXhtZzY5cWZLMFpvS1BSbWFnIiwgIndoaXRlIl0~WyIzTzY0WmVYSjF6XzJWMXdrMGhJdUdBIiwgW3siLi4uIjogImRmVnVjbkwwMC1FVFh0RGpHaDlpRHYtSE5PZmRyZ1VuTlNYRk01VUlIRVkifSwgeyIuLi4iOiAiUlRnVmxQb25RTVZJNkEzNUJic21KTThDeDVTVTN1ZXJBMENyYmpvRW02USJ9XV0~WyJNQTlSbGMwUlAxNnVJWER6blRqOWJ3IiwgIm5hbWUiLCAicHl0aG9uIl0~WyJrblRLb0lKVzZuQ1VzeW1sN3lKWTNBIiwgImFnZSIsIDEwXQ~WyJlUEdwazZjdEhOSS1HS2JKbjZrR3lBIiwgInNuYWtlIiwgeyJfc2QiOiBbIjREU0s5REpJVEhROElITFFESld6SV9yM0lheXBIek5Ma19tc3BUa2xDVzQiLCAiYy11UFhEQkZJX2FDV1BUUHlYNFV0OWdDWW1DQ1FqUEw5TnRFZGotdWZtMCJdfV0~WyJOMzgyX2xTU1dpSzZsbGdPNFFhbUdnIiwgIm5hbWUiLCAiZWFnbGUiXQ~WyJjVWZVRVBrX0pDZm1KQzhWQUp1V1pBIiwgImFnZSIsIDIwXQ~WyJSVDh5My1Odmh6QXo4Q2ctS1NDRGh3IiwgImJpcmQiLCB7Il9zZCI6IFsiUVhINU9mSF8tMGtFYkEwWDBnd0RLenphc05ZYWRWekNWRGFrYlZfWnNxNCIsICJoUmtPNjRIVXZuaEFPbDBRS1NlZDFUWUhtb0VpRW9zb0R0WmsyRVl4ejdNIl19XQ~");
        let expected_presentation = String::from("eyJhbGciOiJFUzI1NiJ9.eyJmb28iOlt7Ii4uLiI6Ii1XMWROTk0tNUI3WlpxR3R4MkF6RTA3X0hpRUpOZVJtNGtEQ1VORTVDNFUifSx7Ii4uLiI6ImpuUURqUEFoclY1bjMtRW5PVEZHWTcwMkd0T3FhN3hua3pVM0E4aElSX3cifV0sImJhciI6eyJfc2QiOlsiX25yZUxad2xVYlp1SmtqS1RVdHR5YkhqUTNrY2J4cnZab1dxUmVBbG4tcyIsImhGcjdBRElQbjZvQ3lSckNBN0VtNldLaGk1UjdXMWJjYWFZUFFrelpGMXciXX0sInF1eCI6W3siLi4uIjoieHl6MkRSSDRTSkpjdFFtMDEtSzROVVllMTMzMWh6U3VkTXd3MENDODEyUSJ9XSwiYmF6IjpbeyIuLi4iOiJRMGcyVmYzNnl6TnNvUkdNb0dsODZnZ2QyWGFVTmg5bGN6STFfbmFZYUhnIn0seyIuLi4iOiJZcGpMNTJKd1BfYmFFS21OaHFLazE3TWFrMl9fSWJCNmctY0haSHd6dmwwIn1dLCJhbmltYWxzIjp7Il9zZCI6WyJyQ19LNzlObG95SkFPWXRCOW9ITFlsTVJSS1V4UTNnaTZ0Wld0Zm90TWRjIiwidjUyd3d6bzB5Ymw2U2V1MjZWYklUODh5bHk1LXVMZkdlYTdkWnMxSHBwMCJdfSwiX3NkX2FsZyI6InNoYS0yNTYifQ.piidRp0pHJYmtExCJnLExaaWMTBX50mLwM6gFVYnD72DszyjpKbAoZhyAXT-I4CqqSpiHZg-2w8s26XBraqX6w~WyJSLXZ0bDBmbWF6N01zR1ZWRFh3T3BnIiwgInR3byJd~WyJTQW5hNUJnaHJxUXJ0amR5SGxiejJBIiwgImdyZWVuIiwgMl0~WyI0Y2tnSjJuWVhhV21jM3pVQ253d3N3IiwgInllbGxvdyJd~WyJ2Ml8tRG5JN0lEZ1loYVMzTG9Kb013IiwgW3siLi4uIjogIkhqMUQtZE1SNXR0YmpLcl9DUENETzRuVGlkTWR1YVNpMnlnYlhtcmR4MGcifSwgeyIuLi4iOiAiUl9Sb253SFY3bzR6Y0o3TV9jcTlobVpLZ2o2RkMtdmNXTko4bzNkeTg2MCJ9XV0~WyJ1b3FDS0lpZGJzQmxhczhUaU5Kakh3IiwgInB1cnBsZSJd~WyJJWWFXMzVPNzBoUWg4OGlqWVBUVXZRIiwgW3siLi4uIjogIjlWdnFSbjk1ZUN6QnVkNkhYOG1faVRNMERZSVVxN0ZheFFtanowV1llbUkifSwgeyIuLi4iOiAiTmFOeXozWEJRZVc4Z1JRd28ySlN5NmhtbnJZT1JxRjMxeUhfWkhqbkRxNCJ9XV0~WyI4cFNkNHl0TWlPdnVGaFhQSXBPbW5BIiwgImJsYWNrIl0~WyJxLWR0QXhtZzY5cWZLMFpvS1BSbWFnIiwgIndoaXRlIl0~WyIzTzY0WmVYSjF6XzJWMXdrMGhJdUdBIiwgW3siLi4uIjogImRmVnVjbkwwMC1FVFh0RGpHaDlpRHYtSE5PZmRyZ1VuTlNYRk01VUlIRVkifSwgeyIuLi4iOiAiUlRnVmxQb25RTVZJNkEzNUJic21KTThDeDVTVTN1ZXJBMENyYmpvRW02USJ9XV0~WyJrblRLb0lKVzZuQ1VzeW1sN3lKWTNBIiwgImFnZSIsIDEwXQ~WyJlUEdwazZjdEhOSS1HS2JKbjZrR3lBIiwgInNuYWtlIiwgeyJfc2QiOiBbIjREU0s5REpJVEhROElITFFESld6SV9yM0lheXBIek5Ma19tc3BUa2xDVzQiLCAiYy11UFhEQkZJX2FDV1BUUHlYNFV0OWdDWW1DQ1FqUEw5TnRFZGotdWZtMCJdfV0~WyJjVWZVRVBrX0pDZm1KQzhWQUp1V1pBIiwgImFnZSIsIDIwXQ~WyJSVDh5My1Odmh6QXo4Q2ctS1NDRGh3IiwgImJpcmQiLCB7Il9zZCI6IFsiUVhINU9mSF8tMGtFYkEwWDBnd0RLenphc05ZYWRWekNWRGFrYlZfWnNxNCIsICJoUmtPNjRIVXZuaEFPbDBRS1NlZDFUWUhtb0VpRW9zb0R0WmsyRVl4ejdNIl19XQ~");

        // Choose what to reveal
        let revealed = json!(
            {
                "foo": [false, true],
                "bar": {
                  "red": false,
                  "green": true
                },
                "qux": [
                  [false, true]
                ],
                "baz": [
                  [false, true],
                  [true, true]
                ],
                "animals": {
                  "snake": {
                    "name": false,
                    "age": true
                  },
                  "bird": {
                    "name": false,
                    "age": true
                  }
                }
              }
        );

        let presentation = SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::Compact)
            .unwrap()
            .create_presentation(revealed.as_object().unwrap().clone(), None, None)
            .unwrap();

        let presentation: HashSet<_> = presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .map(String::from)
            .collect();

        let expected: HashSet<_> = expected_presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .map(String::from)
            .collect();

        assert_eq!(presentation, expected);
    }
}
