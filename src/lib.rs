// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::utils::{
    base64_hash, base64_standard_decode, base64url_decode, jwt_payload_decode, now_seconds,
};

use error::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use strum::Display;
pub use {
    crypto_provider::{KeyRequest, SDJWTCryptoProvider, SDJWTCryptoProviderBuiltin, SignatureRole},
    holder::SDJWTHolder,
    issuer::ClaimsForSelectiveDisclosureStrategy,
    issuer::SDJWTIssuer,
    verifier::SDJWTVerifier,
};

pub mod crypto_provider;
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
#[allow(dead_code)]
pub(crate) struct SDJWTHasSDClaimException(String);

impl SDJWTHasSDClaimException {}

/// SDJWTSerializationFormat is used to determine how an SD-JWT is serialized to String
#[derive(Default, Clone, PartialEq, Debug, Display)]
pub enum SDJWTSerializationFormat {
    /// Flattened JWS JSON representation
    #[default]
    FlattenedJson,
    /// General JWS JSON representation
    GeneralJson,
    /// Base64-encoded representation
    Compact,
}

pub(crate) struct ProtectedHeader {
    pub(crate) alg: String,
    pub(crate) typ: Option<String>,
    pub(crate) kid: Option<String>,
    pub(crate) x5c: Option<Vec<Vec<u8>>>,
}

#[derive(Default)]
pub(crate) struct SDJWTCommon {
    typ: Option<String>,
    serialization_format: SDJWTSerializationFormat,
    unverified_input_key_binding_jwt: Option<String>,
    unverified_sd_jwt: Option<String>,
    unverified_input_sd_jwt_payload: Option<Map<String, Value>>,
    hash_to_decoded_disclosure: HashMap<String, Value>,
    hash_to_disclosure: HashMap<String, String>,
    input_disclosures: Vec<String>,
}

#[derive(Default, Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct SDJWTFlattenedJson {
    protected: String,
    payload: String,
    signature: String,
    pub header: SDJWTUnprotectedHeader,
}

#[derive(Default, Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct SDJWTGeneralJson {
    payload: String,
    pub signatures: Vec<SDJWTGeneralJsonSignature>,
}

#[derive(Default, Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct SDJWTGeneralJsonSignature {
    protected: String,
    signature: String,
    pub header: SDJWTUnprotectedHeader,
}

#[derive(Default, Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct SDJWTUnprotectedHeader {
    pub disclosures: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kb_jwt: Option<String>,
}

// Define the SDJWTCommon struct to hold common properties.
impl SDJWTCommon {
    fn parse_protected_header(jwt: &str) -> Result<ProtectedHeader> {
        let header_b64 = jwt
            .split(JWT_SEPARATOR)
            .next()
            .ok_or(Error::InvalidInput("Cannot extract JWT header".to_string()))?;
        let decoded = base64url_decode(header_b64)?;
        let header: Value = serde_json::from_slice(&decoded)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::InvalidInput("JWT header is missing the `alg` parameter".to_string())
            })?
            .to_owned();
        crate::crypto_provider::reject_unacceptable_alg(&alg)?;
        let typ = header.get("typ").and_then(Value::as_str).map(str::to_owned);
        let kid = header.get("kid").and_then(Value::as_str).map(str::to_owned);
        let x5c = header
            .get("x5c")
            .map(|certs| {
                certs
                    .as_array()
                    .ok_or_else(|| Error::InvalidInput("`x5c` must be an array".to_string()))?
                    .iter()
                    .map(|cert| {
                        cert.as_str()
                            .ok_or_else(|| {
                                Error::InvalidInput("`x5c` entries must be strings".to_string())
                            })
                            .and_then(|cert| {
                                base64_standard_decode(cert).map_err(|e| {
                                    Error::DeserializationError(format!(
                                        "Invalid base64 in `x5c` certificate: {}",
                                        e
                                    ))
                                })
                            })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?;
        Ok(ProtectedHeader { alg, typ, kid, x5c })
    }

    fn build_key_request(&self) -> Result<KeyRequest> {
        let sd_jwt = self
            .unverified_sd_jwt
            .as_ref()
            .ok_or(Error::InvalidState("Cannot reference jwt".to_string()))?;
        let header = Self::parse_protected_header(sd_jwt)?;
        let iss = self
            .unverified_input_sd_jwt_payload
            .as_ref()
            .ok_or(Error::InvalidState("Cannot reference payload".to_string()))?
            .get("iss")
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(KeyRequest {
            role: SignatureRole::IssuerJwt,
            iss,
            kid: header.kid,
            alg: header.alg,
            x5c: header.x5c,
            jwk: None,
        })
    }

    /// Verify a compact JWS with `crypto_provider` and return its decoded
    /// payload claims. Shared by Issuer-JWT and Key Binding JWT verification so
    /// the signing-input reconstruction stays identical for both. Enforces the
    /// provider's algorithm allowlist (RFC 8725 §3.1) before invoking
    /// `verify`, so the (attacker-controlled) header `alg` can never select
    /// the verification algorithm regardless of the provider implementation.
    fn verify_compact_jws(
        jwt: &str,
        request: &KeyRequest,
        crypto_provider: &dyn SDJWTCryptoProvider,
    ) -> Result<Map<String, Value>> {
        let allowed = crypto_provider.allowed_verifying_algs(request.role)?;
        if !allowed.iter().any(|alg| alg == &request.alg) {
            return Err(Error::InvalidInput(format!(
                "JWT `alg` \"{}\" is not an allowed verification algorithm for the {}",
                request.alg,
                match request.role {
                    SignatureRole::IssuerJwt => "Issuer-signed JWT",
                    SignatureRole::KeyBindingJwt => "Key Binding JWT",
                },
            )));
        }
        let (protected, payload, signature) = Self::split_jwt(jwt)?;
        let message = format!("{protected}.{payload}");
        let signature = base64url_decode(&signature)?;
        crypto_provider.verify(message.as_bytes(), &signature, request)?;
        jwt_payload_decode(&payload)
    }

    /// Process an Issuer-signed JWT and return its payload claims. The keyless
    /// checks — `alg` rejection (via `build_key_request`) and temporal
    /// validation — always run; only the cryptographic signature check is
    /// gated on a crypto provider, so a Holder may opt out of signature
    /// verification with `None` while the library still rejects a
    /// malformed-`alg` or expired Issuer JWT.
    fn process_issuer_jwt(
        &self,
        crypto_provider: Option<&dyn SDJWTCryptoProvider>,
    ) -> Result<Map<String, Value>> {
        let sd_jwt = self
            .unverified_sd_jwt
            .as_ref()
            .ok_or(Error::InvalidState("Cannot reference jwt".to_string()))?;
        let request = self.build_key_request()?;
        let claims = match crypto_provider {
            Some(crypto_provider) => Self::verify_compact_jws(sd_jwt, &request, crypto_provider)?,
            None => {
                let (_, payload, _) = Self::split_jwt(sd_jwt)?;
                jwt_payload_decode(&payload)?
            }
        };
        // A present `aud` in the Issuer-signed JWT is deliberately not checked
        // here: `expected_aud` applies to the Key Binding JWT.
        Self::validate_temporal(&claims)?;
        Ok(claims)
    }

    fn validate_temporal(payload: &Map<String, Value>) -> Result<()> {
        // `exp`/`nbf` are optional and checked only when present, with a
        // 60-second leeway. NumericDate may be fractional, so parse as f64; a
        // present-but-non-numeric value fails closed instead of being skipped.
        const LEEWAY_SECONDS: u64 = 60;
        let now = now_seconds()?;
        if let Some(exp) = Self::numeric_date(payload, "exp")? {
            if exp < now.saturating_sub(LEEWAY_SECONDS) as f64 {
                return Err(Error::InvalidInput(
                    "JWT is expired (`exp` is in the past)".to_string(),
                ));
            }
        }
        if let Some(nbf) = Self::numeric_date(payload, "nbf")? {
            if nbf > now.saturating_add(LEEWAY_SECONDS) as f64 {
                return Err(Error::InvalidInput(
                    "JWT is not yet valid (`nbf` is in the future)".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// A JWT NumericDate claim as `f64` (values may be fractional). `Ok(None)`
    /// if absent; `Err` if present but not a JSON number.
    fn numeric_date(payload: &Map<String, Value>, claim: &str) -> Result<Option<f64>> {
        match payload.get(claim) {
            None => Ok(None),
            Some(value) => value.as_f64().map(Some).ok_or_else(|| {
                Error::InvalidInput(format!("`{}` is not a valid NumericDate", claim))
            }),
        }
    }

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
                    if key == SD_DIGESTS_KEY || key == SD_LIST_PREFIX {
                        return Err(Error::DataFieldMismatch(format!(
                            "Claim object cannot have `{}` field",
                            key
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
        if parts.len() < 2 {
            // minimal number of SD-JWT parts according to the standard
            return Err(Error::InvalidInput(format!(
                "Invalid SD-JWT length: {}",
                parts.len()
            )));
        }
        let mut parts = parts.into_iter();
        let sd_jwt = parts.next().ok_or(Error::IndexOutOfBounds {
            idx: 0,
            length: parts.len(),
            msg: format!("Invalid SD-JWT: {}", sd_jwt_with_disclosures),
        })?;
        let trailing = parts.next_back().unwrap_or("");
        self.unverified_input_key_binding_jwt = if trailing.is_empty() {
            None
        } else {
            Some(trailing.to_owned())
        };
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

    fn parse_flattened_json_sd_jwt(&mut self, sd_jwt_with_disclosures: String) -> Result<()> {
        let parsed: SDJWTFlattenedJson = serde_json::from_str(&sd_jwt_with_disclosures)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        self.unverified_input_key_binding_jwt = parsed.header.kb_jwt;
        self.input_disclosures = parsed.header.disclosures;
        self.unverified_input_sd_jwt_payload = Some(jwt_payload_decode(&parsed.payload)?);
        let sd_jwt = format!(
            "{}.{}.{}",
            parsed.protected, parsed.payload, parsed.signature
        );
        self.unverified_sd_jwt = Some(sd_jwt.clone());
        Ok(())
    }

    fn parse_general_json_sd_jwt(&mut self, sd_jwt_with_disclosures: String) -> Result<()> {
        let parsed: SDJWTGeneralJson = serde_json::from_str(&sd_jwt_with_disclosures)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        if parsed.signatures.len() > 1 {
            return Err(Error::InvalidInput(
                "General JSON SD-JWT with multiple signatures is not supported yet".to_string(),
            ));
        }
        // RFC 9901 §8.3: in General JSON Serialization, the Disclosures and the
        // optional KB-JWT live in the first signature's unprotected header.
        let signature = parsed
            .signatures
            .into_iter()
            .next()
            .ok_or(Error::InvalidInput(
                "General JSON SD-JWT must contain at least one signature".to_string(),
            ))?;
        self.unverified_input_key_binding_jwt = signature.header.kb_jwt;
        self.input_disclosures = signature.header.disclosures;
        self.unverified_input_sd_jwt_payload = Some(jwt_payload_decode(&parsed.payload)?);
        let sd_jwt = format!(
            "{}.{}.{}",
            signature.protected, parsed.payload, signature.signature
        );
        self.unverified_sd_jwt = Some(sd_jwt.clone());
        Ok(())
    }

    fn parse_sd_jwt(&mut self, sd_jwt_with_disclosures: String) -> Result<()> {
        match self.serialization_format {
            SDJWTSerializationFormat::Compact => self.parse_compact_sd_jwt(sd_jwt_with_disclosures),
            SDJWTSerializationFormat::FlattenedJson => {
                self.parse_flattened_json_sd_jwt(sd_jwt_with_disclosures)
            }
            SDJWTSerializationFormat::GeneralJson => {
                self.parse_general_json_sd_jwt(sd_jwt_with_disclosures)
            }
        }
    }
    /// Splits a signed JWT (`protected.payload.signature`) into its three parts.
    fn split_jwt(jwt: &str) -> Result<(String, String, String)> {
        let parts: Vec<&str> = jwt.split('.').collect();
        let [protected, payload, signature] = parts.as_slice() else {
            return Err(Error::InvalidState(format!(
                "Invalid signed JWT, expected three parts: {jwt}"
            )));
        };
        Ok((
            protected.to_string(),
            payload.to_string(),
            signature.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{utils, SDJWTCommon};
    use serde_json::json;

    #[test]
    fn test_parse_compact_sd_jwt() {
        let mut sdjwt = SDJWTCommon::default();
        let encoded_empty_object = utils::base64url_encode("{}".as_bytes());
        sdjwt
            .parse_compact_sd_jwt(format!(
                "jwt1.{encoded_empty_object}.jwt3~disc1~disc2~kbjwt"
            ))
            .unwrap();
        assert_eq!(
            sdjwt.unverified_sd_jwt.unwrap(),
            format!("jwt1.{encoded_empty_object}.jwt3")
        );
        assert_eq!(
            sdjwt.unverified_input_key_binding_jwt.as_deref(),
            Some("kbjwt")
        );
        assert_eq!(
            sdjwt.input_disclosures,
            vec!["disc1".to_string(), "disc2".to_string()]
        );

        let mut sdjwt = SDJWTCommon::default();
        sdjwt
            .parse_compact_sd_jwt(format!("jwt1.{encoded_empty_object}.jwt3~disc1~disc2~"))
            .unwrap();
        assert!(sdjwt.unverified_input_key_binding_jwt.is_none());
        assert_eq!(
            sdjwt.input_disclosures,
            vec!["disc1".to_string(), "disc2".to_string()]
        );
    }

    #[test]
    fn test_parse_flattened_json_sd_jwt() {
        let mut sdjwt = SDJWTCommon::default();
        let encoded_empty_object = utils::base64url_encode("{}".as_bytes());
        sdjwt.parse_flattened_json_sd_jwt(format!(
            r#"{{"protected":"jwt1","payload":"{encoded_empty_object}","signature":"jwt3","header":{{"disclosures":["disc1","disc2"],"kb_jwt":"kbjwt"}}}}"#
        )).unwrap();
        assert_eq!(
            sdjwt.unverified_sd_jwt.unwrap(),
            format!("jwt1.{encoded_empty_object}.jwt3")
        );
        assert_eq!(sdjwt.unverified_input_key_binding_jwt.unwrap(), "kbjwt");
        assert_eq!(
            sdjwt.input_disclosures,
            vec!["disc1".to_string(), "disc2".to_string()]
        );
    }

    #[test]
    fn test_parse_general_json_rejects_empty_signatures() {
        // `signatures` is a Vec, so serde accepts `[]`; the parser must reject a
        // signature-less input explicitly rather than panic on `signatures[0]`.
        let mut sdjwt = SDJWTCommon::default();
        let err = sdjwt
            .parse_general_json_sd_jwt(r#"{"payload":"e30","signatures":[]}"#.to_string())
            .unwrap_err();
        assert!(
            format!("{err}").contains("at least one signature"),
            "empty `signatures` array should be rejected: {err}"
        );
    }

    #[test]
    fn validate_temporal_rejects_expired_fractional_exp() {
        // A fractional NumericDate in the past must be rejected, not skipped.
        let payload = json!({ "exp": 1000.5 }).as_object().unwrap().clone();
        let err = SDJWTCommon::validate_temporal(&payload).unwrap_err();
        assert!(format!("{err}").contains("expired"), "got: {err}");
    }

    #[test]
    fn validate_temporal_rejects_non_numeric_exp() {
        // A present-but-non-numeric `exp` fails closed instead of being ignored.
        let payload = json!({ "exp": "1883000000" }).as_object().unwrap().clone();
        let err = SDJWTCommon::validate_temporal(&payload).unwrap_err();
        assert!(format!("{err}").contains("NumericDate"), "got: {err}");
    }

    #[test]
    fn validate_temporal_rejects_future_fractional_nbf() {
        let payload = json!({ "nbf": 9999999999.0_f64 })
            .as_object()
            .unwrap()
            .clone();
        let err = SDJWTCommon::validate_temporal(&payload).unwrap_err();
        assert!(format!("{err}").contains("not yet valid"), "got: {err}");
    }

    #[test]
    fn validate_temporal_accepts_absent_and_valid() {
        assert!(SDJWTCommon::validate_temporal(&json!({}).as_object().unwrap().clone()).is_ok());
        let payload = json!({ "exp": 9999999999_u64, "nbf": 1_u64 })
            .as_object()
            .unwrap()
            .clone();
        assert!(SDJWTCommon::validate_temporal(&payload).is_ok());
    }

    #[test]
    fn test_disallow_reserved_words_as_claim_names() {
        for (claims, reserved) in [
            (json!({ "_sd": "x" }), "_sd"),
            (json!({ "...": "x" }), "..."),
        ] {
            let err = SDJWTCommon::check_for_sd_claim(&claims).unwrap_err();
            assert!(
                format!("{err}").contains("cannot have"),
                "reserved word `{reserved}` was allowed as a claim name: {err}"
            );
        }
        assert!(
            SDJWTCommon::check_for_sd_claim(&json!({ "address": { "street": "x" } })).is_ok(),
            "a claim object without reserved words was rejected"
        );
    }
}
