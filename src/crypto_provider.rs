// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use crate::utils::{base64url_decode, base64url_encode};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use serde::Serialize;
use serde_json::{Map, Value};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureRole {
    IssuerJwt,
    KeyBindingJwt,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct KeyRequest {
    pub role: SignatureRole,
    pub iss: Option<String>,
    pub kid: Option<String>,
    pub alg: String,
    pub x5c: Option<Vec<Vec<u8>>>,
    pub jwk: Option<String>,
}

pub trait SDJWTCryptoProvider: Send + Sync {
    fn signing_alg(&self, role: SignatureRole) -> Result<String>;
    fn allowed_verifying_algs(&self, role: SignatureRole) -> Result<Vec<String>>;
    fn sign(&self, message: &[u8], role: SignatureRole) -> Result<Vec<u8>>;
    fn verify(&self, message: &[u8], signature: &[u8], request: &KeyRequest) -> Result<()>;
}

/// A key bundled with the JWS `alg` it is used with. A key is meaningless
/// without knowing which algorithm to apply it under, so the two travel as one.
struct KeyWithAlg<K> {
    key: K,
    alg: String,
}

/// The asymmetric JWS algorithms `jsonwebtoken` supports. Used as the
/// builtin's Key Binding allowlist: the KB key arrives in-band per
/// presentation (`cnf`), so no single algorithm can be pinned ahead of time,
/// while symmetric algorithms stay excluded.
const ASYMMETRIC_JWS_ALGS: &[&str] = &[
    "ES256", "ES384", "EdDSA", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
];

pub struct SDJWTCryptoProviderBuiltin {
    signing: Option<KeyWithAlg<EncodingKey>>,
    verifying: Option<KeyWithAlg<DecodingKey>>,
    allowed_key_binding_algs: Option<Vec<String>>,
}

impl SDJWTCryptoProviderBuiltin {
    pub fn new() -> Self {
        Self {
            signing: None,
            verifying: None,
            allowed_key_binding_algs: None,
        }
    }

    pub fn with_signing_key(mut self, key: EncodingKey, alg: &str) -> Self {
        self.signing = Some(KeyWithAlg {
            key,
            alg: alg.to_owned(),
        });
        self
    }

    pub fn with_verifying_key(mut self, key: DecodingKey, alg: &str) -> Self {
        self.verifying = Some(KeyWithAlg {
            key,
            alg: alg.to_owned(),
        });
        self
    }

    pub fn with_allowed_key_binding_algs(mut self, algs: &[&str]) -> Self {
        self.allowed_key_binding_algs = Some(algs.iter().map(|s| s.to_string()).collect());
        self
    }
}

impl Default for SDJWTCryptoProviderBuiltin {
    fn default() -> Self {
        Self::new()
    }
}

impl SDJWTCryptoProvider for SDJWTCryptoProviderBuiltin {
    fn signing_alg(&self, _role: SignatureRole) -> Result<String> {
        self.signing
            .as_ref()
            .map(|s| s.alg.clone())
            .ok_or(Error::KeyNotFound("no signing key configured".to_string()))
    }

    fn allowed_verifying_algs(&self, role: SignatureRole) -> Result<Vec<String>> {
        match role {
            SignatureRole::IssuerJwt => {
                self.verifying
                    .as_ref()
                    .map(|v| vec![v.alg.clone()])
                    .ok_or(Error::KeyNotFound(
                        "no verifying key configured".to_string(),
                    ))
            }
            SignatureRole::KeyBindingJwt => Ok(self
                .allowed_key_binding_algs
                .clone()
                .unwrap_or_else(|| ASYMMETRIC_JWS_ALGS.iter().map(|s| s.to_string()).collect())),
        }
    }

    fn sign(&self, message: &[u8], _role: SignatureRole) -> Result<Vec<u8>> {
        let signing = self
            .signing
            .as_ref()
            .ok_or(Error::KeyNotFound("no signing key configured".to_string()))?;
        let algorithm = Algorithm::from_str(&signing.alg)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        let signature = jsonwebtoken::crypto::sign(message, &signing.key, algorithm)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        base64url_decode(&signature)
    }

    fn verify(&self, message: &[u8], signature: &[u8], request: &KeyRequest) -> Result<()> {
        let in_band_key;
        let (key, alg_str) = match (&request.jwk, &self.verifying) {
            // The in-band Holder key: its trust derives from the verified
            // Issuer payload, so it is honored without a pinned key.
            (Some(jwk_json), _) if request.role == SignatureRole::KeyBindingJwt => {
                // Defense-in-depth: `parse_protected_header` already rejects a
                // symmetric `alg` for every crypto provider, but the in-band `cnf` key
                // here is taken verbatim from the (verified) Issuer payload —
                // `DecodingKey::from_jwk` exposes only the public key bytes,
                // so accepting an HMAC alg here would let anyone holding the
                // public key alone forge a signature over them.
                if is_symmetric_alg(&request.alg) {
                    return Err(Error::InvalidInput(format!(
                        "symmetric JWT `alg` \"{}\" is not acceptable for Key Binding JWT verification",
                        request.alg
                    )));
                }
                let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_str(jwk_json).map_err(|_| {
                    Error::DeserializationError("Cannot parse JWK from json".to_string())
                })?;
                in_band_key = DecodingKey::from_jwk(&jwk).map_err(|_| {
                    Error::DeserializationError("Cannot parse DecodingKey from json".to_string())
                })?;
                (&in_band_key, request.alg.as_str())
            }
            // A Key Binding JWT must be verified with the in-band `cnf` key, never
            // the pinned Issuer key; without a `cnf` key there is nothing to verify against.
            (_, _) if request.role == SignatureRole::KeyBindingJwt => {
                return Err(Error::KeyNotFound(
                    "Key Binding JWT verification requires an in-band `cnf` key".to_string(),
                ))
            }
            (_, Some(pinned)) => {
                if request.alg != pinned.alg {
                    return Err(Error::InvalidInput(format!(
                        "unexpected signing algorithm: {}",
                        request.alg
                    )));
                }
                (&pinned.key, pinned.alg.as_str())
            }
            _ => {
                return Err(Error::KeyNotFound(
                    "no verifying key configured".to_string(),
                ))
            }
        };
        let algorithm =
            Algorithm::from_str(alg_str).map_err(|e| Error::DeserializationError(e.to_string()))?;
        let signature = base64url_encode(signature);
        match jsonwebtoken::crypto::verify(&signature, message, key, algorithm) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::InvalidInput(
                "signature verification failed".to_string(),
            )),
            Err(e) => Err(Error::DeserializationError(e.to_string())),
        }
    }
}

/// Whether `alg` names an HMAC (symmetric) JWS algorithm. SD-JWT never uses
/// symmetric signatures — the Issuer JWT must be publicly verifiable and the
/// Key Binding JWT is an asymmetric holder proof-of-possession — so accepting
/// one would let anyone holding a public key forge a signature over it.
pub(crate) fn is_symmetric_alg(alg: &str) -> bool {
    alg.get(..2).map_or(false, |p| p.eq_ignore_ascii_case("hs"))
}

/// Rejects JWS `alg` values SD-JWT must never use: `none` and symmetric HMAC.
/// Applied on both the verify side (header parsing) and the issue side
/// (`encode_jws`), so the library never accepts or mints such a token.
pub(crate) fn reject_unacceptable_alg(alg: &str) -> Result<()> {
    if alg.eq_ignore_ascii_case("none") {
        return Err(Error::InvalidInput(
            "JWT `alg` \"none\" is not acceptable".to_string(),
        ));
    }
    if is_symmetric_alg(alg) {
        return Err(Error::InvalidInput(format!(
            "symmetric JWT `alg` \"{}\" is not acceptable",
            alg
        )));
    }
    Ok(())
}

/// Serialize `header` and `payload` and sign them via `crypto_provider` into
/// a compact JWS. Refuses to mint a token whose header carries an `alg` the
/// library would reject on the verify side (`none`, symmetric `HS*`).
pub(crate) fn encode_jws(
    header: &Map<String, Value>,
    payload: &impl Serialize,
    crypto_provider: &dyn SDJWTCryptoProvider,
    role: SignatureRole,
) -> Result<String> {
    if let Some(alg) = header.get("alg").and_then(Value::as_str) {
        reject_unacceptable_alg(alg)?;
    }
    let header =
        serde_json::to_string(header).map_err(|e| Error::DeserializationError(e.to_string()))?;
    let payload =
        serde_json::to_string(payload).map_err(|e| Error::DeserializationError(e.to_string()))?;
    let message = format!(
        "{}.{}",
        base64url_encode(header.as_bytes()),
        base64url_encode(payload.as_bytes())
    );
    let signature = crypto_provider.sign(message.as_bytes(), role)?;
    Ok(format!("{message}.{}", base64url_encode(&signature)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
    const PUBLIC_ISSUER_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";

    fn request(alg: &str) -> KeyRequest {
        KeyRequest {
            role: SignatureRole::IssuerJwt,
            iss: None,
            kid: None,
            alg: alg.to_owned(),
            x5c: None,
            jwk: None,
        }
    }

    #[test]
    fn builtin_sign_verify_round_trip() {
        let signer = SDJWTCryptoProviderBuiltin::new().with_signing_key(
            EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap(),
            "ES256",
        );
        let verifier = SDJWTCryptoProviderBuiltin::new().with_verifying_key(
            DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap(),
            "ES256",
        );
        let message = b"header.payload";
        let signature = signer.sign(message, SignatureRole::IssuerJwt).unwrap();
        assert!(verifier
            .verify(message, &signature, &request("ES256"))
            .is_ok());
        let mut tampered = signature.clone();
        tampered[0] ^= 0x01;
        assert!(verifier
            .verify(message, &tampered, &request("ES256"))
            .is_err());
    }

    #[test]
    fn builtin_rejects_algorithm_other_than_pinned() {
        let verifier = SDJWTCryptoProviderBuiltin::new().with_verifying_key(
            DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap(),
            "ES256",
        );
        let err = verifier.verify(b"m", b"s", &request("HS256")).unwrap_err();
        assert!(err.to_string().contains("unexpected signing algorithm"));
    }

    #[test]
    fn builtin_allowed_verifying_algs_issuer_is_pinned_alg() {
        let verifier = SDJWTCryptoProviderBuiltin::new().with_verifying_key(
            DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap(),
            "ES256",
        );
        assert_eq!(
            verifier
                .allowed_verifying_algs(SignatureRole::IssuerJwt)
                .unwrap(),
            vec!["ES256".to_string()]
        );
        // Without a pinned key there is nothing to allow.
        assert!(SDJWTCryptoProviderBuiltin::new()
            .allowed_verifying_algs(SignatureRole::IssuerJwt)
            .is_err());
    }

    #[test]
    fn builtin_allowed_verifying_algs_key_binding_excludes_symmetric() {
        // The KB allowlist needs no pinned key (the `cnf` key is in-band) and
        // must never admit an HMAC algorithm.
        let algs = SDJWTCryptoProviderBuiltin::new()
            .allowed_verifying_algs(SignatureRole::KeyBindingJwt)
            .unwrap();
        assert!(algs.contains(&"ES256".to_string()));
        assert!(algs.contains(&"EdDSA".to_string()));
        assert!(!algs.iter().any(|alg| is_symmetric_alg(alg)), "{algs:?}");
    }

    #[test]
    fn builtin_key_binding_allowlist_is_independent_of_issuer_alg() {
        // A Verifier can restrict the KB-JWT allowlist without touching the
        // Issuer-JWT policy, and vice versa.
        let provider = SDJWTCryptoProviderBuiltin::new()
            .with_verifying_key(
                DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap(),
                "ES256",
            )
            .with_allowed_key_binding_algs(&["EdDSA"]);
        assert_eq!(
            provider
                .allowed_verifying_algs(SignatureRole::IssuerJwt)
                .unwrap(),
            vec!["ES256".to_string()]
        );
        assert_eq!(
            provider
                .allowed_verifying_algs(SignatureRole::KeyBindingJwt)
                .unwrap(),
            vec!["EdDSA".to_string()]
        );
    }

    #[test]
    fn builtin_rejects_key_binding_without_cnf_key() {
        // A KB request with no in-band `cnf` key must not fall back to the pinned
        // Issuer key.
        let verifier = SDJWTCryptoProviderBuiltin::new().with_verifying_key(
            DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap(),
            "ES256",
        );
        let mut req = request("ES256");
        req.role = SignatureRole::KeyBindingJwt;
        let err = verifier.verify(b"m", b"s", &req).unwrap_err();
        assert!(
            err.to_string().contains("in-band `cnf` key"),
            "expected a missing-cnf-key error, got: {err}"
        );
    }

    #[test]
    fn builtin_without_signing_key_cannot_sign() {
        let crypto_provider = SDJWTCryptoProviderBuiltin::new();
        assert!(crypto_provider
            .sign(b"m", SignatureRole::KeyBindingJwt)
            .is_err());
        assert!(crypto_provider
            .signing_alg(SignatureRole::KeyBindingJwt)
            .is_err());
        assert!(crypto_provider
            .verify(b"m", b"s", &request("ES256"))
            .unwrap_err()
            .to_string()
            .contains("no verifying key"));
    }

    #[test]
    fn encode_jws_rejects_symmetric_alg_in_header() {
        // A misconfigured provider must not be able to mint a symmetric-`alg` token.
        let signer = SDJWTCryptoProviderBuiltin::new()
            .with_signing_key(EncodingKey::from_secret(b"secret"), "HS256");
        let mut header = Map::new();
        header.insert("alg".to_string(), Value::String("HS256".to_string()));
        let err =
            encode_jws(&header, &json!({"a": 1}), &signer, SignatureRole::IssuerJwt).unwrap_err();
        assert!(err.to_string().contains("symmetric"), "got: {err}");
    }

    #[test]
    fn encode_jws_produces_three_parts() {
        let signer = SDJWTCryptoProviderBuiltin::new().with_signing_key(
            EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap(),
            "ES256",
        );
        let mut header = Map::new();
        header.insert("alg".to_string(), Value::String("ES256".to_string()));
        let jws = encode_jws(&header, &json!({"a": 1}), &signer, SignatureRole::IssuerJwt).unwrap();
        assert_eq!(jws.split('.').count(), 3);
    }
}
