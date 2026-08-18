// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use crate::utils::{base64url_decode, base64url_encode};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use serde::Serialize;
use std::collections::HashMap;
use std::str::FromStr;

/// Which signature a [SDJWTCryptoProvider] call concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SDJWTSignatureRole {
    /// The signature over the Issuer-signed JWT, made with the Issuer's key.
    IssuerJwt,
    /// The signature over the Key Binding JWT, made with the Holder's key.
    KeyBindingJwt,
}

/// Material the library extracts from a JWT for a [SDJWTCryptoProvider] to
/// select the verification key. Every field is unverified, attacker-controlled
/// input: a successful `verify` asserts that the signature was checked against
/// a key trusted for the signer these fields claim. A provider that requires a
/// known issuer should scope its key lookup by `iss` and reject `iss == None`;
/// use `x5c` only after validating the chain to a trust anchor; return an
/// error (e.g. [Error::KeyNotFound]) for an unknown issuer or key.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SDJWTKeyRequest {
    /// Which signature this request is for.
    pub role: SDJWTSignatureRole,
    /// Unverified `iss` claim from the payload, if present.
    pub iss: Option<String>,
    /// `kid` from the protected header, if present.
    pub kid: Option<String>,
    /// JWS `alg` wire name from the protected header (e.g. "ES256"), passed
    /// through raw so crypto providers may support algorithms the library does not.
    pub alg: String,
    /// X.509 certificate chain from the protected header (`x5c`),
    /// base64-decoded to DER.
    pub x5c: Option<Vec<Vec<u8>>>,
    /// [SDJWTSignatureRole::KeyBindingJwt] only: the Holder's public key from the
    /// verified Issuer payload's `cnf`, as a JWK JSON string.
    pub jwk: Option<String>,
}

/// Signing and verification behind one injectable interface, so key storage and
/// crypto can live outside the library (e.g. platform keystores reached over
/// FFI, where keys are non-extractable and only operations cross the
/// boundary). `message` is always the raw JWS signing input
/// (`BASE64URL(header) . BASE64URL(payload)` as bytes); signatures are raw
/// bytes — the library owns all JWS encoding and decoding.
///
/// The methods form two pairs — signing ([Self::signing_alg] + [Self::sign])
/// and verifying ([Self::allowed_verifying_algs] + [Self::verify]) — and each
/// pair has a fail-closed default returning [Error::KeyNotFound], so a
/// provider implements only the pair(s) its party performs. `Send + Sync` so
/// an injected provider can be held by an issuer/holder/verifier shared
/// across threads.
pub trait SDJWTCryptoProvider: Send + Sync {
    /// JWS `alg` wire name that `sign(role)` produces.
    /// Defaults to an error for providers that do not sign.
    fn signing_alg(&self, role: SDJWTSignatureRole) -> Result<String> {
        Err(Error::KeyNotFound(format!(
            "this crypto provider does not implement signing ({role:?})"
        )))
    }
    /// JWS `alg` values this provider accepts when verifying a `role`
    /// signature — the RFC 8725 §3.1 algorithm allowlist. The library
    /// rejects a JWT whose header `alg` is not in this list *before* calling
    /// [SDJWTCryptoProvider::verify], so the (attacker-controlled) header
    /// never selects the algorithm.
    /// Defaults to an error for providers that do not verify.
    fn allowed_verifying_algs(&self, role: SDJWTSignatureRole) -> Result<Vec<String>> {
        Err(Error::KeyNotFound(format!(
            "this crypto provider does not implement verification ({role:?})"
        )))
    }
    /// Sign `message` with the key this crypto provider holds for `role`.
    /// Defaults to an error for providers that do not sign.
    fn sign(&self, _message: &[u8], role: SDJWTSignatureRole) -> Result<Vec<u8>> {
        Err(Error::KeyNotFound(format!(
            "this crypto provider does not implement signing ({role:?})"
        )))
    }
    /// Verify `signature` over `message` for the signer `request` describes.
    /// Key selection AND trust are the implementation's responsibility.
    /// Defaults to an error for providers that do not verify.
    fn verify(&self, _message: &[u8], _signature: &[u8], request: &SDJWTKeyRequest) -> Result<()> {
        Err(Error::KeyNotFound(format!(
            "this crypto provider does not implement verification ({:?})",
            request.role
        )))
    }
}

/// A key bundled with the JWS `alg` wire name (e.g. `"ES256"`) it is used
/// with — each key is used with exactly one algorithm (RFC 8725 §3.1).
/// Whether the `alg` is acceptable is checked where the pair is bound to a
/// provider, against that provider's declared policy — not here.
pub struct SDJWTKeyWithAlg<K> {
    key: K,
    alg: String,
}

impl<K> SDJWTKeyWithAlg<K> {
    /// Bundle `key` with the JWS `alg` wire name it is used with (`key` must
    /// be of the matching family).
    pub fn new(key: K, alg: &str) -> Self {
        Self {
            key,
            alg: alg.to_owned(),
        }
    }
}

/// Software crypto provider over jsonwebtoken. The algorithm policy is
/// declared once, at construction ([Self::new]), and every key bound
/// afterwards carries exactly one JWS algorithm inside that policy. The
/// Issuer JWT is verified with a pinned Issuer key — a `kid`-keyed set for
/// rotation, a default key, or both — under that key's bound algorithm; the
/// Key Binding JWT is verified with the in-band `cnf` key from the request.
/// A symmetric (`HS*`) `alg` is rejected outright in both cases.
pub struct SDJWTCryptoProviderBuiltin {
    issuer_signing: Option<SDJWTKeyWithAlg<EncodingKey>>,
    holder_signing: Option<SDJWTKeyWithAlg<EncodingKey>>,
    issuer_verifying: Option<SDJWTKeyWithAlg<DecodingKey>>,
    issuer_verifying_by_kid: HashMap<String, SDJWTKeyWithAlg<DecodingKey>>,
    allowed_issuer_signing_algs: Vec<String>,
    allowed_holder_signing_algs: Option<Vec<String>>,
}

impl SDJWTCryptoProviderBuiltin {
    /// A crypto provider holding the declared algorithm policy and no keys
    /// yet. `allowed_issuer_signing_algs` is the allowlist for the Issuer's
    /// signature; `allowed_holder_signing_algs` is the Key Binding
    /// counterpart — `None` for a provider that neither signs nor verifies
    /// Key Binding JWTs (KB verification then fails closed).
    pub fn new(
        allowed_issuer_signing_algs: &[&str],
        allowed_holder_signing_algs: Option<&[&str]>,
    ) -> Self {
        Self {
            issuer_signing: None,
            holder_signing: None,
            issuer_verifying: None,
            issuer_verifying_by_kid: HashMap::new(),
            allowed_issuer_signing_algs: allowed_issuer_signing_algs
                .iter()
                .map(|s| s.to_string())
                .collect(),
            allowed_holder_signing_algs: allowed_holder_signing_algs
                .map(|algs| algs.iter().map(|s| s.to_string()).collect()),
        }
    }

    /// Sign Issuer JWTs with the Issuer's `key`, under the algorithm bundled
    /// with it. Binding fails at configuration time if that algorithm is one
    /// SD-JWT never accepts (`none`, symmetric `HS*`) or is outside the
    /// issuer allowlist declared at [Self::new].
    pub fn with_issuer_signing_key(mut self, key: SDJWTKeyWithAlg<EncodingKey>) -> Result<Self> {
        reject_unacceptable_alg(&key.alg)?;
        if !self
            .allowed_issuer_signing_algs
            .iter()
            .any(|allowed_alg| allowed_alg == &key.alg)
        {
            return Err(Error::InvalidInput(format!(
                "issuer signing key algorithm \"{}\" is outside the allowed issuer signing algorithms",
                key.alg
            )));
        }
        self.issuer_signing = Some(key);
        Ok(self)
    }

    /// Sign Key Binding JWTs with the Holder's `key`, under the algorithm
    /// bundled with it. Binding fails at configuration time if the Key
    /// Binding allowlist was not declared at [Self::new], excludes that
    /// algorithm, or the algorithm is one SD-JWT never accepts (`none`,
    /// symmetric `HS*`).
    pub fn with_holder_signing_key(mut self, key: SDJWTKeyWithAlg<EncodingKey>) -> Result<Self> {
        reject_unacceptable_alg(&key.alg)?;
        let allowed = self.allowed_holder_signing_algs.as_ref().ok_or_else(|| {
            Error::InvalidInput(
                "allowed holder signing algorithms must be declared to bind a holder signing key"
                    .to_string(),
            )
        })?;
        if !allowed.iter().any(|allowed_alg| allowed_alg == &key.alg) {
            return Err(Error::InvalidInput(format!(
                "holder signing key algorithm \"{}\" is outside the allowed holder signing algorithms",
                key.alg
            )));
        }
        self.holder_signing = Some(key);
        Ok(self)
    }

    /// Verify Issuer JWTs with the Issuer's public `key`, under exactly the
    /// algorithm bundled with it — a JWT whose header `alg` differs is
    /// rejected before the cryptographic operation. This is the default key:
    /// a token whose `kid` matches no [Self::with_issuer_verifying_key_for_kid]
    /// entry (or that carries no `kid`) verifies against it. The same
    /// configuration-time policy checks apply as for signing keys.
    pub fn with_issuer_verifying_key(mut self, key: SDJWTKeyWithAlg<DecodingKey>) -> Result<Self> {
        self.issuer_verifying = Some(self.issuer_verifying_entry(key)?);
        Ok(self)
    }

    /// Set the pinned Issuer verifying key for tokens whose header `kid`
    /// equals `kid`; setting the same `kid` again replaces that entry. The
    /// (attacker-controlled) header `kid` only ever selects among these
    /// pre-trusted keys — a token whose `kid` matches no entry falls back to
    /// the [Self::with_issuer_verifying_key] default key when one is bound,
    /// and fails otherwise.
    pub fn with_issuer_verifying_key_for_kid(
        mut self,
        kid: &str,
        key: SDJWTKeyWithAlg<DecodingKey>,
    ) -> Result<Self> {
        let entry = self.issuer_verifying_entry(key)?;
        self.issuer_verifying_by_kid.insert(kid.to_owned(), entry);
        Ok(self)
    }

    /// An Issuer verifying-key entry validated against the declared policy:
    /// the key's algorithm must be acceptable to SD-JWT and inside the
    /// issuer allowlist.
    fn issuer_verifying_entry(
        &self,
        key: SDJWTKeyWithAlg<DecodingKey>,
    ) -> Result<SDJWTKeyWithAlg<DecodingKey>> {
        reject_unacceptable_alg(&key.alg)?;
        if !self
            .allowed_issuer_signing_algs
            .iter()
            .any(|allowed_alg| allowed_alg == &key.alg)
        {
            return Err(Error::InvalidInput(format!(
                "issuer verifying key algorithm \"{}\" is outside the allowed issuer signing algorithms",
                key.alg
            )));
        }
        Ok(key)
    }
}

impl SDJWTCryptoProviderBuiltin {
    /// The signing key configured for `role`, or an error naming the
    /// missing configuration.
    fn signing_for(&self, role: SDJWTSignatureRole) -> Result<&SDJWTKeyWithAlg<EncodingKey>> {
        match role {
            SDJWTSignatureRole::IssuerJwt => self.issuer_signing.as_ref().ok_or(
                Error::KeyNotFound("no issuer signing key configured".to_string()),
            ),
            SDJWTSignatureRole::KeyBindingJwt => self.holder_signing.as_ref().ok_or(
                Error::KeyNotFound("no holder signing key configured".to_string()),
            ),
        }
    }
}

impl SDJWTCryptoProvider for SDJWTCryptoProviderBuiltin {
    fn signing_alg(&self, role: SDJWTSignatureRole) -> Result<String> {
        self.signing_for(role).map(|s| s.alg.clone())
    }

    /// The policy declared at [Self::new] for `role`. The Key Binding list
    /// is optional there: undeclared, KB verification fails closed.
    fn allowed_verifying_algs(&self, role: SDJWTSignatureRole) -> Result<Vec<String>> {
        match role {
            SDJWTSignatureRole::IssuerJwt => Ok(self.allowed_issuer_signing_algs.clone()),
            SDJWTSignatureRole::KeyBindingJwt => {
                self.allowed_holder_signing_algs
                    .clone()
                    .ok_or(Error::KeyNotFound(
                        "no allowed holder signing algorithms configured".to_string(),
                    ))
            }
        }
    }

    fn sign(&self, message: &[u8], role: SDJWTSignatureRole) -> Result<Vec<u8>> {
        let signing = self.signing_for(role)?;
        let algorithm = Algorithm::from_str(&signing.alg)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        let signature = jsonwebtoken::crypto::sign(message, &signing.key, algorithm)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        base64url_decode(&signature)
    }

    fn verify(&self, message: &[u8], signature: &[u8], request: &SDJWTKeyRequest) -> Result<()> {
        let in_band_key;
        // Issuer-JWT key selection among the pre-trusted pinned keys: an
        // exact `kid` match wins, else the default key.
        let issuer_verifying = match &request.kid {
            Some(kid) => self
                .issuer_verifying_by_kid
                .get(kid)
                .or(self.issuer_verifying.as_ref()),
            None => self.issuer_verifying.as_ref(),
        };
        let (key, alg_str) = match (&request.jwk, issuer_verifying) {
            // The in-band Holder key: its trust derives from the verified
            // Issuer payload, so it is honored without a pinned key.
            (Some(jwk_json), _) if request.role == SDJWTSignatureRole::KeyBindingJwt => {
                // Defense-in-depth: `parse_protected_header` already rejects
                // symmetric `alg`s; honoring one against the public `cnf` key
                // bytes would let anyone forge (see `is_symmetric_alg`).
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
            (_, _) if request.role == SDJWTSignatureRole::KeyBindingJwt => {
                return Err(Error::KeyNotFound(
                    "Key Binding JWT verification requires an in-band `cnf` key".to_string(),
                ))
            }
            (_, Some(verifying)) => {
                // Defense-in-depth for direct callers: the library already
                // enforces this allowlist before `verify` is invoked.
                if !self
                    .allowed_issuer_signing_algs
                    .iter()
                    .any(|alg| alg == &request.alg)
                {
                    return Err(Error::InvalidInput(format!(
                        "unexpected signing algorithm: {}",
                        request.alg
                    )));
                }
                // The bound alg — never the header's — is what reaches
                // `crypto::verify` below, which does not itself check
                // key-family/alg consistency.
                if request.alg != verifying.alg {
                    return Err(Error::InvalidInput(format!(
                        "JWT `alg` \"{}\" does not match the issuer verifying key's algorithm \"{}\"",
                        request.alg, verifying.alg
                    )));
                }
                (&verifying.key, verifying.alg.as_str())
            }
            _ => {
                return Err(Error::KeyNotFound(match &request.kid {
                    Some(kid) if !self.issuer_verifying_by_kid.is_empty() => {
                        format!("no issuer verifying key registered for kid \"{kid}\"")
                    }
                    _ => "no issuer verifying key configured".to_string(),
                }))
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
/// Applied in [crate::ProtectedHeader::new] — the one constructor both the
/// verify side (header parsing) and the issue side (`encode_jws`) pass
/// through — so the library never accepts or mints such a token.
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
/// a compact JWS.
pub(crate) fn encode_jws(
    header: &crate::ProtectedHeader,
    payload: &impl Serialize,
    crypto_provider: &dyn SDJWTCryptoProvider,
    role: SDJWTSignatureRole,
) -> Result<String> {
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
    use serde_json::{json, Value};

    const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
    const PUBLIC_ISSUER_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";

    fn request(alg: &str) -> SDJWTKeyRequest {
        SDJWTKeyRequest {
            role: SDJWTSignatureRole::IssuerJwt,
            iss: None,
            kid: None,
            alg: alg.to_owned(),
            x5c: None,
            jwk: None,
        }
    }

    fn es256_signing_key() -> EncodingKey {
        EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap()
    }

    fn es256_verifying_key() -> DecodingKey {
        DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()
    }

    #[test]
    fn builtin_sign_verify_round_trip() {
        let signer = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES256"))
            .unwrap();
        let verifier = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_verifying_key(SDJWTKeyWithAlg::new(es256_verifying_key(), "ES256"))
            .unwrap();
        let message = b"header.payload";
        let signature = signer.sign(message, SDJWTSignatureRole::IssuerJwt).unwrap();
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
    fn builtin_rejects_algorithm_outside_issuer_allowlist() {
        let verifier = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_verifying_key(SDJWTKeyWithAlg::new(es256_verifying_key(), "ES256"))
            .unwrap();
        let err = verifier.verify(b"m", b"s", &request("HS256")).unwrap_err();
        assert!(err.to_string().contains("unexpected signing algorithm"));
    }

    #[test]
    fn builtin_rejects_alg_allowed_but_not_bound_to_key() {
        // RFC 8725 §3.1: the key is used with exactly one algorithm even when
        // an explicit allowlist admits several. Asserting on the message
        // proves the rejection happens before the cryptographic operation —
        // jsonwebtoken would otherwise report a signature/key mismatch
        // instead. The matching alg is the positive control: an explicit
        // list narrows, but never blocks, the bound algorithm.
        let signer = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES256"))
            .unwrap();
        let verifier = SDJWTCryptoProviderBuiltin::new(&["ES256", "ES384"], None)
            .with_issuer_verifying_key(SDJWTKeyWithAlg::new(es256_verifying_key(), "ES256"))
            .unwrap();
        let message = b"header.payload";
        let signature = signer.sign(message, SDJWTSignatureRole::IssuerJwt).unwrap();
        assert!(verifier
            .verify(message, &signature, &request("ES256"))
            .is_ok());
        let err = verifier
            .verify(message, &signature, &request("ES384"))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the issuer verifying key's algorithm"),
            "got: {err}"
        );
    }

    #[test]
    fn builtin_rejects_contradictory_issuer_key_and_allowlist() {
        // A bound algorithm outside the policy declared at construction
        // could never verify anything — binding it fails at configuration
        // time instead of failing every verification later.
        let err = SDJWTCryptoProviderBuiltin::new(&["ES384"], None)
            .with_issuer_verifying_key(SDJWTKeyWithAlg::new(es256_verifying_key(), "ES256"))
            .err()
            .unwrap();
        assert!(
            err.to_string()
                .contains("outside the allowed issuer signing algorithms"),
            "got: {err}"
        );
    }

    #[test]
    fn builtin_selects_issuer_verifying_key_by_kid() {
        // The header `kid` selects among the pre-trusted pinned keys; an
        // unknown `kid` falls back to the default key when one is bound and
        // fails otherwise — trust never leaves the registered set.
        let signer = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES256"))
            .unwrap();
        let message = b"header.payload";
        let signature = signer.sign(message, SDJWTSignatureRole::IssuerJwt).unwrap();

        let kid_only = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_verifying_key_for_kid(
                "issuer-key-1",
                SDJWTKeyWithAlg::new(es256_verifying_key(), "ES256"),
            )
            .unwrap();
        let mut req = request("ES256");
        req.kid = Some("issuer-key-1".to_string());
        assert!(kid_only.verify(message, &signature, &req).is_ok());
        req.kid = Some("unknown".to_string());
        let err = kid_only.verify(message, &signature, &req).unwrap_err();
        assert!(
            err.to_string()
                .contains("no issuer verifying key registered for kid"),
            "got: {err}"
        );
        req.kid = None;
        assert!(kid_only.verify(message, &signature, &req).is_err());

        let with_default = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_verifying_key(SDJWTKeyWithAlg::new(es256_verifying_key(), "ES256"))
            .unwrap()
            .with_issuer_verifying_key_for_kid(
                "issuer-key-1",
                SDJWTKeyWithAlg::new(es256_verifying_key(), "ES256"),
            )
            .unwrap();
        req.kid = Some("unknown".to_string());
        assert!(with_default.verify(message, &signature, &req).is_ok());
    }

    #[test]
    fn builtin_kid_keys_carry_their_own_alg_binding() {
        // Each key-set entry keeps one-key-one-alg: selecting a key by `kid`
        // also selects its bound algorithm, and the declared policy gates
        // every entry at registration.
        let verifier = SDJWTCryptoProviderBuiltin::new(&["ES256", "ES384"], None)
            .with_issuer_verifying_key_for_kid(
                "es384-key",
                SDJWTKeyWithAlg::new(es256_verifying_key(), "ES384"),
            )
            .unwrap();
        let mut req = request("ES256");
        req.kid = Some("es384-key".to_string());
        let err = verifier.verify(b"m", b"s", &req).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the issuer verifying key's algorithm"),
            "got: {err}"
        );
        let err = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_verifying_key_for_kid(
                "k",
                SDJWTKeyWithAlg::new(es256_verifying_key(), "ES384"),
            )
            .err()
            .unwrap();
        assert!(
            err.to_string()
                .contains("outside the allowed issuer signing algorithms"),
            "got: {err}"
        );
    }

    #[test]
    fn builtin_rejects_contradictory_signing_key_and_allowlist() {
        // The declared policy also guards the party's own signing keys: a
        // provider must not mint tokens its declared policy rejects.
        let err = SDJWTCryptoProviderBuiltin::new(&["ES384"], None)
            .with_issuer_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES256"))
            .err()
            .unwrap();
        assert!(
            err.to_string()
                .contains("issuer signing key algorithm \"ES256\" is outside"),
            "got: {err}"
        );
        let err = SDJWTCryptoProviderBuiltin::new(&["ES256"], Some(&["EdDSA"]))
            .with_holder_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES256"))
            .err()
            .unwrap();
        assert!(
            err.to_string()
                .contains("holder signing key algorithm \"ES256\" is outside"),
            "got: {err}"
        );
        let err = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_signing_key(SDJWTKeyWithAlg::new(
                EncodingKey::from_secret(b"secret"),
                "HS256",
            ))
            .err()
            .unwrap();
        assert!(err.to_string().contains("not acceptable"), "got: {err}");
    }

    #[test]
    fn builtin_unusable_allowlists_fail_closed() {
        // Declaring an unusable list is the caller's own mistake, not an
        // error — the guards elsewhere keep it harmless: no key binds within
        // an empty list, and `none`/HS* entries are dead because headers and
        // key bindings reject those algorithms regardless of any list.
        let err = SDJWTCryptoProviderBuiltin::new(&[], None)
            .with_issuer_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES256"))
            .err()
            .unwrap();
        assert!(
            err.to_string()
                .contains("outside the allowed issuer signing algorithms"),
            "got: {err}"
        );
        let err = SDJWTCryptoProviderBuiltin::new(&["ES256"], Some(&["HS256"]))
            .with_holder_signing_key(SDJWTKeyWithAlg::new(
                EncodingKey::from_secret(b"secret"),
                "HS256",
            ))
            .err()
            .unwrap();
        assert!(err.to_string().contains("not acceptable"), "got: {err}");
        let err = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_verifying_key(SDJWTKeyWithAlg::new(es256_verifying_key(), "HS256"))
            .err()
            .unwrap();
        assert!(err.to_string().contains("not acceptable"), "got: {err}");
    }

    #[test]
    fn builtin_requires_declared_holder_allowlist() {
        // The issuer allowlist is a construction parameter and so can never
        // be missing; the Key Binding list is optional — undeclared, binding
        // a holder signing key fails and KB verification fails closed.
        let err = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_holder_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES256"))
            .err()
            .unwrap();
        assert!(
            err.to_string()
                .contains("must be declared to bind a holder signing key"),
            "got: {err}"
        );
        assert!(SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .allowed_verifying_algs(SDJWTSignatureRole::KeyBindingJwt)
            .unwrap_err()
            .to_string()
            .contains("no allowed holder signing algorithms"));
    }

    #[test]
    fn builtin_allowed_verifying_algs_issuer_is_configured_list() {
        // The allowlist round-trips as configured — it is the policy gate the
        // library checks before invoking `verify`. The key's bound algorithm
        // further narrows what actually verifies, so extra entries never let
        // the token's `alg` select an algorithm.
        let verifier = SDJWTCryptoProviderBuiltin::new(&["ES256", "ES384"], None)
            .with_issuer_verifying_key(SDJWTKeyWithAlg::new(es256_verifying_key(), "ES256"))
            .unwrap();
        assert_eq!(
            verifier
                .allowed_verifying_algs(SDJWTSignatureRole::IssuerJwt)
                .unwrap(),
            vec!["ES256".to_string(), "ES384".to_string()]
        );
    }

    #[test]
    fn builtin_holder_allowlist_is_independent_of_issuer_allowlist() {
        // A Verifier can restrict the Holder's KB-JWT allowlist without
        // touching the Issuer-JWT policy, and vice versa.
        let provider = SDJWTCryptoProviderBuiltin::new(&["ES256"], Some(&["EdDSA"]))
            .with_issuer_verifying_key(SDJWTKeyWithAlg::new(es256_verifying_key(), "ES256"))
            .unwrap();
        assert_eq!(
            provider
                .allowed_verifying_algs(SDJWTSignatureRole::IssuerJwt)
                .unwrap(),
            vec!["ES256".to_string()]
        );
        assert_eq!(
            provider
                .allowed_verifying_algs(SDJWTSignatureRole::KeyBindingJwt)
                .unwrap(),
            vec!["EdDSA".to_string()]
        );
    }

    #[test]
    fn builtin_rejects_key_binding_without_cnf_key() {
        // A KB request with no in-band `cnf` key must not fall back to the pinned
        // Issuer key.
        let verifier = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_verifying_key(SDJWTKeyWithAlg::new(es256_verifying_key(), "ES256"))
            .unwrap();
        let mut req = request("ES256");
        req.role = SDJWTSignatureRole::KeyBindingJwt;
        let err = verifier.verify(b"m", b"s", &req).unwrap_err();
        assert!(
            err.to_string().contains("in-band `cnf` key"),
            "expected a missing-cnf-key error, got: {err}"
        );
    }

    #[test]
    fn builtin_without_signing_key_cannot_sign() {
        let crypto_provider = SDJWTCryptoProviderBuiltin::new(&["ES256"], None);
        assert!(crypto_provider
            .sign(b"m", SDJWTSignatureRole::KeyBindingJwt)
            .unwrap_err()
            .to_string()
            .contains("no holder signing key"));
        assert!(crypto_provider
            .signing_alg(SDJWTSignatureRole::IssuerJwt)
            .unwrap_err()
            .to_string()
            .contains("no issuer signing key"));
        assert!(crypto_provider
            .verify(b"m", b"s", &request("ES256"))
            .unwrap_err()
            .to_string()
            .contains("no issuer verifying key"));
    }

    #[test]
    fn builtin_signing_keys_are_per_role() {
        // A provider holding both keys signs each role with its own key and
        // algorithm; a role whose key is absent errors instead of borrowing
        // the other role's key.
        let both = SDJWTCryptoProviderBuiltin::new(&["ES256"], Some(&["ES384"]))
            .with_issuer_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES256"))
            .unwrap()
            .with_holder_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES384"))
            .unwrap();
        assert_eq!(
            both.signing_alg(SDJWTSignatureRole::IssuerJwt).unwrap(),
            "ES256"
        );
        assert_eq!(
            both.signing_alg(SDJWTSignatureRole::KeyBindingJwt).unwrap(),
            "ES384"
        );

        let issuer_only = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES256"))
            .unwrap();
        assert!(issuer_only
            .sign(b"m", SDJWTSignatureRole::KeyBindingJwt)
            .unwrap_err()
            .to_string()
            .contains("no holder signing key"));
    }

    #[test]
    fn default_trait_methods_fail_closed() {
        // A provider implements only the pair its deployment needs
        // (issuer-only: signing; verifier-only: verifying) — the other pair
        // defaults to an error, never to acceptance.
        struct EmptyProvider;
        impl SDJWTCryptoProvider for EmptyProvider {}

        let provider = EmptyProvider;
        for role in [
            SDJWTSignatureRole::IssuerJwt,
            SDJWTSignatureRole::KeyBindingJwt,
        ] {
            assert!(provider.signing_alg(role).is_err());
            assert!(provider.sign(b"m", role).is_err());
            assert!(provider.allowed_verifying_algs(role).is_err());
        }
        assert!(provider.verify(b"m", b"s", &request("ES256")).is_err());
    }

    #[test]
    fn protected_header_rejects_unacceptable_alg() {
        // `ProtectedHeader::new` is the single chokepoint every protected
        // header passes through, so a header carrying an `alg` the library
        // must never use (`none`, symmetric `HS*`) is unrepresentable —
        // minting such a token cannot even be attempted.
        assert!(crate::ProtectedHeader::new("HS256".to_string(), None)
            .unwrap_err()
            .to_string()
            .contains("symmetric"));
        assert!(crate::ProtectedHeader::new("none".to_string(), None)
            .unwrap_err()
            .to_string()
            .contains("not acceptable"));
        assert!(crate::ProtectedHeader::new("ES256".to_string(), None).is_ok());
    }

    #[test]
    fn encode_jws_produces_three_parts() {
        let signer = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES256"))
            .unwrap();
        let header = crate::ProtectedHeader::new("ES256".to_string(), None).unwrap();
        let jws = encode_jws(
            &header,
            &json!({"a": 1}),
            &signer,
            SDJWTSignatureRole::IssuerJwt,
        )
        .unwrap();
        assert_eq!(jws.split('.').count(), 3);
    }

    #[test]
    fn encode_jws_emits_only_set_header_fields() {
        // Absent optional fields must not appear as JSON nulls in the minted
        // header — only `alg` (and `typ` when set) go on the wire.
        let signer = SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
            .with_issuer_signing_key(SDJWTKeyWithAlg::new(es256_signing_key(), "ES256"))
            .unwrap();
        let decoded_header = |typ: Option<&str>| -> Value {
            let header =
                crate::ProtectedHeader::new("ES256".to_string(), typ.map(str::to_owned)).unwrap();
            let jws = encode_jws(
                &header,
                &json!({"a": 1}),
                &signer,
                SDJWTSignatureRole::IssuerJwt,
            )
            .unwrap();
            let header_b64 = jws.split('.').next().unwrap();
            serde_json::from_slice(&base64url_decode(header_b64).unwrap()).unwrap()
        };
        assert_eq!(decoded_header(None), json!({"alg": "ES256"}));
        assert_eq!(
            decoded_header(Some("example+sd-jwt")),
            json!({"alg": "ES256", "typ": "example+sd-jwt"})
        );
    }
}
