// Copyright (c) 2026 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! SD-JWTs co-signed by several Issuers in General JSON Serialization
//! (RFC 9901 §8.3).

use crate::utils::fixtures::{
    HOLDER_JWK_KEY, HOLDER_KEY, ISSUER_KEY, ISSUER_KEY_2, ISSUER_PUBLIC_KEY, ISSUER_PUBLIC_KEY_2,
    RFC_9901_GENERAL_JSON_EXAMPLE,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use sd_jwt_rs::error::Error;
use sd_jwt_rs::issuer::ClaimsForSelectiveDisclosureStrategy;
use sd_jwt_rs::{
    SDJWTHolder, SDJWTIssuer, SDJWTKeyRequest, SDJWTKeyWithAlg, SDJWTSerializationFormat,
    SDJWTSignaturePolicy, SDJWTSignatureRole, SDJWTSignatureVerifier,
    SDJWTSignatureVerifierBuiltin, SDJWTSigner, SDJWTSignerBuiltin, SDJWTVerifier,
    DEFAULT_SIGNING_ALG,
};
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};

mod utils;

const K1: &str = "issuer-key-1";
const K2: &str = "issuer-key-2";
const AUD: &str = "https://verifier.example.org";
const NONCE: &str = "1234567890";
const ALGS: &[&str] = &[DEFAULT_SIGNING_ALG];

const TYP: &str = "example+sd-jwt";

fn signer(pem: &str, kid: Option<&str>) -> Box<dyn SDJWTSigner> {
    let signer = SDJWTSignerBuiltin::new(SDJWTKeyWithAlg::new(
        EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
        DEFAULT_SIGNING_ALG,
    ))
    .unwrap();
    Box::new(match kid {
        Some(kid) => signer.with_kid(kid),
        None => signer,
    })
}

fn issuer(pem: &str, kid: Option<&str>) -> SDJWTIssuer {
    SDJWTIssuer::new(signer(pem, kid)).with_typ(TYP)
}

fn kb_signer() -> Option<Box<dyn SDJWTSigner>> {
    Some(signer(HOLDER_KEY, Some("holder-key")))
}

/// Verifying keys pinned by `kid`, no default key.
fn verifier(kids: &[&str]) -> Box<dyn SDJWTSignatureVerifier> {
    let mut verifier = SDJWTSignatureVerifierBuiltin::new(ALGS, Some(ALGS));
    for kid in kids {
        let pem = match *kid {
            K1 => ISSUER_PUBLIC_KEY,
            K2 => ISSUER_PUBLIC_KEY_2,
            _ => unreachable!(),
        };
        verifier = verifier
            .with_issuer_verifying_key_for_kid(
                kid,
                SDJWTKeyWithAlg::new(
                    DecodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
                    DEFAULT_SIGNING_ALG,
                ),
            )
            .unwrap();
    }
    Box::new(verifier)
}

fn verify(
    presentation: &str,
    kids: &[&str],
    policy: SDJWTSignaturePolicy,
) -> sd_jwt_rs::error::Result<SDJWTVerifier> {
    SDJWTVerifier::new_with_policy(
        verifier(kids),
        presentation.to_owned(),
        Some(AUD.to_owned()),
        Some(NONCE.to_owned()),
        SDJWTSerializationFormat::GeneralJson,
        policy,
    )
}

/// An SD-JWT issued with `K1` and co-signed with `K2`.
fn co_signed_sd_jwt() -> String {
    let holder_jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let sd_jwt = issuer(ISSUER_KEY, Some(K1))
        .issue_sd_jwt(
            json!({
                "iss": "https://issuer.example.com",
                "iat": 1683000000,
                "given_name": "John",
                "family_name": "Doe",
            }),
            ClaimsForSelectiveDisclosureStrategy::TopLevel,
            Some(holder_jwk),
            false,
            SDJWTSerializationFormat::GeneralJson,
        )
        .unwrap();
    issuer(ISSUER_KEY_2, Some(K2))
        .add_signature(&sd_jwt)
        .unwrap()
}

/// A Holder presentation of `sd_jwt` disclosing `given_name`, with a KB-JWT.
fn present(sd_jwt: &str, kids: &[&str], policy: SDJWTSignaturePolicy) -> String {
    let mut holder = SDJWTHolder::new_with_policy(
        verifier(kids),
        kb_signer(),
        sd_jwt.to_owned(),
        SDJWTSerializationFormat::GeneralJson,
        policy,
    )
    .unwrap();
    let mut claims = Map::new();
    claims.insert("given_name".to_owned(), Value::Bool(true));
    holder
        .create_presentation(claims, Some(NONCE.to_owned()), Some(AUD.to_owned()))
        .unwrap()
}

fn edit(sd_jwt: &str, f: impl FnOnce(&mut Value)) -> String {
    let mut json: Value = serde_json::from_str(sd_jwt).unwrap();
    f(&mut json);
    json.to_string()
}

fn b64_json(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

fn decode_b64_json(b64: &Value) -> Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(b64.as_str().unwrap()).unwrap()).unwrap()
}

fn assert_err_contains<T>(result: sd_jwt_rs::error::Result<T>, needle: &str) {
    match result {
        Ok(_) => panic!("expected an error containing {needle:?}"),
        Err(err) => assert!(err.to_string().contains(needle), "got: {err}"),
    }
}

#[test]
fn rfc_example_verifies_both_signatures() {
    // `kid` is in the unprotected headers, and the KB-JWT `sd_hash` is
    // computed over `signatures[0]`.
    let verifier = verify(
        RFC_9901_GENERAL_JSON_EXAMPLE,
        &[K1, K2],
        SDJWTSignaturePolicy::All,
    )
    .unwrap();
    assert_eq!(verifier.verified_claims["given_name"], "John");
    assert_eq!(verifier.verified_claims["family_name"], "Doe");
}

#[test]
fn rfc_example_policy_with_one_known_key() {
    assert_err_contains(
        verify(
            RFC_9901_GENERAL_JSON_EXAMPLE,
            &[K1],
            SDJWTSignaturePolicy::All,
        ),
        "issuer-key-2",
    );
    assert!(verify(
        RFC_9901_GENERAL_JSON_EXAMPLE,
        &[K2],
        SDJWTSignaturePolicy::All
    )
    .is_err());

    assert!(verify(
        RFC_9901_GENERAL_JSON_EXAMPLE,
        &[K1],
        SDJWTSignaturePolicy::Any
    )
    .is_ok());
    // `signatures[0]` is the unverified one; the KB-JWT is still checked.
    assert!(verify(
        RFC_9901_GENERAL_JSON_EXAMPLE,
        &[K2],
        SDJWTSignaturePolicy::Any
    )
    .is_ok());
}

#[test]
fn co_signed_round_trip() {
    let sd_jwt = co_signed_sd_jwt();
    let presentation = present(&sd_jwt, &[K1, K2], SDJWTSignaturePolicy::All);
    let verifier = verify(&presentation, &[K1, K2], SDJWTSignaturePolicy::All).unwrap();
    assert_eq!(verifier.verified_claims["given_name"], "John");
    assert!(verifier.verified_claims.get("family_name").is_none());

    // The Holder carries the co-signature over unchanged.
    let issued: Value = serde_json::from_str(&sd_jwt).unwrap();
    let presented: Value = serde_json::from_str(&presentation).unwrap();
    assert_eq!(presented["signatures"][1], issued["signatures"][1]);
    assert_eq!(
        presented["signatures"][0]["protected"],
        issued["signatures"][0]["protected"]
    );

    // The Holder key's `kid` goes into the KB-JWT protected header.
    let kb_jwt = presented["signatures"][0]["header"]["kb_jwt"]
        .as_str()
        .unwrap();
    let kb_header = decode_b64_json(&json!(kb_jwt.split('.').next().unwrap()));
    assert_eq!(kb_header["kid"], "holder-key");
}

#[test]
fn co_signed_shape() {
    let sd_jwt: Value = serde_json::from_str(&co_signed_sd_jwt()).unwrap();
    let signatures = sd_jwt["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), 2);
    for (signature, kid) in signatures.iter().zip([K1, K2]) {
        assert_eq!(
            decode_b64_json(&signature["protected"]),
            json!({"alg": "ES256", "typ": TYP, "kid": kid}),
            "each signature carries its signer's `alg` and `kid`, and the Issuer's `typ`"
        );
    }
    let first_header = signatures[0]["header"].as_object().unwrap();
    assert_eq!(
        first_header.keys().collect::<Vec<_>>(),
        ["disclosures"],
        "only the Disclosures go in the first unprotected header"
    );
    assert!(
        signatures[1].get("header").is_none(),
        "an empty unprotected header must be absent (RFC 7515 §7.2.1)"
    );
}

#[test]
fn holder_policy() {
    let sd_jwt = co_signed_sd_jwt();
    assert!(SDJWTHolder::new(
        verifier(&[K2]),
        kb_signer(),
        sd_jwt.clone(),
        SDJWTSerializationFormat::GeneralJson,
    )
    .is_err());
    let presentation = present(&sd_jwt, &[K2], SDJWTSignaturePolicy::Any);
    assert!(verify(&presentation, &[K1, K2], SDJWTSignaturePolicy::All).is_ok());
}

#[test]
fn tampered_co_signature() {
    let presentation = present(&co_signed_sd_jwt(), &[K1, K2], SDJWTSignaturePolicy::All);
    let tampered = edit(&presentation, |json| {
        json["signatures"][1]["signature"] = json!("AAAA");
    });
    assert!(verify(&tampered, &[K1, K2], SDJWTSignaturePolicy::All).is_err());
    assert!(verify(&tampered, &[K1, K2], SDJWTSignaturePolicy::Any).is_ok());

    let all_tampered = edit(&presentation, |json| {
        let first = json["signatures"][0]["signature"].clone();
        json["signatures"][0]["signature"] = json["signatures"][1]["signature"].clone();
        json["signatures"][1]["signature"] = first;
    });
    let err = verify(&all_tampered, &[K1, K2], SDJWTSignaturePolicy::Any)
        .err()
        .unwrap()
        .to_string();
    assert!(
        err.contains(r#"signature 0 (kid Some("issuer-key-1"))"#)
            && err.contains(r#"signature 1 (kid Some("issuer-key-2"))"#),
        "got: {err}"
    );
}

#[test]
fn stripped_co_signature_passes_all() {
    // The `signatures` array is not integrity protected: the policy covers
    // the signatures present.
    let presentation = present(&co_signed_sd_jwt(), &[K1, K2], SDJWTSignaturePolicy::All);
    let stripped = edit(&presentation, |json| {
        json["signatures"].as_array_mut().unwrap().truncate(1);
    });
    assert!(verify(&stripped, &[K1, K2], SDJWTSignaturePolicy::All).is_ok());
}

#[test]
fn malformed_input_rejected_under_any() {
    let presentation = present(&co_signed_sd_jwt(), &[K1, K2], SDJWTSignaturePolicy::All);
    type Mutation = fn(&mut Value);
    let cases: [(&str, Mutation); 7] = [
        ("both the protected and the unprotected header", |json| {
            json["signatures"][1]["header"] = json!({"kid": K2})
        }),
        ("both the protected and the unprotected header", |json| {
            json["signatures"][0]["header"]["alg"] = json!("ES256")
        }),
        ("must only be present in the first signature", |json| {
            json["signatures"][1]["header"] = json!({"disclosures": []})
        }),
        ("must only be present in the first signature", |json| {
            json["signatures"][1]["header"] = json!({"kb_jwt": null})
        }),
        ("must not contain `crit`", |json| {
            json["signatures"][1]["header"] = json!({"crit": ["x"]})
        }),
        ("`crit` extensions are not supported", |json| {
            json["signatures"][1]["protected"] =
                json!(b64_json(&json!({"alg": "ES256", "kid": K2, "crit": ["x"]})))
        }),
        ("\"none\" is not acceptable", |json| {
            json["signatures"][1]["protected"] = json!(b64_json(&json!({"alg": "none"})))
        }),
    ];
    for (needle, mutate) in cases {
        let malformed = edit(&presentation, mutate);
        // A Verifier that knows only K1 would skip an unverifiable
        // `signatures[1]` under `Any`; a malformed one rejects the input.
        assert_err_contains(verify(&malformed, &[K1], SDJWTSignaturePolicy::Any), needle);
    }
}

#[test]
fn malformed_co_signature_rejected_without_verification() {
    let sd_jwt = edit(&co_signed_sd_jwt(), |json| {
        json["signatures"][1]["protected"] = json!(b64_json(&json!({"alg": "HS256"})))
    });
    assert_err_contains(
        SDJWTHolder::new_unverified(sd_jwt, SDJWTSerializationFormat::GeneralJson),
        "symmetric",
    );
}

#[test]
fn unprotected_header_absent_or_empty() {
    let sd_jwt = co_signed_sd_jwt();
    // sd-jwt-js writes an empty unprotected header as `{}`.
    let empty = edit(&sd_jwt, |json| json["signatures"][1]["header"] = json!({}));
    let presentation = present(&empty, &[K1, K2], SDJWTSignaturePolicy::All);
    assert!(verify(&presentation, &[K1, K2], SDJWTSignaturePolicy::All).is_ok());

    // No Disclosures: the first signature's `header` may be absent too.
    let no_disclosures = edit(&sd_jwt, |json| {
        json["signatures"][0]
            .as_object_mut()
            .unwrap()
            .remove("header");
    });
    assert!(SDJWTHolder::new(
        verifier(&[K1, K2]),
        kb_signer(),
        no_disclosures,
        SDJWTSerializationFormat::GeneralJson,
    )
    .is_ok());
}

#[test]
fn flattened_json_header_checks() {
    let sd_jwt = issuer(ISSUER_KEY, Some(K1))
        .issue_sd_jwt(
            json!({"iss": "https://issuer.example.com", "given_name": "John"}),
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            None,
            false,
            SDJWTSerializationFormat::FlattenedJson,
        )
        .unwrap();
    let holder = |sd_jwt: String| {
        SDJWTHolder::new(
            verifier(&[K1]),
            kb_signer(),
            sd_jwt,
            SDJWTSerializationFormat::FlattenedJson,
        )
    };

    let no_header = edit(&sd_jwt, |json| {
        json.as_object_mut().unwrap().remove("header");
    });
    assert!(holder(no_header).is_ok());

    let overlap = edit(&sd_jwt, |json| json["header"]["alg"] = json!("ES256"));
    assert_err_contains(
        holder(overlap),
        "both the protected and the unprotected header",
    );
}

#[test]
fn unprotected_kid_kept_in_flattened_presentation() {
    // The kid moves from the protected to the unprotected header; only the
    // Holder's pass-through is exercised, so no signature check.
    let sd_jwt = issuer(ISSUER_KEY, None)
        .issue_sd_jwt(
            json!({"iss": "https://issuer.example.com", "given_name": "John"}),
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            None,
            false,
            SDJWTSerializationFormat::FlattenedJson,
        )
        .unwrap();
    let with_kid = edit(&sd_jwt, |json| json["header"]["kid"] = json!(K1));
    let mut holder =
        SDJWTHolder::new_unverified(with_kid, SDJWTSerializationFormat::FlattenedJson).unwrap();
    let presentation: Value =
        serde_json::from_str(&holder.create_presentation(Map::new(), None, None).unwrap()).unwrap();
    assert_eq!(presentation["header"]["kid"], K1);
}

#[test]
fn add_signature_rejections() {
    let sd_jwt = co_signed_sd_jwt();

    let presentation = present(&sd_jwt, &[K1, K2], SDJWTSignaturePolicy::All);
    assert_err_contains(
        issuer(ISSUER_KEY_2, Some("issuer-key-3")).add_signature(&presentation),
        "SD-JWT+KB cannot be co-signed",
    );
}

#[test]
fn co_signature_with_disallowed_alg() {
    // An `alg` outside the allowlist is a failed signature, not malformed
    // input: under `Any` a co-signer using an unsupported algorithm is skipped.
    let sd_jwt = edit(RFC_9901_GENERAL_JSON_EXAMPLE, |json| {
        json["signatures"][1]["protected"] = json!(b64_json(&json!({"alg": "RS256"})));
    });
    assert_err_contains(
        verify(&sd_jwt, &[K1, K2], SDJWTSignaturePolicy::All),
        "not an allowed verification algorithm",
    );
    assert!(verify(&sd_jwt, &[K1, K2], SDJWTSignaturePolicy::Any).is_ok());
}

#[test]
fn add_signature_keeps_unknown_members() {
    let sd_jwt = edit(&co_signed_sd_jwt(), |json| {
        json["signatures"][0]["header"]["x5u"] = json!("https://issuer.example.com/x5u");
        json["extra"] = json!(1);
    });
    let sd_jwt: Value =
        serde_json::from_str(&issuer(ISSUER_KEY_2, None).add_signature(&sd_jwt).unwrap()).unwrap();
    assert_eq!(
        sd_jwt["signatures"][0]["header"]["x5u"],
        "https://issuer.example.com/x5u"
    );
    assert_eq!(sd_jwt["extra"], 1);
    assert_eq!(sd_jwt["signatures"].as_array().unwrap().len(), 3);
}

/// Wraps a verifier, recording the Issuer signature requests it is offered.
struct Recording(
    Box<dyn SDJWTSignatureVerifier>,
    Arc<Mutex<Vec<SDJWTKeyRequest>>>,
);

impl SDJWTSignatureVerifier for Recording {
    fn allowed_algs(&self, role: SDJWTSignatureRole) -> sd_jwt_rs::error::Result<Vec<String>> {
        self.0.allowed_algs(role)
    }
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        request: &SDJWTKeyRequest,
    ) -> sd_jwt_rs::error::Result<()> {
        if request.role == SDJWTSignatureRole::IssuerJwt {
            self.1.lock().unwrap().push(request.clone());
        }
        self.0.verify(message, signature, request)
    }
}

/// Verifies `sd_jwt` with the `K1` and `K2` keys, returning the
/// Issuer signature requests offered to the verifier.
fn offered_requests(sd_jwt: &str, policy: SDJWTSignaturePolicy) -> Vec<SDJWTKeyRequest> {
    let offered = Arc::new(Mutex::new(Vec::new()));
    SDJWTVerifier::new_with_policy(
        Box::new(Recording(verifier(&[K1, K2]), offered.clone())),
        sd_jwt.to_owned(),
        Some(AUD.to_owned()),
        Some(NONCE.to_owned()),
        SDJWTSerializationFormat::GeneralJson,
        policy,
    )
    .unwrap();
    let offered = offered.lock().unwrap().clone();
    offered
}

#[test]
fn any_stops_at_first_verified_signature() {
    // A verifier recording the keys it accepts sees only the signatures
    // offered before the first success.
    let offered = offered_requests(RFC_9901_GENERAL_JSON_EXAMPLE, SDJWTSignaturePolicy::Any);
    let kids: Vec<_> = offered
        .iter()
        .map(|request| request.kid.as_deref())
        .collect();
    assert_eq!(kids, [Some(K1)]);
}

#[test]
fn signer_header_reaches_verifier() {
    let cert = b"not a real certificate".to_vec();
    let jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let co_signer = SDJWTSignerBuiltin::new(SDJWTKeyWithAlg::new(
        EncodingKey::from_ec_pem(ISSUER_KEY_2.as_bytes()).unwrap(),
        DEFAULT_SIGNING_ALG,
    ))
    .unwrap()
    .with_kid(K2)
    .with_x5c(vec![cert.clone()])
    .with_jwk(jwk.clone());
    let sd_jwt = SDJWTIssuer::new(Box::new(co_signer))
        .add_signature(&co_signed_sd_jwt())
        .unwrap();
    let sd_jwt = present(&sd_jwt, &[K1, K2], SDJWTSignaturePolicy::All);

    let offered = offered_requests(&sd_jwt, SDJWTSignaturePolicy::All);
    let request = &offered[2];
    assert_eq!(request.alg, DEFAULT_SIGNING_ALG);
    assert_eq!(request.kid.as_deref(), Some(K2));
    assert_eq!(request.x5c, Some(vec![cert]));
    let jwk_json: Value = serde_json::from_str(request.jwk.as_deref().unwrap()).unwrap();
    assert_eq!(jwk_json, serde_json::to_value(jwk).unwrap());
    assert_eq!(offered[0].x5c, None);
    assert_eq!(offered[0].jwk, None);
}

#[test]
fn relabelled_kids_fail_with_kid_bound_keys() {
    // The unprotected `kid`s are not integrity protected; a verifier that
    // binds every `kid` to its own key (no default key) catches a swap.
    let swapped = edit(RFC_9901_GENERAL_JSON_EXAMPLE, |json| {
        json["signatures"][0]["header"]["kid"] = json!(K2);
        json["signatures"][1]["header"]["kid"] = json!(K1);
    });
    assert!(verify(&swapped, &[K1, K2], SDJWTSignaturePolicy::Any).is_err());
}

#[test]
fn null_members_in_first_header_read_as_absent() {
    let sd_jwt = edit(&co_signed_sd_jwt(), |json| {
        json["signatures"][0]["header"] = json!({"disclosures": null, "kb_jwt": null});
    });
    let holder = SDJWTHolder::new(
        verifier(&[K1, K2]),
        kb_signer(),
        sd_jwt,
        SDJWTSerializationFormat::GeneralJson,
    );
    assert!(holder.is_ok());
}

#[test]
fn single_signature_errors_unchanged() {
    let encode = |value: Value| URL_SAFE_NO_PAD.encode(value.to_string());
    // The algorithm allowlist is checked before the signature is decoded.
    let compact = format!(
        "{}.{}.!!~",
        encode(json!({"alg": "RS256"})),
        encode(json!({}))
    );
    let result = SDJWTVerifier::new(
        verifier(&[K1]),
        compact,
        None,
        None,
        SDJWTSerializationFormat::Compact,
    );
    assert!(matches!(result, Err(Error::InvalidInput(_))));
    assert_err_contains(result, "not an allowed verification algorithm");

    // A protected header that is not a JSON object lacks `alg`.
    let flattened = json!({
        "protected": encode(json!([])),
        "payload": encode(json!({})),
        "signature": "AAAA",
    })
    .to_string();
    let result = SDJWTHolder::new_unverified(flattened, SDJWTSerializationFormat::FlattenedJson);
    assert!(matches!(result, Err(Error::InvalidInput(_))));
    assert_err_contains(result, "missing the `alg` parameter");
}

/// Verifies an Issuer signature with whichever trusted key matches — telling
/// co-signers apart without `kid`.
struct AnyTrustedKey(Vec<DecodingKey>);

impl SDJWTSignatureVerifier for AnyTrustedKey {
    fn allowed_algs(&self, _role: SDJWTSignatureRole) -> sd_jwt_rs::error::Result<Vec<String>> {
        Ok(vec![DEFAULT_SIGNING_ALG.to_owned()])
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        _request: &SDJWTKeyRequest,
    ) -> sd_jwt_rs::error::Result<()> {
        let signature = URL_SAFE_NO_PAD.encode(signature);
        self.0
            .iter()
            .any(|key| {
                jsonwebtoken::crypto::verify(&signature, message, key, Algorithm::ES256)
                    .unwrap_or(false)
            })
            .then_some(())
            .ok_or_else(|| Error::InvalidInput("no trusted key verifies".to_string()))
    }
}

#[test]
fn co_signed_without_kid() {
    let sd_jwt = issuer(ISSUER_KEY, None)
        .issue_sd_jwt(
            json!({"iss": "https://issuer.example.com", "given_name": "John"}),
            ClaimsForSelectiveDisclosureStrategy::TopLevel,
            None,
            false,
            SDJWTSerializationFormat::GeneralJson,
        )
        .unwrap();
    let sd_jwt = issuer(ISSUER_KEY_2, None).add_signature(&sd_jwt).unwrap();
    let verify_with = |signature_verifier: Box<dyn SDJWTSignatureVerifier>| {
        SDJWTVerifier::new(
            signature_verifier,
            sd_jwt.clone(),
            None,
            None,
            SDJWTSerializationFormat::GeneralJson,
        )
    };

    let keys = [ISSUER_PUBLIC_KEY, ISSUER_PUBLIC_KEY_2]
        .map(|pem| DecodingKey::from_ec_pem(pem.as_bytes()).unwrap());
    assert!(verify_with(Box::new(AnyTrustedKey(keys.into()))).is_ok());

    // The builtin verifier checks every `kid`-less signature against its
    // default key, so the co-signature fails.
    let default_key_only = SDJWTSignatureVerifierBuiltin::new(ALGS, None)
        .with_issuer_verifying_key(SDJWTKeyWithAlg::new(
            DecodingKey::from_ec_pem(ISSUER_PUBLIC_KEY.as_bytes()).unwrap(),
            DEFAULT_SIGNING_ALG,
        ))
        .unwrap();
    assert!(verify_with(Box::new(default_key_only)).is_err());
}
