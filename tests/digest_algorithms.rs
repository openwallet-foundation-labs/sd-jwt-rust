// SPDX-License-Identifier: Apache-2.0

use crate::utils::fixtures::{HOLDER_JWK_KEY, HOLDER_KEY, ISSUER_KEY, ISSUER_PUBLIC_KEY};
use jsonwebtoken::{DecodingKey, EncodingKey};
use rstest::rstest;
use sd_jwt_rs::issuer::ClaimsForSelectiveDisclosureStrategy;
use sd_jwt_rs::{
    SDJWTDigestAlgorithm, SDJWTHolder, SDJWTIssuer, SDJWTKeyWithAlg, SDJWTSerializationFormat,
    SDJWTSignatureVerifierBuiltin, SDJWTSignerBuiltin, SDJWTVerifier,
};
use serde_json::json;

mod utils;

#[rstest]
#[case(SDJWTDigestAlgorithm::Sha384)]
#[case(SDJWTDigestAlgorithm::Sha512)]
fn verify_non_default_digests_through_public_api(#[case] algorithm: SDJWTDigestAlgorithm) {
    let issuer_signer = SDJWTSignerBuiltin::new(SDJWTKeyWithAlg::new(
        EncodingKey::from_ec_pem(ISSUER_KEY.as_bytes()).unwrap(),
        "ES256",
    ))
    .unwrap();
    let holder_jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    let issued = SDJWTIssuer::new(Box::new(issuer_signer))
        .with_digest_algorithm(algorithm)
        .issue_sd_jwt(
            json!({"iss": "https://issuer.example", "email": "alice@example.com", "role": "member"}),
            ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.email", "$.role"]),
            Some(holder_jwk),
            false,
            SDJWTSerializationFormat::Compact,
        )
        .unwrap();

    let issuer_jwt = issued.split('~').next().unwrap();
    let payload = issuer_jwt.split('.').nth(1).unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&sd_jwt_rs::utils::base64url_decode(payload).unwrap()).unwrap();
    assert_eq!(payload["_sd_alg"], algorithm.name());

    let verifier = || {
        Box::new(
            SDJWTSignatureVerifierBuiltin::new(&["ES256"], Some(&["ES256"]))
                .with_issuer_verifying_key(SDJWTKeyWithAlg::new(
                    DecodingKey::from_ec_pem(ISSUER_PUBLIC_KEY.as_bytes()).unwrap(),
                    "ES256",
                ))
                .unwrap(),
        )
    };
    let holder_signer = SDJWTSignerBuiltin::new(SDJWTKeyWithAlg::new(
        EncodingKey::from_ec_pem(HOLDER_KEY.as_bytes()).unwrap(),
        "ES256",
    ))
    .unwrap();
    let presentation = SDJWTHolder::new(
        verifier(),
        Some(Box::new(holder_signer)),
        issued,
        SDJWTSerializationFormat::Compact,
    )
    .unwrap()
    .create_presentation(
        json!({"email": true}).as_object().unwrap().clone(),
        Some("nonce".to_string()),
        Some("audience".to_string()),
    )
    .unwrap();

    let claims = SDJWTVerifier::new(
        verifier(),
        presentation,
        Some("audience".to_string()),
        Some("nonce".to_string()),
        SDJWTSerializationFormat::Compact,
    )
    .unwrap()
    .verified_claims;
    assert_eq!(claims["email"], "alice@example.com");
    assert!(claims.get("role").is_none());
    assert_eq!(claims["iss"], "https://issuer.example");
}
