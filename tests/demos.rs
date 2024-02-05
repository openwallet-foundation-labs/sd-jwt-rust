use crate::utils::fixtures::{
    ADDRESS_CLAIMS, ADDRESS_ONLY_STRUCTURED_JSONPATH, ADDRESS_ONLY_STRUCTURED_ONE_OPEN_JSONPATH,
    ARRAYED_CLAIMS, ARRAYED_CLAIMS_JSONPATH, COMPLEX_EIDAS_CLAIMS, COMPLEX_EIDAS_JSONPATH,
    HOLDER_JWK_KEY, HOLDER_KEY, ISSUER_KEY, ISSUER_PUBLIC_KEY, NESTED_ARRAY_CLAIMS,
    NESTED_ARRAY_JSONPATH, W3C_VC_CLAIMS, W3C_VC_JSONPATH,
};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rstest::{fixture, rstest};
use sd_jwt_rs::issuer::ClaimsForSelectiveDisclosureStrategy;
use sd_jwt_rs::{SDJWTHolder, SDJWTIssuer, SDJWTJson, SDJWTVerifier, SDJWTSerializationFormat};
use sd_jwt_rs::{COMBINED_SERIALIZATION_FORMAT_SEPARATOR, DEFAULT_SIGNING_ALG};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

mod utils;

#[fixture]
fn issuer_key() -> EncodingKey {
    let private_issuer_bytes = ISSUER_KEY.as_bytes();
    EncodingKey::from_ec_pem(private_issuer_bytes).unwrap()
}

fn holder_jwk() -> Option<Jwk> {
    let jwk: Jwk = serde_json::from_str(HOLDER_JWK_KEY).unwrap();
    Some(jwk)
}

#[allow(unused)]
fn holder_key() -> Option<EncodingKey> {
    let private_issuer_bytes = HOLDER_KEY.as_bytes();
    let key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
    Some(key)
}

fn _address_claims() -> serde_json::Value {
    serde_json::from_str(ADDRESS_CLAIMS).unwrap()
}

#[fixture]
fn address_flat<'a>() -> (
    serde_json::Value,
    ClaimsForSelectiveDisclosureStrategy<'a>,
    Map<String, Value>,
    usize,
) {
    let value = _address_claims();
    let number_of_revealed_sds = 2; // 2 == 1('sub') + 1('address')
    (
        value.clone(),
        ClaimsForSelectiveDisclosureStrategy::TopLevel,
        value.as_object().unwrap().clone(),
        number_of_revealed_sds,
    )
}

#[fixture]
fn address_full_recursive<'a>() -> (
    serde_json::Value,
    ClaimsForSelectiveDisclosureStrategy<'a>,
    Map<String, Value>,
    usize,
) {
    let value = _address_claims();
    let claims_to_disclose = value.as_object().unwrap().clone();

    // revealed sds are:
    //    sub
    //    address
    //    address.street_address
    //    address.locality
    //    address.region
    //    address.country
    let number_of_revealed_sds = 6;
    (
        value,
        ClaimsForSelectiveDisclosureStrategy::AllLevels,
        claims_to_disclose,
        number_of_revealed_sds,
    )
}

#[fixture]
fn address_only_structured<'a>() -> (
    serde_json::Value,
    ClaimsForSelectiveDisclosureStrategy<'a>,
    Map<String, Value>,
    usize,
) {
    let value = _address_claims();
    let mut claims_to_disclose = value.clone();
    claims_to_disclose["address"] = json!({
        "street_address": "Schulstr. 12",
        "region": "Sachsen-Anhalt",
        "country": "DE"
    });

    let claims_to_disclose = claims_to_disclose.as_object().unwrap().clone();
    let number_of_revealed_sds = 3;

    (
        value.clone(),
        ClaimsForSelectiveDisclosureStrategy::Custom(ADDRESS_ONLY_STRUCTURED_JSONPATH.to_vec()),
        claims_to_disclose,
        number_of_revealed_sds,
    )
}

#[fixture]
fn address_only_structured_one_open<'a>() -> (
    serde_json::Value,
    ClaimsForSelectiveDisclosureStrategy<'a>,
    Map<String, Value>,
    usize,
) {
    let value = _address_claims();
    let mut claims_to_disclose = value.clone();
    claims_to_disclose["address"] = json!({
        "region": "Sachsen-Anhalt",
        "country": "DE"
    });

    let claims_to_disclose = claims_to_disclose.as_object().unwrap().clone();
    let number_of_revealed_sds = 1;

    (
        value,
        ClaimsForSelectiveDisclosureStrategy::Custom(ADDRESS_ONLY_STRUCTURED_ONE_OPEN_JSONPATH.to_vec()),
        claims_to_disclose,
        number_of_revealed_sds,
    )
}

#[fixture]
fn arrayed_claims<'a>() -> (
    serde_json::Value,
    ClaimsForSelectiveDisclosureStrategy<'a>,
    Map<String, Value>,
    usize,
) {
    let value: serde_json::Value = serde_json::from_str(ARRAYED_CLAIMS).unwrap();
    let mut claims_to_disclose = value.clone();
    claims_to_disclose["addresses"] = json!([true, true]);
    claims_to_disclose["nationalities"] = json!([false, true]);

    let claims_to_disclose = claims_to_disclose.as_object().unwrap().clone();
    let number_of_revealed_sds = 1;

    (
        value,
        ClaimsForSelectiveDisclosureStrategy::Custom(ARRAYED_CLAIMS_JSONPATH.to_vec()),
        claims_to_disclose,
        number_of_revealed_sds,
    )
}

#[fixture]
fn nested_array<'a>() -> (
    serde_json::Value,
    ClaimsForSelectiveDisclosureStrategy<'a>,
    Map<String, Value>,
    usize,
) {
    let value: serde_json::Value = serde_json::from_str(NESTED_ARRAY_CLAIMS).unwrap();
    let mut claims_to_disclose = value.clone();
    claims_to_disclose["nationalities"] = json!([[false, true]]);

    let claims_to_disclose = claims_to_disclose.as_object().unwrap().clone();

    // since the claim are nested the holder must reveal
    // all parents of the desired claim.
    // 2 is 1 (desired claim) + 1 (parent SD item of desired claim)
    let number_of_revealed_sds = 2;

    (
        value.clone(),
        ClaimsForSelectiveDisclosureStrategy::Custom(NESTED_ARRAY_JSONPATH.to_vec()),
        claims_to_disclose,
        number_of_revealed_sds,
    )
}

#[fixture]
fn complex_eidas<'a>() -> (
    serde_json::Value,
    ClaimsForSelectiveDisclosureStrategy<'a>,
    Map<String, Value>,
    usize,
) {
    let value: serde_json::Value = serde_json::from_str(COMPLEX_EIDAS_CLAIMS).unwrap();
    let mut claims_to_disclose = value.clone();
    claims_to_disclose["verified_claims"] = json!({
        "verification": {
          "trust_framework": "eidas",
          "assurance_level": "high",
          "evidence": [
            {
              "document": {
                "type": "idcard",
                "issuer": {
                  "name": "c_d612",
                  "country": "IT"
                }
              }
            }
          ]
        },
        "claims": {
          "place_of_birth": {
            "country": "IT",
            "locality": "Firenze"
          },
          "nationalities": [
            "IT"
          ]
        }
    });

    let claims_to_disclose = claims_to_disclose.as_object().unwrap().clone();
    let number_of_revealed_sds = 5;

    (
        value.clone(),
        ClaimsForSelectiveDisclosureStrategy::Custom(COMPLEX_EIDAS_JSONPATH.to_vec()),
        claims_to_disclose,
        number_of_revealed_sds,
    )
}

#[fixture]
fn w3c_vc<'a>() -> (
    serde_json::Value,
    ClaimsForSelectiveDisclosureStrategy<'a>,
    Map<String, Value>,
    usize,
) {
    let value: serde_json::Value = serde_json::from_str(W3C_VC_CLAIMS).unwrap();
    let mut claims_to_disclose = value.clone();
    claims_to_disclose["credentialSubject"] = json!({
        "email": "johndoe@example.com",
        "address": {
          "street_address": "123 Main St",
          "locality": "Anytown",
          "region": "Anystate",
          "country": "US"
        },
        "birthdate": "1940-01-01",
        "is_over_18": true,
        "is_over_21": true,
        "is_over_65": true
    });

    let claims_to_disclose = claims_to_disclose.as_object().unwrap().clone();
    let number_of_revealed_sds = 6;

    (
        value.clone(),
        ClaimsForSelectiveDisclosureStrategy::Custom(W3C_VC_JSONPATH.to_vec()),
        claims_to_disclose,
        number_of_revealed_sds,
    )
}

#[allow(unused)]
fn presentation_metadata() -> (
    Option<String>,
    Option<String>,
    Option<EncodingKey>,
    Option<Jwk>,
) {
    (
        Some("1234567890".to_owned()),
        Some("https://verifier.example.org".to_owned()),
        holder_key(),
        holder_jwk(),
    )
}

#[rstest]
#[case(address_flat())]
#[case(address_full_recursive())]
#[case(address_only_structured())]
#[case(address_only_structured_one_open())]
#[case(arrayed_claims())]
#[case(nested_array())]
#[case(complex_eidas())]
#[case(w3c_vc())]
fn demo_positive_cases(
    issuer_key: EncodingKey,
    #[case] data: (
        serde_json::Value,
        ClaimsForSelectiveDisclosureStrategy,
        Map<String, Value>,
        usize,
    ),
    #[values((None, None, None, None), presentation_metadata())] presentation_metadata: (
        Option<String>,
        Option<String>,
        Option<EncodingKey>,
        Option<Jwk>,
    ),
    #[values(SDJWTSerializationFormat::Compact, SDJWTSerializationFormat::JSON)] format: SDJWTSerializationFormat,
    #[values(None, Some(DEFAULT_SIGNING_ALG.to_owned()))] sign_algo: Option<String>,
    #[values(true, false)] add_decoy: bool,
) {
    let (user_claims, strategy, holder_disclosed_claims, number_of_revealed_sds) = data;
    let (nonce, aud, holder_key, holder_jwk) = presentation_metadata;
    // Issuer issues SD-JWT
    let sd_jwt = SDJWTIssuer::new(issuer_key, sign_algo.clone()).issue_sd_jwt(
        user_claims.clone(),
        strategy,
        holder_jwk.clone(),
        add_decoy,
        format.clone(),
    )
        .unwrap();
    let issued = sd_jwt.clone();
    // Holder creates presentation
    let mut holder = SDJWTHolder::new(sd_jwt.clone(), format.clone()).unwrap();
    let presentation = holder
        .create_presentation(
            holder_disclosed_claims,
            nonce.clone(),
            aud.clone(),
            holder_key,
            sign_algo,
        )
        .unwrap();

    if format == SDJWTSerializationFormat::Compact {
        let mut issued_parts: HashSet<&str> = issued
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        issued_parts.remove("");

        let mut revealed_parts: HashSet<&str> = presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        revealed_parts.remove("");

        let intersected_parts: HashSet<_> = issued_parts.intersection(&revealed_parts).collect();
        // Compare that number of disclosed parts are equal
        let mut revealed_parts_number = revealed_parts.len();
        if holder_jwk.is_some() {
            // Remove KB
            revealed_parts_number -= 1;
        }
        assert_eq!(intersected_parts.len(), revealed_parts_number);
        // here `+1` means adding issued jwt part also
        assert_eq!(number_of_revealed_sds + 1, revealed_parts_number);
    } else {
        let mut issued: SDJWTJson = serde_json::from_str(&issued).unwrap();
        let mut revealed: SDJWTJson = serde_json::from_str(&presentation).unwrap();
        let disclosures: Vec<String> = revealed
            .disclosures
            .clone()
            .into_iter()
            .filter(|d| issued.disclosures.contains(d))
            .collect();
        assert_eq!(number_of_revealed_sds, disclosures.len());

        if holder_jwk.is_some() {
            assert!(revealed.kb_jwt.is_some());
        }

        issued.disclosures = disclosures;
        revealed.kb_jwt = None;
        assert_eq!(revealed, issued);
    }

    // Verify presentation
    let _verified = SDJWTVerifier::new(
        presentation.clone(),
        Box::new(|_, _| {
            let public_issuer_bytes = ISSUER_PUBLIC_KEY.as_bytes();
            DecodingKey::from_ec_pem(public_issuer_bytes).unwrap()
        }),
        aud,
        nonce,
        format,
    )
        .unwrap();
}
