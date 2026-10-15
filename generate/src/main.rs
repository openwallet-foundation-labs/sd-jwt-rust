// Copyright (c) 2026 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

mod error;
mod types;
mod utils;

use jsonwebtoken::jwk::Jwk;

use crate::error::{Error, ErrorKind, Result};
use crate::utils::funcs::{load_salts, parse_sdjwt_paylod};
use clap::Parser;
use jsonwebtoken::{DecodingKey, EncodingKey};
use sd_jwt_rs::holder::SDJWTHolder;
use sd_jwt_rs::issuer::{ClaimsForSelectiveDisclosureStrategy, SDJWTIssuer};
use sd_jwt_rs::utils::base64url_decode;
use sd_jwt_rs::verifier::SDJWTVerifier;
use sd_jwt_rs::{SDJWTKeyWithAlg, SDJWTSignatureVerifierBuiltin, SDJWTSignerBuiltin};
use sd_jwt_rs::{SDJWTSerializationFormat, SDJWTSignaturePolicy};
use serde_json::{Number, Value};
use std::path::{Path, PathBuf};
use types::cli::{Cli, GenerateType, Reference};
use types::settings::{Key, Settings};
use types::specification::Specification;

const SETTINGS_FILE_NAME: &str = "settings.yml";
const SPECIFICATION_FILE_NAME: &str = "specification.yml";
const SALTS_FILE_NAME: &str = "claims_vs_salts.json";
const SD_JWT_FILE_NAME_TEMPLATE: &str = "sd_jwt_issuance";
const SD_JWT_PRESENTATION_FILE_NAME: &str = "sd_jwt_presentation.json";
const VERIFIED_CLAIMS_FILE_NAME: &str = "verified_contents.json";

const SIGNING_ALG: &str = "ES256";

fn main() {
    let args = Cli::parse();

    println!("type_: {:?}, paths: {:?}", args.type_.clone(), args.paths);

    sd_jwt_rs::utils::set_mock_disclosure_python_spacing(matches!(args.reference, Reference::Python));

    let basedir = std::env::current_dir().expect("Unable to get current directory");
    let spec_directories = get_specification_paths(&args, basedir).unwrap();

    for mut directory in spec_directories {
        println!("Generating data for '{:?}'", directory);
        let specs = Specification::from(&directory);
        let settings = get_settings(
            &directory
                .parent()
                .unwrap()
                .join("..")
                .join(SETTINGS_FILE_NAME),
            specs.settings_override.as_ref(),
        );

        // Remove specification.yaml from path
        directory.pop();

        generate_and_check(&directory, &settings, specs, args.type_.clone()).unwrap();
    }
}

fn generate_and_check(
    directory: &PathBuf,
    settings: &Settings,
    specs: Specification,
    _: GenerateType,
) -> Result<()> {
    let decoy = specs.add_decoy_claims.unwrap_or(false);
    let serialization_format;
    let stored_sd_jwt_file_path;

    match &specs.serialization_format {
        Some(format) if format == "json" => {
            serialization_format = if settings.key_settings.issuer_keys.len() > 1 {
                SDJWTSerializationFormat::GeneralJson
            } else {
                SDJWTSerializationFormat::FlattenedJson
            };
            stored_sd_jwt_file_path = directory.join(format!("{SD_JWT_FILE_NAME_TEMPLATE}.json"));
        }
        Some(format) if format == "compact" => {
            serialization_format = SDJWTSerializationFormat::Compact;
            stored_sd_jwt_file_path = directory.join(format!("{SD_JWT_FILE_NAME_TEMPLATE}.txt"));
        }
        None => {
            println!("using default serialization format: Compact");
            serialization_format = SDJWTSerializationFormat::Compact;
            stored_sd_jwt_file_path = directory.join(format!("{SD_JWT_FILE_NAME_TEMPLATE}.txt"));
        }
        Some(format) => {
            panic!("unsupported format: {format}");
        }
    };

    let key_binding = specs.key_binding.unwrap_or(false);
    let issuer_keys = &settings.key_settings.issuer_keys;
    let sd_jwt = issue_sd_jwt(&specs, settings, serialization_format.clone(), decoy)?;
    let presentation = create_presentation(
        settings,
        &sd_jwt,
        serialization_format.clone(),
        &specs.holder_disclosed_claims,
        key_binding,
    )?;

    // Verify presentation
    let verified_claims = verify_presentation(
        settings,
        &presentation,
        serialization_format.clone(),
        key_binding,
        issuer_keys,
        SDJWTSignaturePolicy::All,
    )
    .unwrap()
    .verified_claims;

    let loaded_sd_jwt = load_sd_jwt(&stored_sd_jwt_file_path)?;

    let loaded_sdjwt_paylod = parse_sdjwt_paylod(
        &loaded_sd_jwt.replace('\n', ""),
        &serialization_format,
        decoy,
    )?;
    let issued_sdjwt_paylod = parse_sdjwt_paylod(&sd_jwt, &serialization_format, decoy)?;

    compare_jwt_payloads(&loaded_sdjwt_paylod, &issued_sdjwt_paylod)?;

    let loaded_verified_claims_content = load_sd_jwt(&directory.join(VERIFIED_CLAIMS_FILE_NAME))?;
    let loaded_verified_claims = parse_verified_claims(&loaded_verified_claims_content)?;

    compare_verified_claims(&loaded_verified_claims, &verified_claims)?;

    if serialization_format != SDJWTSerializationFormat::Compact {
        check_reference_json(
            directory,
            settings,
            &specs,
            serialization_format,
            &loaded_sd_jwt,
            &sd_jwt,
            &loaded_verified_claims,
        )?;
    }

    Ok(())
}

/// Feeds the reference implementation's JWS JSON artifacts through the Rust
/// Holder and Verifier, and compares the signature layout of the Rust and
/// the reference issuance.
fn check_reference_json(
    directory: &Path,
    settings: &Settings,
    specs: &Specification,
    serialization_format: SDJWTSerializationFormat,
    loaded_sd_jwt: &str,
    issued_sd_jwt: &str,
    loaded_verified_claims: &Value,
) -> Result<()> {
    let key_binding = specs.key_binding.unwrap_or(false);
    let issuer_keys = &settings.key_settings.issuer_keys;

    // The Holder accepts the reference issuance and carries every signature over into its presentation.
    let presentation = create_presentation(
        settings,
        loaded_sd_jwt,
        serialization_format.clone(),
        &specs.holder_disclosed_claims,
        key_binding,
    )?;
    if serialization_format == SDJWTSerializationFormat::GeneralJson {
        compare_values(
            "co-signatures carried over by the Holder",
            &co_signatures(loaded_sd_jwt)?,
            &co_signatures(&presentation)?,
        )?;
        compare_values(
            "signature layout",
            &signature_layout(loaded_sd_jwt)?,
            &signature_layout(issued_sd_jwt)?,
        )?;
    }

    let reference_presentation = load_sd_jwt(&directory.join(SD_JWT_PRESENTATION_FILE_NAME))?;
    let verified = verify_presentation(
        settings,
        &reference_presentation,
        serialization_format.clone(),
        key_binding,
        issuer_keys,
        SDJWTSignaturePolicy::All,
    )
    .unwrap();
    compare_verified_claims(loaded_verified_claims, &verified.verified_claims)?;

    // A Verifier that knows only the first Issuer key: every signature present
    // must verify by default, at least one under `Any`.
    if serialization_format == SDJWTSerializationFormat::GeneralJson && issuer_keys.len() > 1 {
        let first_key_only = &issuer_keys[..1];
        let verify_with = |policy| {
            verify_presentation(
                settings,
                &reference_presentation,
                serialization_format.clone(),
                key_binding,
                first_key_only,
                policy,
            )
        };
        if verify_with(SDJWTSignaturePolicy::All).is_ok() {
            return Err(Error::from_msg(
                ErrorKind::DataNotEqual,
                "presentation accepted without every Issuer signature verified",
            ));
        }
        verify_with(SDJWTSignaturePolicy::Any).unwrap();
    }

    println!("Reference JSON artifacts verified");
    Ok(())
}

/// Per signature: its `kid` (protected or unprotected header) and the other
/// unprotected header members.
fn signature_layout(sd_jwt: &str) -> Result<Value> {
    let sd_jwt: Value = serde_json::from_str(sd_jwt)?;
    let signatures = sd_jwt["signatures"].as_array().cloned().unwrap_or_default();
    let mut layout = Vec::new();
    for signature in signatures {
        let protected: Value = serde_json::from_slice(
            &base64url_decode(signature["protected"].as_str().unwrap_or_default())
                .map_err(|e| Error::from_msg(ErrorKind::Input, e.to_string()))?,
        )?;
        let header = signature["header"].as_object().cloned().unwrap_or_default();
        let kid = protected.get("kid").or(header.get("kid")).cloned();
        let members: Vec<&String> = header.keys().filter(|name| *name != "kid").collect();
        layout.push(serde_json::json!({"kid": kid, "unprotected": members}));
    }
    Ok(Value::Array(layout))
}

/// `protected`, `signature` and unprotected `kid` of every signature after the
/// first — what a Holder must carry over (other unprotected members, and an
/// empty `header`, are not preserved).
fn co_signatures(sd_jwt: &str) -> Result<Value> {
    let sd_jwt: Value = serde_json::from_str(sd_jwt)?;
    let signatures = sd_jwt["signatures"].as_array().cloned().unwrap_or_default();
    Ok(signatures
        .iter()
        .skip(1)
        .map(|signature| {
            serde_json::json!({
                "protected": signature["protected"],
                "signature": signature["signature"],
                "kid": signature["header"]["kid"],
            })
        })
        .collect())
}

fn compare_values(what: &str, loaded: &Value, actual: &Value) -> Result<()> {
    if loaded == actual {
        println!("{what}: equal");
        Ok(())
    } else {
        eprintln!("{what}: NOT equal\n reference: {loaded}\n rust:      {actual}");
        Err(Error::from_msg(
            ErrorKind::DataNotEqual,
            format!("{what} differ"),
        ))
    }
}

fn issue_sd_jwt(
    specs: &Specification,
    settings: &Settings,
    serialization_format: SDJWTSerializationFormat,
    decoy: bool,
) -> Result<String> {
    let mut user_claims = specs.user_claims.claims_to_json_value()?;
    let claims_obj = user_claims.as_object_mut().expect("must be an object");

    if !claims_obj.contains_key("iss") {
        claims_obj.insert(
            String::from("iss"),
            Value::String(settings.identifiers.issuer.clone()),
        );
    }

    if !claims_obj.contains_key("iat") {
        let iat = settings
            .iat
            .expect("'iat' value must be provided by settings.yml");
        claims_obj.insert(String::from("iat"), Value::Number(Number::from(iat)));
    }

    if !claims_obj.contains_key("exp") {
        let exp = settings
            .exp
            .expect("'expt' value must be provided by settings.yml");
        claims_obj.insert(String::from("exp"), Value::Number(Number::from(exp)));
    }

    let sd_claims_jsonpaths = specs.user_claims.sd_claims_to_jsonpath()?;

    let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(
        sd_claims_jsonpaths.iter().map(String::as_str).collect(),
    );

    let jwk: Option<Jwk> = if specs.key_binding.unwrap_or(false) {
        let jwk: Jwk = serde_yaml::from_value(settings.key_settings.holder_key.clone()).unwrap();
        Some(jwk)
    } else {
        None
    };

    let issuer_keys = &settings.key_settings.issuer_keys;
    let mut sd_jwt = issuer(&issuer_keys[0])
        .issue_sd_jwt(
            user_claims,
            strategy,
            jwk,
            decoy,
            serialization_format.clone(),
        )
        .unwrap();
    if serialization_format == SDJWTSerializationFormat::GeneralJson {
        for key in &issuer_keys[1..] {
            sd_jwt = issuer(key).add_signature(&sd_jwt).unwrap();
        }
    }

    Ok(sd_jwt)
}

fn issuer(key: &Key) -> SDJWTIssuer {
    SDJWTIssuer::new(Box::new(signer(key)))
}

/// Signs with `key`, writing its `kid` (if any) to the protected header.
fn signer(key: &Key) -> SDJWTSignerBuiltin {
    let signer =
        SDJWTSignerBuiltin::new(SDJWTKeyWithAlg::new(p256_signing_key(key), SIGNING_ALG)).unwrap();
    match &key.kid {
        Some(kid) => signer.with_kid(kid),
        None => signer,
    }
}

fn create_presentation(
    settings: &Settings,
    sd_jwt: &str,
    serialization_format: SDJWTSerializationFormat,
    disclosed_claims: &serde_json::Map<String, serde_json::Value>,
    key_binding: bool,
) -> Result<String> {
    let holder_key: Key = serde_yaml::from_value(settings.key_settings.holder_key.clone())
        .expect("Holder key must be a P-256 JWK");
    let mut holder = SDJWTHolder::new(
        Box::new(signature_verifier(&settings.key_settings.issuer_keys)),
        Some(Box::new(signer(&holder_key))),
        sd_jwt.to_string(),
        serialization_format,
    )
    .unwrap();

    let (nonce, aud) = key_binding_params(settings, key_binding);
    let presentation = holder
        .create_presentation(disclosed_claims.clone(), nonce, aud)
        .unwrap();

    Ok(presentation)
}

fn verify_presentation(
    settings: &Settings,
    presentation: &str,
    serialization_format: SDJWTSerializationFormat,
    key_binding: bool,
    issuer_keys: &[Key],
    signature_policy: SDJWTSignaturePolicy,
) -> sd_jwt_rs::error::Result<SDJWTVerifier> {
    let (nonce, aud) = key_binding_params(settings, key_binding);
    SDJWTVerifier::new_with_policy(
        Box::new(signature_verifier(issuer_keys)),
        presentation.to_string(),
        aud,
        nonce,
        serialization_format,
        signature_policy,
    )
}

/// `(nonce, aud)` of the Key Binding JWT, when the spec asks for one.
fn key_binding_params(settings: &Settings, key_binding: bool) -> (Option<String>, Option<String>) {
    if key_binding {
        (
            Some(settings.key_binding_nonce.clone()),
            Some(settings.identifiers.verifier.clone()),
        )
    } else {
        (None, None)
    }
}

fn parse_verified_claims(content: &str) -> Result<Value> {
    let json_value: Value = serde_json::from_str(content)?;

    // TODO: check if the json_value is json object
    Ok(json_value)
}

fn load_sd_jwt(path: &PathBuf) -> Result<String> {
    let content = std::fs::read_to_string(path)?;
    Ok(content)
}

fn compare_jwt_payloads(loaded_payload: &Value, issued_payload: &Value) -> Result<()> {
    if issued_payload.eq(loaded_payload) {
        println!("\nJWT payloads are equal");
    } else {
        eprintln!("\nJWT payloads are NOT equal");

        println!("Issued SD-JWT \n {:#?}", issued_payload);
        println!("Loaded SD-JWT \n {:#?}", loaded_payload);

        return Err(Error::from_msg(
            ErrorKind::DataNotEqual,
            "JWT payloads are different",
        ));
    }

    Ok(())
}

fn compare_verified_claims(loaded_claims: &Value, verified_claims: &Value) -> Result<()> {
    if loaded_claims.eq(verified_claims) {
        println!("Verified claims are equal",);
    } else {
        eprintln!("Verified claims are NOT equal");

        println!("Issued verified claims \n {:#?}", verified_claims);
        println!("Loaded verified claims \n {:#?}", loaded_claims);

        return Err(Error::from_msg(
            ErrorKind::DataNotEqual,
            "verified claims are different",
        ));
    }

    Ok(())
}

/// Verifies the `issuer_keys` — pinned by `kid` when they have one — and
/// Key Binding JWTs under the signing algorithm.
fn signature_verifier(issuer_keys: &[Key]) -> SDJWTSignatureVerifierBuiltin {
    let mut verifier = SDJWTSignatureVerifierBuiltin::new(&[SIGNING_ALG], Some(&[SIGNING_ALG]));
    for key in issuer_keys {
        let verifying_key = SDJWTKeyWithAlg::new(
            DecodingKey::from_ec_components(&key.x, &key.y).expect("Unable to create DecodingKey"),
            SIGNING_ALG,
        );
        verifier = match &key.kid {
            Some(kid) => verifier.with_issuer_verifying_key_for_kid(kid, verifying_key),
            None => verifier.with_issuer_verifying_key(verifying_key),
        }
        .unwrap();
    }
    verifier
}

/// P-256 signing key from its JWK. `jsonwebtoken` has no
/// `EncodingKey::from_jwk`, so the PKCS#8 DER is assembled from `d`, `x`, `y`.
fn p256_signing_key(key: &Key) -> EncodingKey {
    // PrivateKeyInfo { version 0, ecPublicKey/prime256v1, ECPrivateKey {
    // version 1, privateKey d, [1] publicKey 04||x||y } }, as in the PEMs the
    // reference generators write.
    const PREFIX: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    const PUBLIC_KEY_TAG: &[u8] = &[0xa1, 0x44, 0x03, 0x42, 0x00, 0x04];
    let decode = |v: &str| base64url_decode(v).expect("Invalid base64url in JWK");
    let der = [
        PREFIX,
        &decode(&key.d),
        PUBLIC_KEY_TAG,
        &decode(&key.x),
        &decode(&key.y),
    ]
    .concat();
    EncodingKey::from_ec_der(&der)
}

fn get_settings(path: &PathBuf, override_value: Option<&serde_yaml::Value>) -> Settings {
    println!("settings.yaml - {:?}", path);

    Settings::from_path_with_override(path, override_value)
}

fn get_specification_paths(args: &Cli, basedir: PathBuf) -> Result<Vec<PathBuf>> {
    let glob: Vec<PathBuf>;
    if args.paths.is_empty() {
        glob = basedir
            .read_dir()?
            .filter_map(|entry| {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_dir() && path.join(SPECIFICATION_FILE_NAME).exists() {
                        // load_salts(&path).map_err(|err| Error::from_msg(ErrorKind::IOError, err.to_string()))?;
                        load_salts(&path.join(SALTS_FILE_NAME)).unwrap();
                        return Some(path.join(SPECIFICATION_FILE_NAME));
                    }
                }
                None
            })
            .collect();
    } else {
        glob = args
            .paths
            .iter()
            .map(|d| {
                // load_salts(&path).map_err(|err| Error::from_msg(ErrorKind::IOError, err.to_string()))?;
                load_salts(&d.join(SALTS_FILE_NAME)).unwrap();
                basedir.join(d).join(SPECIFICATION_FILE_NAME)
            })
            .collect();
    }

    println!("specification.yaml files - {:?}", glob);

    Ok(glob)
}
