// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;
use sd_jwt_rs::SDJWTSerializationFormat;
use sd_jwt_rs::utils::{base64_hash, base64url_decode};
use sd_jwt_rs::utils::SALTS;
use crate::error::{Error, ErrorKind, Result};

// Mirrors of the lib's JWS JSON serialization structs (SDJWTFlattenedJson / SDJWTGeneralJson)
// The lib's `payload` field is private, so they cannot be reused here
#[derive(Deserialize)]
struct FlattenedJsonSdJwt {
    payload: String,
    header: UnprotectedHeader,
}

#[derive(Deserialize)]
struct GeneralJsonSdJwt {
    payload: String,
    signatures: Vec<GeneralJsonSignature>,
}

#[derive(Deserialize)]
struct GeneralJsonSignature {
    header: UnprotectedHeader,
}

#[derive(Deserialize)]
struct UnprotectedHeader {
    disclosures: Vec<String>,
}


pub fn parse_sdjwt_paylod(
    sd_jwt: &str,
    serialization_format: &SDJWTSerializationFormat,
    remove_decoy: bool
) -> Result<Value> {

    match serialization_format {
        SDJWTSerializationFormat::FlattenedJson => {
            parse_payload_flattened_json(sd_jwt, remove_decoy)
        },
        SDJWTSerializationFormat::GeneralJson => {
            parse_payload_general_json(sd_jwt, remove_decoy)
        },
        SDJWTSerializationFormat::Compact => {
            parse_payload_compact(sd_jwt, remove_decoy)
        }
    }
}

fn parse_payload_flattened_json(sd_jwt: &str, remove_decoy: bool) -> Result<Value> {
    let parsed: FlattenedJsonSdJwt = serde_json::from_str(sd_jwt)?;

    decode_payload(&parsed.payload, &parsed.header.disclosures, remove_decoy)
}

fn parse_payload_general_json(sd_jwt: &str, remove_decoy: bool) -> Result<Value> {
    let parsed: GeneralJsonSdJwt = serde_json::from_str(sd_jwt)?;

    // RFC 9901 §8.3: the Disclosures live in the first signature's unprotected header.
    let signature = parsed.signatures.first().ok_or_else(|| Error::from_msg(
        ErrorKind::Input,
        "General JSON SD-JWT must contain at least one signature",
    ))?;

    decode_payload(&parsed.payload, &signature.header.disclosures, remove_decoy)
}

fn decode_payload(payload: &str, disclosures: &[String], remove_decoy: bool) -> Result<Value> {
    let mut hashes: HashSet<String> = HashSet::new();

    for disclosure in disclosures {
        let hash = base64_hash(disclosure.as_bytes());
        hashes.insert(hash);
    }

    let payload = base64url_decode(payload).unwrap();

    let payload: serde_json::Value = serde_json::from_slice(&payload)?;

    if remove_decoy {
        return Ok(remove_decoy_items(&payload, &hashes));
    }

    Ok(payload)
}

fn parse_payload_compact(sd_jwt: &str, remove_decoy: bool) -> Result<Value> {
    let mut disclosures: Vec<String> = sd_jwt
            .split('~')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

    let payload = disclosures.remove(0);

    let payload: Vec<_> = payload.split('.').collect();
    let payload = String::from(payload[1]);

    let mut hashes: HashSet<String> = HashSet::new();

    for disclosure in disclosures {
        let hash = base64_hash(disclosure.as_bytes());
        hashes.insert(hash.clone());
    }

    let payload = base64url_decode(&payload).unwrap();

    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();

    if remove_decoy {
        return Ok(remove_decoy_items(&payload, &hashes));
    }

    Ok(payload)
}

fn remove_decoy_items(payload: &Value, hashes: &HashSet<String>) -> Value {
    let mut map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    for (key, val) in payload.as_object().unwrap() {
        if key == "_sd" {
            let v1: Vec<_> = val.as_array().unwrap().iter()
                .filter(|item| hashes.contains(item.as_str().unwrap())).cloned()
                .collect();

            let filtered_array = serde_json::Value::Array(v1);
            map.insert(key.clone(), filtered_array);
        } else if val.is_object() {
            let filtered_object = remove_decoy_items(val, hashes);
            map.insert(key.clone(), filtered_object);
        } else {
            map.insert(key.clone(), val.clone());
        }
    }

    Value::Object(map)
}

pub fn load_salts(path: &PathBuf) -> Result<()> {
    let json_data = std::fs::read_to_string(path)
        .map_err(|e| Error::from_msg(ErrorKind::IOError, e.to_string()))?;
    let salts: Vec<String> = serde_json::from_str(&json_data)?;

    {
        let mut s = SALTS.lock().unwrap();

        for salt in salts.iter() {
            s.push_back(salt.clone());
        }
    }

    Ok(())
}
