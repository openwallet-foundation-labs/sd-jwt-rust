use crate::error;
use error::{Error, Result};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::str::FromStr;
use std::time;

use crate::utils::base64_hash;
use crate::SDJWTCommon;
use crate::{
    COMBINED_SERIALIZATION_FORMAT_SEPARATOR, DEFAULT_SIGNING_ALG, KB_DIGEST_KEY, SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
};

pub struct SDJWTHolder {
    sd_jwt_engine: SDJWTCommon,
    hs_disclosures: Vec<String>,
    key_binding_jwt_header: HashMap<String, Value>,
    key_binding_jwt_payload: HashMap<String, Value>,
    //FIXME restore key_binding_jwt: JWS,
    serialized_key_binding_jwt: String,
    sd_jwt_payload: Map<String, Value>,
    serialized_sd_jwt: String,
    sd_jwt: String,
    pub sd_jwt_presentation: String,
}

impl SDJWTHolder {
    pub fn new(sd_jwt_with_disclosures: String, serialization_format: String) -> Result<Self> {
        let serialization_format = serialization_format.to_lowercase();
        if serialization_format != "compact" && serialization_format != "json" {
            return Err(Error::InvalidInput(format!(
                "Serialization format \"{}\" is not supported",
                serialization_format
            )));
        }

        let mut holder = SDJWTHolder {
            sd_jwt_engine: SDJWTCommon {
                serialization_format,
                ..Default::default()
            },
            hs_disclosures: Vec::new(),
            key_binding_jwt_header: HashMap::new(),
            key_binding_jwt_payload: HashMap::new(),
            serialized_key_binding_jwt: "".to_string(),
            sd_jwt_presentation: "".to_string(),
            sd_jwt_payload: Map::new(),
            serialized_sd_jwt: "".to_string(),
            sd_jwt: "".to_string(),
        };

        holder.sd_jwt_engine.parse_sd_jwt(sd_jwt_with_disclosures)?;

        //TODO Verify signature before accepting the JWT
        holder.sd_jwt_payload = holder
            .sd_jwt_engine
            .unverified_input_sd_jwt_payload
            .take()
            .ok_or(Error::InvalidState("Cannot take payload".to_string()))?;
        holder.serialized_sd_jwt = holder
            .sd_jwt_engine
            .unverified_sd_jwt
            .take()
            .ok_or(Error::InvalidState("Cannot take jwt".to_string()))?;

        Ok(holder)
    }

    pub fn create_presentation(
        mut self,
        claims_to_disclose: Map<String, Value>,
        nonce: Option<String>,
        aud: Option<String>,
        holder_key: Option<EncodingKey>,
        sign_alg: Option<String>,
    ) -> Result<String> {
        self.sd_jwt_engine.create_hash_mappings()?;
        self.hs_disclosures = self.select_disclosures(&self.sd_jwt_payload, claims_to_disclose)?;

        match (nonce, aud, holder_key) {
            (Some(nonce), Some(aud), Some(holder_key)) => {
                self.create_key_binding_jwt(nonce, aud, &holder_key, sign_alg)?
            }
            (None, None, None) => {}
            _ => {
                return Err(Error::InvalidInput(
                    "Inconsistency in parameters to determine JWT KB by holder".to_string(),
                ));
            }
        }

        if self.sd_jwt_engine.serialization_format == "compact" {
            let mut combined: Vec<&str> = Vec::with_capacity(self.hs_disclosures.len() + 2);
            combined.push(&self.serialized_sd_jwt);
            combined.extend(self.hs_disclosures.iter().map(|s| s.as_str()));
            combined.push(&self.serialized_key_binding_jwt);
            let joined = combined.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
            self.sd_jwt_presentation = joined.to_string();
        } else {
            let mut sd_jwt_parsed: Map<String, Value> = serde_json::from_str(&self.sd_jwt)
                .map_err(|e| Error::DeserializationError(e.to_string()))?;
            sd_jwt_parsed.insert(
                crate::JWS_KEY_DISCLOSURES.to_owned(),
                self.hs_disclosures.clone().into(),
            );
            if !self.serialized_key_binding_jwt.is_empty() {
                sd_jwt_parsed.insert(
                    crate::JWS_KEY_KB_JWT.to_owned(),
                    self.serialized_key_binding_jwt.clone().into(),
                );
            }
            self.sd_jwt_presentation = serde_json::to_string(&sd_jwt_parsed)
                .map_err(|e| Error::DeserializationError(e.to_string()))?;
        }

        Ok(self.sd_jwt_presentation)
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
                let digest = match digest.as_str() {
                    Some(digest) => digest,
                    None => return None,
                };
                if let Some(Value::Array(disclosure)) =
                    self.sd_jwt_engine.hash_to_decoded_disclosure.get(digest)
                {
                    let key = match disclosure[1].as_str() {
                        Some(digest) => digest,
                        None => return None,
                    };
                    return Some((key, (&disclosure[2], digest)));
                }
                None
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
        sd_jwt_claims: &Vec<Value>,
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
    fn create_key_binding_jwt(
        &mut self,
        nonce: String,
        aud: String,
        _holder_key: &EncodingKey,
        sign_alg: Option<String>,
    ) -> Result<()> {
        let _alg = sign_alg.unwrap_or_else(|| DEFAULT_SIGNING_ALG.to_string());
        // Set key-binding fields
        self.key_binding_jwt_header
            .insert("alg".to_string(), _alg.clone().into());
        self.key_binding_jwt_header
            .insert("typ".to_string(), crate::KB_JWT_TYP_HEADER.into());
        self.key_binding_jwt_payload
            .insert("nonce".to_string(), nonce.into());
        self.key_binding_jwt_payload
            .insert("aud".to_string(), aud.into());
        let timestamp = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .map_err(|e| Error::ConversionError(format!("timestamp: {}", e)))?
            .as_secs();
        self.key_binding_jwt_payload
            .insert("iat".to_string(), timestamp.into());
        self._set_key_binding_digest_key()?;
        // Create key-binding jwt
        let mut header = Header::new(
            Algorithm::from_str(_alg.as_str())
                .map_err(|e| Error::DeserializationError(e.to_string()))?,
        );
        header.typ = Some(crate::KB_JWT_TYP_HEADER.into());
        self.serialized_key_binding_jwt =
            jsonwebtoken::encode(&header, &self.key_binding_jwt_payload, _holder_key)
                .map_err(|e| Error::DeserializationError(e.to_string()))?;
        Ok(())
    }

    fn _set_key_binding_digest_key(&mut self) -> Result<()> {
        let mut combined: Vec<&str> = Vec::with_capacity(self.hs_disclosures.len() + 1);
        combined.push(&self.serialized_sd_jwt);
        combined.extend(self.hs_disclosures.iter().map(|s| s.as_str()));
        let combined = combined.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);

        let _sd_hash = base64_hash(combined.as_bytes());
        let _sd_hash = serde_json::to_value(_sd_hash)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;
        self.key_binding_jwt_payload
            .insert(KB_DIGEST_KEY.to_owned(), _sd_hash);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::issuer::SDJWTClaimsStrategy;
    use crate::{SDJWTHolder, SDJWTIssuer, COMBINED_SERIALIZATION_FORMAT_SEPARATOR};
    use jsonwebtoken::EncodingKey;
    use serde_json::{json, Map, Value};
    use std::collections::HashSet;

    const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";

    #[test]
    fn create_full_presentation() {
        let user_claims = json!({
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "iss": "https://example.com/issuer",
            "iat": "1683000000",
            "exp": "1883000000",
            "address": {
                "street_address": "Schulstr. 12",
                "locality": "Schulpforta",
                "region": "Sachsen-Anhalt",
                "country": "DE"
            }
        });
        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::issue_sd_jwt(
            user_claims.clone(),
            SDJWTClaimsStrategy::Full,
            issuer_key,
            None,
            None,
            false,
            "compact".to_owned(),
        )
            .unwrap();
        let presentation = SDJWTHolder::new(
            sd_jwt.serialized_sd_jwt.clone(),
            "compact".to_ascii_lowercase(),
        )
            .unwrap()
            .create_presentation(
                user_claims.as_object().unwrap().clone(),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(sd_jwt.serialized_sd_jwt, presentation);
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

        let sd_jwt = SDJWTIssuer::issue_sd_jwt(
            user_claims.clone(),
            SDJWTClaimsStrategy::Full,
            issuer_key,
            None,
            None,
            false,
            "compact".to_owned(),
        )
            .unwrap();
        let issued = sd_jwt.serialized_sd_jwt.clone();
        user_claims["address"] = Value::Object(Map::new());
        let presentation =
            SDJWTHolder::new(sd_jwt.serialized_sd_jwt, "compact".to_ascii_lowercase())
                .unwrap()
                .create_presentation(
                    user_claims.as_object().unwrap().clone(),
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap();

        let mut parts: Vec<&str> = issued
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .collect();
        parts.remove(4);
        parts.remove(3);
        parts.remove(2);
        parts.remove(1);
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
        let strategy = SDJWTClaimsStrategy::Partial(vec![
            "$.name",
            "$.addresses[1]",
            "$.addresses[1].country",
            "$.nationalities[0]",
        ]);

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::issue_sd_jwt(
            user_claims.clone(),
            strategy,
            issuer_key,
            None,
            None,
            false,
            "compact".to_owned(),
        )
            .unwrap();
        // Choose what to reveal
        user_claims["addresses"] = Value::Array(vec![Value::Bool(true), Value::Bool(false)]);
        user_claims["nationalities"] = Value::Array(vec![Value::Bool(true), Value::Bool(true)]);

        let issued = sd_jwt.serialized_sd_jwt.clone();
        println!("{}", issued);
        let presentation =
            SDJWTHolder::new(sd_jwt.serialized_sd_jwt, "compact".to_ascii_lowercase())
                .unwrap()
                .create_presentation(
                    user_claims.as_object().unwrap().clone(),
                    None,
                    None,
                    None,
                    None,
                )
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
}
