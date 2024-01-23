use crate::{error, SDJWTJson, SDJWTSerializationFormat};
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
    serialized_key_binding_jwt: String,
    sd_jwt_payload: Map<String, Value>,
    serialized_sd_jwt: String,
    sd_jwt_json: Option<SDJWTJson>,
}

impl SDJWTHolder {
    /// Build an instance of holder to create one or more presentations based on SD JWT provided by issuer.
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
    pub fn new(sd_jwt_with_disclosures: String, serialization_format: SDJWTSerializationFormat) -> Result<Self> {
        let mut holder = SDJWTHolder {
            sd_jwt_engine: SDJWTCommon {
                serialization_format,
                ..Default::default()
            },
            hs_disclosures: Vec::new(),
            key_binding_jwt_header: HashMap::new(),
            key_binding_jwt_payload: HashMap::new(),
            serialized_key_binding_jwt: "".to_string(),
            sd_jwt_payload: Map::new(),
            serialized_sd_jwt: "".to_string(),
            sd_jwt_json: None,
        };

        holder
            .sd_jwt_engine
            .parse_sd_jwt(sd_jwt_with_disclosures.clone())?;

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
        holder.sd_jwt_json = holder.sd_jwt_engine.unverified_sd_jwt_json.clone();

        holder.sd_jwt_engine.create_hash_mappings()?;

        Ok(holder)
    }

    /// Create a presentation based on the SD JWT provided by issuer.
    ///
    /// # Arguments
    /// * `claims_to_disclose` - Claims to disclose in the presentation
    /// * `nonce` - Nonce to be used in the key-binding JWT
    /// * `aud` - Audience to be used in the key-binding JWT
    /// * `holder_key` - Key to sign the key-binding JWT
    /// * `sign_alg` - Signing algorithm to be used in the key-binding JWT
    ///
    /// # Returns
    /// * `String` - Presentation in the format specified by `serialization_format` in the constructor. It can be either compact or json.
    pub fn create_presentation(
        &mut self,
        claims_to_disclose: Map<String, Value>,
        nonce: Option<String>,
        aud: Option<String>,
        holder_key: Option<EncodingKey>,
        sign_alg: Option<String>,
    ) -> Result<String> {
        self.key_binding_jwt_header = Default::default();
        self.key_binding_jwt_payload = Default::default();
        self.serialized_key_binding_jwt = Default::default();
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

        let sd_jwt_presentation = if self.sd_jwt_engine.serialization_format == SDJWTSerializationFormat::Compact {
            let mut combined: Vec<&str> = Vec::with_capacity(self.hs_disclosures.len() + 2);
            combined.push(&self.serialized_sd_jwt);
            combined.extend(self.hs_disclosures.iter().map(|s| s.as_str()));
            combined.push(&self.serialized_key_binding_jwt);
            let joined = combined.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
            joined.to_string()
        } else {
            let mut sd_jwt_json = self
                .sd_jwt_json
                .take()
                .ok_or(Error::InvalidState("Cannot take SDJWTJson".to_string()))?;
            sd_jwt_json.disclosures = self.hs_disclosures.clone();
            if !self.serialized_key_binding_jwt.is_empty() {
                sd_jwt_json.kb_jwt = Some(self.serialized_key_binding_jwt.clone());
            }
            serde_json::to_string(&sd_jwt_json)
                .map_err(|e| Error::DeserializationError(e.to_string()))?
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
                                hash_to_disclosure.push(
                                    self.sd_jwt_engine.hash_to_disclosure[digest].clone()
                                );
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
        holder_key: &EncodingKey,
        sign_alg: Option<String>,
    ) -> Result<()> {
        let alg = sign_alg.unwrap_or_else(|| DEFAULT_SIGNING_ALG.to_string());
        // Set key-binding fields
        self.key_binding_jwt_header
            .insert("alg".to_string(), alg.clone().into());
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
        self.set_key_binding_digest_key()?;
        // Create key-binding jwt
        let mut header = Header::new(
            Algorithm::from_str(alg.as_str())
                .map_err(|e| Error::DeserializationError(e.to_string()))?,
        );
        header.typ = Some(crate::KB_JWT_TYP_HEADER.into());
        self.serialized_key_binding_jwt =
            jsonwebtoken::encode(&header, &self.key_binding_jwt_payload, holder_key)
                .map_err(|e| Error::DeserializationError(e.to_string()))?;
        Ok(())
    }

    fn set_key_binding_digest_key(&mut self) -> Result<()> {
        let mut combined: Vec<&str> = Vec::with_capacity(self.hs_disclosures.len() + 1);
        combined.push(&self.serialized_sd_jwt);
        combined.extend(self.hs_disclosures.iter().map(|s| s.as_str()));
        let combined = combined.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);

        let sd_hash = base64_hash(combined.as_bytes());
        self.key_binding_jwt_payload
            .insert(KB_DIGEST_KEY.to_owned(), Value::String(sd_hash));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::issuer::ClaimsForSelectiveDisclosureStrategy;
    use crate::{SDJWTHolder, SDJWTIssuer, COMBINED_SERIALIZATION_FORMAT_SEPARATOR, SDJWTSerializationFormat};
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
        let sd_jwt = SDJWTIssuer::new(issuer_key, None).issue_sd_jwt(
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

        let sd_jwt = SDJWTIssuer::new(issuer_key, None).issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
            .unwrap();
        let issued = sd_jwt.clone();
        user_claims["address"] = Value::Object(Map::new());
        let presentation =
            SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
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
        let sd_jwt = SDJWTIssuer::new(issuer_key, None).issue_sd_jwt(
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
        let presentation =
            SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
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
        // let sd_jwt = SDJWTIssuer::new(issuer_key, None).issue_sd_jwt(
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

        let presentation =
            SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact)
                .unwrap()
                .create_presentation(
                    revealed.as_object().unwrap().clone(),
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap();

        let presentation: HashSet<_> = presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR).map(String::from)
            .collect();

        let expected: HashSet<_> = expected_presentation
            .split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR)
            .map(String::from).collect();

        assert_eq!(presentation, expected);
    }
}
