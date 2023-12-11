use std::collections::HashMap;
use std::time;

use jsonwebtoken::EncodingKey;
use serde_json::{json, Map, Value};

use crate::{COMBINED_SERIALIZATION_FORMAT_SEPARATOR, DEFAULT_SIGNING_ALG, SD_DIGESTS_KEY, SD_LIST_PREFIX};
use crate::SDJWTCommon;

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
    pub fn new(sd_jwt_with_disclosures: String, serialization_format: String) -> Self {
        let serialization_format = serialization_format.to_lowercase();
        if serialization_format != "compact" && serialization_format != "json" {
            panic!("Unknown serialization format: {}", serialization_format);
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

        holder.sd_jwt_engine.parse_sd_jwt(sd_jwt_with_disclosures).unwrap();

        //TODO Verify signature before accepting the JWT
        holder.sd_jwt_payload = holder.sd_jwt_engine.unverified_input_sd_jwt_payload.take().unwrap();
        holder.serialized_sd_jwt = holder.sd_jwt_engine.unverified_sd_jwt.take().unwrap();

        holder
    }

    pub fn create_presentation(
        mut self,
        claims_to_disclose: Map<String, Value>,
        nonce: Option<String>,
        aud: Option<String>,
        holder_key: Option<EncodingKey>,
        sign_alg: Option<String>,
    ) -> String {
        self.sd_jwt_engine.create_hash_mappings().unwrap();
        self.hs_disclosures = self.select_disclosures(&self.sd_jwt_payload, claims_to_disclose);

        match (nonce, aud, holder_key) {
            (Some(nonce), Some(aud), Some(holder_key)) => self.create_key_binding_jwt(nonce, aud, &holder_key, sign_alg),
            (None, None, None) => {}
            _ => panic!("Inconsistency in parameters to determine JWT KB by holder")
        }

        if self.sd_jwt_engine.serialization_format == "compact" {
            let mut combined: Vec<&str> = Vec::with_capacity(self.hs_disclosures.len()+2);
            combined.push(&self.serialized_sd_jwt);
            combined.extend(self.hs_disclosures.iter().map(|s| s.as_str()));
            combined.push(&self.serialized_key_binding_jwt);
            let joined = combined.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR);
            self.sd_jwt_presentation = joined.to_string();
        } else {
            let mut sd_jwt_parsed: Map<String, Value> = serde_json::from_str(&self.sd_jwt).unwrap();
            sd_jwt_parsed.insert(crate::JWS_KEY_DISCLOSURES.to_owned(), self.hs_disclosures.clone().into());
            if !self.serialized_key_binding_jwt.is_empty() {
                sd_jwt_parsed.insert(crate::JWS_KEY_KB_JWT.to_owned(), self.serialized_key_binding_jwt.clone().into());
            }
            self.sd_jwt_presentation = serde_json::to_string(&sd_jwt_parsed).unwrap();
        }

        self.sd_jwt_presentation
    }

    fn select_disclosures(
        &self,
        sd_jwt_claims: &Map<String, Value>,
        claims_to_disclose: Map<String, Value>,
    ) -> Vec<String> {
        let mut hash_to_disclosure = Vec::new();

        let default_list = Vec::new();
        let sd_map: HashMap<&str, (&Value, &str)> = sd_jwt_claims[SD_DIGESTS_KEY].as_array().unwrap_or(&default_list).iter().map(|digest| {
            let digest = digest.as_str().unwrap();
            let disclosure = self.sd_jwt_engine.hash_to_decoded_disclosure[digest].as_array().unwrap();
            (disclosure[1].as_str().unwrap(), (&disclosure[2], digest))
        }).collect(); //TODO split to 2 maps
        for (key_to_disclose, value_to_disclose) in claims_to_disclose {
            match value_to_disclose {
                Value::Null | Value::Bool(true) | Value::Number(_) | Value::String(_) => { /* disclose without children */ }
                Value::Array(arr_to_disclose) => {
                    if let Some(arr) = sd_jwt_claims.get(&key_to_disclose).and_then(Value::as_array) {
                        hash_to_disclosure.append(&mut self.select_disclosures_from_disclosed_list(&arr, &arr_to_disclose))
                    }
                }
                Value::Object(next_disclosure) if (!next_disclosure.is_empty()) => {
                    let next_sd_jwt_claims = if let Some(next) = sd_jwt_claims.get(&key_to_disclose).and_then(Value::as_object) {
                        next
                    } else {
                        sd_map[key_to_disclose.as_str()].0.as_object().unwrap()
                    };
                    hash_to_disclosure.append(&mut self.select_disclosures(next_sd_jwt_claims, next_disclosure));
                }
                Value::Object(_) => { /* disclose without children */ }
                Value::Bool(false) => {
                    // skip unrevealed
                    continue
                }
            }
            if sd_jwt_claims.contains_key(&key_to_disclose) {
                continue;
            } else if let Some((_, digest)) = sd_map.get(key_to_disclose.as_str()) {
                hash_to_disclosure.push(self.sd_jwt_engine.hash_to_disclosure[*digest].to_owned());
            } else { panic!("Requested claim doesn't exist") }
        }

        hash_to_disclosure
    }

    fn select_disclosures_from_disclosed_list(&self, sd_jwt_claims: &Vec<Value>, claims_to_disclose: &Vec<Value>) -> Vec<String> {
        let mut hash_to_disclosure: Vec<String> = Vec::new();
        for (claim_to_disclose, claim) in claims_to_disclose.iter().zip(sd_jwt_claims) {
            match (claim_to_disclose, claim) {
                (Value::Bool(true), Value::Object(claim)) => {
                    if let Some(Value::String(digest)) = claim.get(SD_LIST_PREFIX) {
                        hash_to_disclosure.push(self.sd_jwt_engine.hash_to_disclosure[digest].to_owned());
                    }
                }
                (Value::Array(new_claims_to_disclose), Value::Array(claim)) => {
                    self.select_disclosures_from_disclosed_list(claim, new_claims_to_disclose);
                }
                _ => {}
            }
        }

        return hash_to_disclosure;
    }
    fn create_key_binding_jwt(
        &mut self,
        nonce: String,
        aud: String,
        _holder_key: &EncodingKey,
        sign_alg: Option<String>,
    ) {
        let _alg = sign_alg.unwrap_or_else(|| DEFAULT_SIGNING_ALG.to_string());

        self.key_binding_jwt_header.insert("alg".to_string(), _alg.into());
        self.key_binding_jwt_header.insert("typ".to_string(), crate::KB_JWT_TYP_HEADER.into());

        self.key_binding_jwt_payload.insert("nonce".to_string(), nonce.into());
        self.key_binding_jwt_payload.insert("aud".to_string(), aud.into());
        let timestamp = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs();
        self.key_binding_jwt_payload.insert("iat".to_string(), timestamp.into());

        let _payload = json!(self.key_binding_jwt_payload);

        //FIXME jsonwebtoken signature self.serialized_key_binding_jwt = payload.sign_with_key(holder_key).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use jsonwebtoken::EncodingKey;
    use serde_json::{json, Map, Value};
    use crate::issuer::SDJWTClaimsStrategy;
    use crate::{COMBINED_SERIALIZATION_FORMAT_SEPARATOR, SDJWTHolder, SDJWTIssuer};

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
        let sd_jwt = SDJWTIssuer::issue_sd_jwt(user_claims.clone(), SDJWTClaimsStrategy::Full, issuer_key, None, None, false, "compact".to_owned());
        let presentation = SDJWTHolder::new(sd_jwt.serialized_sd_jwt.clone(), "compact".to_ascii_lowercase()).create_presentation(user_claims.as_object().unwrap().clone(),None,None,None,None);
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

        let sd_jwt = SDJWTIssuer::issue_sd_jwt(user_claims.clone(), SDJWTClaimsStrategy::Full, issuer_key, None, None, false, "compact".to_owned());
        let issued = sd_jwt.serialized_sd_jwt.clone();
        user_claims["address"] = Value::Object(Map::new());
        let presentation = SDJWTHolder::new(sd_jwt.serialized_sd_jwt, "compact".to_ascii_lowercase()).create_presentation(user_claims.as_object().unwrap().clone(),None,None,None,None);

        let mut parts: Vec<&str> = issued.split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR).collect();
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
        let strategy = SDJWTClaimsStrategy::Partial(vec!["$.name", "$.addresses[1]", "$.addresses[1].country", "$.nationalities[0]"]);

        let private_issuer_bytes = PRIVATE_ISSUER_PEM.as_bytes();
        let issuer_key = EncodingKey::from_ec_pem(private_issuer_bytes).unwrap();
        let sd_jwt = SDJWTIssuer::issue_sd_jwt(user_claims.clone(), strategy, issuer_key, None, None, false, "compact".to_owned());
        // Choose what to reveal
        user_claims["addresses"] = Value::Array(vec![Value::Bool(true), Value::Bool(false)]);
        user_claims["nationalities"] = Value::Array(vec![Value::Bool(true), Value::Bool(true)]);

        let issued = sd_jwt.serialized_sd_jwt.clone();
        println!("{}", issued);
        let presentation = SDJWTHolder::new(sd_jwt.serialized_sd_jwt, "compact".to_ascii_lowercase()).create_presentation(user_claims.as_object().unwrap().clone(), None, None, None, None);
        println!("{}", presentation);
        let mut issued_parts: HashSet<&str> = issued.split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR).collect();
        issued_parts.remove("");

        let mut revealed_parts: HashSet<&str> = presentation.split(COMBINED_SERIALIZATION_FORMAT_SEPARATOR).collect();
        revealed_parts.remove("");

        let union: HashSet<_> = issued_parts.intersection(&revealed_parts).collect();
        assert_eq!(union.len(), 3);

    }
}