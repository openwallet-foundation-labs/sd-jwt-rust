use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::vec::Vec;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand::Rng;
use serde_json::{json, Map as SJMap, Map};
use serde_json::Value;

use crate::{COMBINED_SERIALIZATION_FORMAT_SEPARATOR, DEFAULT_DIGEST_ALG, DIGEST_ALG_KEY,
            SD_DIGESTS_KEY, SD_LIST_PREFIX, DEFAULT_SIGNING_ALG,
            SDJWTCommon, SDJWTHasSDClaimException};
use crate::disclosure::SDJWTDisclosure;

pub struct SDJWTIssuer {
    // parameters
    sign_alg: String,
    add_decoy_claims: bool,
    extra_header_parameters: Option<HashMap<String, String>>,

    // input data
    issuer_key: EncodingKey,
    holder_key: Option<EncodingKey>,

    // internal fields
    inner: SDJWTCommon,
    all_disclosures: Vec<SDJWTDisclosure>,
    sd_jwt_payload: SJMap<String, Value>,
    signed_sd_jwt: String,
    pub(crate) serialized_sd_jwt: String,
}

pub enum SDJWTClaimsStrategy<'a> {
    // Full disclosure
    No,
    // Top-level selective disclosure, nested objects as full disclosure
    Flat,
    // Full recursive selective disclosure
    Full,
    //TODO gather JSONPaths to point the claims to be SD
    Partial(Vec<&'a str>),
}

// {
// let strategy = Partial(vec!["$.address", "$.address.street_address"])
// }
impl<'a> SDJWTClaimsStrategy<'a> {

    fn finalize_input(&mut self) -> Result<(), SDJWTHasSDClaimException> {
        match self {
            SDJWTClaimsStrategy::Partial(keys) => {
                for key in keys.iter_mut() {
                    if let Some(new_key) = key.strip_prefix("$.") {
                        *key = new_key;
                    } else {
                        return Err(SDJWTHasSDClaimException("Invalid JSONPath".to_owned()))
                    }
                }
                Ok(())
            }
            _ => Ok(())
        }
    }

    fn next_level(&self, key: &str) -> Self {
        match self {
            Self::No => Self::No,
            Self::Flat => Self::No,
            Self::Full => Self::Full,
            Self::Partial(sd_keys) => {
                let next_sd_keys = sd_keys.iter().filter_map(|str| {
                    str.strip_prefix(key).and_then(|str| str.strip_prefix('.'))
                }).collect();
                Self::Partial(next_sd_keys)
            }
        }
    }

    fn sd_for_key(&self, key: &str) -> bool {
        match self {
            Self::No => false,
            Self::Flat => true,
            Self::Full => true,
            Self::Partial(sd_keys) => {
                sd_keys.contains(&key)
            }
        }
    }
}

impl SDJWTIssuer {
    const DECOY_MIN_ELEMENTS: u32 = 2;
    const DECOY_MAX_ELEMENTS: u32 = 5;

    pub fn issue_sd_jwt(
        user_claims: Value,
        mut sd_strategy: SDJWTClaimsStrategy,
        issuer_key: EncodingKey,
        holder_key: Option<EncodingKey>,
        sign_alg: Option<String>,
        add_decoy_claims: bool,
        serialization_format: String,
        // extra_header_parameters: Option<HashMap<String, String>>,
    ) -> Self {
        let sign_alg = sign_alg.unwrap_or_else(|| DEFAULT_SIGNING_ALG.to_string());

        let inner = SDJWTCommon {
            serialization_format,
            ..Default::default()
        };

        sd_strategy.finalize_input().unwrap();

        SDJWTCommon::check_for_sd_claim(&user_claims).unwrap();

        let mut issuer = SDJWTIssuer {
            issuer_key,
            holder_key,
            sign_alg,
            add_decoy_claims,
            extra_header_parameters: None,
            inner,
            all_disclosures: Vec::new(),
            sd_jwt_payload: serde_json::Map::new(),
            signed_sd_jwt: String::new(),
            serialized_sd_jwt: String::new(),
        };

        issuer.assemble_sd_jwt_payload(user_claims, sd_strategy);
        issuer.create_signed_jws();
        issuer.create_combined();

        issuer
    }

    fn assemble_sd_jwt_payload(&mut self, mut user_claims: Value, sd_strategy: SDJWTClaimsStrategy) {
        let claims_obj_ref = user_claims.as_object_mut().unwrap();
        let always_revealed_root_keys = vec!["sub", "iss", "iat", "exp"];
        let mut always_revealed_claims: Map<String, Value> = always_revealed_root_keys.into_iter().filter_map(|key| claims_obj_ref.remove_entry(key)).collect();

        self.sd_jwt_payload = self.create_sd_claims(&user_claims, sd_strategy).as_object().unwrap().clone();

        self.sd_jwt_payload.insert(DIGEST_ALG_KEY.to_owned(), Value::String(DEFAULT_DIGEST_ALG.to_owned())); //TODO
        self.sd_jwt_payload.append(&mut always_revealed_claims);

        if let Some(holder_key) = &self.holder_key {
            let _ = holder_key;
            unimplemented!("holder key is not supported for issuance");
            //TODO public? self.sd_jwt_payload.insert("cnf".to_string(), json!({"jwk": holder_key.export_public(true)}));
        }
    }

    fn create_sd_claims(&mut self, user_claims: &Value, sd_strategy: SDJWTClaimsStrategy) -> Value {
        match user_claims {
            Value::Array(list) => {
                self.create_sd_claims_list(list, sd_strategy)
            }
            Value::Object(object) => {
                self.create_sd_claims_object(object, sd_strategy)
            }
            _ => user_claims.to_owned()
        }
    }

    fn create_sd_claims_list(&mut self, list: &[Value], sd_strategy: SDJWTClaimsStrategy) -> Value {
        let mut claims = Vec::new();
        for (idx, object) in list.iter().enumerate() {
            let key = idx.to_string();
            let strategy_for_child = sd_strategy.next_level(&key);
            let subtree = self.create_sd_claims(object, strategy_for_child);

            if sd_strategy.sd_for_key(&key) {
                let disclosure = SDJWTDisclosure::new(Some(key.to_owned()), subtree, &self.inner);
                claims.push(json!({ SD_LIST_PREFIX: disclosure.hash}));
                self.all_disclosures.push(disclosure);
            } else {
                claims.push(subtree);
            }
        }
        Value::Array(claims)
    }

    fn create_sd_claims_object(&mut self, user_claims: &SJMap<String, Value>, sd_strategy: SDJWTClaimsStrategy) -> Value {
        let mut claims = SJMap::new();
        let mut sd_claims = Vec::new();

        for (key, value) in user_claims.iter() {
            let strategy_for_child = sd_strategy.next_level(key);
            let subtree_from_here = self.create_sd_claims(value, strategy_for_child);

            if sd_strategy.sd_for_key(key) {
                let disclosure = SDJWTDisclosure::new(Some(key.to_owned()), subtree_from_here, &self.inner);
                sd_claims.push(disclosure.hash.clone());
                self.all_disclosures.push(disclosure);
            } else {
                claims.insert(key.to_owned(), subtree_from_here);
            }
        }

        if self.add_decoy_claims {
            let num_decoy_elements = rand::thread_rng().gen_range(Self::DECOY_MIN_ELEMENTS..Self::DECOY_MAX_ELEMENTS);
            for _ in 0..num_decoy_elements {
                sd_claims.push(self.create_decoy_claim_entry());
            }
        }

        if !sd_claims.is_empty() {
            sd_claims.sort();
            claims.insert(SD_DIGESTS_KEY.to_owned(), Value::Array(sd_claims.into_iter().map(Value::String).collect()));
        }

        Value::Object(claims)
    }

    fn create_signed_jws(&mut self) {
        if let Some(extra_headers) = &self.extra_header_parameters {
            let mut _protected_headers = extra_headers.clone();
            for (key, value) in extra_headers.iter() {
                _protected_headers.insert(key.to_string(), value.to_string());
            }
            unimplemented!("extra_headers are not supported for issuance");
        }

        let mut header = Header::new(Algorithm::from_str(&self.sign_alg).unwrap());
        header.typ = self.inner.typ.clone();
        self.signed_sd_jwt = jsonwebtoken::encode(&header, &self.sd_jwt_payload, &self.issuer_key).unwrap();

        if self.inner.serialization_format == "json" {
            unimplemented!("json serialization is not supported for issuance");
            // let  jws_content = serde_json::from_str(&self.serialized_sd_jwt).unwrap();
            // jws_content.insert(JWS_KEY_DISCLOSURES.to_string(), self.ii_disclosures.iter().map(|d| d.b64.to_string()).collect());
            // self.serialized_sd_jwt = serde_json::to_string(&jws_content).unwrap();
        }
    }

    fn create_combined(&mut self) {
        if self.inner.serialization_format == "compact" {
            let mut disclosures: VecDeque<String> = self.all_disclosures.iter().map(|d| d.raw_b64.to_string()).collect();
            disclosures.push_front(self.signed_sd_jwt.clone());

            let disclosures: Vec<&str> = disclosures.iter().map(|s| s.as_str()).collect();

            self.serialized_sd_jwt = format!(
                "{}{}",
                disclosures.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR),
                COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
            );
        } else if self.inner.serialization_format == "json" {
            self.serialized_sd_jwt = self.signed_sd_jwt.clone();
        } else {
            unimplemented!("Unexpected format, should be an error")
        }
    }

    fn create_decoy_claim_entry(&mut self) -> String {
        let digest = self.inner.b64hash(SDJWTCommon::generate_salt(None).as_bytes()).to_string();
        digest
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::EncodingKey;
    use log::trace;
    use serde_json::json;

    use crate::issuer::SDJWTClaimsStrategy;
    use crate::SDJWTIssuer;

    const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";

    #[test]
    fn test_assembly_sd_full_recursive() {
        let user_claims = json!({
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
        let sd_jwt = SDJWTIssuer::issue_sd_jwt(user_claims, SDJWTClaimsStrategy::Full, issuer_key, None, None, false, "compact".to_owned());
        trace!("{:?}", sd_jwt.serialized_sd_jwt)
    }
}
