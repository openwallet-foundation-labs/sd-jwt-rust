// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::{error, SDJWTJson};
use error::Result;
use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::vec::Vec;

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand::Rng;
use serde_json::Value;
use serde_json::{json, Map as SJMap, Map};

use crate::disclosure::SDJWTDisclosure;
use crate::error::Error;
use crate::utils::{base64_hash, generate_salt};
use crate::{
    SDJWTCommon, CNF_KEY, COMBINED_SERIALIZATION_FORMAT_SEPARATOR, DEFAULT_DIGEST_ALG,
    DEFAULT_SIGNING_ALG, DIGEST_ALG_KEY, JWK_KEY, SD_DIGESTS_KEY, SD_LIST_PREFIX,
    SDJWTSerializationFormat,
};

pub struct SDJWTIssuer {
    // parameters
    sign_alg: String,
    add_decoy_claims: bool,
    extra_header_parameters: Option<HashMap<String, String>>,

    // input data
    issuer_key: EncodingKey,
    holder_key: Option<Jwk>,

    // internal fields
    inner: SDJWTCommon,
    all_disclosures: Vec<SDJWTDisclosure>,
    sd_jwt_payload: SJMap<String, Value>,
    signed_sd_jwt: String,
    serialized_sd_jwt: String,
}

/// ClaimsForSelectiveDisclosureStrategy is used to determine which claims can be selectively disclosed later by the holder.
#[derive(PartialEq, Debug)]
pub enum ClaimsForSelectiveDisclosureStrategy<'a> {
    /// No claims can be selectively disclosed, so all claims are always disclosed in presentations generated by the holder.
    NoSDClaims,
    /// Top-level claims can be selectively disclosed, nested objects are fully disclosed, if a parent claim is disclosed.
    TopLevel,
    /// All claims can be selectively disclosed (recursively including nested objects).
    AllLevels,
    /// Claims can be selectively disclosed based on the provided JSONPaths.
    /// Other claims are always disclosed in presentation generated by the holder.
    /// # Examples
    /// ```
    /// use sd_jwt_rs::issuer::ClaimsForSelectiveDisclosureStrategy;
    ///
    /// let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec!["$.address", "$.address.street_address"]);
    /// ```
    Custom(Vec<&'a str>),
}

impl<'a> ClaimsForSelectiveDisclosureStrategy<'a> {
    fn finalize_input(&mut self) -> Result<()> {
        match self {
            ClaimsForSelectiveDisclosureStrategy::Custom(keys) => {
                for key in keys.iter_mut() {
                    if let Some(new_key) = key.strip_prefix("$.") {
                        *key = new_key;
                    } else {
                        return Err(Error::InvalidPath("Invalid JSONPath".to_owned()));
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn next_level(&self, key: &str) -> Self {
        match self {
            Self::NoSDClaims => Self::NoSDClaims,
            Self::TopLevel => Self::NoSDClaims,
            Self::AllLevels => Self::AllLevels,
            Self::Custom(sd_keys) => {
                let next_sd_keys = sd_keys
                    .iter()
                    .filter_map(|str| {
                        str.strip_prefix(key).and_then(|str|
                            match str.chars().next() {
                                Some('.') => Some(&str[1..]), // next token
                                Some('[') => Some(str),       // array index
                                _ => None,
                            }
                        )
                    })
                    .collect();
                Self::Custom(next_sd_keys)
            }
        }
    }

    fn sd_for_key(&self, key: &str) -> bool {
        match self {
            Self::NoSDClaims => false,
            Self::TopLevel => true,
            Self::AllLevels => true,
            Self::Custom(sd_keys) => sd_keys.contains(&key),
        }
    }
}

impl SDJWTIssuer {
    const DECOY_MIN_ELEMENTS: u32 = 2;
    const DECOY_MAX_ELEMENTS: u32 = 5;

    /// Creates a new SDJWTIssuer instance.
    ///
    /// The instance can be used mutliple times to issue SD-JWTs.
    ///
    /// # Arguments
    /// * `issuer_key` - The key used to sign the SD-JWT.
    /// * `sign_alg` - The signing algorithm used to sign the SD-JWT. If not provided, the default algorithm is used.
    ///
    /// # Returns
    /// A new SDJWTIssuer instance.
    pub fn new(issuer_key: EncodingKey, sign_alg: Option<String>) -> Self {
        SDJWTIssuer {
            sign_alg: sign_alg.unwrap_or(DEFAULT_SIGNING_ALG.to_owned()),
            add_decoy_claims: false,
            extra_header_parameters: None,
            issuer_key,
            holder_key: None,
            inner: Default::default(),
            all_disclosures: vec![],
            sd_jwt_payload: Default::default(),
            signed_sd_jwt: "".to_string(),
            serialized_sd_jwt: "".to_string(),
        }
    }

    fn reset(&mut self) {
        self.extra_header_parameters = Default::default();
        self.all_disclosures = Default::default();
        self.sd_jwt_payload = Default::default();
        self.signed_sd_jwt = Default::default();
        self.serialized_sd_jwt = Default::default();
    }

    /// Issues a SD-JWT.
    ///
    /// # Arguments
    /// * `user_claims` - The claims to be included in the SD-JWT.
    /// * `sd_strategy` - The strategy to be used to determine which claims to be selectively disclosed. See [ClaimsForSelectiveDisclosureStrategy] for more details.
    /// * `holder_key` - The key used to sign the SD-JWT. If not provided, no key binding is added to the SD-JWT.
    /// * `add_decoy_claims` - If true, decoy claims are added to the SD-JWT.
    /// * `serialization_format` - The serialization format to be used for the SD-JWT, see [SDJWTSerializationFormat].
    ///
    /// # Returns
    /// The issued SD-JWT as a string in the requested serialization format.
    pub fn issue_sd_jwt(
        &mut self,
        user_claims: Value,
        mut sd_strategy: ClaimsForSelectiveDisclosureStrategy,
        holder_key: Option<Jwk>,
        add_decoy_claims: bool,
        serialization_format: SDJWTSerializationFormat,
        // extra_header_parameters: Option<HashMap<String, String>>,
    ) -> Result<String> {
        let inner = SDJWTCommon {
            serialization_format,
            ..Default::default()
        };

        sd_strategy.finalize_input()?;

        SDJWTCommon::check_for_sd_claim(&user_claims)?;

        self.reset();
        self.inner = inner;
        self.holder_key = holder_key;
        self.add_decoy_claims = add_decoy_claims;

        self.assemble_sd_jwt_payload(user_claims, sd_strategy)?;
        self.create_signed_jws()?;
        self.create_combined()?;

        Ok(self.serialized_sd_jwt.clone())
    }

    fn assemble_sd_jwt_payload(
        &mut self,
        mut user_claims: Value,
        sd_strategy: ClaimsForSelectiveDisclosureStrategy,
    ) -> Result<()> {
        let claims_obj_ref = user_claims
            .as_object_mut()
            .ok_or(Error::ConversionError("json object".to_string()))?;
        let always_revealed_root_keys = vec!["iss", "iat", "exp"];
        let mut always_revealed_claims: Map<String, Value> = always_revealed_root_keys
            .into_iter()
            .filter_map(|key| claims_obj_ref.shift_remove_entry(key))
            .collect();

        self.sd_jwt_payload = self
            .create_sd_claims(&user_claims, sd_strategy)
            .as_object()
            .ok_or(Error::ConversionError("json object".to_string()))?
            .clone();

        self.sd_jwt_payload.insert(
            DIGEST_ALG_KEY.to_owned(),
            Value::String(DEFAULT_DIGEST_ALG.to_owned()),
        ); //TODO
        self.sd_jwt_payload.append(&mut always_revealed_claims);

        if let Some(holder_key) = &self.holder_key {
            self.sd_jwt_payload
                .entry(CNF_KEY)
                .or_insert_with(|| json!({JWK_KEY: holder_key}));
        }

        Ok(())
    }

    fn create_sd_claims(&mut self, user_claims: &Value, sd_strategy: ClaimsForSelectiveDisclosureStrategy) -> Value {
        match user_claims {
            Value::Array(list) => self.create_sd_claims_list(list, sd_strategy),
            Value::Object(object) => self.create_sd_claims_object(object, sd_strategy),
            _ => user_claims.to_owned(),
        }
    }

    fn create_sd_claims_list(&mut self, list: &[Value], sd_strategy: ClaimsForSelectiveDisclosureStrategy) -> Value {
        let mut claims = Vec::new();
        for (idx, object) in list.iter().enumerate() {
            let key = format!("[{idx}]");
            let strategy_for_child = sd_strategy.next_level(&key);
            let subtree = self.create_sd_claims(object, strategy_for_child);

            if sd_strategy.sd_for_key(&key) {
                let disclosure = SDJWTDisclosure::new(None, subtree);
                claims.push(json!({ SD_LIST_PREFIX: disclosure.hash}));
                self.all_disclosures.push(disclosure);
            } else {
                claims.push(subtree);
            }
        }
        Value::Array(claims)
    }

    fn create_sd_claims_object(
        &mut self,
        user_claims: &SJMap<String, Value>,
        sd_strategy: ClaimsForSelectiveDisclosureStrategy,
    ) -> Value {
        let mut claims = SJMap::new();

        // to have the first key "_sd" in the ordered map
        claims.insert(SD_DIGESTS_KEY.to_owned(), Value::Null);

        let mut sd_claims = Vec::new();

        for (key, value) in user_claims.iter() {
            let strategy_for_child = sd_strategy.next_level(key);
            let subtree_from_here = self.create_sd_claims(value, strategy_for_child);

            if sd_strategy.sd_for_key(key) {
                let disclosure = SDJWTDisclosure::new(Some(key.to_owned()), subtree_from_here);
                sd_claims.push(disclosure.hash.clone());
                self.all_disclosures.push(disclosure);
            } else {
                claims.insert(key.to_owned(), subtree_from_here);
            }
        }

        if self.add_decoy_claims {
            let num_decoy_elements =
                rand::thread_rng().gen_range(Self::DECOY_MIN_ELEMENTS..Self::DECOY_MAX_ELEMENTS);
            for _ in 0..num_decoy_elements {
                sd_claims.push(self.create_decoy_claim_entry());
            }
        }

        if !sd_claims.is_empty() {
            sd_claims.sort();
            claims.insert(
                SD_DIGESTS_KEY.to_owned(),
                Value::Array(sd_claims.into_iter().map(Value::String).collect()),
            );
        } else {
            claims.shift_remove(SD_DIGESTS_KEY);
        }

        Value::Object(claims)
    }

    fn create_signed_jws(&mut self) -> Result<()> {
        if let Some(extra_headers) = &self.extra_header_parameters {
            let mut _protected_headers = extra_headers.clone();
            for (key, value) in extra_headers.iter() {
                _protected_headers.insert(key.to_string(), value.to_string());
            }
            unimplemented!("extra_headers are not supported for issuance");
        }

        let mut header = Header::new(
            Algorithm::from_str(&self.sign_alg)
                .map_err(|e| Error::DeserializationError(e.to_string()))?,
        );
        header.typ = self.inner.typ.clone();
        self.signed_sd_jwt = jsonwebtoken::encode(&header, &self.sd_jwt_payload, &self.issuer_key)
            .map_err(|e| Error::DeserializationError(e.to_string()))?;

        Ok(())
    }

    fn create_combined(&mut self) -> Result<()> {
        match self.inner.serialization_format  {
            SDJWTSerializationFormat::Compact => {
                let mut disclosures: VecDeque<String> = self
                    .all_disclosures
                    .iter()
                    .map(|d| d.raw_b64.to_string())
                    .collect();
                disclosures.push_front(self.signed_sd_jwt.clone());

                let disclosures: Vec<&str> = disclosures.iter().map(|s| s.as_str()).collect();

                self.serialized_sd_jwt = format!(
                    "{}{}",
                    disclosures.join(COMBINED_SERIALIZATION_FORMAT_SEPARATOR),
                    COMBINED_SERIALIZATION_FORMAT_SEPARATOR,
                );
            },
            SDJWTSerializationFormat::JSON => {
                let jwt: Vec<&str> = self.signed_sd_jwt.split('.').collect();
                if jwt.len() != 3 {
                    return Err(Error::InvalidInput(format!(
                        "Invalid JWT, JWT must contain three parts after splitting with \".\": jwt {}",
                        self.signed_sd_jwt
                    )));
                }
                let sd_jwt_json = SDJWTJson {
                    protected: jwt[0].to_owned(),
                    payload: jwt[1].to_owned(),
                    signature: jwt[2].to_owned(),
                    kb_jwt: None,
                    disclosures: self
                        .all_disclosures
                        .iter()
                        .map(|d| d.raw_b64.to_string())
                        .collect(),
                };
                self.serialized_sd_jwt = serde_json::to_string(&sd_jwt_json)
                    .map_err(|e| Error::DeserializationError(e.to_string()))?;
            }
        }

        Ok(())
    }

    fn create_decoy_claim_entry(&mut self) -> String {
        let digest = base64_hash(generate_salt().as_bytes()).to_string();
        digest
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::EncodingKey;
    use log::trace;
    use serde_json::json;

    use crate::issuer::ClaimsForSelectiveDisclosureStrategy;
    use crate::{SDJWTIssuer, SDJWTSerializationFormat};

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
        let sd_jwt = SDJWTIssuer::new(issuer_key, None).issue_sd_jwt(
            user_claims,
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
            .unwrap();
        trace!("{:?}", sd_jwt)
    }

    #[test]
    fn test_next_level_array() {
        let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
            "name",
            "addresses[1]",
            "addresses[1].country",
            "nationalities[0]",
        ]);

        let next_strategy = strategy.next_level("addresses");
        assert_eq!(&next_strategy, &ClaimsForSelectiveDisclosureStrategy::Custom(vec!["[1]", "[1].country"]));
        let next_strategy = next_strategy.next_level("[1]");
        assert_eq!(&next_strategy, &ClaimsForSelectiveDisclosureStrategy::Custom(vec!["country"]));
    }

    #[test]
    fn test_next_level_object() {
        let strategy = ClaimsForSelectiveDisclosureStrategy::Custom(vec![
            "address.street_address",
            "address.locality",
            "address.region",
            "address.country",
        ]);

        let next_strategy = strategy.next_level("address");
        assert_eq!(&next_strategy, &ClaimsForSelectiveDisclosureStrategy::Custom(vec![
            "street_address",
            "locality",
            "region",
            "country"
        ]));
    }
}
