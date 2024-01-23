use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct KeySettings {
    pub key_size: i32,
    pub kty: String,
    pub issuer_key: Key,
    pub holder_key: Value,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Key {
    pub kty: String,
    pub d: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Identifiers {
    pub issuer: String,
    pub verifier: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Settings {
    pub identifiers: Identifiers,
    pub key_settings: KeySettings,
    pub key_binding_nonce: String,
    pub expiry_seconds: Option<u64>,
    pub random_seed: Option<u64>,
    pub iat: Option<u64>,
    pub exp: Option<u64>,
}

impl From<&PathBuf> for Settings {
    fn from(path: &PathBuf) -> Self {
        let contents = std::fs::read_to_string(path)
            .expect("Failed to read settings file");

        let settings: Settings = serde_yaml::from_str(&contents)
            .expect("Failed to parse YAML");

        settings
    }
}

#[cfg(test)]
mod tests {
    use crate::types::settings::Settings;

    #[test]
    fn test_test_settings() {
        let yaml_str = r#"
        identifiers:
            issuer: "https://example.com/issuer"
            verifier: "https://example.com/verifier"

        key_settings:
            key_size: 256
            kty: "EC"
            issuer_key:
                kty: "EC"
                d: "Ur2bNKuBPOrAaxsRnbSH6hIhmNTxSGXshDSUD1a1y7g"
                crv: "P-256"
                x: "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ"
                y: "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
            holder_key:
                kty: "EC"
                d: "5K5SCos8zf9zRemGGUl6yfok-_NiiryNZsvANWMhF-I"
                crv: "P-256"
                x: "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc"
                y: "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"

        key_binding_nonce: "1234567890"

        expiry_seconds: 86400000
        random_seed: 0
        iat: 1683000000
        exp: 1883000000
    "#;

        let settings: Settings = serde_yaml::from_str(yaml_str).unwrap();
        println!("{:#?}", settings);
        assert_eq!(settings.identifiers.issuer, "https://example.com/issuer");
    }
}

