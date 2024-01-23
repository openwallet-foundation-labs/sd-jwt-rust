use crate::utils::generate::generate_jsonpath_from_tagged_values;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::path::PathBuf;
use crate::error::Result;

const SD_TAG: &str = "!sd";

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Default)]
pub struct Specification {
    pub user_claims: UserClaims,
    pub holder_disclosed_claims: serde_json::Map<String, serde_json::Value>,
    pub add_decoy_claims: Option<bool>,
    pub key_binding: Option<bool>,
    pub serialization_format: Option<String>,
}

impl Specification {
    fn update_disclosed_claims(&mut self) {
        // not to transform top-level empty object
        if self.holder_disclosed_claims.is_empty() {
            return;
        }

        let res = replace_empty_items(&serde_json::Value::Object(self.holder_disclosed_claims.clone()));
        self.holder_disclosed_claims = res.as_object().unwrap().clone();
    }
}

fn replace_empty_items(m: &serde_json::Value) -> serde_json::Value {
    match m {
        serde_json::Value::Array(arr) if (arr.is_empty()) => {
            serde_json::Value::Bool(false)
        }
        serde_json::Value::Object(obj) if (obj.is_empty()) => {
            serde_json::Value::Bool(false)
        }
        serde_json::Value::Array(arr) => {
            let mut result = Vec::new();

            for value in arr {
                result.push(replace_empty_items(value));
            }

            serde_json::Value::Array(result)
        }
        serde_json::Value::Object(obj) => {
            let mut result = serde_json::Map::new();

            for (key, value) in obj {
                result.insert(key.clone(), replace_empty_items(value));
            }

            serde_json::Value::Object(result)
        }
        _ => {
            m.clone()
        }
    }
}

impl From<&str> for Specification {
    fn from(value: &str) -> Self {
        let mut result = serde_yaml::from_str(value).unwrap_or(Specification::default());
        result.update_disclosed_claims();
        result
    }
}

impl From<&PathBuf> for Specification {
    fn from(path: &PathBuf) -> Self {
        let contents = std::fs::read_to_string(path).expect("Failed to read specification file");

        let mut spec: Specification = serde_yaml::from_str(&contents).expect("Failed to parse YAML");

        spec.update_disclosed_claims();

        spec
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Default)]
pub struct UserClaims(Value);

impl UserClaims {
    pub fn claims_to_json_value(&self) -> Result<serde_json::Value> {
        let filtered_value = _remove_tags(&self.0);
        let json_value: serde_json::Value =
            serde_yaml::from_value(filtered_value).expect("Failed to convert serde_json::Value");

        Ok(json_value)
    }

    pub fn sd_claims_to_jsonpath(&self) -> Result<Vec<String>> {
        let path = "".to_string();
        let mut paths = Vec::new();
        let mut claims = self.0.clone();

        let _ = generate_jsonpath_from_tagged_values(&mut claims, path, &mut paths);

        Ok(paths)
    }
}

fn _validate(value: &Value) -> Result<()> {
    match value {
        Value::String(_) | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::Tagged(tag) => {
            if tag.tag == SD_TAG {
                _validate(&tag.value)
            } else {
                panic!(
                    "Unsupported tag {:?} in claim-name, only !sd tag is supported",
                    tag.tag
                );
            }
        }
        Value::Sequence(list) => {
            for v in list {
                _validate(v)?;
            }

            Ok(())
        }
        Value::Mapping(map) => {
            for (key, value) in map {
                _validate(key)?;
                _validate(value)?;
            }

            Ok(())
        }

        _ => {
            panic!("Unsupported type for claim-name, it can be only string or tagged");
        }
    }
}

fn _remove_tags(original: &Value) -> Value {
    match original {
        Value::Tagged(tag) => _remove_tags(&tag.value),
        Value::Mapping(map) => {
            let mut filtered_map = serde_yaml::Mapping::new();

            for (key, value) in map.iter() {
                match key {
                    Value::Tagged(tag) => {
                        let filtered_value = _remove_tags(value);

                        filtered_map.insert(tag.value.clone(), filtered_value);
                    }
                    Value::Null => {}
                    _ => {
                        let filtered_value = _remove_tags(value);
                        filtered_map.insert(key.clone(), filtered_value);
                    }
                }
            }

            Value::Mapping(filtered_map)
        }
        Value::Sequence(seq) => {
            let filtered_seq: Vec<Value> = seq.iter().map(_remove_tags).collect();

            Value::Sequence(filtered_seq)
        }
        other => other.clone(),
    }
}
#[cfg(test)]
mod tests {
    use crate::types::specification::Specification;

    #[test]
    fn test_specification() {
        let yaml_str = r#"
        user_claims:
          sub: 6c5c0a49-b589-431d-bae7-219122a9ec2c
          !sd address:
            street_address: Schulstr. 12
            !sd street_address1: Schulstr. 12

        holder_disclosed_claims: {}
    "#;

        let spec = Specification::from(yaml_str);
        println!("{:?}", spec.user_claims.claims_to_json_value().unwrap())
    }
}
