use serde_yaml::Value;
use crate::error::Result;

#[allow(unused)]
pub fn generate_jsonpath_from_tagged_values(
    yaml: &Value,
    path: &mut String,
    paths: &mut Vec<String>,
) -> Result<()> {
    match yaml {
        Value::Mapping(map) => {
            for (key, value) in map {
                let len = path.len();

                if path.is_empty() {
                    path.push_str("$.");
                }
                // Handle nested
                match key {
                    Value::Tagged(tagged) => {
                        path.push_str(tagged.value.as_str().unwrap());

                        match value {
                            Value::Mapping(_) => {
                                path.push('.');
                                generate_jsonpath_from_tagged_values(value, path, paths);
                            }
                            Value::Sequence(_) => {
                                generate_jsonpath_from_tagged_values(value, path, paths);
                            }
                            _ => {},
                        }

                        if path.ends_with('.') {
                            path.pop().unwrap();
                        }

                        paths.push(path.clone());
                    }
                    Value::String(s) => {
                        path.push_str(s);
                        path.push('.');

                        generate_jsonpath_from_tagged_values(value, path, paths);
                    }
                    _ => {}
                }

                path.truncate(len);
            }
        }
        Value::Sequence(seq) => {
            for (idx, value) in seq.iter().enumerate() {
                let len = path.len();

                path.push_str(&format!("[{}].", idx));
                generate_jsonpath_from_tagged_values(value, path, paths);

                path.truncate(len);
            }
        }
        _ => {}
    }

    Ok(())
}
