use serde_yaml::Value;
use crate::error::Result;

#[allow(unused)]
pub fn generate_jsonpath_from_tagged_values(
    yaml: &Value,
    mut path: String,
    paths: &mut Vec<String>,
) -> Result<()> {

    if path.is_empty() {
        path.push('$');
    }

    match yaml {
        Value::Mapping(map) => {
            for (key, value) in map {
                // Handle nested

                let mut subpath: String;

                match key {
                    Value::Tagged(tagged) => {
                        subpath = format!("{}.{}", &path, tagged.value.as_str().unwrap());
                        paths.push(subpath.clone());
                        generate_jsonpath_from_tagged_values(value, subpath, paths);
                    }
                    Value::String(s) => {
                        subpath = format!("{}.{}", &path, &s);
                        generate_jsonpath_from_tagged_values(value, subpath, paths);
                    }
                    _ => {}
                }
            }
        }
        Value::Sequence(seq) => {
            for (idx, value) in seq.iter().enumerate() {

                let mut subpath = format!("{}.[{}]", &path, idx);
                generate_jsonpath_from_tagged_values(value, subpath, paths);
            }
        }
        Value::Tagged(tagged) => {
            // TODO: handle other value types (int/bool/etc)

            match &tagged.value {
                Value::Mapping(m) => {
                    paths.push(path.clone());
                    generate_jsonpath_from_tagged_values(&tagged.value, path.clone(), paths);
                }
                Value::Sequence(s) => {
                    paths.push(path.clone());
                    generate_jsonpath_from_tagged_values(&tagged.value, path.clone(), paths);
                }
                _ => {
                    paths.push(path.clone());
                }
            }

        }
        _ => {}
    }

    Ok(())
}
