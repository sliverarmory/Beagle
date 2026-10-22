//! BloodHound relationship shortcuts and the pinned official AD query catalog.
use anyhow::{Context, Result, bail};
use serde_json::Value;

pub fn catalog() -> Vec<Value> {
    serde_json::from_str(include_str!("../data/queries.json")).expect("embedded catalog")
}
pub fn saved_query(name_or_guid: &str) -> Result<Value> {
    let mut query = catalog()
        .into_iter()
        .find(|q| q["guid"] == name_or_guid || q["name"] == name_or_guid)
        .with_context(|| format!("unknown saved query: {name_or_guid}"))?;
    let parameters = template_parameters(query["guid"].as_str().unwrap_or_default());
    query["parameters"] = serde_json::json!(
        parameters
            .iter()
            .map(|(_, parameter)| (*parameter, "string"))
            .collect::<std::collections::BTreeMap<_, _>>()
    );
    query["parameterized_query"] = Value::String(parameterize(
        query["query"].as_str().context("query body")?,
        parameters,
    ));
    Ok(query)
}
pub fn prepare_saved(name_or_guid: &str, params: &Value) -> Result<String> {
    let query = saved_query(name_or_guid)?;
    for parameter in query["parameters"].as_object().unwrap().keys() {
        if !params.get(parameter).is_some_and(Value::is_string) {
            bail!("saved query requires string parameter ${parameter}; pass --params JSON");
        }
    }
    Ok(query["parameterized_query"].as_str().unwrap().to_owned())
}
fn template_parameters(guid: &str) -> &'static [(&'static str, &'static str)] {
    match guid {
        "1d75a21e-0d34-40c5-9360-281b60737d87" => &[("HOSTNAME/FQDN", "hostname")],
        "1f67e538-19d4-4020-89c8-5b39b31571bd" => &[("HOSTNAME", "hostname")],
        "251fc893-7a6b-4a0a-8650-9d5408d38c3c" => &[
            (
                "S-1-5-21-1111111111-1111111111-1111111111",
                "trusted_domain_sid",
            ),
            (
                "S-1-5-21-2222222222-2222222222-2222222222",
                "trusting_domain_sid",
            ),
        ],
        "38a9c4c9-3d70-453f-a017-cbfd35ed9917" => &[("KEYWORD", "keyword")],
        _ => &[],
    }
}
fn parameterize(source: &str, parameters: &[(&str, &str)]) -> String {
    source
        .split_inclusive('\n')
        .map(|line| {
            if line.trim_start().starts_with("//") {
                return line.to_owned();
            }
            let mut line = line.to_owned();
            for (literal, parameter) in parameters {
                for quote in ['\'', '"'] {
                    line = line.replace(
                        &format!("{quote}{literal}{quote}"),
                        &format!("${parameter}"),
                    );
                }
            }
            line
        })
        .collect()
}
pub fn attack_path_kinds() -> Vec<String> {
    serde_json::from_str(include_str!("../data/ad-attack-paths.json")).expect("embedded kinds")
}

/// Expand shortcut type identifiers only inside relationship patterns. Strings,
/// comments, map keys, variables and list values are preserved byte-for-byte.
pub fn expand_shortcuts(query: &str) -> Result<String> {
    let bytes = query.as_bytes();
    let mut output = String::with_capacity(query.len());
    let (mut i, mut copied) = (0, 0);
    let mut previous = b' ';
    let mut relationship = false;
    let mut type_position = false;
    let mut bracket_depth = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if i + 1 < bytes.len() && b == b'/' && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && b == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        if b == b'\'' || b == b'"' {
            let quote = b;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == quote {
                    i += 1;
                    if i < bytes.len() && bytes[i] == quote {
                        i += 1;
                    } else {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            previous = quote;
            continue;
        }
        // Backtick identifiers outside a relationship type are opaque. They
        // may legally contain brackets, dashes, and shortcut-looking text.
        if b == b'`' && !(relationship && bracket_depth == 1) {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'`' {
                    i += 1;
                    if i < bytes.len() && bytes[i] == b'`' {
                        i += 1;
                    } else {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            previous = b'x';
            continue;
        }
        if b == b'[' {
            if bracket_depth == 0 {
                relationship = previous == b'-';
                type_position = false;
            }
            bracket_depth += 1;
        } else if b == b']' {
            bracket_depth -= 1;
            if bracket_depth == 0 {
                relationship = false;
                type_position = false;
            }
        } else if relationship && bracket_depth == 1 {
            if b == b':' || b == b'|' {
                type_position = true;
            } else if b == b'*' || b == b'{' {
                type_position = false;
                relationship = false;
            } else if b.is_ascii_alphabetic() || b == b'_' || b == b'`' {
                let start = i;
                let quoted = b == b'`';
                if quoted {
                    i += 1;
                    while i < bytes.len() {
                        if bytes[i] == b'`' {
                            i += 1;
                            if i < bytes.len() && bytes[i] == b'`' {
                                i += 1;
                            } else {
                                break;
                            }
                        } else {
                            i += 1;
                        }
                    }
                } else {
                    i += 1;
                    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                    {
                        i += 1;
                    }
                }
                let identifier = if quoted {
                    query.get(start + 1..i.saturating_sub(1)).unwrap_or("")
                } else {
                    &query[start..i]
                };
                if type_position {
                    if identifier == "AZ_ATTACK_PATHS" {
                        bail!(
                            "AZ_ATTACK_PATHS requires Azure data; this implementation targets Active Directory"
                        );
                    }
                    if identifier == "AD_ATTACK_PATHS" || identifier == "ALL_ATTACK_PATHS" {
                        output.push_str(&query[copied..start]);
                        output.push_str(&attack_path_kinds().join("|"));
                        copied = i;
                    }
                    type_position = false;
                }
                previous = b'x';
                continue;
            }
        }
        if !b.is_ascii_whitespace() {
            previous = b;
        }
        i += 1;
    }
    output.push_str(&query[copied..]);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shortcuts_are_relationship_types_only() {
        let query = "MATCH (AD_ATTACK_PATHS)-[r:AD_ATTACK_PATHS*1..]->(b) WHERE b.name='AD_ATTACK_PATHS' RETURN ['AD_ATTACK_PATHS'] // [:AD_ATTACK_PATHS]\n";
        let result = expand_shortcuts(query).unwrap();
        assert!(result.contains("[r:Owns|GenericAll|"));
        assert!(result.contains("(AD_ATTACK_PATHS)"));
        assert!(result.contains("b.name='AD_ATTACK_PATHS'"));
        assert!(result.ends_with("// [:AD_ATTACK_PATHS]\n"));
        assert!(
            expand_shortcuts("MATCH (a)<-[:`AD_ATTACK_PATHS`]-(b) RETURN a")
                .unwrap()
                .contains("[:Owns|")
        );
        assert_eq!(
            expand_shortcuts("RETURN [AD_ATTACK_PATHS], {AD_ATTACK_PATHS: 1}").unwrap(),
            "RETURN [AD_ATTACK_PATHS], {AD_ATTACK_PATHS: 1}"
        );
    }
    #[test]
    fn shortcuts_preserve_opaque_and_escaped_backtick_identifiers() {
        for query in [
            "RETURN `-[x:AD_ATTACK_PATHS]` AS value",
            "MATCH (a)-[:`AD_ATTACK_PATHS``suffix`]->(b) RETURN a",
            "MATCH (`node``-[r:AD_ATTACK_PATHS]`)-[r:MemberOf]->(b) RETURN b",
        ] {
            assert_eq!(expand_shortcuts(query).unwrap(), query);
        }
        assert!(
            expand_shortcuts("MATCH (a)-[:`AD_ATTACK_PATHS`]->(b) RETURN a")
                .unwrap()
                .contains("[:Owns|")
        );
    }
    #[test]
    fn catalog_is_pinned_and_unique() {
        let catalog = catalog();
        let ids: std::collections::BTreeSet<_> = catalog
            .iter()
            .map(|q| q["guid"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), catalog.len());
        assert!(catalog.len() >= 177);
        for query in catalog {
            assert!(!query["query"].as_str().unwrap().is_empty());
        }
    }
}

#[cfg(test)]
mod template_tests {
    use super::*;
    #[test]
    fn saved_template_values_are_bound_and_never_interpolated() {
        let params = serde_json::json!({"hostname":"O'Reilly\" OR true //"});
        let source = prepare_saved(
            "All incoming and local paths for a specific computer",
            &params,
        )
        .unwrap();
        assert!(source.contains("m.name CONTAINS $hostname"));
        assert!(source.starts_with("// Replace 'HOSTNAME'"));
        assert!(!source.contains("O'Reilly"));
        assert!(prepare_saved("Principal with SPN keyword", &serde_json::json!({})).is_err());
        assert!(
            prepare_saved(
                "Principal with SPN keyword",
                &serde_json::json!({"keyword":1})
            )
            .is_err()
        );
    }
}
