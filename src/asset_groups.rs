//! Headless AD asset-group selection. Expansion follows BloodHound CE v9.8.0
//! packages/go/analysis/agt.go (Apache-2.0, Copyright Specter Ops, Inc.).
use crate::GraphData;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub groups: Vec<AssetGroup>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetGroup {
    /// Physical BloodHound label, e.g. Tag_Owned or Tag_Tier_Zero.
    pub label: String,
    pub seeds: Vec<Seed>,
    #[serde(default)]
    pub expansion: Expansion,
    #[serde(default)]
    pub exclusions: BTreeSet<String>,
    /// Tier precedence: earlier tier groups win when memberships overlap.
    #[serde(default)]
    pub tier: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Seed {
    Objectid(String),
    Cypher(String),
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expansion {
    #[default]
    None,
    All,
    Children,
    Parents,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SelectionReport {
    pub selected: BTreeMap<String, Vec<String>>,
    pub missing_objectids: BTreeSet<String>,
}

/// Cypher selectors must return nodes or object IDs. Selection is completed before
/// modifying the graph, so failed selectors never leave partially applied tags.
pub fn apply(
    graph: &mut GraphData,
    config: &Configuration,
    query: impl Fn(&str) -> Result<Value>,
) -> Result<SelectionReport> {
    let mut report = SelectionReport::default();
    let mut tiers = BTreeSet::new();
    let mut labels = BTreeSet::new();
    for group in &config.groups {
        if !group.label.starts_with("Tag_")
            || !group
                .label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            bail!("asset-group label must be a Tag_ identifier");
        }
        if !labels.insert(group.label.clone()) {
            bail!("duplicate asset-group label {}", group.label);
        }
        let mut seeds = BTreeSet::new();
        for seed in &group.seeds {
            match seed {
                Seed::Objectid(id) => {
                    if graph.nodes.contains_key(id) {
                        seeds.insert(id.clone());
                    } else {
                        report.missing_objectids.insert(id.clone());
                    }
                }
                Seed::Cypher(source) => {
                    let result =
                        query(source).with_context(|| format!("selector for {}", group.label))?;
                    let rows = result["rows"]
                        .as_array()
                        .context("selector requires rows")?;
                    for row in rows {
                        for value in row.as_object().context("selector row")?.values() {
                            collect_ids(value, graph, &mut seeds)?;
                        }
                    }
                }
            }
        }
        let children = matches!(group.expansion, Expansion::All | Expansion::Children);
        let parents = matches!(group.expansion, Expansion::All | Expansion::Parents);
        let mut selected = crate::analysis::expand_asset_group(graph, &seeds, children, parents);
        selected
            .retain(|id| !group.exclusions.contains(id) && (!group.tier || !tiers.contains(id)));
        if group.tier {
            tiers.extend(selected.iter().cloned());
        }
        report
            .selected
            .insert(group.label.clone(), selected.into_iter().collect());
    }
    for group in &config.groups {
        let selected: BTreeSet<_> = report.selected[&group.label].iter().collect();
        for node in graph.nodes.values_mut() {
            let include = selected.contains(&node.objectid);
            if include {
                node.labels.insert(group.label.clone());
            } else {
                node.labels.remove(&group.label);
            }
            if group.label == "Tag_Tier_Zero" {
                let mut tags: BTreeSet<String> = node
                    .properties
                    .get("system_tags")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .split_whitespace()
                    .map(str::to_string)
                    .collect();
                if include {
                    tags.insert("admin_tier_0".into());
                } else {
                    tags.remove("admin_tier_0");
                }
                if !tags.is_empty() || node.properties.contains_key("system_tags") {
                    node.properties.insert(
                        "system_tags".into(),
                        json!(tags.into_iter().collect::<Vec<_>>().join(" ")),
                    );
                }
            }
        }
    }
    Ok(report)
}
fn collect_ids(value: &Value, graph: &GraphData, ids: &mut BTreeSet<String>) -> Result<()> {
    if value.is_null() {
        return Ok(());
    }
    if let Some(id) = value.as_str().or_else(|| {
        value
            .get("properties")
            .and_then(|p| p.get("objectid"))
            .and_then(Value::as_str)
    }) {
        if !graph.nodes.contains_key(id) {
            bail!("selector returned unknown objectid {id}");
        }
        ids.insert(id.into());
        return Ok(());
    }
    if let Some(items) = value.as_array() {
        for item in items {
            collect_ids(item, graph, ids)?;
        }
        return Ok(());
    }
    bail!("asset-group selector must return nodes or objectid strings")
}
