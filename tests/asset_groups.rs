use beagle::{
    Edge, GraphData, Node,
    asset_groups::{Configuration, apply},
};
use serde_json::json;
use std::collections::BTreeSet;
fn graph() -> GraphData {
    let mut g = GraphData::default();
    for (id, kind) in [("user", "User"), ("group", "Group"), ("other", "User")] {
        g.upsert_node(Node {
            objectid: id.into(),
            labels: BTreeSet::from(["Base".into(), kind.into()]),
            ..Default::default()
        });
    }
    g.upsert_edge(Edge {
        source: "user".into(),
        target: "group".into(),
        kind: "MemberOf".into(),
        ..Default::default()
    });
    g
}
#[test]
fn objectid_selectors_expand_exclude_and_obey_tier_precedence() {
    let mut g = graph();
    let config:Configuration=serde_json::from_value(json!({"groups":[
  {"label":"Tag_Tier_Zero","tier":true,"seeds":[{"type":"objectid","value":"group"}],"expansion":"children","exclusions":["group"]},
  {"label":"Tag_Tier_One","tier":true,"seeds":[{"type":"objectid","value":"user"},{"type":"objectid","value":"other"}]}]})).unwrap();
    let report = apply(&mut g, &config, |_| panic!("noquery")).unwrap();
    assert_eq!(report.selected["Tag_Tier_Zero"], vec!["user"]);
    assert_eq!(report.selected["Tag_Tier_One"], vec!["other"]);
    assert!(g.nodes["user"].labels.contains("Tag_Tier_Zero"));
    assert_eq!(g.nodes["user"].properties["system_tags"], "admin_tier_0");
}
#[test]
fn cypher_selectors_preserve_atomicity_on_invalid_results() {
    let mut g = graph();
    let original = g.snapshot().nodes;
    let config:Configuration=serde_json::from_value(json!({"groups":[{"label":"Tag_Owned","seeds":[{"type":"cypher","value":"MATCH (n) RETURN n"}]}]})).unwrap();
    assert!(apply(&mut g, &config, |_| Ok(json!({"rows":[{"count":1}]}))).is_err());
    assert_eq!(g.snapshot().nodes, original);
    apply(&mut g, &config, |_| {
        Ok(json!({"rows":[{"n":{"properties":{"objectid":"user"}}}]}))
    })
    .unwrap();
    assert!(g.nodes["user"].labels.contains("Tag_Owned"));
}
