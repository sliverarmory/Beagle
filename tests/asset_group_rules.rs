use beagle::{Beagle, ExportKind, GraphSnapshot, SnapshotImportOptions};
use serde_json::{Value, json};

fn value(engine: &Beagle) -> Value {
    serde_json::to_value(engine.export(ExportKind::Current).unwrap()).unwrap()
}
fn has_label(engine: &Beagle, id: &str, label: &str) -> bool {
    engine
        .export(ExportKind::Current)
        .unwrap()
        .nodes
        .iter()
        .find(|n| n.objectid == id)
        .unwrap()
        .labels
        .contains(label)
}
fn configuration(value: Value) -> beagle::AssetGroupConfiguration {
    serde_json::from_value(value).unwrap()
}
fn graph() -> GraphSnapshot {
    serde_json::from_value(json!({"nodes":[
        {"objectid":"user","labels":["Base","User"],"properties":{"isaclprotected":false}},
        {"objectid":"sibling","labels":["Base","User"],"properties":{}},
        {"objectid":"group","labels":["Base","Group"],"properties":{}},
        {"objectid":"ou","labels":["Base","OU"],"properties":{}},
        {"objectid":"gpo","labels":["Base","GPO"],"properties":{}}
    ],"edges":[
        {"source":"user","target":"group","kind":"MemberOf","properties":{},"derived":false},
        {"source":"ou","target":"user","kind":"Contains","properties":{},"derived":false},
        {"source":"ou","target":"sibling","kind":"Contains","properties":{},"derived":false},
        {"source":"gpo","target":"ou","kind":"GPLink","properties":{},"derived":false}
    ]}))
    .unwrap()
}
#[test]
fn preview_is_read_only_and_applied_rules_survive_reopen_and_analysis() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("rules.db");
    let mut engine = Beagle::open(&database).unwrap();
    engine
        .import_snapshot(graph(), SnapshotImportOptions { analyze: true })
        .unwrap();
    let before = value(&engine);
    let config = configuration(json!({"groups":[
        {"label":"Tag_Later","priority":20,"tier":true,"seeds":[{"type":"objectid","value":"user"}]},
        {"label":"Tag_First","priority":10,"tier":true,"seeds":[{"type":"cypher","value":"MATCH (g:Group) RETURN g"},{"type":"objectid","value":"missing"}],"expansion":"all","exclusions":["group"]},
        {"label":"Tag_Disabled","enabled":false,"priority":0,"seeds":[{"type":"cypher","value":"INVALID QUERY"}]}
    ]}));
    let preview = engine.preview_asset_groups(&config).unwrap();
    assert_eq!(preview.selected["Tag_First"], vec!["gpo", "ou", "user"]);
    assert!(preview.selected["Tag_Later"].is_empty());
    assert!(preview.selected["Tag_Disabled"].is_empty());
    assert_eq!(
        preview.missing_objectids.into_iter().collect::<Vec<_>>(),
        vec!["missing"]
    );
    assert_eq!(value(&engine), before);
    assert!(
        engine
            .asset_group_configuration()
            .unwrap()
            .groups
            .is_empty()
    );
    let applied = engine.apply_asset_groups(&config).unwrap();
    assert_eq!(applied.selected["Tag_First"], vec!["gpo", "ou", "user"]);
    drop(engine);
    let mut engine = Beagle::open(&database).unwrap();
    assert_eq!(
        serde_json::to_value(engine.asset_group_configuration().unwrap()).unwrap(),
        serde_json::to_value(&config).unwrap()
    );
    engine.analyze(None).unwrap();
    assert!(has_label(&engine, "user", "Tag_First"));
    assert!(!has_label(&engine, "sibling", "Tag_First"));
    let mut disabled = engine.asset_group_configuration().unwrap();
    disabled.groups[1].enabled = false;
    engine.apply_asset_groups(&disabled).unwrap();
    assert!(!has_label(&engine, "user", "Tag_First"));
    assert!(has_label(&engine, "user", "Tag_Later"));
    let committed = value(&engine);
    let mut invalid = disabled.clone();
    invalid.groups[0].seeds = vec![beagle::asset_groups::Seed::Cypher(
        "RETURN 1 AS invalid".into(),
    )];
    assert!(engine.preview_asset_groups(&invalid).is_err());
    assert!(engine.apply_asset_groups(&invalid).is_err());
    assert_eq!(value(&engine), committed);
    assert_eq!(
        serde_json::to_value(engine.asset_group_configuration().unwrap()).unwrap(),
        serde_json::to_value(disabled).unwrap()
    );
}
#[test]
fn expansion_directions_and_equal_priority_stability_remain_distinct() {
    let mut engine = Beagle::open(":memory:").unwrap();
    engine
        .import_snapshot(graph(), SnapshotImportOptions { analyze: true })
        .unwrap();
    for (direction, expected) in [
        ("none", vec!["group"]),
        ("children", vec!["group", "user"]),
        ("parents", vec!["group"]),
        ("all", vec!["gpo", "group", "ou", "user"]),
    ] {
        let config = configuration(
            json!({"groups":[{"label":"Tag_First","seeds":[{"type":"objectid","value":"group"}],"expansion":direction}]}),
        );
        assert_eq!(
            engine.preview_asset_groups(&config).unwrap().selected["Tag_First"],
            expected
        );
    }
    let config = configuration(json!({"groups":[
        {"label":"Tag_First","tier":true,"seeds":[{"type":"objectid","value":"user"}]},
        {"label":"Tag_Second","tier":true,"seeds":[{"type":"objectid","value":"user"}]}
    ]}));
    let report = engine.preview_asset_groups(&config).unwrap();
    assert_eq!(report.selected["Tag_First"], vec!["user"]);
    assert!(report.selected["Tag_Second"].is_empty());
}

#[test]
fn applied_rules_return_the_actual_analysis_ambiguity_diagnostics() {
    let mut engine = Beagle::open(":memory:").unwrap();
    let graph = serde_json::from_value(json!({"nodes":[
        {"objectid":"computer","labels":["Base","Computer"],"properties":{}},
        {"objectid":"a-544","labels":["Base","LocalGroup"],"properties":{}},
        {"objectid":"b-544","labels":["Base","LocalGroup"],"properties":{}},
        {"objectid":"one","labels":["Base","User"],"properties":{}},
        {"objectid":"two","labels":["Base","User"],"properties":{}}
    ],"edges":[
        {"source":"a-544","target":"computer","kind":"LocalToComputer","properties":{},"derived":false},
        {"source":"b-544","target":"computer","kind":"LocalToComputer","properties":{},"derived":false},
        {"source":"one","target":"a-544","kind":"MemberOfLocalGroup","properties":{},"derived":false},
        {"source":"two","target":"b-544","kind":"MemberOfLocalGroup","properties":{},"derived":false}
    ]})).unwrap();
    engine
        .import_snapshot(graph, SnapshotImportOptions { analyze: false })
        .unwrap();
    let outcome = engine
        .apply_asset_groups_with_analysis(&configuration(
            json!({"groups":[{"label":"Tag_Owned","seeds":[{"type":"objectid","value":"one"}]}]}),
        ))
        .unwrap();
    let report = serde_json::to_value(outcome).unwrap();
    assert_eq!(
        report["analysis"]["local_group_ambiguities"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        report["asset_groups"]["selected"]["Tag_Owned"],
        json!(["one"])
    );
    let graph = engine.export(ExportKind::Current).unwrap();
    assert_eq!(
        graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "AdminTo")
            .count(),
        1
    );
}
