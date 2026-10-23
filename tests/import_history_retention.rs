use beagle::{Beagle, ExportKind, IngestOptions};
use serde_json::{Value, json};

fn snapshot(engine: &Beagle) -> Value {
    serde_json::to_value(engine.export(ExportKind::Current).unwrap()).unwrap()
}
fn collection(directory: &std::path::Path, index: usize) -> std::path::PathBuf {
    let path = directory.join(format!("users-{index}.json"));
    std::fs::write(&path, json!({"meta":{"type":"users","version":6,"count":1},"data":[{"ObjectIdentifier":format!("USER-{index}"),"Properties":{"name":format!("User {index}")}}]}).to_string()).unwrap();
    path
}
#[test]
fn explicit_retention_prunes_archives_and_persists_across_imports_without_changing_graph() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("retention.db");
    let mut engine = Beagle::open(&db).unwrap();
    for index in 0..12 {
        engine
            .ingest(&[collection(temp.path(), index)], IngestOptions::default())
            .unwrap();
    }
    assert_eq!(engine.store().import_history().unwrap().len(), 12);
    assert_eq!(engine.store().import_history_retention().unwrap(), None);
    let before = snapshot(&engine);
    let report = engine.set_import_history_retention(10).unwrap();
    assert_eq!(report, json!({"limit":10,"retained":10,"removed":2}));
    assert_eq!(snapshot(&engine), before);
    let history = engine.store().import_history().unwrap();
    assert_eq!(history.len(), 10);
    assert_eq!(
        engine.store().metadata("last_import").unwrap().as_ref(),
        history.last()
    );
    drop(engine);
    let mut engine = Beagle::open(&db).unwrap();
    assert_eq!(engine.store().import_history_retention().unwrap(), Some(10));
    engine
        .ingest(&[collection(temp.path(), 12)], IngestOptions::default())
        .unwrap();
    assert_eq!(engine.store().import_history().unwrap().len(), 10);
    assert_eq!(engine.export(ExportKind::Raw).unwrap().nodes.len(), 13);
    engine
        .ingest_with_history_retention(
            &[collection(temp.path(), 13)],
            IngestOptions::default(),
            Some(25),
        )
        .unwrap();
    assert_eq!(engine.store().import_history_retention().unwrap(), Some(25));
    assert_eq!(engine.store().import_history().unwrap().len(), 11);
    assert_eq!(engine.export(ExportKind::Raw).unwrap().nodes.len(), 14);
    let before = snapshot(&engine);
    let history = engine.store().import_history().unwrap();
    let malformed = temp.path().join("broken.json");
    std::fs::write(&malformed, "{").unwrap();
    assert!(
        engine
            .ingest_with_history_retention(&[malformed], IngestOptions::default(), Some(10))
            .is_err()
    );
    assert_eq!(snapshot(&engine), before);
    assert_eq!(engine.store().import_history().unwrap(), history);
    assert_eq!(engine.store().import_history_retention().unwrap(), Some(25));
    assert!(engine.set_import_history_retention(0).is_err());
    assert!(
        engine
            .ingest_with_history_retention(&[], IngestOptions::default(), Some(11))
            .is_err()
    );
    assert_eq!(engine.store().import_history_retention().unwrap(), Some(25));
}
#[test]
fn failed_database_commit_does_not_publish_retention_or_history() {
    let temp = tempfile::tempdir().unwrap();
    let mut engine = Beagle::open(":memory:").unwrap();
    engine
        .ingest_with_history_retention(
            &[collection(temp.path(), 0)],
            IngestOptions::default(),
            Some(50),
        )
        .unwrap();
    let before = snapshot(&engine);
    let history = engine.store().import_history().unwrap();
    let mut graph = engine.store().raw_graph().unwrap();
    graph.upsert_edge(beagle::Edge {
        source: "USER-0".into(),
        target: "missing".into(),
        kind: "MemberOf".into(),
        ..Default::default()
    });
    assert!(
        engine
            .store()
            .save_import_with_retention(
                &graph,
                &graph,
                &json!({"sentinel":"must not persist"}),
                false,
                Some(10)
            )
            .is_err()
    );
    assert_eq!(snapshot(&engine), before);
    assert_eq!(engine.store().import_history().unwrap(), history);
    assert_eq!(engine.store().import_history_retention().unwrap(), Some(50));
}
