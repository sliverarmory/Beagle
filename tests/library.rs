use beagle::{
    AnalysisOptions, Beagle, Edge, ExportKind, ImportMode, IngestOptions, SnapshotImportOptions,
    SystemTag,
};
use serde_json::{Value, json};
use std::{fs, path::Path, time::Duration};

fn collection(directory: &Path, name: &str, id: &str) -> std::path::PathBuf {
    let path = directory.join(format!("{name}.json"));
    fs::write(
        &path,
        json!({"meta":{"type":"users","version":6,"count":1},"data":[{
            "ObjectIdentifier":id,"Properties":{"name":name,"enabled":true},
            "FutureCollectorField":{"retained":name}
        }]})
        .to_string(),
    )
    .unwrap();
    path
}

fn snapshot(engine: &Beagle, kind: ExportKind) -> Value {
    serde_json::to_value(engine.export(kind).unwrap()).unwrap()
}

#[cfg(feature = "cli")]
fn cli(db: &Path, arguments: &[&str]) -> Value {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_beagle"))
        .arg("--db")
        .arg(db)
        .args(arguments)
        .env_remove("GRAPHQLITE_EXTENSION")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[cfg(feature = "cli")]
fn without_collection_times(mut value: Value) -> Value {
    fn normalize(value: &mut Value) {
        match value {
            Value::Object(object) => {
                for key in ["ingested_at", "lastseen", "firstseen", "lastcollected"] {
                    object.remove(key);
                }
                object.values_mut().for_each(normalize);
            }
            Value::Array(values) => values.iter_mut().for_each(normalize),
            _ => {}
        }
    }
    normalize(&mut value);
    value
}

#[test]
fn library_workflow_preserves_settings_history_and_atomicity() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("library.db");
    let first = collection(temp.path(), "Alice", "ALICE");
    let second = collection(temp.path(), "Bob", "BOB");
    let mut engine = Beagle::open(&db).unwrap();
    let initial = engine
        .ingest(
            std::slice::from_ref(&first),
            IngestOptions {
                mode: ImportMode::Merge,
                analyze: true,
            },
        )
        .unwrap();
    assert_eq!(initial.ingest.records, 1);
    assert!(initial.analysis.is_some());
    let options = AnalysisOptions {
        ntlm_enabled: false,
        ..Default::default()
    };
    engine.analyze(Some(&options)).unwrap();
    engine.tag("ALICE", SystemTag::Owned, true).unwrap();
    let config = serde_json::from_value(json!({"groups":[{
        "label":"Tag_Review","seeds":[{"type":"cypher","value":"MATCH (u:User) RETURN u"}]
    }]}))
    .unwrap();
    engine.apply_asset_groups(&config).unwrap();
    engine
        .ingest(
            std::slice::from_ref(&second),
            IngestOptions {
                mode: ImportMode::Merge,
                analyze: true,
            },
        )
        .unwrap();
    let report = engine.analyze(None).unwrap();
    assert!(!report.options.ntlm_enabled);
    assert_eq!(engine.store().import_history().unwrap().len(), 2);
    assert_eq!(
        engine
            .query(
                "MATCH (u:Tag_Review) RETURN u.objectid AS id ORDER BY id",
                &json!({})
            )
            .unwrap()["rows"],
        json!([{"id":"ALICE"},{"id":"BOB"}])
    );
    assert_eq!(
        engine
            .query("MATCH (u:Tag_Owned) RETURN u.objectid AS id", &json!({}))
            .unwrap()["rows"],
        json!([{"id":"ALICE"}])
    );
    let before = snapshot(&engine, ExportKind::Current);
    let raw = snapshot(&engine, ExportKind::Raw);
    let history = engine.store().import_history().unwrap();
    // High-level snapshot replacement must retain both graphs and reports if
    // validation fails after the workflow has prepared an invalid graph.
    let mut invalid = engine.export(ExportKind::Raw).unwrap();
    invalid.edges.push(Edge {
        source: "ALICE".into(),
        target: "missing".into(),
        kind: "MemberOf".into(),
        ..Default::default()
    });
    assert!(
        engine
            .import_snapshot(invalid, SnapshotImportOptions { analyze: false })
            .is_err()
    );
    assert_eq!(snapshot(&engine, ExportKind::Current), before);
    assert_eq!(snapshot(&engine, ExportKind::Raw), raw);
    assert_eq!(engine.store().import_history().unwrap(), history);
    let invalid_config = serde_json::from_value(json!({"groups":[{
        "label":"Tag_Review","seeds":[{"type":"cypher","value":"MATCH (n) DELETE n"}]
    }]}))
    .unwrap();
    assert!(engine.apply_asset_groups(&invalid_config).is_err());
    assert_eq!(snapshot(&engine, ExportKind::Current), before);
    assert!(engine.query("MATCH (n) DELETE n", &json!({})).is_err());
    engine.set_query_timeout(Duration::ZERO);
    assert!(
        engine
            .query("UNWIND range(1,100000) AS n RETURN sum(n)", &json!({}))
            .is_err()
    );
    engine.set_query_timeout(Duration::from_secs(3));
    assert_eq!(
        engine
            .query(
                "RETURN $value + 1 AS answer, 'Beagle' =~ '(?i)beagle' AS regex",
                &json!({"value":41})
            )
            .unwrap()["rows"],
        json!([{"answer":42,"regex":true}])
    );
    drop(engine);
    let reopened = Beagle::open(&db).unwrap();
    assert_eq!(snapshot(&reopened, ExportKind::Current), before);
    assert_eq!(snapshot(&reopened, ExportKind::Raw), raw);
    assert_eq!(reopened.store().import_history().unwrap(), history);
    assert!(!reopened.analysis_options().unwrap().ntlm_enabled);

    // Both public interfaces drive the same workflow. Ignore only collection
    // timestamps, which necessarily differ between these independent runs.
    #[cfg(feature = "cli")]
    {
        let cli_db = temp.path().join("cli.db");
        cli(&cli_db, &["ingest", first.to_str().unwrap(), "--analyze"]);
        let options_path = temp.path().join("options.json");
        fs::write(&options_path, serde_json::to_vec(&options).unwrap()).unwrap();
        cli(
            &cli_db,
            &["analyze", "--options", options_path.to_str().unwrap()],
        );
        cli(&cli_db, &["tag", "ALICE", "owned"]);
        let config_path = temp.path().join("groups.json");
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        cli(&cli_db, &["asset-groups", config_path.to_str().unwrap()]);
        cli(&cli_db, &["ingest", second.to_str().unwrap(), "--analyze"]);
        cli(&cli_db, &["analyze"]);
        assert_eq!(
            without_collection_times(cli(&cli_db, &["export"])),
            without_collection_times(before)
        );
        assert_eq!(
            without_collection_times(cli(&cli_db, &["export", "--raw"])),
            without_collection_times(raw)
        );
        let cli_engine = Beagle::open(&cli_db).unwrap();
        assert_eq!(
            without_collection_times(json!(cli_engine.store().import_history().unwrap())),
            without_collection_times(json!(history))
        );
        assert_eq!(
            serde_json::to_value(cli_engine.analysis_options().unwrap()).unwrap(),
            serde_json::to_value(reopened.analysis_options().unwrap()).unwrap()
        );
    }
}
