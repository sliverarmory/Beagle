#![cfg(feature = "cli")]

use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};
fn call(db: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_beagle"))
        .arg("--db")
        .arg(db)
        .env_remove("GRAPHQLITE_EXTENSION")
        .args(args)
        .output()
        .unwrap()
}
fn success(db: &Path, args: &[&str]) -> Value {
    let out = call(db, args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn build_info_works_without_creating_a_database() {
    let isolated = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_beagle"))
        .arg("--build-info")
        .current_dir(isolated.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let info: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["name"], "beagle");
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(info["protocol"], 1);
    assert_eq!(info["beagleRevision"], env!("BEAGLE_BUILD_REVISION"));
    assert_eq!(info["target"], env!("BEAGLE_BUILD_TARGET"));
    assert_eq!(fs::read_dir(isolated.path()).unwrap().count(), 0);
}

#[test]
fn copied_binary_runs_without_external_libraries_or_repository_assets() {
    let isolated = tempfile::tempdir().unwrap();
    let executable = isolated
        .path()
        .join(format!("beagle{}", std::env::consts::EXE_SUFFIX));
    fs::copy(env!("CARGO_BIN_EXE_beagle"), &executable).unwrap();
    // Only the executable is deployed. All other files are user input or output.
    assert_eq!(fs::read_dir(isolated.path()).unwrap().count(), 1);
    let run = |args: &[&str]| {
        let mut command = Command::new(&executable);
        command.current_dir(isolated.path()).env_clear();
        #[cfg(windows)]
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
        let output = command.args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    assert_eq!(run(&["queries"]).as_array().unwrap().len(), 177);
    fs::write(
        isolated.path().join("collection.json"),
        json!({
            "meta": {"type": "users", "version": 6, "count": 1},
            "data": [{"ObjectIdentifier": "S-1-5-21-1-2-3-1100", "Properties": {
                "name": "ALICE@LAB.LOCAL", "enabled": true, "domainsid": "S-1-5-21-1-2-3"
            }}]
        })
        .to_string(),
    )
    .unwrap();
    run(&["ingest", "collection.json", "--analyze"]);
    assert_eq!(
        run(&[
            "query",
            "MATCH (u:User) WHERE u.name =~ '(?i)alice@.*' RETURN u.name AS name"
        ])["rows"],
        json!([{"name": "ALICE@LAB.LOCAL"}])
    );
    assert_eq!(
        run(&["query", "MATCH (u:Absent) RETURN u.name AS name"]),
        json!({"columns": ["name"], "rows": []})
    );
    run(&["tag", "S-1-5-21-1-2-3-1100", "owned"]);
    assert_eq!(
        run(&["query", "MATCH (u:Tag_Owned) RETURN u.objectid AS id"])["rows"],
        json!([{"id": "S-1-5-21-1-2-3-1100"}])
    );
    assert!(isolated.path().join("beagle.db").exists());
    assert!(
        run(&["export"])["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["objectid"] == "S-1-5-21-1-2-3-1100")
    );
    let files: Vec<_> = fs::read_dir(isolated.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        files.iter().all(
            |name| name == executable.file_name().unwrap().to_str().unwrap()
                || name == "collection.json"
                || name.starts_with("beagle.db")
        ),
        "unexpected runtime assets: {files:?}"
    );
}

#[test]
fn headless_workflow_persists_tags_selectors_and_empty_schema() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("graph.db");
    let snapshot = tmp.path().join("graph.json");
    fs::write(&snapshot,json!({"nodes":[{"objectid":"user","labels":["Base","User"],"properties":{"objectid":"user","name":"Alice"}},{"objectid":"group","labels":["Base","Group"],"properties":{"objectid":"group","name":"Team"}}],"edges":[{"source":"user","target":"group","kind":"MemberOf","properties":{}}]}).to_string()).unwrap();
    success(
        &db,
        &["import-snapshot", snapshot.to_str().unwrap(), "--analyze"],
    );
    success(&db, &["tag", "user", "owned"]);
    success(&db, &["analyze"]);
    assert_eq!(
        success(
            &db,
            &["query", "MATCH (n:Tag_Owned) RETURN n.objectid AS id"]
        )["rows"],
        json!([{"id":"user"}])
    );
    let config = tmp.path().join("selectors.json");
    fs::write(&config,json!({"groups":[{"label":"Tag_Review","seeds":[{"type":"cypher","value":"MATCH (g:Group) RETURN g"}],"expansion":"children","exclusions":["group"]}]}).to_string()).unwrap();
    success(&db, &["asset-groups", config.to_str().unwrap()]);
    success(&db, &["analyze"]);
    assert_eq!(
        success(
            &db,
            &["query", "MATCH (n:Tag_Review) RETURN n.objectid AS id"]
        )["rows"],
        json!([{"id":"user"}])
    );
    assert_eq!(
        success(
            &db,
            &[
                "query",
                "MATCH (n:Absent) RETURN n.name AS zebra,n.objectid AS alpha"
            ]
        ),
        json!({"columns":["zebra","alpha"],"rows":[]})
    );
    assert_eq!(
        success(
            &db,
            &["paths", "--source", "user", "--target", "group", "--all"]
        )["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let before = success(&db, &["export"]);
    fs::write(&config,json!({"groups":[{"label":"Tag_Review","seeds":[{"type":"cypher","value":"MATCH (n) DELETE n"}]}]}).to_string()).unwrap();
    assert!(
        !call(&db, &["asset-groups", config.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(success(&db, &["export"]), before);
    fs::write(&config, json!({"groups":[]}).to_string()).unwrap();
    success(&db, &["asset-groups", config.to_str().unwrap()]);
    assert_eq!(
        success(
            &db,
            &["query", "MATCH (n:Tag_Review) RETURN n.objectid AS id"]
        )["rows"],
        json!([])
    );
    assert_eq!(
        success(
            &db,
            &["query", "MATCH (n:Tag_Owned) RETURN n.objectid AS id"]
        )["rows"],
        json!([{"id":"user"}])
    );
}

#[test]
fn paths_reject_bounds_that_would_overflow_backend_range() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("graph.db");
    for bound in ["0", "2147483648", "4294967295"] {
        let result = call(
            &db,
            &[
                "paths",
                "--source",
                "a",
                "--target",
                "b",
                "--max-hops",
                bound,
            ],
        );
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("--max-hops must be between"));
    }
}

#[test]
fn analyzed_snapshot_uses_saved_settings_while_plain_snapshot_stays_exact() {
    use beagle::{GraphData, Node};
    use std::collections::BTreeSet;

    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("settings.db");
    let snapshot = tmp.path().join("raw.json");
    let domain = "S-1-5-21-1-2-3";
    let mut raw = GraphData::default();
    for (id, kind, properties) in [
        (
            domain,
            "Domain",
            json!({"name":"LAB.LOCAL","domainsid":domain,"collected":true,"functionallevel":"2016"}),
        ),
        (
            "victim",
            "Computer",
            json!({"domainsid":domain,"restrictoutboundntlm":false,"webclientrunning":true}),
        ),
        (
            "dc",
            "Computer",
            json!({"domainsid":domain,"isdc":true,"ldapavailable":true,"ldapsigning":false}),
        ),
    ] {
        raw.upsert_node(Node {
            objectid: id.into(),
            labels: BTreeSet::from(["Base".into(), kind.into()]),
            properties: properties.as_object().unwrap().clone(),
        });
    }
    let raw_json = serde_json::to_value(raw.snapshot()).unwrap();
    fs::write(&snapshot, raw_json.to_string()).unwrap();
    let relay_count = |db: &Path| {
        success(
            db,
            &[
                "query",
                "MATCH ()-[r:CoerceAndRelayNTLMToLDAP]->() RETURN count(r) AS count",
            ],
        )["rows"][0]["count"]
            .as_u64()
            .unwrap()
    };
    // Positive control: this same raw graph derives an NTLM edge by default.
    success(
        &db,
        &["import-snapshot", snapshot.to_str().unwrap(), "--analyze"],
    );
    assert_eq!(relay_count(&db), 1);

    let options = tmp.path().join("options.json");
    fs::write(&options, json!({"ntlm_enabled":false}).to_string()).unwrap();
    success(&db, &["analyze", "--options", options.to_str().unwrap()]);
    assert_eq!(relay_count(&db), 0);
    success(&db, &["tag", "victim", "owned"]);
    let selectors = tmp.path().join("selectors.json");
    fs::write(
        &selectors,
        json!({"groups":[{"label":"Tag_Review","seeds":[{
            "type":"cypher","value":"MATCH (n:Computer {objectid:'victim'}) RETURN n"
        }]}]})
        .to_string(),
    )
    .unwrap();
    success(&db, &["asset-groups", selectors.to_str().unwrap()]);

    // Plain interchange neither changes the supplied graph nor discards settings.
    success(&db, &["import-snapshot", snapshot.to_str().unwrap()]);
    assert_eq!(success(&db, &["export"]), raw_json);
    assert_eq!(success(&db, &["export", "--raw"]), raw_json);

    let result = success(
        &db,
        &["import-snapshot", snapshot.to_str().unwrap(), "--analyze"],
    );
    assert_eq!(relay_count(&db), 0, "saved ntlm_enabled=false must apply");
    assert_eq!(
        result["asset_groups"]["selected"]["Tag_Review"],
        json!(["victim"])
    );
    for label in ["Tag_Owned", "Tag_Review"] {
        assert_eq!(
            success(
                &db,
                &[
                    "query",
                    &format!("MATCH (n:{label}) RETURN n.objectid AS id")
                ]
            )["rows"],
            json!([{"id":"victim"}])
        );
    }
    assert_eq!(success(&db, &["export", "--raw"]), raw_json);
}
