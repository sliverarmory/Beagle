use beagle::{Beagle, ExportKind, ImportMode, IngestOptions, SystemTag};
use serde_json::json;
use std::{error::Error, fs, path::Path};

fn collection(path: &Path, id: &str, name: &str) -> Result<(), Box<dyn Error>> {
    fs::write(
        path,
        json!({
            "meta": {"type": "users", "version": 6, "count": 1},
            "data": [{"ObjectIdentifier": id, "Properties": {
                "name": name, "enabled": true,
                "domainsid": "S-1-5-21-1-2-3"
            }}]
        })
        .to_string(),
    )?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let alice = "S-1-5-21-1-2-3-1100";
    let bob = "S-1-5-21-1-2-3-1101";
    let first = Path::new("first.json");
    let second = Path::new("second.json");
    collection(first, alice, "ALICE@LAB.LOCAL")?;
    collection(second, bob, "BOB@LAB.LOCAL")?;
    let database = Path::new("consumer.db");
    let mut engine = Beagle::open(database)?;
    let options = IngestOptions {
        mode: ImportMode::Merge,
        analyze: true,
    };
    engine.ingest(&[first.into()], options)?;
    engine.tag(alice, SystemTag::Owned, true)?;
    engine.apply_asset_groups(&serde_json::from_value(json!({
        "groups": [{"label": "Tag_Review", "seeds": [{
            "type": "cypher", "value": "MATCH (u:User) RETURN u"
        }]}]
    }))?)?;
    engine.ingest(
        &[second.into()],
        IngestOptions {
            mode: ImportMode::Merge,
            analyze: true,
        },
    )?;
    engine.analyze(None)?;
    assert_eq!(engine.store().import_history()?.len(), 2);
    assert_eq!(
        engine.query("MATCH (u:Tag_Review) RETURN count(u) AS count", &json!({}))?["rows"],
        json!([{"count": 2}])
    );
    let before = serde_json::to_value(engine.export(ExportKind::Current)?)?;
    let history = engine.store().import_history()?;
    fs::write("invalid.json", "invalid collection")?;
    assert!(
        engine
            .ingest(
                &["invalid.json".into()],
                IngestOptions {
                    mode: ImportMode::Replace,
                    analyze: true,
                }
            )
            .is_err()
    );
    assert_eq!(
        serde_json::to_value(engine.export(ExportKind::Current)?)?,
        before
    );
    assert_eq!(engine.store().import_history()?, history);
    assert!(engine.query("MATCH (n) DELETE n", &json!({})).is_err());
    let result = engine.query(
        "RETURN 'Beagle' =~ '(?i)beagle' AS regex, $value + 1 AS answer",
        &json!({"value": 41}),
    )?;
    assert_eq!(result["rows"], json!([{"regex": true, "answer": 42}]));
    drop(engine);
    let reopened = Beagle::open(database)?;
    assert_eq!(
        serde_json::to_value(reopened.export(ExportKind::Current)?)?,
        before
    );
    assert_eq!(reopened.store().import_history()?.len(), 2);
    assert_eq!(
        reopened.query("MATCH (u:Tag_Owned) RETURN u.objectid AS id", &json!({}))?["rows"],
        json!([{"id": alice}])
    );
    assert_eq!(
        reopened.query("MATCH (u:User) RETURN count(u) AS count", &json!({}))?["rows"],
        json!([{"count": 2}])
    );
    println!(
        "{}",
        json!({
            "library": true, "users": 2, "import_batches": 2,
            "regex": true, "read_only": true, "rollback": true,
            "reopened": true, "asset_groups": true, "manual_tags": true
        })
    );
    Ok(())
}
