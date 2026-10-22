use beagle::{Edge, GraphData, Node, Store};
use serde_json::json;
use std::collections::BTreeSet;
fn fixture() -> GraphData {
    let mut g = GraphData::default();
    for (id, kind) in [("u", "User"), ("g", "Group")] {
        g.upsert_node(Node{objectid:id.into(),labels:BTreeSet::from(["Base".into(),kind.into()]),properties:json!({"name":id,"active":true,"integer":42,"real":1.5,"array":["x","y"],"empty":[],"quote":"O'Reilly"}).as_object().unwrap().clone()});
    }
    g.upsert_edge(Edge {
        source: "u".into(),
        target: "g".into(),
        kind: "MemberOf".into(),
        properties: json!({"isacl":false}).as_object().unwrap().clone(),
        derived: false,
    });
    g
}

#[test]
fn built_in_backend_connections_have_independent_lifetimes() {
    let left = Store::open(":memory:").unwrap();
    left.save(&fixture(), None, None).unwrap();
    let right = Store::open(":memory:").unwrap();
    assert_eq!(
        right
            .query("MATCH (n) RETURN count(n) AS count", &json!({}))
            .unwrap()["rows"],
        json!([{"count": 0}])
    );
    drop(right);
    assert_eq!(
        left.query("MATCH (n) RETURN count(n) AS count", &json!({}))
            .unwrap()["rows"],
        json!([{"count": 2}])
    );
    // Registration and SQLite allocation must also be independent across threads.
    let threads: Vec<_> = (0..4)
        .map(|index| {
            std::thread::spawn(move || {
                let store = Store::open(":memory:").unwrap();
                store.save(&fixture(), None, None).unwrap();
                for _ in 0..8 {
                    assert_eq!(
                        store
                            .query(
                                "RETURN $id AS id, 'Beagle' =~ '(?i)beagle' AS matches",
                                &json!({"id": index})
                            )
                            .unwrap()["rows"],
                        json!([{"id": index, "matches": true}])
                    );
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(left.graph().unwrap().nodes.len(), 2);
}

#[test]
fn persistence_types_query_readonly_and_rollback() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("test.db");
    let g = fixture();
    {
        let store = Store::open(&db).unwrap();
        store.save(&g, Some(&g), None).unwrap();
        assert_eq!(store.graph().unwrap().snapshot().nodes, g.snapshot().nodes);
        assert_eq!(store.graph().unwrap().snapshot().edges, g.snapshot().edges);
        assert_eq!(store.query("MATCH (u:User) RETURN u.active AS active, u.integer AS integer, u.array AS array",&json!({})).unwrap()["rows"],json!([{"active":true,"integer":42,"array":["x","y"]}]));
        assert!(
            store
                .query("CREATE (:User {objectid:'bad'})", &json!({}))
                .is_err()
        );
        assert!(store.query("MATCH (n) DELETE n", &json!({})).is_err());
        assert!(
            store
                .query("MATCH (n) SET n.name = 'bad'", &json!({}))
                .is_err()
        );
        assert_eq!(store.graph().unwrap().snapshot().nodes, g.snapshot().nodes);
        let mut broken = g.clone();
        broken.upsert_edge(Edge {
            source: "missing".into(),
            target: "g".into(),
            kind: "MemberOf".into(),
            ..Default::default()
        });
        assert!(store.save(&broken, None, None).is_err());
        assert_eq!(store.graph().unwrap().snapshot().nodes, g.snapshot().nodes);
    }
    let reopened = Store::open(&db).unwrap();
    assert_eq!(
        reopened.graph().unwrap().snapshot().nodes,
        g.snapshot().nodes
    );
    assert_eq!(
        reopened.raw_graph().unwrap().snapshot().edges,
        g.snapshot().edges
    );
}
#[test]
fn tags_and_path_shortcuts_survive_reopen() {
    let store = Store::open(":memory:").unwrap();
    let g = fixture();
    store.save(&g, Some(&g), None).unwrap();
    store.tag("u", "owned", true).unwrap();
    let mut fresh = store.raw_graph().unwrap();
    store.apply_manual_tags(&mut fresh).unwrap();
    assert_eq!(fresh.nodes["u"].properties["system_tags"], "owned");
    assert!(fresh.nodes["u"].labels.contains("Tag_Owned"));
    assert_eq!(store.query("MATCH p=allShortestPaths((u {objectid:$source})-[:AD_ATTACK_PATHS*]->(g {objectid:$target})) RETURN length(p) AS length",&json!({"source":"u","target":"g"})).unwrap()["rows"],json!([{"length":1}]));
    store.tag("u", "owned", false).unwrap();
    assert_eq!(
        store.graph().unwrap().nodes["u"].properties["system_tags"],
        ""
    );
}
#[test]
fn query_timeout_is_an_error_and_connection_recovers() {
    let mut store = Store::open(":memory:").unwrap();
    store.set_query_timeout(std::time::Duration::ZERO);
    assert!(
        store
            .query("UNWIND range(1,100000) AS n RETURN sum(n)", &json!({}))
            .is_err()
    );
    store.set_query_timeout(std::time::Duration::from_secs(3));
    assert_eq!(
        store.query("RETURN true AS ok", &json!({})).unwrap()["rows"],
        json!([{"ok":true}])
    );
}

#[test]
fn inconsistent_identity_rolls_back_graph_raw_snapshot_and_metadata() {
    let store = Store::open(":memory:").unwrap();
    let g = fixture();
    store
        .save(&g, Some(&g), Some(("test_report", &json!({"version":1}))))
        .unwrap();
    for bad in [json!("wrong"), json!(null)] {
        let mut broken = g.clone();
        broken
            .nodes
            .get_mut("u")
            .unwrap()
            .properties
            .insert("objectid".into(), bad);
        assert!(
            store
                .save(
                    &broken,
                    Some(&broken),
                    Some(("test_report", &json!({"version":2})))
                )
                .is_err()
        );
        assert_eq!(store.graph().unwrap().snapshot().nodes, g.snapshot().nodes);
        assert_eq!(store.graph().unwrap().snapshot().edges, g.snapshot().edges);
        assert_eq!(
            store.raw_graph().unwrap().snapshot().nodes,
            g.snapshot().nodes
        );
        assert_eq!(
            store.metadata("test_report").unwrap(),
            Some(json!({"version":1}))
        );
    }
}

#[test]
fn import_history_retains_batches_and_rolls_back_with_graph() {
    use beagle::ingest::{apply_import, ingest_paths, ingest_paths_with_existing};

    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("history.db");
    let input = |name: &str| {
        let path = temp.path().join(format!("{name}.json"));
        std::fs::write(
            &path,
            json!({
                "meta":{"type":"users","version":6,"count":1},
                "data":[{"ObjectIdentifier":name,"Properties":{"name":name},
                    "FutureCollectorField":{"retained":name}}]
            })
            .to_string(),
        )
        .unwrap();
        path
    };
    let (mut graph, report_a) = ingest_paths(&[input("a")]).unwrap();
    let report_a = json!({"ingest":report_a});
    let store = Store::open(&db).unwrap();
    // Legacy databases have only last_import; the first new import must keep it.
    store
        .save(&graph, Some(&graph), Some(("last_import", &report_a)))
        .unwrap();
    assert_eq!(store.import_history().unwrap(), vec![report_a.clone()]);
    let (batch_b, report_b) = ingest_paths_with_existing(&[input("b")], &graph).unwrap();
    apply_import(&mut graph, &batch_b, &report_b);
    let report_b = json!({"ingest":report_b});
    store.save_import(&graph, &graph, &report_b, false).unwrap();
    let expected_history = vec![report_a.clone(), report_b.clone()];
    assert_eq!(store.import_history().unwrap(), expected_history);
    assert_eq!(
        store.metadata("last_import").unwrap(),
        Some(report_b.clone())
    );
    assert_eq!(store.graph().unwrap().nodes.len(), 2);
    assert_eq!(
        store.import_history().unwrap()[0]["ingest"]["retained_fields"][0]["fields"]["FutureCollectorField"],
        json!({"retained":"a"})
    );
    assert_eq!(
        store.import_history().unwrap()[1]["ingest"]["source_records"][0]["data"]["FutureCollectorField"],
        json!({"retained":"b"})
    );
    let mut broken = graph.clone();
    broken.upsert_edge(Edge {
        source: "missing".into(),
        target: "A".into(),
        kind: "MemberOf".into(),
        ..Default::default()
    });
    for replace in [false, true] {
        assert!(
            store
                .save_import(&broken, &broken, &json!({"rejected":true}), replace)
                .is_err()
        );
        assert_eq!(store.import_history().unwrap(), expected_history);
        assert_eq!(
            store.metadata("last_import").unwrap(),
            Some(report_b.clone())
        );
        assert_eq!(
            store.graph().unwrap().snapshot().nodes,
            graph.snapshot().nodes
        );
        assert_eq!(
            store.graph().unwrap().snapshot().edges,
            graph.snapshot().edges
        );
        assert_eq!(
            store.raw_graph().unwrap().snapshot().nodes,
            graph.snapshot().nodes
        );
        assert_eq!(
            store.raw_graph().unwrap().snapshot().edges,
            graph.snapshot().edges
        );
    }
    drop(store);
    let store = Store::open(&db).unwrap();
    assert_eq!(store.import_history().unwrap(), expected_history);
    store
        .save_import(&batch_b, &batch_b, &report_b, true)
        .unwrap();
    assert_eq!(store.import_history().unwrap(), vec![report_b.clone()]);
    assert_eq!(
        store.graph().unwrap().snapshot().nodes,
        batch_b.snapshot().nodes
    );
    assert_eq!(
        store.raw_graph().unwrap().snapshot().nodes,
        batch_b.snapshot().nodes
    );
    drop(store);
    assert_eq!(
        Store::open(&db).unwrap().import_history().unwrap(),
        vec![report_b]
    );
}

fn assert_protected_users_saved_query(guid: &str, delegable_only: bool) {
    let store = Store::open(":memory:").unwrap();
    let query = beagle::query::prepare_saved(guid, &json!({})).unwrap();
    let mut graph = GraphData::default();
    for (id, tier_zero, enabled) in [
        ("enabled-admin", true, true),
        ("disabled-admin", true, false),
        ("ordinary-user", false, true),
    ] {
        let mut labels = BTreeSet::from(["Base".into(), "User".into()]);
        if tier_zero {
            labels.insert("Tag_Tier_Zero".into());
        }
        graph.upsert_node(Node {
            objectid: id.into(),
            labels,
            properties: json!({"enabled":enabled,"sensitive":false})
                .as_object()
                .unwrap()
                .clone(),
        });
    }
    for id in ["domain-525", "unrelated-group", "nested-group"] {
        graph.ensure_node(id, "Group");
    }
    let membership = |source: &str, target: &str| Edge {
        source: source.into(),
        target: target.into(),
        kind: "MemberOf".into(),
        ..Default::default()
    };
    let assert_ids = |graph: &GraphData, stage: &str, expected: &[&str]| {
        store.save(graph, None, None).unwrap();
        let result = store.query(&query, &json!({})).unwrap();
        assert_eq!(result["columns"], json!(["m"]), "{stage}");
        let mut ids: Vec<_> = result["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                row["m"]["properties"]["objectid"]
                    .as_str()
                    .expect("preserved outer row must return its original node")
                    .to_owned()
            })
            .collect();
        ids.sort();
        let mut expected = expected.to_vec();
        expected.sort();
        assert_eq!(ids, expected, "{stage}: {query}");
    };
    let unprotected: &[&str] = if delegable_only {
        &["enabled-admin"]
    } else {
        &["enabled-admin", "disabled-admin"]
    };
    let only_disabled: &[&str] = if delegable_only {
        &[]
    } else {
        &["disabled-admin"]
    };

    // An empty optional path produces an empty COLLECT, preserving each m.
    assert_ids(&graph, "empty Protected Users group", unprotected);
    graph.upsert_edge(membership("enabled-admin", "unrelated-group"));
    graph.upsert_edge(membership("ordinary-user", "unrelated-group"));
    assert_ids(
        &graph,
        "paths exist only to a nonmatching group",
        unprotected,
    );

    graph.upsert_edge(membership("enabled-admin", "domain-525"));
    assert_ids(&graph, "direct Protected Users membership", only_disabled);
    graph
        .edges
        .retain(|_, edge| !(edge.source == "enabled-admin" && edge.target == "domain-525"));
    graph.upsert_edge(membership("enabled-admin", "nested-group"));
    graph.upsert_edge(membership("nested-group", "domain-525"));
    assert_ids(
        &graph,
        "transitive Protected Users membership",
        only_disabled,
    );

    graph.upsert_edge(membership("disabled-admin", "domain-525"));
    assert_ids(&graph, "all tier-zero users are protected", &[]);
    graph.nodes.remove("domain-525");
    graph.edges.retain(|_, edge| edge.target != "domain-525");
    assert_ids(&graph, "Protected Users group is absent", unprotected);
}

#[test]
fn tier_zero_delegable_accounts_preserve_empty_optional_match() {
    assert_protected_users_saved_query("4316eaf1-6af0-4879-8f55-ac2633a711c3", true);
}

#[test]
fn tier_zero_unprotected_users_preserve_empty_optional_match() {
    assert_protected_users_saved_query("543eb01d-9fa3-4b8f-a936-b46bbfdaa2ae", false);
}
