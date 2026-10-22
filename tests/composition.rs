use beagle::composition::{compose, relay_targets};
use beagle::{Edge, GraphData, Node};
use serde_json::json;
use std::collections::BTreeSet;
fn node(g: &mut GraphData, id: &str, label: &str, props: serde_json::Value) {
    g.upsert_node(Node {
        objectid: id.into(),
        labels: BTreeSet::from(["Base".into(), label.into()]),
        properties: props.as_object().unwrap().clone(),
    });
}
fn edge(g: &mut GraphData, s: &str, t: &str, k: &str) {
    g.upsert_edge(Edge {
        source: s.into(),
        target: t.into(),
        kind: k.into(),
        properties: Default::default(),
        derived: false,
    });
}
#[test]
fn known_noncomposable_edge_is_empty_and_missing_edge_errors() {
    let mut g = GraphData::default();
    node(&mut g, "u", "User", json!({}));
    node(&mut g, "g", "Group", json!({}));
    edge(&mut g, "u", "g", "MemberOf");
    assert!(compose(&g, "u", "g", "MemberOf").unwrap().nodes.is_empty());
    assert!(relay_targets(&g, "u", "g", "MemberOf").unwrap().is_empty());
    assert!(compose(&g, "g", "u", "MemberOf").is_err());
}
#[test]
fn ldap_targets_require_all_collected_flags_and_same_domain() {
    let mut g = GraphData::default();
    node(&mut g, "auth", "Group", json!({"domainsid":"D"}));
    node(&mut g, "victim", "Computer", json!({}));
    for (id, props) in [
        (
            "dc",
            json!({"domainsid":"D","isdc":true,"ldapavailable":true,"ldapsigning":false}),
        ),
        (
            "unknown",
            json!({"domainsid":"D","isdc":true,"ldapavailable":true}),
        ),
        (
            "other",
            json!({"domainsid":"X","isdc":true,"ldapavailable":true,"ldapsigning":false}),
        ),
    ] {
        node(&mut g, id, "Computer", props);
    }
    edge(&mut g, "auth", "victim", "CoerceAndRelayNTLMToLDAP");
    let result = relay_targets(&g, "auth", "victim", "CoerceAndRelayNTLMToLDAP").unwrap();
    assert_eq!(
        result
            .iter()
            .map(|n| n.objectid.as_str())
            .collect::<Vec<_>>(),
        vec!["dc"]
    );
}
#[test]
fn golden_cert_requires_both_cert_chain_and_ntauth_and_excludes_chords() {
    let mut g = GraphData::default();
    for (id, k) in [
        ("h", "Computer"),
        ("ca", "EnterpriseCA"),
        ("root", "RootCA"),
        ("nt", "NTAuthStore"),
        ("d", "Domain"),
        ("unrelated", "Group"),
    ] {
        node(&mut g, id, k, json!({}));
    }
    for (s, t, k) in [
        ("h", "d", "GoldenCert"),
        ("h", "ca", "HostsCAService"),
        ("ca", "root", "EnterpriseCAFor"),
        ("root", "d", "RootCAFor"),
        ("ca", "nt", "TrustedForNTAuth"),
        ("nt", "d", "NTAuthStoreFor"),
        ("h", "ca", "GenericAll"),
        ("unrelated", "ca", "Enroll"),
    ] {
        edge(&mut g, s, t, k);
    }
    let result = compose(&g, "h", "d", "GoldenCert").unwrap();
    assert_eq!(result.nodes.len(), 5);
    assert_eq!(result.edges.len(), 5);
    assert!(
        !result
            .edges
            .iter()
            .any(|e| e.kind == "GenericAll" || e.kind == "GoldenCert")
    );
    node(&mut g, "extra", "NTAuthStore", json!({}));
    edge(&mut g, "d", "extra", "TrustedForNTAuth");
    assert!(
        compose(&g, "h", "d", "GoldenCert")
            .unwrap()
            .edges
            .is_empty()
    );
    g.edges.retain(|_, e| e.source != "d");
    g.edges.retain(|_, e| e.kind != "NTAuthStoreFor");
    assert!(
        compose(&g, "h", "d", "GoldenCert")
            .unwrap()
            .edges
            .is_empty()
    );
}
#[test]
fn esc3_retains_direct_self_enrollment_agent_edge() {
    let mut g = GraphData::default();
    for (id, k) in [
        ("u", "User"),
        ("ca", "EnterpriseCA"),
        ("root", "RootCA"),
        ("nt", "NTAuthStore"),
        ("d", "Domain"),
    ] {
        node(&mut g, id, k, json!({}));
    }
    node(
        &mut g,
        "ct",
        "CertTemplate",
        json!({"requiresmanagerapproval":false,"schemaversion":1,"authenticationenabled":true,"subjectaltrequiredns":false,"subjectaltrequiredomaindns":false}),
    );
    for (s, t, k) in [
        ("u", "d", "ADCSESC3"),
        ("u", "ct", "Enroll"),
        ("u", "ca", "Enroll"),
        ("ct", "ct", "EnrollOnBehalfOf"),
        ("ct", "ca", "PublishedTo"),
        ("ca", "root", "EnterpriseCAFor"),
        ("root", "d", "RootCAFor"),
        ("ca", "nt", "TrustedForNTAuth"),
        ("nt", "d", "NTAuthStoreFor"),
    ] {
        edge(&mut g, s, t, k);
    }
    let result = compose(&g, "u", "d", "ADCSESC3").unwrap();
    assert!(
        result
            .edges
            .iter()
            .any(|e| e.source == "ct" && e.target == "ct" && e.kind == "EnrollOnBehalfOf")
    );
    assert_eq!(result.edges.len(), 8);
}

#[test]
fn pattern_membership_cycles_are_excluded_like_dawgs() {
    let mut graph = GraphData::default();
    for (id, label) in [
        ("u", "User"),
        ("a", "Group"),
        ("b", "Group"),
        ("ca", "EnterpriseCA"),
        ("root", "RootCA"),
        ("nt", "NTAuthStore"),
        ("d", "Domain"),
    ] {
        node(&mut graph, id, label, json!({}));
    }
    node(
        &mut graph,
        "ct",
        "CertTemplate",
        json!({"requiresmanagerapproval":false,"schemaversion":1,"authenticationenabled":true,"enrolleesuppliessubject":true}),
    );
    for (source, target, kind) in [
        ("u", "d", "ADCSESC1"),
        ("u", "a", "MemberOf"),
        ("a", "b", "MemberOf"),
        ("b", "a", "MemberOf"),
        ("b", "ct", "Enroll"),
        ("b", "ca", "Enroll"),
        ("ct", "ca", "PublishedTo"),
        ("ca", "root", "EnterpriseCAFor"),
        ("root", "d", "RootCAFor"),
        ("ca", "nt", "TrustedForNTAuth"),
        ("nt", "d", "NTAuthStoreFor"),
    ] {
        edge(&mut graph, source, target, kind);
    }
    let result = compose(&graph, "u", "d", "ADCSESC1").unwrap();
    assert_eq!(result.edges.len(), 9);
    assert!(
        !result
            .edges
            .iter()
            .any(|e| e.source == "b" && e.target == "a")
    );
}

#[test]
fn deep_pattern_returns_explicit_limit_error_on_a_small_stack() {
    std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| {
            let mut graph = GraphData::default();
            node(&mut graph, "u", "User", json!({}));
            node(&mut graph, "d", "Domain", json!({}));
            edge(&mut graph, "u", "d", "ADCSESC1");
            let mut previous = "u".to_owned();
            for index in 0..4097 {
                let id = format!("group-{index}");
                node(&mut graph, &id, "Group", json!({}));
                edge(&mut graph, &previous, &id, "MemberOf");
                previous = id;
            }
            let error = compose(&graph, "u", "d", "ADCSESC1").unwrap_err();
            assert!(error.to_string().contains("no partial graph returned"));
        })
        .unwrap()
        .join()
        .unwrap();
}
