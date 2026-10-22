//! Expectations follow CE v9.8.0 analysis/ad/ntlm.go and dawgs v0.9.0
//! ops/traversal.go terminal/descent semantics.
use beagle::composition::{compose, relay_targets};
use beagle::{Edge, GraphData, GraphSnapshot, Node};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const D: &str = "S-1-5-21-1-2-3";
const AUTH: &str = "LAB.LOCAL-S-1-5-11";
fn node(g: &mut GraphData, id: &str, label: &str, props: Value) {
    g.upsert_node(Node {
        objectid: id.into(),
        labels: BTreeSet::from(["Base".into(), label.into()]),
        properties: props.as_object().unwrap().clone(),
    });
}
fn edge(g: &mut GraphData, source: &str, target: &str, kind: &str) {
    g.upsert_edge(Edge {
        source: source.into(),
        target: target.into(),
        kind: kind.into(),
        ..Default::default()
    });
}
fn keys(g: &GraphSnapshot) -> BTreeSet<(String, String, String)> {
    g.edges
        .iter()
        .map(|e| (e.source.clone(), e.target.clone(), e.kind.clone()))
        .collect()
}
fn ids(nodes: Vec<Node>) -> BTreeSet<String> {
    nodes.into_iter().map(|n| n.objectid).collect()
}
fn base() -> GraphData {
    let mut g = GraphData::default();
    node(
        &mut g,
        D,
        "Domain",
        json!({"domainsid":D,"name":"LAB.LOCAL","collected":true}),
    );
    node(&mut g, AUTH, "Group", json!({"domainsid":D}));
    node(
        &mut g,
        "target",
        "Computer",
        json!({"domainsid":D,"smbsigning":false}),
    );
    g
}

#[test]
fn smb_composition_and_targets_follow_only_qualifying_terminal_paths() {
    let mut g = base();
    node(
        &mut g,
        "group",
        "Group",
        json!({"domainsid":D,"restrictoutboundntlm":false}),
    );
    node(
        &mut g,
        "good",
        "Computer",
        json!({"domainsid":D,"restrictoutboundntlm":false}),
    );
    node(
        &mut g,
        "blocked",
        "Computer",
        json!({"domainsid":D,"restrictoutboundntlm":true}),
    );
    node(&mut g, "unknown", "Computer", json!({"domainsid":D}));
    node(
        &mut g,
        "foreign",
        "Computer",
        json!({"domainsid":"OTHER","restrictoutboundntlm":false}),
    );
    node(
        &mut g,
        "user",
        "User",
        json!({"domainsid":D,"restrictoutboundntlm":false}),
    );
    node(
        &mut g,
        "behind-computer",
        "Computer",
        json!({"domainsid":D,"restrictoutboundntlm":false}),
    );
    edge(&mut g, "group", "target", "AdminTo");
    for id in ["good", "blocked", "unknown", "foreign", "user"] {
        edge(&mut g, id, "group", "MemberOf");
    }
    edge(&mut g, "behind-computer", "good", "AdminTo");
    edge(&mut g, AUTH, "target", "CoerceAndRelayNTLMToSMB");
    let actual = compose(&g, AUTH, "target", "CoerceAndRelayNTLMToSMB").unwrap();
    assert_eq!(
        keys(&actual),
        BTreeSet::from([
            ("good".into(), "group".into(), "MemberOf".into()),
            ("group".into(), "target".into(), "AdminTo".into()),
        ])
    );
    assert_eq!(
        ids(relay_targets(&g, AUTH, "target", "CoerceAndRelayNTLMToSMB").unwrap()),
        BTreeSet::from(["good".into()])
    );
    // An eligible intermediary group is not a completed path when all of its
    // actual terminals are disqualified.
    g.nodes
        .get_mut("good")
        .unwrap()
        .properties
        .insert("restrictoutboundntlm".into(), json!(true));
    assert!(
        compose(&g, AUTH, "target", "CoerceAndRelayNTLMToSMB")
            .unwrap()
            .nodes
            .is_empty()
    );
    assert!(
        relay_targets(&g, AUTH, "target", "CoerceAndRelayNTLMToSMB")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn smb_cycles_stop_and_zero_edge_root_is_not_a_composition() {
    let mut g = base();
    g.nodes
        .get_mut("target")
        .unwrap()
        .properties
        .insert("restrictoutboundntlm".into(), json!(false));
    edge(&mut g, AUTH, "target", "CoerceAndRelayNTLMToSMB");
    assert!(
        compose(&g, AUTH, "target", "CoerceAndRelayNTLMToSMB")
            .unwrap()
            .nodes
            .is_empty()
    );
    edge(&mut g, "target", "target", "AdminTo");
    assert!(
        compose(&g, AUTH, "target", "CoerceAndRelayNTLMToSMB")
            .unwrap()
            .nodes
            .is_empty()
    );
    assert!(
        relay_targets(&g, AUTH, "target", "CoerceAndRelayNTLMToSMB")
            .unwrap()
            .is_empty()
    );
    for id in ["a", "b"] {
        node(&mut g, id, "Group", json!({"domainsid":D}));
    }
    node(
        &mut g,
        "coercible",
        "Computer",
        json!({"domainsid":D,"restrictoutboundntlm":false}),
    );
    edge(&mut g, "a", "target", "AdminTo");
    edge(&mut g, "a", "b", "MemberOf");
    edge(&mut g, "b", "a", "MemberOf");
    edge(&mut g, "coercible", "b", "MemberOf");
    assert_eq!(
        ids(relay_targets(&g, AUTH, "target", "CoerceAndRelayNTLMToSMB").unwrap()),
        BTreeSet::from(["coercible".into()])
    );
    assert_eq!(
        compose(&g, AUTH, "target", "CoerceAndRelayNTLMToSMB")
            .unwrap()
            .edges
            .len(),
        3
    );
}

#[test]
fn ldap_targets_use_source_domain_and_explicit_protocol_flags() {
    let mut g = base();
    for (id, props) in [
        (
            "ldap",
            json!({"domainsid":D,"isdc":true,"ldapavailable":true,"ldapsigning":false}),
        ),
        (
            "ldaps",
            json!({"domainsid":D,"isdc":true,"ldapsavailable":true,"ldapsepa":false}),
        ),
        (
            "secure",
            json!({"domainsid":D,"isdc":true,"ldapavailable":true,"ldapsigning":true,"ldapsavailable":true,"ldapsepa":true}),
        ),
        (
            "unknown",
            json!({"domainsid":D,"isdc":true,"ldapavailable":true}),
        ),
        (
            "foreign",
            json!({"domainsid":"OTHER","isdc":true,"ldapavailable":true,"ldapsigning":false}),
        ),
    ] {
        node(&mut g, id, "Computer", props);
    }
    for kind in ["CoerceAndRelayNTLMToLDAP", "CoerceAndRelayNTLMToLDAPS"] {
        edge(&mut g, AUTH, "target", kind);
    }
    assert_eq!(
        ids(relay_targets(&g, AUTH, "target", "CoerceAndRelayNTLMToLDAP").unwrap()),
        BTreeSet::from(["ldap".into()])
    );
    assert_eq!(
        ids(relay_targets(&g, AUTH, "target", "CoerceAndRelayNTLMToLDAPS").unwrap()),
        BTreeSet::from(["ldaps".into()])
    );
    assert!(
        compose(&g, AUTH, "target", "CoerceAndRelayNTLMToLDAP")
            .unwrap()
            .nodes
            .is_empty()
    );
    g.nodes
        .get_mut(AUTH)
        .unwrap()
        .properties
        .remove("domainsid");
    assert!(relay_targets(&g, AUTH, "target", "CoerceAndRelayNTLMToLDAP").is_err());
}

#[test]
fn adcs_relay_composition_intersects_template_and_ca_enrollment_chains() {
    let mut g = base();
    node(
        &mut g,
        "template",
        "CertTemplate",
        json!({"requiresmanagerapproval":false,"authenticationenabled":true,"schemaversion":2,"authorizedsignatures":0}),
    );
    node(
        &mut g,
        "ca",
        "EnterpriseCA",
        json!({"hasvulnerableendpoint":true}),
    );
    node(&mut g, "root", "RootCA", json!({}));
    node(&mut g, "ntauth", "NTAuthStore", json!({}));
    for (a, b, k) in [
        ("target", "template", "Enroll"),
        ("template", "ca", "PublishedTo"),
        ("ca", "root", "IssuedSignedBy"),
        ("root", D, "RootCAFor"),
        (AUTH, "ca", "Enroll"),
        ("ca", "ntauth", "TrustedForNTAuth"),
        ("ntauth", D, "NTAuthStoreFor"),
    ] {
        edge(&mut g, a, b, k);
    }
    edge(&mut g, AUTH, "target", "CoerceAndRelayNTLMToADCS");
    assert_eq!(
        compose(&g, AUTH, "target", "CoerceAndRelayNTLMToADCS")
            .unwrap()
            .edges
            .len(),
        7
    );
    assert_eq!(
        ids(relay_targets(&g, AUTH, "target", "CoerceAndRelayNTLMToADCS").unwrap()),
        BTreeSet::from(["ca".into()])
    );
    // Composition checks its two chains and template predicate; it does not
    // add a host or outbound-NTLM prerequisite absent from the CE routine.
    g.nodes
        .get_mut("ca")
        .unwrap()
        .properties
        .insert("hasvulnerableendpoint".into(), json!(false));
    assert!(
        compose(&g, AUTH, "target", "CoerceAndRelayNTLMToADCS")
            .unwrap()
            .nodes
            .is_empty()
    );
    g.nodes
        .get_mut("ca")
        .unwrap()
        .properties
        .insert("hasvulnerableendpoint".into(), json!(true));
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("authorizedsignatures".into(), json!(1));
    assert!(
        compose(&g, AUTH, "target", "CoerceAndRelayNTLMToADCS")
            .unwrap()
            .nodes
            .is_empty()
    );
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("schemaversion".into(), json!(1));
    assert_eq!(
        compose(&g, AUTH, "target", "CoerceAndRelayNTLMToADCS")
            .unwrap()
            .edges
            .len(),
        7
    );
    g.edges.retain(|_, e| e.kind != "TrustedForNTAuth");
    assert!(
        compose(&g, AUTH, "target", "CoerceAndRelayNTLMToADCS")
            .unwrap()
            .nodes
            .is_empty()
    );
}

#[test]
fn local_group_evidence_produces_a_positive_smb_edge_and_composition() {
    let mut g = base();
    node(
        &mut g,
        "coercible",
        "Computer",
        json!({"domainsid":D,"restrictoutboundntlm":false}),
    );
    node(&mut g, "target-544", "ADLocalGroup", json!({"domainsid":D}));
    edge(&mut g, "coercible", "target-544", "MemberOfLocalGroup");
    edge(&mut g, "target-544", "target", "LocalToComputer");
    beagle::analysis::analyze(&mut g).unwrap();
    assert_eq!(
        keys(&compose(&g, AUTH, "target", "CoerceAndRelayNTLMToSMB").unwrap()),
        BTreeSet::from([("coercible".into(), "target".into(), "AdminTo".into())])
    );
    assert_eq!(
        ids(relay_targets(&g, AUTH, "target", "CoerceAndRelayNTLMToSMB").unwrap()),
        BTreeSet::from(["coercible".into()])
    );
}
