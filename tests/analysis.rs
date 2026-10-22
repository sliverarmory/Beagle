//! Regression expectations are derived from BloodHound CE v9.8.0's
//! analysis/ad/{post,local_groups,owns,esc*,ntlm}.go and integration tests.
use beagle::analysis::analyze;
use beagle::{Edge, GraphData, Node};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const D: &str = "S-1-5-21-1-2-3";
fn node(g: &mut GraphData, id: &str, label: &str, props: Value) {
    g.upsert_node(Node {
        objectid: id.into(),
        labels: BTreeSet::from(["Base".into(), label.into()]),
        properties: props.as_object().unwrap().clone(),
    });
}
fn edge(g: &mut GraphData, a: &str, b: &str, k: &str) {
    g.upsert_edge(Edge {
        source: a.into(),
        target: b.into(),
        kind: k.into(),
        ..Default::default()
    });
}
fn has(g: &GraphData, a: &str, b: &str, k: &str) -> bool {
    g.edges
        .values()
        .any(|e| e.source == a && e.target == b && e.kind == k)
}
fn sources(g: &GraphData, target: &str, kind: &str) -> BTreeSet<String> {
    g.edges
        .values()
        .filter(|e| e.target == target && e.kind == kind)
        .map(|e| e.source.clone())
        .collect()
}
fn base() -> GraphData {
    let mut g = GraphData::default();
    node(
        &mut g,
        D,
        "Domain",
        json!({"name":"LAB.LOCAL","domainsid":D,"collected":true,"functionallevel":"2016"}),
    );
    g
}
fn account(g: &mut GraphData, id: &str, label: &str) {
    node(g, id, label, json!({"domainsid":D}));
}

#[test]
fn replication_rights_intersect_transitive_groups_without_redundant_member_edges() {
    let mut g = base();
    for id in ["left", "right", "shared"] {
        account(&mut g, id, "Group");
    }
    for id in ["alice", "bob"] {
        account(&mut g, id, "User");
    }
    edge(&mut g, "shared", "left", "MemberOf");
    edge(&mut g, "shared", "right", "MemberOf");
    edge(&mut g, "alice", "shared", "MemberOf");
    edge(&mut g, "bob", "left", "MemberOf");
    edge(&mut g, "left", D, "GetChanges");
    edge(&mut g, "right", D, "GetChangesAll");
    analyze(&mut g).unwrap();
    assert_eq!(sources(&g, D, "DCSync"), BTreeSet::from(["shared".into()]));
    // The MemberOf cycle must terminate and retain the common component.
    edge(&mut g, "left", "shared", "MemberOf");
    analyze(&mut g).unwrap();
    assert!(!sources(&g, D, "DCSync").is_empty());
}
#[test]
fn special_groups_shortcut_permissions_and_uncollected_domains_fail_closed() {
    let mut g = base();
    account(&mut g, "alice", "User");
    node(
        &mut g,
        "LAB.LOCAL-S-1-5-11",
        "Group",
        json!({"domainsid":D}),
    );
    edge(&mut g, "LAB.LOCAL-S-1-5-11", D, "GetChanges");
    edge(&mut g, "alice", D, "GetChangesAll");
    analyze(&mut g).unwrap();
    assert_eq!(sources(&g, D, "DCSync"), BTreeSet::from(["alice".into()]));
    g.nodes
        .get_mut(D)
        .unwrap()
        .properties
        .insert("collected".into(), json!(false));
    analyze(&mut g).unwrap();
    assert!(sources(&g, D, "DCSync").is_empty());
}
#[test]
fn laps_and_adminsdholder_are_scoped_to_domain_and_collection() {
    let mut g = base();
    account(&mut g, "alice", "User");
    edge(&mut g, "alice", D, "GetChanges");
    edge(&mut g, "alice", D, "GetChangesInFilteredSet");
    node(
        &mut g,
        "laps",
        "Computer",
        json!({"domainsid":D,"haslaps":true}),
    );
    node(&mut g, "unknown", "Computer", json!({"domainsid":D}));
    node(
        &mut g,
        "other",
        "Computer",
        json!({"domainsid":"other","haslaps":true}),
    );
    node(
        &mut g,
        "holder",
        "Container",
        json!({"domainsid":D,"distinguishedname":"CN=ADMINSDHOLDER,CN=SYSTEM,DC=LAB,DC=LOCAL"}),
    );
    node(
        &mut g,
        "protected",
        "User",
        json!({"domainsid":D,"adminsdholderprotected":true}),
    );
    analyze(&mut g).unwrap();
    assert!(has(&g, "alice", "laps", "SyncLAPSPassword"));
    assert!(!has(&g, "alice", "unknown", "SyncLAPSPassword"));
    assert!(!has(&g, "alice", "other", "SyncLAPSPassword"));
    assert!(has(&g, "holder", "protected", "ProtectAdminGroups"));
}
#[test]
fn local_groups_project_direct_members_and_rdp_requires_logon_right() {
    let mut g = base();
    account(&mut g, "pc", "Computer");
    account(&mut g, "alice", "User");
    account(&mut g, "team", "Group");
    edge(&mut g, "alice", "team", "MemberOf");
    for (suffix, kind) in [
        ("544", "AdminTo"),
        ("580", "CanPSRemote"),
        ("562", "ExecuteDCOM"),
        ("555", "CanRDP"),
    ] {
        let group = format!("PC-S-1-5-32-{suffix}");
        account(&mut g, &group, "ADLocalGroup");
        edge(&mut g, &group, "pc", "LocalToComputer");
        edge(&mut g, "team", &group, "MemberOfLocalGroup");
        if kind != "CanRDP" {
            analyze(&mut g).unwrap();
            assert!(has(&g, "team", "pc", kind));
            assert!(!has(&g, "alice", "pc", kind));
        }
    }
    analyze(&mut g).unwrap();
    assert!(!has(&g, "team", "pc", "CanRDP"));
    edge(&mut g, "alice", "pc", "RemoteInteractiveLogonRight");
    analyze(&mut g).unwrap();
    assert_eq!(
        sources(&g, "pc", "CanRDP"),
        BTreeSet::from(["alice".into()])
    );
    edge(
        &mut g,
        "PC-S-1-5-32-555",
        "pc",
        "RemoteInteractiveLogonRight",
    );
    analyze(&mut g).unwrap();
    assert_eq!(sources(&g, "pc", "CanRDP"), BTreeSet::from(["team".into()]));
}
#[test]
fn ownership_respects_dsheuristics_and_domain_admin_exception() {
    let mut g = base();
    g.nodes
        .get_mut(D)
        .unwrap()
        .properties
        .insert("dsheuristics".into(), json!(format!("{}1", "0".repeat(28))));
    for (id, label) in [
        ("owner", "User"),
        ("admin", "User"),
        ("pc", "Computer"),
        ("user", "User"),
        ("gmsa", "User"),
    ] {
        account(&mut g, id, label);
    }
    g.nodes
        .get_mut("gmsa")
        .unwrap()
        .properties
        .insert("gmsa".into(), json!(true));
    let da = format!("{D}-512");
    account(&mut g, &da, "Group");
    edge(&mut g, "admin", &da, "MemberOf");
    for target in ["pc", "user", "gmsa"] {
        for source in ["owner", "admin"] {
            edge(&mut g, source, target, "OwnsRaw");
            edge(&mut g, source, target, "WriteOwnerRaw");
        }
    }
    analyze(&mut g).unwrap();
    assert!(!has(&g, "owner", "pc", "Owns"));
    assert!(has(&g, "admin", "pc", "Owns"));
    assert!(!has(&g, "admin", "pc", "WriteOwner"));
    assert!(has(&g, "owner", "user", "WriteOwner"));
    assert!(!has(&g, "owner", "gmsa", "Owns"));
    g.nodes
        .get_mut(D)
        .unwrap()
        .properties
        .insert("dsheuristics".into(), json!(""));
    analyze(&mut g).unwrap();
    assert!(has(&g, "owner", "pc", "Owns"));
    assert!(has(&g, "admin", "pc", "WriteOwner"));
}
#[test]
fn trusts_use_outbound_direction_and_trust_account_netbios() {
    let mut g = base();
    g.nodes
        .get_mut(D)
        .unwrap()
        .properties
        .insert("netbios".into(), json!("LAB"));
    node(
        &mut g,
        "foreign",
        "Domain",
        json!({"domainsid":"foreign","collected":true}),
    );
    node(
        &mut g,
        "trust",
        "User",
        json!({"domainsid":"foreign","samaccountname":"LAB$"}),
    );
    edge(&mut g, D, "foreign", "CrossForestTrust");
    analyze(&mut g).unwrap();
    assert!(has(&g, D, "trust", "HasTrustKeys"));
    assert!(!has(&g, "foreign", "trust", "HasTrustKeys"));
}
fn adcs_graph() -> GraphData {
    let mut g = base();
    account(&mut g, "alice", "User");
    node(
        &mut g,
        "ca-host",
        "Computer",
        json!({"domainsid":D,"enabled":true}),
    );
    node(
        &mut g,
        "ca",
        "EnterpriseCA",
        json!({"domainsid":D,"certthumbprint":"LEAF","certchain":["LEAF","ROOT"],"isuserspecifiessanenabledcollected":true,"isuserspecifiessanenabled":true,"enrollmentagentrestrictionscollected":false,"hasvulnerableendpoint":true}),
    );
    node(&mut g, "root", "RootCA", json!({"certthumbprint":"ROOT"}));
    node(
        &mut g,
        "ntauth",
        "NTAuthStore",
        json!({"certthumbprints":["LEAF"]}),
    );
    node(
        &mut g,
        "template",
        "CertTemplate",
        json!({"domainsid":D,"requiresmanagerapproval":false,"authenticationenabled":true,"enrolleesuppliessubject":true,"schemaversion":2,"authorizedsignatures":0,"nosecurityextension":true,"schannelauthenticationenabled":true,"subjectaltrequiredns":false,"subjectaltrequiredomaindns":false,"subjectaltrequireupn":true,"subjectaltrequirespn":false,"effectiveekus":["1.3.6.1.5.5.7.3.2"]}),
    );
    for (a, b, k) in [
        ("ca-host", "ca", "HostsCAService"),
        ("root", D, "RootCAFor"),
        ("ntauth", D, "NTAuthStoreFor"),
        ("template", "ca", "PublishedTo"),
        ("alice", "ca", "Enroll"),
        ("alice", "template", "Enroll"),
    ] {
        edge(&mut g, a, b, k);
    }
    node(
        &mut g,
        "dc",
        "Computer",
        json!({"domainsid":D,"certificatemappingmethodsraw":4,"strongcertificatebindingenforcementraw":1}),
    );
    edge(&mut g, "dc", D, "DCFor");
    g
}
#[test]
fn adcs_requires_both_ca_chains_and_enabled_in_forest_host() {
    let mut g = adcs_graph();
    analyze(&mut g).unwrap();
    for k in ["ADCSESC1", "ADCSESC6a", "ADCSESC6b"] {
        assert!(has(&g, "alice", D, k), "{k}");
    }
    assert!(has(&g, "ca-host", D, "GoldenCert"));
    assert!(has(&g, "ca", "root", "IssuedSignedBy"));
    g.nodes
        .get_mut("ca-host")
        .unwrap()
        .properties
        .insert("enabled".into(), json!(false));
    analyze(&mut g).unwrap();
    assert!(!has(&g, "alice", D, "ADCSESC1"));
    assert!(!has(&g, "ca-host", D, "GoldenCert"));
    g.nodes
        .get_mut("ca-host")
        .unwrap()
        .properties
        .insert("enabled".into(), json!(true));
    g.nodes
        .get_mut("ntauth")
        .unwrap()
        .properties
        .insert("certthumbprints".into(), json!([]));
    analyze(&mut g).unwrap();
    assert!(!has(&g, "alice", D, "ADCSESC1"));
}
#[test]
fn adcs_cross_forest_host_is_rejected_and_same_forest_host_allowed() {
    let mut g = adcs_graph();
    node(&mut g, "foreign", "Domain", json!({"domainsid":"foreign"}));
    g.nodes
        .get_mut("ca-host")
        .unwrap()
        .properties
        .insert("domainsid".into(), json!("foreign"));
    edge(&mut g, "foreign", D, "CrossForestTrust");
    analyze(&mut g).unwrap();
    assert!(!has(&g, "alice", D, "ADCSESC1"));
    edge(&mut g, "foreign", D, "SameForestTrust");
    analyze(&mut g).unwrap();
    assert!(has(&g, "alice", D, "ADCSESC1"));
}
#[test]
fn adcs_template_unknowns_fail_closed_and_schannel_fallback_works() {
    let mut g = adcs_graph();
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .remove("requiresmanagerapproval");
    analyze(&mut g).unwrap();
    assert!(!has(&g, "alice", D, "ADCSESC1"));
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("requiresmanagerapproval".into(), json!(false));
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .remove("schannelauthenticationenabled");
    analyze(&mut g).unwrap();
    assert!(has(&g, "alice", D, "ADCSESC6b"));
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("subjectaltrequiredns".into(), json!(true));
    analyze(&mut g).unwrap();
    assert!(!has(&g, "alice", D, "ADCSESC6a"));
    g.nodes
        .get_mut("alice")
        .unwrap()
        .properties
        .insert("gmsa".into(), json!(true));
    analyze(&mut g).unwrap();
    assert!(has(&g, "alice", D, "ADCSESC6a"));
}
#[test]
fn esc4_permission_combinations_and_esc13_policy_scope() {
    let mut g = adcs_graph();
    account(&mut g, "writer", "User");
    edge(&mut g, "writer", "ca", "Enroll");
    edge(&mut g, "writer", "template", "GenericWrite");
    analyze(&mut g).unwrap();
    assert!(!has(&g, "writer", D, "ADCSESC4"));
    edge(&mut g, "writer", "template", "Enroll");
    analyze(&mut g).unwrap();
    assert!(has(&g, "writer", D, "ADCSESC4"));
    node(
        &mut g,
        "policy",
        "IssuancePolicy",
        json!({"domainsid":D,"certtemplateoid":"1.2.3.4"}),
    );
    account(&mut g, "privileged", "Group");
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("certificatepolicy".into(), json!(["1.2.3.4"]));
    edge(&mut g, "policy", "privileged", "OIDGroupLink");
    edge(&mut g, D, "privileged", "Contains");
    analyze(&mut g).unwrap();
    assert!(has(&g, "template", "policy", "ExtendedByPolicy"));
    assert!(has(&g, "alice", "privileged", "ADCSESC13"));
    g.nodes
        .get_mut("policy")
        .unwrap()
        .properties
        .insert("domainsid".into(), json!("other"));
    analyze(&mut g).unwrap();
    assert!(!has(&g, "alice", "privileged", "ADCSESC13"));
}
#[test]
fn esc9_and_10_require_victim_control_and_mapping_configuration() {
    let mut g = adcs_graph();
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("enrolleesuppliessubject".into(), json!(false));
    account(&mut g, "attacker", "User");
    edge(&mut g, "attacker", "alice", "GenericWrite");
    analyze(&mut g).unwrap();
    assert!(has(&g, "attacker", D, "ADCSESC9a"));
    assert!(has(&g, "attacker", D, "ADCSESC10a"));
    assert!(!has(&g, "attacker", D, "ADCSESC9b"));
    g.nodes
        .get_mut("dc")
        .unwrap()
        .properties
        .insert("strongcertificatebindingenforcementraw".into(), json!(2));
    g.nodes
        .get_mut("dc")
        .unwrap()
        .properties
        .insert("certificatemappingmethodsraw".into(), json!(-1));
    analyze(&mut g).unwrap();
    assert!(!has(&g, "attacker", D, "ADCSESC9a"));
    assert!(!has(&g, "attacker", D, "ADCSESC10a"));
}
#[test]
fn esc3_enrollment_agent_restrictions_and_template_pair() {
    let mut g = adcs_graph();
    let mut agent = g.nodes["template"].clone();
    agent.objectid = "agent".into();
    agent
        .properties
        .insert("effectiveekus".into(), json!(["1.3.6.1.4.1.311.20.2.1"]));
    g.upsert_node(agent);
    edge(&mut g, "agent", "ca", "PublishedTo");
    edge(&mut g, "alice", "agent", "Enroll");
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("schemaversion".into(), json!(1));
    analyze(&mut g).unwrap();
    assert!(has(&g, "agent", "template", "EnrollOnBehalfOf"));
    assert!(has(&g, "alice", D, "ADCSESC3"));
    g.nodes
        .get_mut("ca")
        .unwrap()
        .properties
        .insert("enrollmentagentrestrictionscollected".into(), json!(true));
    g.nodes
        .get_mut("ca")
        .unwrap()
        .properties
        .insert("hasenrollmentagentrestrictions".into(), json!(true));
    analyze(&mut g).unwrap();
    assert!(!has(&g, "alice", D, "ADCSESC3"));
    edge(&mut g, "alice", "template", "DelegatedEnrollmentAgent");
    analyze(&mut g).unwrap();
    assert!(has(&g, "alice", D, "ADCSESC3"));
}
#[test]
fn ntlm_relay_missing_flags_protection_self_relay_and_adcs() {
    let mut g = adcs_graph();
    node(
        &mut g,
        "victim",
        "Computer",
        json!({"domainsid":D,"restrictoutboundntlm":false,"webclientrunning":true}),
    );
    node(
        &mut g,
        "smb",
        "Computer",
        json!({"domainsid":D,"smbsigning":false}),
    );
    account(&mut g, "smb-544", "ADLocalGroup");
    edge(&mut g, "smb-544", "smb", "LocalToComputer");
    edge(&mut g, "victim", "smb-544", "MemberOfLocalGroup");
    for (k, v) in [
        ("isdc", true),
        ("ldapavailable", true),
        ("ldapsavailable", true),
        ("ldapsigning", false),
        ("ldapsepa", false),
    ] {
        g.nodes
            .get_mut("dc")
            .unwrap()
            .properties
            .insert(k.into(), json!(v));
    }
    edge(&mut g, "victim", "ca", "Enroll");
    edge(&mut g, "victim", "template", "Enroll");
    analyze(&mut g).unwrap();
    let auth = "LAB.LOCAL-S-1-5-11";
    for (target, k) in [
        ("smb", "CoerceAndRelayNTLMToSMB"),
        ("victim", "CoerceAndRelayNTLMToLDAP"),
        ("victim", "CoerceAndRelayNTLMToLDAPS"),
        ("victim", "CoerceAndRelayNTLMToADCS"),
    ] {
        assert!(has(&g, auth, target, k), "{k}");
    }
    g.nodes
        .get_mut("victim")
        .unwrap()
        .properties
        .remove("restrictoutboundntlm");
    analyze(&mut g).unwrap();
    assert!(!has(&g, auth, "smb", "CoerceAndRelayNTLMToSMB"));
    assert!(!has(&g, auth, "victim", "CoerceAndRelayNTLMToLDAP"));
    g.nodes
        .get_mut("victim")
        .unwrap()
        .properties
        .insert("restrictoutboundntlm".into(), json!(false));
    let protected = format!("{D}-525");
    account(&mut g, &protected, "Group");
    edge(&mut g, "victim", &protected, "MemberOf");
    analyze(&mut g).unwrap();
    assert!(!has(&g, auth, "victim", "CoerceAndRelayNTLMToADCS"));
    g.nodes
        .get_mut(D)
        .unwrap()
        .properties
        .insert("functionallevel".into(), json!("2012"));
    analyze(&mut g).unwrap();
    assert!(has(&g, auth, "victim", "CoerceAndRelayNTLMToADCS"));
}
#[test]
fn reruns_are_idempotent_remove_stale_derived_edges_and_preserve_collected_edges() {
    let mut g = base();
    account(&mut g, "alice", "User");
    edge(&mut g, "alice", D, "GetChanges");
    edge(&mut g, "alice", D, "GetChangesAll");
    edge(&mut g, "alice", D, "Owns");
    let report = analyze(&mut g).unwrap();
    let first = g.snapshot();
    let second = analyze(&mut g).unwrap();
    assert_eq!(first.nodes, g.snapshot().nodes);
    assert_eq!(first.edges, g.snapshot().edges);
    assert_eq!(report.edges_created, second.edges_created);
    assert!(!second.unsupported_gaps.is_empty());
    g.edges.retain(|_, e| e.kind != "GetChangesAll");
    analyze(&mut g).unwrap();
    assert!(!has(&g, "alice", D, "DCSync"));
    assert!(has(&g, "alice", D, "Owns"));
}

#[test]
fn esc9b_and_esc10b_use_computer_victims_and_ignore_write_public_information() {
    let mut g = adcs_graph();
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("enrolleesuppliessubject".into(), json!(false));
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("subjectaltrequiredns".into(), json!(true));
    account(&mut g, "victim", "Computer");
    account(&mut g, "attacker", "User");
    edge(&mut g, "victim", "template", "Enroll");
    edge(&mut g, "victim", "ca", "Enroll");
    edge(&mut g, "attacker", "victim", "WritePublicInformation");
    analyze(&mut g).unwrap();
    assert!(!has(&g, "attacker", D, "ADCSESC9b"));
    assert!(!has(&g, "attacker", D, "ADCSESC10b"));
    edge(&mut g, "attacker", "victim", "WriteDacl");
    analyze(&mut g).unwrap();
    assert!(has(&g, "attacker", D, "ADCSESC9b"));
    assert!(has(&g, "attacker", D, "ADCSESC10b"));
}
#[test]
fn enrollment_agent_v2_requires_signatures_policy_and_appropriate_eku() {
    let mut g = adcs_graph();
    let mut agent = g.nodes["template"].clone();
    agent.objectid = "agent".into();
    agent
        .properties
        .insert("effectiveekus".into(), json!(["1.3.6.1.4.1.311.20.2.1"]));
    g.upsert_node(agent);
    edge(&mut g, "agent", "ca", "PublishedTo");
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("authorizedsignatures".into(), json!(1));
    g.nodes.get_mut("template").unwrap().properties.insert(
        "applicationpolicies".into(),
        json!(["1.3.6.1.4.1.311.20.2.1"]),
    );
    analyze(&mut g).unwrap();
    assert!(has(&g, "agent", "template", "EnrollOnBehalfOf"));
    g.nodes.get_mut("agent").unwrap().properties.insert(
        "effectiveekus".into(),
        json!(["1.3.6.1.4.1.311.20.2.1", "2.5.29.37.0"]),
    );
    analyze(&mut g).unwrap();
    assert!(!has(&g, "agent", "template", "EnrollOnBehalfOf"));
}
#[test]
fn default_tier_zero_expands_members_and_parents_without_tagging_ou_siblings() {
    let mut g = base();
    let da = format!("{D}-512");
    account(&mut g, &da, "Group");
    account(&mut g, "alice", "User");
    account(&mut g, "bob", "User");
    edge(&mut g, "alice", &da, "MemberOf");
    account(&mut g, "ou", "OU");
    account(&mut g, "gpo", "GPO");
    edge(&mut g, "ou", "alice", "Contains");
    edge(&mut g, "ou", "bob", "Contains");
    edge(&mut g, "gpo", "ou", "GPLink");
    analyze(&mut g).unwrap();
    for id in ["alice", "ou", "gpo"] {
        assert!(g.nodes[id].labels.contains("Tag_Tier_Zero"));
        assert_eq!(g.nodes[id].properties["system_tags"], "admin_tier_0");
    }
    assert!(!g.nodes["bob"].labels.contains("Tag_Tier_Zero"));
}
#[test]
fn computer_scoped_local_group_wins_over_ambiguous_domain_builtin_suffix() {
    let mut g = base();
    account(&mut g, "pc", "Computer");
    account(&mut g, "alice", "User");
    account(&mut g, "bob", "User");
    for id in ["LAB.LOCAL-S-1-5-32-544", "pc-544"] {
        account(&mut g, id, "ADLocalGroup");
        edge(&mut g, id, "pc", "LocalToComputer");
    }
    edge(
        &mut g,
        "bob",
        "LAB.LOCAL-S-1-5-32-544",
        "MemberOfLocalGroup",
    );
    edge(&mut g, "alice", "pc-544", "MemberOfLocalGroup");
    analyze(&mut g).unwrap();
    assert_eq!(
        sources(&g, "pc", "AdminTo"),
        BTreeSet::from(["alice".into()])
    );
}
#[test]
fn citrix_requires_direct_access_membership_and_logon_right() {
    let mut g = base();
    account(&mut g, "pc", "Computer");
    account(&mut g, "alice", "User");
    account(&mut g, "bob", "User");
    node(
        &mut g,
        "rdp-555",
        "ADLocalGroup",
        json!({"name":"REMOTE DESKTOP USERS@PC"}),
    );
    node(
        &mut g,
        "dau",
        "ADLocalGroup",
        json!({"name":"Direct Access Users"}),
    );
    for id in ["rdp-555", "dau"] {
        edge(&mut g, id, "pc", "LocalToComputer");
    }
    for id in ["alice", "bob"] {
        edge(&mut g, id, "rdp-555", "MemberOfLocalGroup");
        edge(&mut g, id, "pc", "RemoteInteractiveLogonRight");
    }
    edge(&mut g, "alice", "dau", "MemberOfLocalGroup");
    analyze(&mut g).unwrap();
    assert_eq!(
        sources(&g, "pc", "CanRDP"),
        BTreeSet::from(["alice".into()])
    );
    // The upstream DAU lookup is a case-insensitive prefix, restricted to
    // ADLocalGroup; a similarly named domain Group does not enable Citrix.
    g.nodes
        .get_mut("dau")
        .unwrap()
        .properties
        .insert("name".into(), json!("dIrEcT AcCeSs UsErS extra"));
    analyze(&mut g).unwrap();
    assert_eq!(
        sources(&g, "pc", "CanRDP"),
        BTreeSet::from(["alice".into()])
    );
    g.nodes
        .get_mut("dau")
        .unwrap()
        .labels
        .remove("ADLocalGroup");
    g.nodes
        .get_mut("dau")
        .unwrap()
        .labels
        .insert("Group".into());
    analyze(&mut g).unwrap();
    assert_eq!(
        sources(&g, "pc", "CanRDP"),
        BTreeSet::from(["alice".into(), "bob".into()])
    );
}
#[test]
fn ntlm_relay_never_uses_self_as_sole_target() {
    let mut g = base();
    node(
        &mut g,
        "pc",
        "Computer",
        json!({"domainsid":D,"isdc":true,"ldapavailable":true,"ldapsigning":false,"webclientrunning":true,"restrictoutboundntlm":false,"smbsigning":false}),
    );
    account(&mut g, "pc-544", "ADLocalGroup");
    edge(&mut g, "pc-544", "pc", "LocalToComputer");
    edge(&mut g, "pc", "pc-544", "MemberOfLocalGroup");
    analyze(&mut g).unwrap();
    assert!(!has(
        &g,
        "LAB.LOCAL-S-1-5-11",
        "pc",
        "CoerceAndRelayNTLMToSMB"
    ));
    assert!(!has(
        &g,
        "LAB.LOCAL-S-1-5-11",
        "pc",
        "CoerceAndRelayNTLMToLDAP"
    ));
}

#[test]
#[ignore = "exports synthetic source graph for an independent live CE oracle run"]
fn export_analysis_synthetic_fixture() {
    let mut g = adcs_graph();
    g.nodes
        .get_mut(D)
        .unwrap()
        .properties
        .insert("distinguishedname".into(), json!("DC=LAB,DC=LOCAL"));
    account(&mut g, "attacker", "User");
    node(
        &mut g,
        "victim",
        "Computer",
        json!({"domainsid":D,"restrictoutboundntlm":false,"webclientrunning":true}),
    );
    node(
        &mut g,
        "smb",
        "Computer",
        json!({"domainsid":D,"smbsigning":false,"haslaps":true}),
    );
    edge(&mut g, "victim", "smb", "AdminTo");
    for (key, value) in [
        ("isdc", true),
        ("ldapavailable", true),
        ("ldapsavailable", true),
        ("ldapsigning", false),
        ("ldapsepa", false),
    ] {
        g.nodes
            .get_mut("dc")
            .unwrap()
            .properties
            .insert(key.into(), json!(value));
    }
    for id in ["victim", "attacker"] {
        edge(&mut g, id, "ca", "Enroll");
        edge(&mut g, id, "template", "Enroll");
    }
    edge(&mut g, "attacker", "alice", "GenericWrite");
    edge(&mut g, "attacker", "victim", "GenericWrite");
    edge(&mut g, "attacker", "template", "GenericWrite");
    let mut victim_template = g.nodes["template"].clone();
    victim_template.objectid = "victim-template".into();
    victim_template
        .properties
        .insert("enrolleesuppliessubject".into(), json!(false));
    victim_template
        .properties
        .insert("subjectaltrequiredns".into(), json!(true));
    g.upsert_node(victim_template);
    edge(&mut g, "victim-template", "ca", "PublishedTo");
    edge(&mut g, "victim", "victim-template", "Enroll");
    let mut user_template = g.nodes["victim-template"].clone();
    user_template.objectid = "user-template".into();
    user_template
        .properties
        .insert("subjectaltrequiredns".into(), json!(false));
    g.upsert_node(user_template);
    edge(&mut g, "user-template", "ca", "PublishedTo");
    edge(&mut g, "alice", "user-template", "Enroll");
    let mut agent = g.nodes["template"].clone();
    agent.objectid = "agent".into();
    agent
        .properties
        .insert("effectiveekus".into(), json!(["1.3.6.1.4.1.311.20.2.1"]));
    g.upsert_node(agent);
    edge(&mut g, "agent", "ca", "PublishedTo");
    edge(&mut g, "attacker", "agent", "Enroll");
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("schemaversion".into(), json!(1));
    node(
        &mut g,
        "policy",
        "IssuancePolicy",
        json!({"domainsid":D,"certtemplateoid":"1.2.3.4"}),
    );
    account(&mut g, "privileged", "Group");
    g.nodes
        .get_mut("template")
        .unwrap()
        .properties
        .insert("certificatepolicy".into(), json!(["1.2.3.4"]));
    edge(&mut g, "policy", "privileged", "OIDGroupLink");
    edge(&mut g, D, "privileged", "Contains");
    for right in ["GetChanges", "GetChangesAll", "GetChangesInFilteredSet"] {
        edge(&mut g, "attacker", D, right);
    }
    node(
        &mut g,
        "holder",
        "Container",
        json!({"domainsid":D,"distinguishedname":"CN=ADMINSDHOLDER,CN=SYSTEM,DC=LAB,DC=LOCAL"}),
    );
    g.nodes
        .get_mut("alice")
        .unwrap()
        .properties
        .insert("adminsdholderprotected".into(), json!(true));
    for (suffix, right) in [
        ("544", "AdminTo"),
        ("555", "CanRDP"),
        ("580", "CanPSRemote"),
        ("562", "ExecuteDCOM"),
    ] {
        let id = format!("smb-{suffix}");
        account(&mut g, &id, "ADLocalGroup");
        edge(&mut g, &id, "smb", "LocalToComputer");
        edge(&mut g, "attacker", &id, "MemberOfLocalGroup");
        if right == "CanRDP" {
            edge(&mut g, &id, "smb", "RemoteInteractiveLogonRight");
        }
    }
    for (principal, right) in [("raw-owner", "OwnsRaw"), ("raw-writer", "WriteOwnerRaw")] {
        account(&mut g, principal, "User");
        edge(&mut g, principal, "ca", "Enroll");
        edge(&mut g, principal, "template", right);
    }
    edge(&mut g, "attacker", "smb", "OwnsRaw");
    edge(&mut g, "attacker", "smb", "WriteOwnerRaw");
    std::fs::write(
        std::env::var("BH_SYNTHETIC_OUT").unwrap(),
        serde_json::to_vec_pretty(&g.snapshot()).unwrap(),
    )
    .unwrap();
}

#[test]
fn analysis_options_match_ura_citrix_and_ntlm_feature_switches() {
    use beagle::analysis::{AnalysisOptions, analyze_with_options};
    let mut g = base();
    for (id, label) in [
        ("pc", "Computer"),
        ("alice", "User"),
        ("bob", "User"),
        ("pc-555", "ADLocalGroup"),
    ] {
        account(&mut g, id, label);
    }
    node(
        &mut g,
        "dau",
        "ADLocalGroup",
        json!({"name":"Direct Access Users"}),
    );
    for group in ["pc-555", "dau"] {
        edge(&mut g, group, "pc", "LocalToComputer");
    }
    for id in ["alice", "bob"] {
        edge(&mut g, id, "pc-555", "MemberOfLocalGroup");
    }
    edge(&mut g, "alice", "dau", "MemberOfLocalGroup");
    let mut options = AnalysisOptions {
        enforce_ura: false,
        restrict_citrix: false,
        ..Default::default()
    };
    analyze_with_options(&mut g, &options).unwrap();
    assert_eq!(
        sources(&g, "pc", "CanRDP"),
        BTreeSet::from(["alice".into(), "bob".into()])
    );
    options.restrict_citrix = true;
    analyze_with_options(&mut g, &options).unwrap();
    assert_eq!(
        sources(&g, "pc", "CanRDP"),
        BTreeSet::from(["alice".into()])
    );
    // A collected hasura=true keeps URA enforcement enabled even if the global
    // setting is false, matching FetchCanRDPEntityBitmapForComputer.
    g.nodes
        .get_mut("pc")
        .unwrap()
        .properties
        .insert("hasura".into(), json!(true));
    analyze_with_options(&mut g, &options).unwrap();
    assert!(sources(&g, "pc", "CanRDP").is_empty());
    edge(&mut g, "bob", "pc", "RemoteInteractiveLogonRight");
    options.restrict_citrix = false;
    analyze_with_options(&mut g, &options).unwrap();
    assert_eq!(sources(&g, "pc", "CanRDP"), BTreeSet::from(["bob".into()]));

    node(
        &mut g,
        "source",
        "Computer",
        json!({"domainsid":D,"restrictoutboundntlm":false}),
    );
    node(
        &mut g,
        "target",
        "Computer",
        json!({"domainsid":D,"smbsigning":false}),
    );
    account(&mut g, "target-544", "ADLocalGroup");
    edge(&mut g, "target-544", "target", "LocalToComputer");
    edge(&mut g, "source", "target-544", "MemberOfLocalGroup");
    analyze_with_options(&mut g, &options).unwrap();
    assert!(has(
        &g,
        "LAB.LOCAL-S-1-5-11",
        "target",
        "CoerceAndRelayNTLMToSMB"
    ));
    options.ntlm_enabled = false;
    analyze_with_options(&mut g, &options).unwrap();
    assert!(!has(
        &g,
        "LAB.LOCAL-S-1-5-11",
        "target",
        "CoerceAndRelayNTLMToSMB"
    ));
}

#[test]
fn asset_group_expansion_respects_independent_modes_and_missing_seeds() {
    use beagle::analysis::expand_asset_group;
    let mut g = base();
    for (id, label) in [
        ("group", "Group"),
        ("alice", "User"),
        ("bob", "User"),
        ("ou", "OU"),
        ("gpo", "GPO"),
    ] {
        account(&mut g, id, label);
    }
    edge(&mut g, "alice", "group", "MemberOf");
    edge(&mut g, "ou", "alice", "Contains");
    edge(&mut g, "ou", "bob", "Contains");
    edge(&mut g, "gpo", "ou", "GPLink");
    let seeds = BTreeSet::from(["group".into(), "missing".into()]);
    assert_eq!(
        expand_asset_group(&g, &seeds, false, false),
        BTreeSet::from(["group".into()])
    );
    assert_eq!(
        expand_asset_group(&g, &seeds, true, false),
        BTreeSet::from(["group".into(), "alice".into()])
    );
    assert_eq!(
        expand_asset_group(&g, &seeds, true, true),
        BTreeSet::from(["group".into(), "alice".into(), "ou".into(), "gpo".into()])
    );
    assert_eq!(
        expand_asset_group(&g, &BTreeSet::from(["alice".into()]), false, true),
        BTreeSet::from(["alice".into(), "ou".into(), "gpo".into()])
    );
}

#[test]
fn ownership_refresh_follows_adcs_and_retains_previous_pass_until_refresh() {
    let mut g = adcs_graph();
    for (id, raw) in [("owner", "OwnsRaw"), ("writer", "WriteOwnerRaw")] {
        account(&mut g, id, "User");
        edge(&mut g, id, "ca", "Enroll");
        edge(&mut g, id, "template", raw);
    }
    analyze(&mut g).unwrap();
    assert!(has(&g, "owner", "template", "Owns"));
    assert!(has(&g, "writer", "template", "WriteOwner"));
    for id in ["owner", "writer"] {
        assert!(!has(&g, id, D, "ADCSESC4"));
    }
    analyze(&mut g).unwrap();
    for id in ["owner", "writer"] {
        assert!(has(&g, id, D, "ADCSESC4"));
    }
    g.edges
        .retain(|_, e| !matches!(e.kind.as_str(), "OwnsRaw" | "WriteOwnerRaw"));
    analyze(&mut g).unwrap();
    assert!(!has(&g, "owner", "template", "Owns"));
    assert!(!has(&g, "writer", "template", "WriteOwner"));
    // ADCS observes the previous ownership snapshot once, just like the CE
    // post-processing order, then loses the path on the following pass.
    for id in ["owner", "writer"] {
        assert!(has(&g, id, D, "ADCSESC4"));
    }
    analyze(&mut g).unwrap();
    for id in ["owner", "writer"] {
        assert!(!has(&g, id, D, "ADCSESC4"));
    }
}

#[test]
fn supplied_transit_edges_are_deleted_before_recomputation_like_ce() {
    let mut g = base();
    node(
        &mut g,
        "source",
        "Computer",
        json!({"domainsid":D,"restrictoutboundntlm":false}),
    );
    node(
        &mut g,
        "target",
        "Computer",
        json!({"domainsid":D,"smbsigning":false}),
    );
    edge(&mut g, "source", "target", "AdminTo");
    analyze(&mut g).unwrap();
    assert!(!has(&g, "source", "target", "AdminTo"));
    assert!(!has(
        &g,
        "LAB.LOCAL-S-1-5-11",
        "target",
        "CoerceAndRelayNTLMToSMB"
    ));
    account(&mut g, "target-544", "ADLocalGroup");
    edge(&mut g, "target-544", "target", "LocalToComputer");
    edge(&mut g, "source", "target-544", "MemberOfLocalGroup");
    analyze(&mut g).unwrap();
    assert!(has(&g, "source", "target", "AdminTo"));
    assert!(has(
        &g,
        "LAB.LOCAL-S-1-5-11",
        "target",
        "CoerceAndRelayNTLMToSMB"
    ));
}

#[test]
fn default_tier_zero_recomputes_tags_after_membership_removal() {
    let mut g = base();
    let da = format!("{D}-512");
    account(&mut g, &da, "Group");
    account(&mut g, "alice", "User");
    g.nodes
        .get_mut("alice")
        .unwrap()
        .labels
        .insert("Tag_Owned".into());
    edge(&mut g, "alice", &da, "MemberOf");
    analyze(&mut g).unwrap();
    assert!(g.nodes["alice"].labels.contains("Tag_Tier_Zero"));
    assert_eq!(g.nodes["alice"].properties["system_tags"], "admin_tier_0");
    g.edges
        .retain(|_, e| !(e.source == "alice" && e.target == da && e.kind == "MemberOf"));
    analyze(&mut g).unwrap();
    assert!(!g.nodes["alice"].labels.contains("Tag_Tier_Zero"));
    assert!(!g.nodes["alice"].properties.contains_key("system_tags"));
    assert!(g.nodes["alice"].labels.contains("Tag_Owned"));
}

#[test]
fn analysis_options_reject_unknown_fields_instead_of_enabling_defaults() {
    assert!(
        serde_json::from_value::<beagle::analysis::AnalysisOptions>(json!({"ntlm_enabeld":false}))
            .is_err()
    );
    assert!(
        !serde_json::from_value::<beagle::analysis::AnalysisOptions>(json!({"ntlm_enabled":false}))
            .unwrap()
            .ntlm_enabled
    );
}

#[test]
fn multiple_local_groups_report_selected_privileges_and_all_candidates() {
    let mut g = base();
    for (id, kind) in [
        ("computer", "Computer"),
        ("computer-544", "ADLocalGroup"),
        ("builtin-544", "ADLocalGroup"),
        ("a", "User"),
        ("b", "User"),
    ] {
        account(&mut g, id, kind);
    }
    edge(&mut g, "computer-544", "computer", "LocalToComputer");
    edge(&mut g, "builtin-544", "computer", "LocalToComputer");
    edge(&mut g, "a", "computer-544", "MemberOfLocalGroup");
    edge(&mut g, "b", "builtin-544", "MemberOfLocalGroup");
    let report = analyze(&mut g).unwrap();
    assert_eq!(report.local_group_ambiguities.len(), 1);
    let choice = &report.local_group_ambiguities[0];
    assert_eq!(choice.selected_group, "computer-544");
    assert_eq!(choice.computer, "computer");
    assert_eq!(choice.relationship_kind, "AdminTo");
    assert_eq!(choice.candidate_groups["computer-544"], vec!["a"]);
    assert_eq!(choice.candidate_groups["builtin-544"], vec!["b"]);
    assert_eq!(
        sources(&g, "computer", "AdminTo"),
        BTreeSet::from(["a".into()])
    );
}
