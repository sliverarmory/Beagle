use beagle::ingest::{apply_import, ingest_paths, ingest_paths_with_existing};
use beagle::model::{Edge, GraphData, Node};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, io::Read, path::PathBuf};

fn collection(t: &str, data: Value) -> Value {
    json!({"data":data,"meta":{"type":t,"version":6,"count":data.as_array().unwrap().len(),"methods":1}})
}
fn write(dir: &std::path::Path, name: &str, value: Value) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, serde_json::to_vec(&value).unwrap()).unwrap();
    p
}
fn clean(mut g: GraphData) -> GraphData {
    for n in g.nodes.values_mut() {
        n.properties.remove("lastseen");
        n.properties.remove("lastcollected");
    }
    for e in g.edges.values_mut() {
        e.properties.remove("lastseen");
    }
    g
}

#[test]
fn ingest_merges_stubs_preserves_types_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let group = write(
        dir.path(),
        "a_groups.json",
        collection(
            "groups",
            json!([{"ObjectIdentifier":"g","Properties":{"name":"group@lab"},"Members":[{"ObjectIdentifier":"u","ObjectType":"User"}]}]),
        ),
    );
    let user = write(
        dir.path(),
        "b_users.json",
        collection(
            "users",
            json!([{"ObjectIdentifier":"u","Properties":{"name":"user@lab","enabled":true,"admincount":1,"serviceprincipalnames":["host/a"]},"PrimaryGroupSID":"g"}]),
        ),
    );
    let (g, report) = ingest_paths(&[dir.path().into()]).unwrap();
    assert_eq!(report.records, 2);
    assert_eq!(g.nodes.len(), 2);
    assert_eq!(g.edges.len(), 1);
    let n = &g.nodes["U"];
    assert_eq!(n.labels, BTreeSet::from(["Base".into(), "User".into()]));
    assert_eq!(n.properties["name"], "USER@LAB");
    assert_eq!(n.properties["enabled"], true);
    assert_eq!(n.properties["admincount"], 1.0);
    assert_eq!(n.properties["serviceprincipalnames"], json!(["host/a"]));
    assert_eq!(
        serde_json::to_value(clean(g).snapshot()).unwrap(),
        serde_json::to_value(
            clean(
                ingest_paths(&[user.clone(), group.clone(), user, group])
                    .unwrap()
                    .0
            )
            .snapshot()
        )
        .unwrap()
    );
}

#[test]
fn ingest_incremental_null_updates_remove_properties_and_keep_last_write_order() {
    let dir = tempfile::tempdir().unwrap();
    let input = write(
        dir.path(),
        "users.json",
        collection(
            "users",
            json!([
                {"ObjectIdentifier":"u","Properties":{"name":"before","description":"remove","enabled":true,"stable":"keep"}}
            ]),
        ),
    );
    let (mut graph, _) = ingest_paths(std::slice::from_ref(&input)).unwrap();
    write(
        dir.path(),
        "users.json",
        collection(
            "users",
            json!([
                {"ObjectIdentifier":"u","Properties":{"name":null,"description":null,"enabled":null}},
                {"ObjectIdentifier":"u","Properties":{"name":"after","description":"temporary"}},
                {"ObjectIdentifier":"u","Properties":{"description":null}}
            ]),
        ),
    );
    let (incoming, report) = ingest_paths_with_existing(&[input], &graph).unwrap();
    apply_import(&mut graph, &incoming, &report);
    let properties = &graph.nodes["U"].properties;
    assert_eq!(properties["name"], "AFTER");
    assert_eq!(properties["stable"], "keep");
    assert!(!properties.contains_key("description"));
    assert!(!properties.contains_key("enabled"));
    assert!(report.property_deletions["U"].contains("description"));
}

#[test]
fn ingest_incremental_invalid_domain_and_trust_values_clear_old_properties() {
    let dir = tempfile::tempdir().unwrap();
    let make = |attr: Value, min: Value| {
        collection(
            "domains",
            json!([
                {"ObjectIdentifier":"domain","Properties":{"minpwdlength":min},"Trusts":[
                    {"TargetDomainSid":"trusted","TargetDomainName":"trusted.lab","TrustDirection":"Bidirectional","TrustType":"ParentChild","TrustAttributes":attr}
                ]}
            ]),
        )
    };
    let input = write(dir.path(), "domains.json", make(json!(8), json!(12)));
    let (mut graph, _) = ingest_paths(std::slice::from_ref(&input)).unwrap();
    write(
        dir.path(),
        "domains.json",
        make(Value::Null, json!("invalid")),
    );
    let (incoming, report) = ingest_paths_with_existing(&[input], &graph).unwrap();
    apply_import(&mut graph, &incoming, &report);
    assert!(
        !graph.nodes["DOMAIN"]
            .properties
            .contains_key("minpwdlength")
    );
    assert_eq!(report.edge_property_deletions.len(), 2);
    for edge in graph.edges.values() {
        assert!(!edge.properties.contains_key("trustattributesinbound"));
        assert!(!edge.properties.contains_key("trustattributesoutbound"));
    }
}

#[test]
fn ingest_null_distinguished_name_does_not_resolve_a_stale_reference() {
    let dir = tempfile::tempdir().unwrap();
    let input = write(
        dir.path(),
        "users.json",
        collection(
            "users",
            json!([
                {"ObjectIdentifier":"u","Properties":{"distinguishedname":"DN=CN=OLD,DC=LAB"}}
            ]),
        ),
    );
    let (existing, _) = ingest_paths(&[input]).unwrap();
    write(
        dir.path(),
        "users.json",
        collection(
            "users",
            json!([
                {"ObjectIdentifier":"u","Properties":{"distinguishedname":null}}
            ]),
        ),
    );
    write(
        dir.path(),
        "groups.json",
        collection(
            "groups",
            json!([
                {"ObjectIdentifier":"g","Members":[{"ObjectIdentifier":"DN=CN=OLD,DC=LAB","ObjectType":"User"}]}
            ]),
        ),
    );
    assert!(
        format!(
            "{:#}",
            ingest_paths_with_existing(&[dir.path().into()], &existing).unwrap_err()
        )
        .contains("unresolved distinguished-name")
    );
}

#[test]
fn ingest_resolves_distinguished_names_across_batches_without_refreshing_unrelated_nodes() {
    let dir = tempfile::tempdir().unwrap();
    let initial = write(
        dir.path(),
        "users.json",
        collection(
            "users",
            json!([
                {"ObjectIdentifier":"u","Properties":{"name":"user@lab","distinguishedname":"DN=CN=USER,DC=LAB"}},
                {"ObjectIdentifier":"unrelated","Properties":{"name":"unrelated@lab"}}
            ]),
        ),
    );
    let (existing, _) = ingest_paths(&[initial]).unwrap();
    let before = serde_json::to_value(existing.snapshot()).unwrap();
    let groups = write(
        dir.path(),
        "groups.json",
        collection(
            "groups",
            json!([
                {"ObjectIdentifier":"g","Members":[
                    {"ObjectIdentifier":"u","ObjectType":"User"},
                    {"ObjectIdentifier":"DN=CN=USER,DC=LAB","ObjectType":"User"}
                ]}
            ]),
        ),
    );
    assert!(ingest_paths(std::slice::from_ref(&groups)).is_err());
    let (incoming, _) = ingest_paths_with_existing(&[groups], &existing).unwrap();
    assert_eq!(incoming.edges.len(), 1);
    let relationship = incoming.edges.values().next().unwrap();
    assert_eq!(
        (
            &*relationship.source,
            &*relationship.kind,
            &*relationship.target
        ),
        ("U", "MemberOf", "G")
    );
    assert!(!incoming.nodes.contains_key("UNRELATED"));
    assert_eq!(serde_json::to_value(existing.snapshot()).unwrap(), before);
}

#[test]
fn ingest_new_distinguished_name_overrides_existing_and_rejects_ambiguous_names() {
    let dir = tempfile::tempdir().unwrap();
    let users = write(
        dir.path(),
        "users.json",
        collection(
            "users",
            json!([
                {"ObjectIdentifier":"u","Properties":{"distinguishedname":"DN=CN=OLD,DC=LAB"}}
            ]),
        ),
    );
    let (existing, _) = ingest_paths(std::slice::from_ref(&users)).unwrap();
    write(
        dir.path(),
        "users.json",
        collection(
            "users",
            json!([
                {"ObjectIdentifier":"u","Properties":{"distinguishedname":"DN=CN=NEW,DC=LAB"}}
            ]),
        ),
    );
    let groups = write(
        dir.path(),
        "groups.json",
        collection(
            "groups",
            json!([
                {"ObjectIdentifier":"g","Members":[{"ObjectIdentifier":"DN=CN=NEW,DC=LAB","ObjectType":"User"}]}
            ]),
        ),
    );
    assert!(ingest_paths_with_existing(&[users.clone(), groups.clone()], &existing).is_ok());
    write(
        dir.path(),
        "users.json",
        collection(
            "users",
            json!([
                {"ObjectIdentifier":"u","Properties":{"distinguishedname":"DN=CN=NEW,DC=LAB"}},
                {"ObjectIdentifier":"v","Properties":{"distinguishedname":"DN=CN=NEW,DC=LAB"}}
            ]),
        ),
    );
    assert!(
        format!(
            "{:#}",
            ingest_paths_with_existing(&[users, groups], &existing).unwrap_err()
        )
        .contains("ambiguous distinguished-name")
    );
}

#[test]
fn ingest_acl_owner_rights_keeps_raw_and_limited_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let input = write(
        dir.path(),
        "users.json",
        collection(
            "users",
            json!([
                {"ObjectIdentifier":"target","Properties":{},"Aces":[
                    {"PrincipalSID":"owner","PrincipalType":"User","RightName":"Owns","IsInherited":false},
                    {"PrincipalSID":"writer","PrincipalType":"Group","RightName":"WriteOwner","IsInherited":true,"InheritanceHash":"h"},
                    {"PrincipalSID":"domain-S-1-3-4","PrincipalType":"Group","RightName":"GenericAll","IsInherited":true}
                ]}
            ]),
        ),
    );
    let (g, _) = ingest_paths(&[input]).unwrap();
    let kinds: BTreeSet<_> = g.edges.values().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        BTreeSet::from(["OwnsLimitedRights", "WriteOwnerLimitedRights"])
    );
    let writer = g.edges.values().find(|e| e.source == "WRITER").unwrap();
    assert_eq!(writer.properties["privileges"], json!(["GenericAll"]));
    assert_eq!(writer.properties["inheritancehash"], "h");
}

#[test]
fn ingest_rejects_malformed_unsupported_and_unknown_ace() {
    let dir = tempfile::tempdir().unwrap();
    for value in [
        json!({"data":[],"meta":{"type":"users","version":4}}),
        json!({"data":[],"meta":{"type":"azure","version":6}}),
        collection("users", json!([{"ObjectIdentifier":"u","Sessions":3}])),
        collection(
            "users",
            json!([{"ObjectIdentifier":"u","Aces":[{"PrincipalSID":"a","RightName":"MadeUp"}]}]),
        ),
        collection(
            "groups",
            json!([{"ObjectIdentifier":"g","Members":[{"ObjectIdentifier":"u","ObjectType":"MadeUp"}]}]),
        ),
    ] {
        let file = write(dir.path(), "input.json", value);
        assert!(ingest_paths(&[file]).is_err());
    }
}

#[test]
fn ingest_unknown_fields_are_retained_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    let file = write(
        dir.path(),
        "input.json",
        collection(
            "users",
            json!([{"ObjectIdentifier":"u","FutureData":{"nested":[1,2]},"IsDeleted":false}]),
        ),
    );
    let (_, report) = ingest_paths(&[file]).unwrap();
    assert!(report.warnings.iter().any(|s| s.contains("FutureData")));
    assert_eq!(
        report.retained_fields[0].fields["FutureData"],
        json!({"nested":[1,2]})
    );
}

#[test]
fn ingest_sites_and_ca_registry() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "sites.json",
        collection(
            "sites",
            json!([{"ObjectIdentifier":"site","Properties":{},"Links":[{"Guid":"gpo","IsEnforced":true}],"ChildObjects":[{"ObjectIdentifier":"server","ObjectType":"SiteServer"}]}]),
        ),
    );
    write(
        dir.path(),
        "servers.json",
        collection(
            "siteservers",
            json!([{"ObjectIdentifier":"server","ServerIs":{"ObjectIdentifier":"dc","ObjectType":"Computer"}}]),
        ),
    );
    write(
        dir.path(),
        "ca.json",
        collection(
            "enterprisecas",
            json!([{"ObjectIdentifier":"ca","HostingComputer":"dc","EnabledCertTemplates":[{"ObjectIdentifier":"template","ObjectType":"CertTemplate"}],"HttpEnrollmentEndpoints":[{"Collected":true,"Result":{"Url":"http://ca/certsrv/","ADCSWebEnrollmentHTTP":true}}],"CARegistryData":{"IsUserSpecifiesSanEnabled":{"Collected":true,"Value":true}}}]),
        ),
    );
    let (g, _) = ingest_paths(&[dir.path().into()]).unwrap();
    assert_eq!(g.nodes["CA"].properties["hasvulnerableendpoint"], true);
    assert_eq!(g.nodes["CA"].properties["isuserspecifiessanenabled"], true);
    let rels: BTreeSet<_> = g.edges.values().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        rels,
        BTreeSet::from([
            "Contains",
            "GPLink",
            "ServerIs",
            "HostsCAService",
            "PublishedTo"
        ])
    );
}

#[test]
fn ingest_sessions_local_groups_delegation_and_sid_history_directions() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "computers.json",
        collection(
            "computers",
            json!([{
                "ObjectIdentifier":"computer","Properties":{"domainsid":"domain","unconstraineddelegation":true},
                "AllowedToAct":[{"ObjectIdentifier":"actor","ObjectType":"User"}],
                "AllowedToDelegate":[{"ObjectIdentifier":"delegate","ObjectType":"Computer"}],
                "HasSIDHistory":[{"ObjectIdentifier":"history","ObjectType":"Computer"}],
                "Sessions":{"Collected":true,"Results":[{"ComputerSID":"computer","UserSID":"session-user"}]},
                "PrivilegedSessions":{"Collected":false,"Results":[{"ComputerSID":"computer","UserSID":"not-collected"}]},
                "LocalGroups":[{"Collected":true,"ObjectIdentifier":"computer-544","Name":"administrators@computer","Results":[{"ObjectIdentifier":"admin","ObjectType":"User"}],"LocalNames":[{"ObjectIdentifier":"admin","PrincipalName":"administrator@computer"}]}],
                "UserRights":[{"Collected":true,"Privilege":"SeRemoteInteractiveLogonRight","Results":[{"ObjectIdentifier":"rdp-user","ObjectType":"User"}]}]
            }]),
        ),
    );
    let (g, _) = ingest_paths(&[dir.path().into()]).unwrap();
    let relationships: BTreeSet<_> = g
        .edges
        .values()
        .map(|e| (e.source.as_str(), e.kind.as_str(), e.target.as_str()))
        .collect();
    assert_eq!(
        relationships,
        BTreeSet::from([
            ("ACTOR", "AllowedToAct", "COMPUTER"),
            ("COMPUTER", "AllowedToDelegate", "DELEGATE"),
            ("COMPUTER", "HasSIDHistory", "HISTORY"),
            ("COMPUTER", "CoerceToTGT", "DOMAIN"),
            ("COMPUTER", "HasSession", "SESSION-USER"),
            ("COMPUTER-544", "LocalToComputer", "COMPUTER"),
            ("ADMIN", "MemberOfLocalGroup", "COMPUTER-544"),
            ("RDP-USER", "RemoteInteractiveLogonRight", "COMPUTER")
        ])
    );
    assert!(g.nodes["COMPUTER-544"].labels.contains("ADLocalGroup"));
    assert_eq!(g.nodes["COMPUTER"].properties["hasura"], true);
    assert_eq!(
        g.nodes["ADMIN"].properties["name"],
        "ADMINISTRATOR@COMPUTER"
    );
}

#[test]
fn ingest_trusts_gpo_changes_and_domain_property_normalization() {
    let dir = tempfile::tempdir().unwrap();
    let file = write(
        dir.path(),
        "domains.json",
        collection(
            "domains",
            json!([{
                "ObjectIdentifier":"domain","Properties":{"machineaccountquota":"10","expirepasswordsonsmartcardonlyaccounts":"TRUE"},
                "Trusts":[{"TargetDomainSid":"foreign","TargetDomainName":"foreign.local","TrustDirection":"Bidirectional","TrustType":"Forest","IsTransitive":true,"SidFilteringEnabled":false,"TGTDelegationEnabled":true,"TrustAttributes":"8"}],
                "GPOChanges":{"AffectedComputers":[{"ObjectIdentifier":"pc","ObjectType":"Computer"}],"LocalAdmins":[{"ObjectIdentifier":"u","ObjectType":"User"}]}
            }]),
        ),
    );
    let (g, _) = ingest_paths(&[file]).unwrap();
    assert_eq!(g.nodes["DOMAIN"].properties["machineaccountquota"], 10);
    assert_eq!(
        g.nodes["DOMAIN"].properties["expirepasswordsonsmartcardonlyaccounts"],
        true
    );
    let kinds: BTreeSet<_> = g.edges.values().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        BTreeSet::from([
            "CrossForestTrust",
            "SpoofSIDHistory",
            "AbuseTGTDelegation",
            "LocalToComputer",
            "MemberOfLocalGroup"
        ])
    );
    assert_eq!(g.edges.len(), 6);
    assert!(g.nodes["PC-544"].labels.contains("ADLocalGroup"));
}

#[test]
fn ingest_registry_and_properties_follow_upstream_precedence() {
    let dir = tempfile::tempdir().unwrap();
    let file = write(
        dir.path(),
        "computers.json",
        collection(
            "computers",
            json!([{
                "ObjectIdentifier":"dc","Properties":{"ldapenabled":true,"vulnerablenetlogonsecuritydescriptorcollected":true},
                "IsDC":true,"DomainSID":"domain",
                "NTLMRegistryData":{"Collected":true,"Result":{"RestrictSendingNtlmTraffic":2,"RestrictReceivingNTLMTraffic":0,"RequireSecuritySignature":1,"NtlmMinClientSec":536870912}},
                "DCRegistryData":{"CertificateMappingMethods":{"Collected":true,"Value":5},"StrongCertificateBindingEnforcement":{"Collected":true,"Value":2}}
            }]),
        ),
    );
    let (g, _) = ingest_paths(&[file]).unwrap();
    let p = &g.nodes["DC"].properties;
    assert_eq!(p["ldapavailable"], true);
    assert!(!p.contains_key("ldapenabled"));
    assert_eq!(p["restrictoutboundntlm"], true);
    assert_eq!(p["restrictreceivingntmltraffic"], false);
    assert_eq!(
        p["strongcertificatebindingenforcement"],
        "Full enforcement mode"
    );
    assert_eq!(
        p["certificatemappingmethods"],
        json!([
            "0x01: One-to-one (subject/issuer)",
            "0x04: User principal name (UPN/SAN)"
        ])
    );
    assert_eq!(p["vulnerablenetlogonsecuritydescriptorcollected"], true);
    assert!(g.edges.values().any(|e| e.kind == "DCFor"));
}

#[test]
fn ingest_owner_rights_blocks_unjustified_ownership_paths() {
    let dir = tempfile::tempdir().unwrap();
    for (any, inherited, expected) in [
        (false, false, vec!["OwnsRaw", "WriteOwnerRaw"]),
        (true, false, vec!["WriteOwnerRaw"]),
        (true, true, vec![]),
    ] {
        let file = write(
            dir.path(),
            "users.json",
            collection(
                "users",
                json!([{"ObjectIdentifier":"u","Properties":{"doesanyacegrantownerrights":any,"doesanyinheritedacegrantownerrights":inherited},"Aces":[
                    {"PrincipalSID":"owner","PrincipalType":"User","RightName":"Owns"},
                    {"PrincipalSID":"writer","PrincipalType":"User","RightName":"WriteOwner"}
                ]}]),
            ),
        );
        let (g, _) = ingest_paths(&[file]).unwrap();
        let actual: BTreeSet<_> = g.edges.values().map(|e| e.kind.as_str()).collect();
        assert_eq!(actual, expected.into_iter().collect());
    }
}

// Go's fixture JSON encoder renders integral float64 as JSON integer tokens,
// losing the native Neo4j numeric type. Only this serialized-fixture comparator
// normalizes numeric representation. ingest_oracle.rs compares native types.
fn serialized_fixture_numbers(mut graph: GraphData) -> GraphData {
    fn convert(value: &mut Value) {
        match value {
            Value::Number(number) => {
                *number = serde_json::Number::from_f64(number.as_f64().unwrap()).unwrap();
            }
            Value::Array(values) => values.iter_mut().for_each(convert),
            Value::Object(values) => values.values_mut().for_each(convert),
            _ => {}
        }
    }
    for node in graph.nodes.values_mut() {
        node.properties.values_mut().for_each(convert);
    }
    for edge in graph.edges.values_mut() {
        edge.properties.values_mut().for_each(convert);
    }
    graph
}

fn golden(value: Value) -> GraphData {
    let mut g = GraphData::default();
    for n in value["graph"]["nodes"].as_array().unwrap() {
        g.upsert_node(Node {
            objectid: n["id"].as_str().unwrap().into(),
            labels: n["kinds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().into())
                .collect(),
            properties: n["properties"].as_object().unwrap().clone(),
        });
    }
    for e in value["graph"]["edges"].as_array().unwrap() {
        g.upsert_edge(Edge {
            source: e["start"]["value"].as_str().unwrap().into(),
            target: e["end"]["value"].as_str().unwrap().into(),
            kind: e["kind"].as_str().unwrap().into(),
            properties: e["properties"].as_object().unwrap().clone(),
            derived: false,
        });
    }
    serialized_fixture_numbers(clean(g))
}

#[test]
#[ignore = "requires BLOODHOUND_UPSTREAM pointing to pinned BloodHound CE v9.8.0"]
fn ingest_matches_upstream_golden_corpus() {
    let root =
        PathBuf::from(std::env::var("BLOODHOUND_UPSTREAM").expect("set BLOODHOUND_UPSTREAM"));
    let root = root.join("cmd/api/src/services/graphify/fixtures");
    for fixture in [
        "Version5JSON",
        "Version6JSON",
        "Version5ZIP",
        "Version6ZIP",
        "Version6ADCSJSON",
        "Version6ADCSZIP",
        "Version6AllJSON",
        "Version6AllZIP",
    ] {
        // Upstream ZIP golden files are empty placeholders. Verify their raw
        // records equal the paired JSON corpus, then use that real CE golden.
        let oracle_fixture = fixture.replace("ZIP", "JSON");
        if fixture.ends_with("ZIP") {
            let mut archive = zip::ZipArchive::new(
                fs::File::open(root.join(fixture).join("raw/archive.zip")).unwrap(),
            )
            .unwrap();
            for index in 0..archive.len() {
                let mut member = archive.by_index(index).unwrap();
                if !member.name().ends_with(".json") {
                    continue;
                }
                let filename = PathBuf::from(member.name()).file_name().unwrap().to_owned();
                let mut bytes = Vec::new();
                member.read_to_end(&mut bytes).unwrap();
                let zipped: Value = serde_json::from_slice(&bytes).unwrap();
                let plain: Value = serde_json::from_slice(
                    &fs::read(root.join(&oracle_fixture).join("raw").join(filename)).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    zipped["data"], plain["data"],
                    "ZIP/JSON source divergence in {fixture}"
                );
            }
        }
        let expected = golden(
            serde_json::from_slice(
                &fs::read(root.join(&oracle_fixture).join("ingest/ingested.json")).unwrap(),
            )
            .unwrap(),
        );
        let (actual, report) = ingest_paths(&[root.join(fixture).join("raw")])
            .unwrap_or_else(|e| panic!("{fixture}: {e:#}"));
        let actual = serialized_fixture_numbers(clean(actual));
        let mut differences = Vec::new();
        for (id, n) in &expected.nodes {
            if actual.nodes.get(id) != Some(n) {
                differences.push(format!(
                    "node {id}: expected {n:?}, actual {:?}",
                    actual.nodes.get(id)
                ));
            }
        }
        for (id, n) in &actual.nodes {
            if !expected.nodes.contains_key(id) {
                differences.push(format!("extra node {n:?}"));
            }
        }
        for (key, e) in &expected.edges {
            if actual.edges.get(key) != Some(e) {
                differences.push(format!(
                    "edge {key:?}: expected {e:?}, actual {:?}",
                    actual.edges.get(key)
                ));
            }
        }
        for (key, e) in &actual.edges {
            if !expected.edges.contains_key(key) {
                differences.push(format!("extra edge {e:?}"));
            }
        }
        eprintln!(
            "{fixture}: records {}, nodes {}/{}, edges {}/{}, differences {}",
            report.records,
            actual.nodes.len(),
            expected.nodes.len(),
            actual.edges.len(),
            expected.edges.len(),
            differences.len()
        );
        assert!(
            differences.is_empty(),
            "{fixture}: {}",
            differences
                .into_iter()
                .take(20)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
