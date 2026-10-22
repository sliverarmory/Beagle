//! BloodHound CE v9.8.0 AD edge explanations and NTLM relay targets.
//!
//! This follows the composition routines, which are deliberately distinct from
//! the predicates that create an attack edge. Returned graphs contain only edges
//! in qualifying component paths, never an induced neighborhood.
mod ntlm;

use crate::model::{Edge, EdgeKey, GraphData, GraphSnapshot, Node};
use anyhow::{Context as _, Result, bail};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
};

type Set = BTreeSet<String>;
// Canonical AD kind strings from pinned graphschema/ad/ad.go.
const VALID_AD_KINDS: &[&str] = &[
    "ADCSESC1",
    "ADCSESC10a",
    "ADCSESC10b",
    "ADCSESC13",
    "ADCSESC3",
    "ADCSESC4",
    "ADCSESC6a",
    "ADCSESC6b",
    "ADCSESC9a",
    "ADCSESC9b",
    "ADLocalGroup",
    "ADLocalUser",
    "AIACA",
    "AbuseTGTDelegation",
    "AddAllowedToAct",
    "AddKeyCredentialLink",
    "AddMember",
    "AddSelf",
    "AdminTo",
    "AllExtendedRights",
    "AllowedToAct",
    "AllowedToDelegate",
    "Base",
    "CanApplyGPO",
    "CanPSRemote",
    "CanRDP",
    "CertTemplate",
    "ClaimSpecialIdentity",
    "CoerceAndRelayNTLMToADCS",
    "CoerceAndRelayNTLMToLDAP",
    "CoerceAndRelayNTLMToLDAPS",
    "CoerceAndRelayNTLMToSMB",
    "CoerceToTGT",
    "Computer",
    "Container",
    "Contains",
    "ContainsIdentity",
    "CrossForestTrust",
    "DCFor",
    "DCSync",
    "DelegatedEnrollmentAgent",
    "Domain",
    "DumpSMSAPassword",
    "Enroll",
    "EnrollOnBehalfOf",
    "EnterpriseCA",
    "EnterpriseCAFor",
    "ExecuteDCOM",
    "ExtendedByPolicy",
    "ForceChangePassword",
    "GPLink",
    "GPO",
    "GPOAppliesTo",
    "GenericAll",
    "GenericWrite",
    "GetChanges",
    "GetChangesAll",
    "GetChangesInFilteredSet",
    "GoldenCert",
    "Group",
    "HasSIDHistory",
    "HasSession",
    "HasTrustKeys",
    "HostsCAService",
    "IssuancePolicy",
    "IssuedSignedBy",
    "LocalToComputer",
    "ManageCA",
    "ManageCertificates",
    "MemberOf",
    "MemberOfLocalGroup",
    "NTAuthStore",
    "NTAuthStoreFor",
    "OIDGroupLink",
    "OU",
    "Owns",
    "OwnsLimitedRights",
    "OwnsRaw",
    "PropagatesACEsTo",
    "ProtectAdminGroups",
    "PublishedTo",
    "ReadGMSAPassword",
    "ReadLAPSPassword",
    "RemoteInteractiveLogonRight",
    "RootCA",
    "RootCAFor",
    "SQLAdmin",
    "SameForestTrust",
    "ServerIs",
    "Site",
    "SiteServer",
    "SiteSubnet",
    "SpoofSIDHistory",
    "SyncLAPSPassword",
    "SyncedToADUser",
    "TrustedForNTAuth",
    "User",
    "WriteAccountRestrictions",
    "WriteAltSecurityIdentities",
    "WriteDacl",
    "WriteGPLink",
    "WriteOwner",
    "WriteOwnerLimitedRights",
    "WriteOwnerRaw",
    "WritePKIEnrollmentFlag",
    "WritePKINameFlag",
    "WritePublicInformation",
    "WriteSPN",
];
const ENROLL: &[&str] = &["GenericAll", "Enroll", "AllExtendedRights"];
const CONTROL: &[&str] = &["GenericAll", "Owns", "WriteOwner", "WriteDacl"];
const VICTIM_CONTROL: &[&str] = &[
    "GenericWrite",
    "GenericAll",
    "Owns",
    "WriteOwner",
    "WriteDacl",
];
const CHAIN: &[&str] = &["IssuedSignedBy", "EnterpriseCAFor"];

fn kind(n: &Node, k: &str) -> bool {
    n.labels.contains(k)
}
fn flag(n: &Node, p: &str, expected: bool) -> bool {
    n.properties.get(p).and_then(|v| v.as_bool()) == Some(expected)
}
fn number(n: &Node, p: &str) -> Option<f64> {
    n.properties.get(p).and_then(|v| v.as_f64())
}
fn text<'a>(n: &'a Node, p: &str) -> Option<&'a str> {
    n.properties.get(p).and_then(|v| v.as_str())
}
fn signature(n: &Node) -> bool {
    number(n, "schemaversion") == Some(1.)
        || number(n, "schemaversion").is_some_and(|v| v > 1.)
            && number(n, "authorizedsignatures") == Some(0.)
}
fn loose_signature(n: &Node) -> bool {
    number(n, "schemaversion") == Some(1.) || number(n, "authorizedsignatures") == Some(0.)
}
fn user_template(n: &Node) -> bool {
    flag(n, "subjectaltrequiredns", false) && flag(n, "subjectaltrequiredomaindns", false)
}
fn schannel(n: &Node) -> bool {
    flag(n, "schannelauthenticationenabled", true)
        || n.properties
            .get("effectiveekus")
            .and_then(|v| v.as_array())
            .is_some_and(|a| {
                a.is_empty()
                    || a.iter()
                        .any(|v| v == "1.3.6.1.5.5.7.3.2" || v == "2.5.29.37.0")
            })
}
fn relay_template(n: &Node) -> bool {
    flag(n, "requiresmanagerapproval", false)
        && flag(n, "authenticationenabled", true)
        && number(n, "schemaversion")
            .is_some_and(|v| v <= 1. || number(n, "authorizedsignatures") == Some(0.))
}

struct Step<'a> {
    kinds: &'a [&'a str],
    incoming: bool,
    repeat: bool,
    labels: &'a [&'a str],
    predicate: Box<dyn Fn(&Node) -> bool + 'a>,
}
impl<'a> Step<'a> {
    fn out(kinds: &'a [&'a str]) -> Self {
        Self {
            kinds,
            incoming: false,
            repeat: false,
            labels: &[],
            predicate: Box::new(|_| true),
        }
    }
    fn inbound(mut self) -> Self {
        self.incoming = true;
        self
    }
    fn repeated(mut self) -> Self {
        self.repeat = true;
        self
    }
    fn labels(mut self, labels: &'a [&'a str]) -> Self {
        self.labels = labels;
        self
    }
    fn filter(mut self, p: impl Fn(&Node) -> bool + 'a) -> Self {
        self.predicate = Box::new(p);
        self
    }
}
#[derive(Clone, Default)]
struct Path {
    nodes: Vec<String>,
    edges: Vec<EdgeKey>,
}
struct Index<'a> {
    graph: &'a GraphData,
    out: BTreeMap<String, Vec<&'a Edge>>,
    incoming: BTreeMap<String, Vec<&'a Edge>>,
    work: Cell<usize>,
    exceeded: Cell<bool>,
}
impl<'a> Index<'a> {
    fn new(graph: &'a GraphData) -> Self {
        let mut out: BTreeMap<String, Vec<&Edge>> = BTreeMap::new();
        let mut incoming: BTreeMap<String, Vec<&Edge>> = BTreeMap::new();
        for e in graph.edges.values() {
            out.entry(e.source.clone()).or_default().push(e);
            incoming.entry(e.target.clone()).or_default().push(e);
        }
        Self {
            graph,
            out,
            incoming,
            work: Cell::new(0),
            exceeded: Cell::new(false),
        }
    }
    fn node(&self, id: &str) -> &Node {
        &self.graph.nodes[id]
    }
    fn special_roots(&self, source: &str) -> Vec<String> {
        let mut ids: Set = self
            .graph
            .nodes
            .values()
            .filter(|n| {
                kind(n, "Group")
                    && (n.objectid.ends_with("S-1-5-11") || n.objectid.ends_with("S-1-1-0"))
            })
            .map(|n| n.objectid.clone())
            .collect();
        ids.insert(source.to_owned());
        ids.into_iter().collect()
    }
    // Pattern expansion in dawgs v0.9.0 rejects repeated node IDs. It does
    // not use Cypher's relationship-uniqueness rule. Use explicit DFS frames to
    // keep adversarially deep input off the call stack and avoid cloning pending
    // branches. Completed paths alone are retained for the composition union.
    fn walk(&self, roots: &[String], steps: &[Step<'_>]) -> Vec<Path> {
        struct Frame {
            stage: usize,
            next_edge: usize,
            entered: bool,
            optional_done: bool,
            added_edge: bool,
        }
        impl Frame {
            fn new(stage: usize, added_edge: bool) -> Self {
                Self {
                    stage,
                    next_edge: 0,
                    entered: false,
                    optional_done: false,
                    added_edge,
                }
            }
        }
        let mut result = vec![];
        for root in roots {
            if self.exceeded.get() {
                break;
            }
            let mut path = Path {
                nodes: vec![root.clone()],
                edges: vec![],
            };
            let mut stack = vec![Frame::new(0, false)];
            while let Some(frame) = stack.last_mut() {
                if !frame.entered {
                    frame.entered = true;
                    let work = self.work.get() + 1;
                    self.work.set(work);
                    if work > 2_000_000 || path.nodes.len() > 4096 {
                        self.exceeded.set(true);
                        break;
                    }
                }
                if frame.stage == steps.len() {
                    result.push(path.clone());
                    let done = stack.pop().unwrap();
                    if done.added_edge {
                        path.nodes.pop();
                        path.edges.pop();
                    }
                    continue;
                }
                let stage = frame.stage;
                let step = &steps[stage];
                if step.repeat && !frame.optional_done {
                    frame.optional_done = true;
                    stack.push(Frame::new(stage + 1, false));
                    continue;
                }
                let adjacency = if step.incoming {
                    &self.incoming
                } else {
                    &self.out
                };
                let edges = adjacency.get(path.nodes.last().unwrap());
                let mut next_edge = None;
                while let Some(edge) = edges.and_then(|edges| edges.get(frame.next_edge)) {
                    frame.next_edge += 1;
                    if !step.kinds.contains(&edge.kind.as_str()) {
                        continue;
                    }
                    let id = if step.incoming {
                        &edge.source
                    } else {
                        &edge.target
                    };
                    let Some(node) = self.graph.nodes.get(id) else {
                        continue;
                    };
                    if path.nodes.contains(id)
                        || !step.labels.is_empty()
                            && !step.labels.iter().any(|label| kind(node, label))
                        || !(step.predicate)(node)
                    {
                        continue;
                    }
                    next_edge = Some((
                        id.clone(),
                        EdgeKey(edge.source.clone(), edge.target.clone(), edge.kind.clone()),
                    ));
                    break;
                }
                if let Some((id, edge)) = next_edge {
                    path.nodes.push(id);
                    path.edges.push(edge);
                    stack.push(Frame::new(
                        if step.repeat { stage } else { stage + 1 },
                        true,
                    ));
                } else {
                    let done = stack.pop().unwrap();
                    if done.added_edge {
                        path.nodes.pop();
                        path.edges.pop();
                    }
                }
            }
        }
        result
    }
    fn first<'p>(&self, p: &'p Path, label: &str) -> Option<&'p str> {
        p.nodes
            .iter()
            .find(|id| kind(self.node(id), label))
            .map(String::as_str)
    }
    fn last<'p>(&self, p: &'p Path) -> &'p str {
        p.nodes.last().unwrap()
    }
    fn graph_for(&self, paths: &[Path]) -> GraphSnapshot {
        let mut result = GraphData::default();
        for p in paths {
            for id in &p.nodes {
                result.upsert_node(self.node(id).clone());
            }
            for e in &p.edges {
                result.upsert_edge(self.graph.edges[e].clone());
            }
        }
        result.snapshot()
    }
}
fn member<'a>() -> Step<'a> {
    Step::out(&["MemberOf"]).labels(&["Group"]).repeated()
}
fn chain<'a>(domain: Option<&'a str>) -> Vec<Step<'a>> {
    vec![
        Step::out(CHAIN)
            .labels(&["EnterpriseCA", "AIACA"])
            .repeated(),
        Step::out(CHAIN).labels(&["RootCA"]),
        Step::out(&["RootCAFor"])
            .labels(&["Domain"])
            .filter(move |n| domain.is_none_or(|d| n.objectid == d)),
    ]
}
fn auth<'a>(domain: Option<&'a str>) -> Vec<Step<'a>> {
    vec![
        Step::out(&["TrustedForNTAuth"]).labels(&["NTAuthStore"]),
        Step::out(&["NTAuthStoreFor"]).filter(move |n| domain.is_none_or(|d| n.objectid == d)),
    ]
}
fn ca_paths(i: &Index<'_>, roots: &[String], domain: Option<&str>, san: bool) -> Vec<Path> {
    let mut steps = vec![
        member(),
        Step::out(&["Enroll"])
            .labels(&["EnterpriseCA"])
            .filter(move |n| !san || flag(n, "isuserspecifiessanenabled", true)),
    ];
    steps.extend(auth(domain));
    i.walk(roots, &steps)
}
fn template_paths(
    i: &Index<'_>,
    roots: &[String],
    domain: Option<&str>,
    privileges: &[&str],
    predicate: impl Fn(&Node) -> bool,
    cas: Option<&Set>,
    vulnerable: bool,
) -> Vec<Path> {
    let mut steps = vec![
        member(),
        Step::out(privileges)
            .labels(&["CertTemplate"])
            .filter(predicate),
        Step::out(&["PublishedTo"])
            .labels(&["EnterpriseCA"])
            .filter(move |n| {
                cas.is_none_or(|s| s.contains(&n.objectid))
                    && (!vulnerable || flag(n, "hasvulnerableendpoint", true))
            }),
    ];
    steps.extend(chain(domain));
    i.walk(roots, &steps)
}
fn keyed(i: &Index<'_>, paths: Vec<Path>, label: &str) -> BTreeMap<String, Vec<Path>> {
    let mut map: BTreeMap<String, Vec<Path>> = BTreeMap::new();
    for p in paths {
        if let Some(id) = i.first(&p, label) {
            map.entry(id.to_owned()).or_default().push(p);
        }
    }
    map
}
fn combine_ca(i: &Index<'_>, p1: Vec<Path>, p2: Vec<Path>) -> Vec<Path> {
    let mut out = vec![];
    let b = keyed(i, p2, "EnterpriseCA");
    for p in p1 {
        if let Some(q) = i.first(&p, "EnterpriseCA").and_then(|ca| b.get(ca)) {
            out.push(p);
            out.extend(q.clone());
        }
    }
    out
}
fn forest_dc(i: &Index<'_>, domain: &str, mapping: bool) -> Vec<Path> {
    i.walk(
        &[domain.to_owned()],
        &[
            Step::out(&["SameForestTrust"])
                .inbound()
                .labels(&["Domain"])
                .repeated(),
            Step::out(&["DCFor"])
                .inbound()
                .labels(&["Computer"])
                .filter(move |n| {
                    if mapping {
                        number(n, "certificatemappingmethodsraw")
                            .is_some_and(|v| v != -1. && (v as i64) & 4 == 4)
                    } else {
                        matches!(
                            number(n, "strongcertificatebindingenforcementraw"),
                            Some(0. | 1.)
                        )
                    }
                }),
        ],
    )
}

fn golden(i: &Index<'_>, source: &str, target: &str) -> Vec<Path> {
    // HostsCAService is fetched directly in CE, so a self-loop is not excluded
    // by the traversal cycle rule (the same distinction applies in ESC3).
    let hosts: Vec<Path> = i
        .graph
        .edges
        .values()
        .filter(|e| {
            e.source == source
                && e.kind == "HostsCAService"
                && kind(i.node(&e.target), "EnterpriseCA")
        })
        .map(|e| Path {
            nodes: vec![e.source.clone(), e.target.clone()],
            edges: vec![EdgeKey(e.source.clone(), e.target.clone(), e.kind.clone())],
        })
        .collect();
    let mut result = vec![];
    for host in hosts {
        let root = i.last(&host).to_owned();
        let chains = i
            .walk(
                std::slice::from_ref(&root),
                &[Step::out(&["IssuedSignedBy", "EnterpriseCAFor", "RootCAFor"]).repeated()],
            )
            .into_iter()
            .filter(|p| {
                i.last(p) == target
                    && !p.nodes[..p.nodes.len() - 1]
                        .iter()
                        .any(|n| kind(i.node(n), "Domain"))
            })
            .collect::<Vec<_>>();
        let auth = i.walk(&[root], &[Step::out(&["TrustedForNTAuth", "NTAuthStoreFor"]).repeated()])
   .into_iter().filter(|p| i.last(p) == target && !p.edges.is_empty()
    // ops.TraversePaths applies PathFilter only to completed paths. A target
    // with another accepted descendant is not a terminal, even if it is a Domain.
    && !i.out.get(target).into_iter().flatten().any(|e| ["TrustedForNTAuth", "NTAuthStoreFor"].contains(&e.kind.as_str()) && !p.nodes.contains(&e.target)))
   .collect::<Vec<_>>();
        if !chains.is_empty() && !auth.is_empty() {
            result.push(host);
            result.extend(chains);
            result.extend(auth);
        }
    }
    result
}

fn esc1(i: &Index<'_>, source: &str, target: &str) -> Vec<Path> {
    let roots = i.special_roots(source);
    combine_ca(
        i,
        template_paths(
            i,
            &roots,
            Some(target),
            ENROLL,
            |n| {
                flag(n, "requiresmanagerapproval", false)
                    && signature(n)
                    && flag(n, "authenticationenabled", true)
                    && flag(n, "enrolleesuppliessubject", true)
            },
            None,
            false,
        ),
        ca_paths(i, &roots, Some(target), false),
    )
}
fn esc6(i: &Index<'_>, source: &str, target: &str, scenario_b: bool) -> Vec<Path> {
    let roots = i.special_roots(source);
    let ca = ca_paths(i, &roots, Some(target), true);
    let cas: Set = ca
        .iter()
        .filter_map(|p| i.first(p, "EnterpriseCA").map(str::to_owned))
        .collect();
    let p = template_paths(
        i,
        &roots,
        Some(target),
        ENROLL,
        |n| {
            flag(n, "requiresmanagerapproval", false)
                && loose_signature(n)
                && (if scenario_b {
                    schannel(n)
                } else {
                    flag(n, "nosecurityextension", true) && flag(n, "authenticationenabled", true)
                })
                && (!kind(i.node(source), "User") || user_template(n))
        },
        Some(&cas),
        false,
    );
    let mut result = combine_ca(i, p, ca);
    if scenario_b && !result.is_empty() {
        result.extend(forest_dc(i, target, true));
    }
    result
}
fn esc9_10(i: &Index<'_>, source: &str, target: &str, kind_name: &str) -> Vec<Path> {
    let b = kind_name.ends_with('b');
    let ten = kind_name.starts_with("ADCSESC10");
    let victim_kind = if b {
        &["Computer"][..]
    } else {
        &["Computer", "User"][..]
    };
    let mut steps = vec![
        Step::out(VICTIM_CONTROL).labels(victim_kind),
        member(),
        Step::out(ENROLL)
            .labels(&["CertTemplate"])
            .filter(move |n| {
                flag(n, "requiresmanagerapproval", false)
                    && signature(n)
                    && flag(n, "enrolleesuppliessubject", false)
                    && (if ten {
                        schannel(n)
                    } else {
                        flag(n, "authenticationenabled", true)
                            && flag(n, "nosecurityextension", true)
                    })
                    && (if b {
                        flag(n, "subjectaltrequiredns", true)
                    } else {
                        flag(n, "subjectaltrequireupn", true)
                            || flag(n, "subjectaltrequirespn", true)
                    })
            }),
        Step::out(&["PublishedTo"]).labels(&["EnterpriseCA"]),
    ];
    steps.extend(chain(Some(target)));
    let p1: Vec<_> = i
        .walk(&[source.to_owned()], &steps)
        .into_iter()
        .filter(|p| {
            !kind(i.node(&p.nodes[1]), "User")
                || i.first(p, "CertTemplate")
                    .is_some_and(|ct| user_template(i.node(ct)))
        })
        .collect();
    let mut victims: BTreeMap<String, Set> = BTreeMap::new();
    for p in &p1 {
        victims
            .entry(p.nodes[1].clone())
            .or_default()
            .insert(i.first(p, "EnterpriseCA").unwrap().to_owned());
    }
    let mut p2 = vec![];
    for (victim, cas) in victims {
        p2.extend(
            ca_paths(i, &[victim], Some(target), false)
                .into_iter()
                .filter(|p| {
                    i.first(p, "EnterpriseCA")
                        .is_some_and(|ca| cas.contains(ca))
                }),
        );
    }
    let mut result = combine_ca(i, p1, p2);
    if !result.is_empty() {
        result.extend(forest_dc(i, target, ten));
    }
    result
}
fn template_auth(
    i: &Index<'_>,
    roots: &[String],
    target: &str,
    cas: &Set,
    predicate: impl Fn(&Node) -> bool,
) -> Vec<Path> {
    let mut steps = vec![
        member(),
        Step::out(ENROLL)
            .labels(&["CertTemplate"])
            .filter(predicate),
        Step::out(&["PublishedTo"])
            .labels(&["EnterpriseCA"])
            .filter(|n| cas.contains(&n.objectid)),
    ];
    steps.extend(auth(Some(target)));
    i.walk(roots, &steps)
}
fn direct_rights(
    i: &Index<'_>,
    roots: &[String],
    rights: &[&str],
    ids: &Set,
    predicate: impl Fn(&Node) -> bool,
) -> Vec<Path> {
    i.walk(
        roots,
        &[
            member(),
            Step::out(rights).filter(|n| ids.contains(&n.objectid) && predicate(n)),
        ],
    )
}
fn esc3(i: &Index<'_>, source: &str, target: &str) -> Vec<Path> {
    let roots = i.special_roots(source);
    let enroll = keyed(
        i,
        i.walk(
            &roots,
            &[member(), Step::out(&["Enroll"]).labels(&["EnterpriseCA"])],
        ),
        "EnterpriseCA",
    );
    let cas: Set = enroll.keys().cloned().collect();
    let p1 = keyed(
        i,
        template_auth(i, &roots, target, &cas, |n| {
            flag(n, "requiresmanagerapproval", false) && signature(n)
        }),
        "CertTemplate",
    );
    let valid_ct: Set = p1
        .keys()
        .filter(|ct| !kind(i.node(source), "User") || user_template(i.node(ct)))
        .cloned()
        .collect();
    let behalf: Vec<Path> = i
        .graph
        .edges
        .values()
        .filter(|e| {
            e.kind == "EnrollOnBehalfOf"
                && valid_ct.contains(&e.source)
                && kind(i.node(&e.target), "CertTemplate")
        })
        .map(|e| Path {
            nodes: vec![e.source.clone(), e.target.clone()],
            edges: vec![EdgeKey(e.source.clone(), e.target.clone(), e.kind.clone())],
        })
        .collect();
    let ct2: Set = behalf.iter().map(|p| i.last(p).to_owned()).collect();
    let p2 = keyed(
        i,
        template_auth(i, &roots, target, &cas, |n| {
            ct2.contains(&n.objectid)
                && flag(n, "authenticationenabled", true)
                && flag(n, "requiresmanagerapproval", false)
        }),
        "CertTemplate",
    );
    let delegated = keyed(
        i,
        direct_rights(i, &roots, &["DelegatedEnrollmentAgent"], &ct2, |_| true),
        "CertTemplate",
    );
    let mut chains = BTreeMap::new();
    for ca in &cas {
        let p = i.walk(std::slice::from_ref(ca), &chain(Some(target)));
        if !p.is_empty() {
            chains.insert(ca.clone(), p);
        }
    }
    let mut out = vec![];
    for link in behalf {
        let a = &link.nodes[0];
        let b = i.last(&link);
        let (Some(p1s), Some(p2s)) = (p1.get(a), p2.get(b)) else {
            continue;
        };
        for a_path in p1s {
            let ca1 = i.first(a_path, "EnterpriseCA").unwrap();
            let Some(c1) = chains.get(ca1) else {
                continue;
            };
            for b_path in p2s {
                let ca2 = i.first(b_path, "EnterpriseCA").unwrap();
                let Some(c2) = chains.get(ca2) else {
                    continue;
                };
                let ca = i.node(ca2);
                if flag(ca, "enrollmentagentrestrictionscollected", true)
                    && flag(ca, "hasenrollmentagentrestrictions", true)
                {
                    let Some(d) = delegated.get(b) else {
                        continue;
                    };
                    out.extend(d.clone());
                }
                out.extend(enroll[ca1].clone());
                out.extend(enroll[ca2].clone());
                out.extend(c1.clone());
                out.extend(c2.clone());
                out.push(link.clone());
                out.push(a_path.clone());
                out.push(b_path.clone());
            }
        }
    }
    out
}
fn esc4(i: &Index<'_>, source: &str, target: &str) -> Vec<Path> {
    let roots = i.special_roots(source);
    let ca = ca_paths(i, &roots, Some(target), false);
    let cas: Set = ca
        .iter()
        .filter_map(|p| i.first(p, "EnterpriseCA").map(str::to_owned))
        .collect();
    let mut result = template_paths(
        i,
        &roots,
        Some(target),
        CONTROL,
        |_| true,
        Some(&cas),
        false,
    );
    for privilege in ["GenericWrite", "WritePKINameFlag", "WritePKIEnrollmentFlag"] {
        let privileges = [privilege];
        let paths = template_paths(
            i,
            &roots,
            Some(target),
            &privileges,
            |_| true,
            Some(&cas),
            false,
        );
        let ct: Set = paths
            .iter()
            .filter_map(|p| i.first(p, "CertTemplate").map(str::to_owned))
            .collect();
        result.extend(paths);
        // CE collects these adjunct paths without intersecting away the primary
        // privilege paths. Preserve that composition behavior exactly.
        result.extend(direct_rights(
            i,
            &roots,
            &["Enroll", "AllExtendedRights"],
            &ct,
            |n| match privilege {
                "WritePKINameFlag" => {
                    flag(n, "requiresmanagerapproval", false)
                        && flag(n, "authenticationenabled", true)
                        && loose_signature(n)
                }
                _ => true,
            },
        ));
        if privilege == "WritePKIEnrollmentFlag" {
            result.extend(direct_rights(i, &roots, &["WritePKINameFlag"], &ct, |n| {
                flag(n, "authenticationenabled", true) && loose_signature(n)
            }));
        }
    }
    let final_cas: Set = result
        .iter()
        .filter_map(|p| i.first(p, "EnterpriseCA").map(str::to_owned))
        .collect();
    result.extend(ca.into_iter().filter(|p| {
        i.first(p, "EnterpriseCA")
            .is_some_and(|ca| final_cas.contains(ca))
    }));
    result
}
fn esc13(i: &Index<'_>, source: &str, target: &str) -> Vec<Path> {
    let roots = i.special_roots(source);
    let p1 = template_paths(
        i,
        &roots,
        None,
        ENROLL,
        |n| {
            flag(n, "authenticationenabled", true)
                && signature(n)
                && flag(n, "requiresmanagerapproval", false)
        },
        None,
        false,
    );
    let cas: Set = p1
        .iter()
        .filter_map(|p| i.first(p, "EnterpriseCA").map(str::to_owned))
        .collect();
    let domains: Set = p1.iter().map(|p| i.last(p).to_owned()).collect();
    let cts: Set = p1
        .iter()
        .filter_map(|p| i.first(p, "CertTemplate").map(str::to_owned))
        .collect();
    let p2 = keyed(
        i,
        ca_paths(i, &roots, None, false)
            .into_iter()
            .filter(|p| {
                domains.contains(i.last(p))
                    && i.first(p, "EnterpriseCA")
                        .is_some_and(|ca| cas.contains(ca))
            })
            .collect(),
        "EnterpriseCA",
    );
    let p3 = keyed(
        i,
        i.walk(
            &[target.to_owned()],
            &[
                Step::out(&["OIDGroupLink"])
                    .inbound()
                    .labels(&["IssuancePolicy"]),
                Step::out(&["ExtendedByPolicy"])
                    .inbound()
                    .filter(|n| cts.contains(&n.objectid)),
            ],
        ),
        "CertTemplate",
    );
    let p4 = i.walk(
        &[target.to_owned()],
        &[
            Step::out(&["Contains"]).inbound(),
            Step::out(&["SameForestTrust"]).inbound().repeated(),
        ],
    );
    let mut out = vec![];
    for p in p1 {
        let ca = i.first(&p, "EnterpriseCA").unwrap();
        let ct = i.first(&p, "CertTemplate").unwrap();
        let (Some(auths), Some(policies)) = (p2.get(ca), p3.get(ct)) else {
            continue;
        };
        let domain = i.last(&p);
        let contains: Vec<_> = p4
            .iter()
            .filter(|q| i.last(q) == domain && kind(i.node(i.last(q)), "Domain"))
            .cloned()
            .collect();
        if contains.is_empty() {
            continue;
        }
        for q in auths {
            if i.last(q) == domain {
                out.push(p.clone());
                out.push(q.clone());
                out.extend(policies.clone());
                out.extend(contains.clone());
            }
        }
    }
    out
}

/// Explain an existing AD edge using the pinned CE composition dispatch.
/// Existing kinds without a composition implementation return an empty graph,
/// matching CE. A missing edge is an error, matching its API's edge lookup.
pub fn compose(
    graph: &GraphData,
    source: &str,
    target: &str,
    kind_name: &str,
) -> Result<GraphSnapshot> {
    require_edge(graph, source, target, kind_name)?;
    let i = Index::new(graph);
    let paths = match kind_name {
        "GoldenCert" => golden(&i, source, target),
        "ADCSESC1" => esc1(&i, source, target),
        "ADCSESC3" => esc3(&i, source, target),
        "ADCSESC4" => esc4(&i, source, target),
        "ADCSESC6a" | "ADCSESC6b" => esc6(&i, source, target, kind_name.ends_with('b')),
        "ADCSESC9a" | "ADCSESC9b" | "ADCSESC10a" | "ADCSESC10b" => {
            esc9_10(&i, source, target, kind_name)
        }
        "ADCSESC13" => esc13(&i, source, target),
        "CoerceAndRelayNTLMToADCS" => ntlm::adcs(&i, source, target)?,
        "CoerceAndRelayNTLMToSMB" => ntlm::smb(&i, source, target)?,
        _ => vec![],
    };
    if i.exceeded.get() {
        bail!("composition traversal exceeded its work limit; no partial graph returned");
    }
    Ok(i.graph_for(&paths))
}
fn require_edge(graph: &GraphData, source: &str, target: &str, kind_name: &str) -> Result<()> {
    if !VALID_AD_KINDS.contains(&kind_name) {
        bail!("unknown Active Directory kind: {kind_name}");
    }
    if !graph.nodes.contains_key(source)
        || !graph.nodes.contains_key(target)
        || !graph.edges.contains_key(&EdgeKey(
            source.to_owned(),
            target.to_owned(),
            kind_name.to_owned(),
        ))
    {
        bail!("could not find edge matching source, target, and kind");
    }
    Ok(())
}

/// Return relay target nodes using the pinned CE kind-specific filters.
pub fn relay_targets(
    graph: &GraphData,
    source: &str,
    target: &str,
    kind_name: &str,
) -> Result<Vec<Node>> {
    ntlm::relay_targets(graph, source, target, kind_name)
}
