//! Native AD post-processing, referenced to BloodHound CE v9.8.0 (1759e16).
//! See docs/analysis-coverage.md for the supported boundary and validation.
mod adcs;
mod ntlm;

use crate::model::{Edge, GraphData, Node, Properties};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

type Set = BTreeSet<String>;
type Jobs = Vec<(String, String, String)>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub reference: String,
    pub derived_edges_removed: usize,
    pub edges_created: usize,
    pub nodes_created: usize,
    pub nodes_updated: usize,
    pub counts_by_rule: BTreeMap<String, usize>,
    pub unsupported_gaps: Vec<String>,
    /// Multiple eligible collected/GPO-inferred groups can yield different
    /// privileges: CE takes an unspecified database-first match.
    #[serde(default)]
    pub local_group_ambiguities: Vec<LocalGroupAmbiguity>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalGroupAmbiguity {
    pub computer: String,
    pub suffix: String,
    pub relationship_kind: String,
    pub selected_group: String,
    /// Candidate group object IDs and their direct local-group members.
    pub candidate_groups: BTreeMap<String, Vec<String>>,
}

/// Feature settings corresponding to CE AD post-processing configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisOptions {
    /// Require RemoteInteractiveLogonRight even without collected hasura=true.
    pub enforce_ura: bool,
    /// Intersect Remote Desktop Users with Citrix Direct Access Users when present.
    pub restrict_citrix: bool,
    /// Enable the four NTLM coercion/relay derived relationships.
    pub ntlm_enabled: bool,
}
impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            enforce_ura: true,
            restrict_citrix: true,
            ntlm_enabled: true,
        }
    }
}

/// Recompute native derived edges using CE's enabled defaults.
/// CE transit relationship kinds are refreshed even when supplied by a snapshot. Non-transit collected edges are retained.
pub fn analyze(graph: &mut GraphData) -> Result<AnalysisReport> {
    analyze_with_options(graph, &AnalysisOptions::default())
}

pub fn analyze_with_options(
    graph: &mut GraphData,
    options: &AnalysisOptions,
) -> Result<AnalysisReport> {
    let mut report = AnalysisReport {
        reference: "BloodHound CE v9.8.0 / 1759e16".into(),
        unsupported_gaps: vec![
            "Database-managed certification, selector enablement, and tiering-disabled legacy mode are not inferred from GraphData; supply effective custom selections through asset_groups configuration.".into(),
            "Operational firstseen/lastseen timestamps are retained on collected data but are not generated for derived records.".into(),
            "Ambiguous local-group suffixes select the computer-scoped identifier first, then lexical order; CE uses its database's first match.".into(),
        ],
        ..Default::default()
    };
    let old_len = graph.edges.len();
    // CE's transit deletion deliberately excludes Owns/WriteOwner. ADCS sees
    // the previous ownership stage until ownership is refreshed below.
    graph.edges.retain(|_, edge| {
        !is_transit_kind(&edge.kind)
            && (!edge.derived || matches!(edge.kind.as_str(), "Owns" | "WriteOwner"))
    });
    report.derived_edges_removed = old_len - graph.edges.len();
    normalize(graph, &mut report);
    report.local_group_ambiguities = local_group_ambiguities(&Index::new(graph));
    let jobs = basic(&Index::new(graph), options);
    apply(graph, jobs, &mut report);
    let jobs = adcs::preprocess(&Index::new(graph));
    apply(graph, jobs, &mut report);
    let jobs = adcs::enroll_on_behalf(&Index::new(graph));
    apply(graph, jobs, &mut report);
    let jobs = adcs::analyze(&Index::new(graph));
    apply(graph, jobs, &mut report);
    let old_len = graph.edges.len();
    graph
        .edges
        .retain(|_, edge| !edge.derived || !matches!(edge.kind.as_str(), "Owns" | "WriteOwner"));
    report.derived_edges_removed += old_len - graph.edges.len();
    let jobs = ownership(&Index::new(graph));
    apply(graph, jobs, &mut report);
    if options.ntlm_enabled {
        let jobs = ntlm::analyze(&Index::new(graph));
        apply(graph, jobs, &mut report);
    }
    tag_tier_zero(graph, &mut report);
    Ok(report)
}

fn local_group_ambiguities(index: &Index<'_>) -> Vec<LocalGroupAmbiguity> {
    let mut ambiguities = Vec::new();
    for computer in index.nodes("Computer") {
        let groups = index.incoming(&computer.objectid, &["LocalToComputer"]);
        for (suffix, relationship_kind) in [
            ("-544", "AdminTo"),
            ("-580", "CanPSRemote"),
            ("-562", "ExecuteDCOM"),
            ("-555", "CanRDP"),
        ] {
            let candidates: BTreeMap<_, _> = groups
                .iter()
                .filter(|id| id.ends_with(suffix))
                .map(|id| {
                    (
                        id.clone(),
                        index
                            .incoming(id, &["MemberOfLocalGroup"])
                            .into_iter()
                            .collect(),
                    )
                })
                .collect();
            if candidates.len() > 1 {
                let scoped = format!("{}{suffix}", computer.objectid);
                let selected_group = if candidates.contains_key(&scoped) {
                    scoped
                } else {
                    candidates.keys().next().unwrap().clone()
                };
                ambiguities.push(LocalGroupAmbiguity {
                    computer: computer.objectid.clone(),
                    suffix: suffix.into(),
                    relationship_kind: relationship_kind.into(),
                    selected_group,
                    candidate_groups: candidates,
                });
            }
        }
    }
    ambiguities
}

/// Exact CE v9.8 graphschema/ad.PostProcessedRelationships list.
fn is_transit_kind(kind: &str) -> bool {
    matches!(
        kind,
        "DCSync"
            | "ProtectAdminGroups"
            | "SyncLAPSPassword"
            | "CanRDP"
            | "AdminTo"
            | "CanPSRemote"
            | "ExecuteDCOM"
            | "TrustedForNTAuth"
            | "IssuedSignedBy"
            | "EnterpriseCAFor"
            | "GoldenCert"
            | "ADCSESC1"
            | "ADCSESC3"
            | "ADCSESC4"
            | "ADCSESC6a"
            | "ADCSESC6b"
            | "ADCSESC10a"
            | "ADCSESC10b"
            | "ADCSESC9a"
            | "ADCSESC9b"
            | "ADCSESC13"
            | "EnrollOnBehalfOf"
            | "SyncedToADUser"
            | "ExtendedByPolicy"
            | "CoerceAndRelayNTLMToADCS"
            | "CoerceAndRelayNTLMToSMB"
            | "CoerceAndRelayNTLMToLDAP"
            | "CoerceAndRelayNTLMToLDAPS"
            | "GPOAppliesTo"
            | "CanApplyGPO"
            | "HasTrustKeys"
    )
}

fn apply(graph: &mut GraphData, jobs: Jobs, report: &mut AnalysisReport) {
    for (source, target, kind) in jobs {
        if !graph.nodes.contains_key(&source) || !graph.nodes.contains_key(&target) {
            continue;
        }
        let mut properties = Properties::new();
        if kind == "Owns" || kind == "WriteOwner" {
            let raw_key =
                crate::model::EdgeKey(source.clone(), target.clone(), format!("{kind}Raw"));
            let raw = graph.edges.get(&raw_key);
            properties.insert("isacl".into(), json!(true));
            properties.insert(
                "isinherited".into(),
                json!(
                    raw.and_then(|e| e.properties.get("isinherited"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                ),
            );
            properties.insert(
                "inheritancehash".into(),
                json!(
                    raw.and_then(|e| e.properties.get("inheritancehash"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                ),
            );
        }
        let edge = Edge {
            source,
            target,
            kind: kind.clone(),
            derived: true,
            properties,
        };
        if graph.upsert_edge(edge) {
            report.edges_created += 1;
            *report.counts_by_rule.entry(kind).or_default() += 1;
        }
    }
}
fn push(jobs: &mut Jobs, source: &str, target: &str, kind: &str) {
    jobs.push((source.into(), target.into(), kind.into()));
}
fn text<'a>(n: &'a Node, key: &str) -> Option<&'a str> {
    n.properties.get(key)?.as_str()
}
fn flag(n: &Node, key: &str) -> Option<bool> {
    n.properties.get(key)?.as_bool()
}
fn number(n: &Node, key: &str) -> Option<f64> {
    n.properties.get(key)?.as_f64()
}
fn strings<'a>(n: &'a Node, key: &str) -> Option<Vec<&'a str>> {
    n.properties
        .get(key)?
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect()
}
fn kind(n: &Node, label: &str) -> bool {
    n.labels.contains(label)
}
fn is_group(n: &Node) -> bool {
    kind(n, "Group") || kind(n, "ADLocalGroup")
}
fn computer_derived(n: &Node) -> bool {
    kind(n, "Computer") || flag(n, "gmsa") == Some(true) || flag(n, "msa") == Some(true)
}
fn singleton(id: &str) -> Set {
    Set::from([id.into()])
}

struct Index<'a> {
    graph: &'a GraphData,
    inbound: BTreeMap<String, Vec<&'a Edge>>,
    outbound: BTreeMap<String, Vec<&'a Edge>>,
    members: RefCell<BTreeMap<String, Set>>,
}
impl<'a> Index<'a> {
    fn new(graph: &'a GraphData) -> Self {
        let mut index = Self {
            graph,
            inbound: BTreeMap::new(),
            outbound: BTreeMap::new(),
            members: RefCell::new(BTreeMap::new()),
        };
        for edge in graph.edges.values() {
            index
                .inbound
                .entry(edge.target.clone())
                .or_default()
                .push(edge);
            index
                .outbound
                .entry(edge.source.clone())
                .or_default()
                .push(edge);
        }
        index
    }
    fn node(&self, id: &str) -> Option<&'a Node> {
        self.graph.nodes.get(id)
    }
    fn nodes(&self, label: &str) -> Vec<&'a Node> {
        self.graph
            .nodes
            .values()
            .filter(|n| kind(n, label))
            .collect()
    }
    fn incoming(&self, id: &str, kinds: &[&str]) -> Set {
        self.inbound
            .get(id)
            .into_iter()
            .flatten()
            .filter(|e| kinds.contains(&e.kind.as_str()))
            .map(|e| e.source.clone())
            .collect()
    }
    fn outgoing(&self, id: &str, kinds: &[&str]) -> Set {
        self.outbound
            .get(id)
            .into_iter()
            .flatten()
            .filter(|e| kinds.contains(&e.kind.as_str()))
            .map(|e| e.target.clone())
            .collect()
    }
    fn reach(&self, start: &str, kinds: &[&str], inbound: bool) -> Set {
        let mut seen = singleton(start);
        let mut queue = VecDeque::from([start.to_owned()]);
        while let Some(id) = queue.pop_front() {
            let adjacent = if inbound {
                self.incoming(&id, kinds)
            } else {
                self.outgoing(&id, kinds)
            };
            for next in adjacent {
                if seen.insert(next.clone()) {
                    queue.push_back(next);
                }
            }
        }
        seen
    }
    /// Includes the component root, including isolated principals.
    fn members(&self, id: &str) -> Set {
        if let Some(cached) = self.members.borrow().get(id) {
            return cached.clone();
        }
        let result = self.reach(id, &["MemberOf", "MemberOfLocalGroup"], true);
        self.members.borrow_mut().insert(id.into(), result.clone());
        result
    }
    fn special(&self, id: &str) -> bool {
        self.node(id).is_some_and(|n| {
            kind(n, "Group") && (id.ends_with("-S-1-1-0") || id.ends_with("-S-1-5-11"))
        })
    }
    fn has_special(&self, set: &Set) -> bool {
        set.iter().any(|id| {
            self.special(id)
                || self.node(id).is_some_and(is_group)
                    && self.members(id).iter().any(|m| self.special(m))
        })
    }
    fn expand(&self, set: &Set) -> Set {
        set.iter()
            .flat_map(|id| {
                if self.node(id).is_some_and(is_group) {
                    self.members(id)
                } else {
                    singleton(id)
                }
            })
            .collect()
    }
    /// Port of CalculateCrossProductNodeSets, retaining group shortcuts instead
    /// of creating a redundant edge for each member of a shared permission group.
    fn cross(&self, sets: &[Set]) -> Set {
        if sets.len() < 2 || sets.iter().any(Set::is_empty) {
            return Set::new();
        }
        let non_special: Vec<_> = sets.iter().filter(|s| !self.has_special(s)).collect();
        if non_special.is_empty() {
            return sets.iter().flat_map(|s| s.iter().cloned()).collect();
        }
        if non_special.len() == 1 {
            return non_special[0].clone();
        }
        let mut check = self.expand(non_special[1]);
        for set in &non_special[2..] {
            check = check.intersection(&self.expand(set)).cloned().collect();
        }
        let mut result = Set::new();
        let mut unrolled = Set::new();
        for id in non_special[0] {
            if check.contains(id) {
                result.insert(id.clone());
            } else {
                unrolled.extend(self.members(id));
            }
        }
        let mut groups: Vec<_> = unrolled
            .iter()
            .filter(|id| self.node(id).is_some_and(is_group))
            .map(|id| (self.members(id).len(), id.clone()))
            .collect();
        groups.sort();
        for (_, id) in groups {
            if !unrolled.contains(&id) {
                continue;
            }
            if check.contains(&id) {
                result.insert(id.clone());
                for member in self.members(&id) {
                    unrolled.remove(&member);
                }
            } else {
                unrolled.remove(&id);
            }
        }
        result.extend(unrolled.intersection(&check).cloned());
        result
    }
    fn domain(&self, n: &Node) -> Option<&'a Node> {
        let sid = text(n, "domainsid")?;
        self.nodes("Domain")
            .into_iter()
            .find(|d| d.objectid == sid || text(d, "domainsid") == Some(sid))
    }
    fn forest(&self, domain: &str) -> Set {
        self.reach(domain, &["SameForestTrust"], true)
    }
}

const GROUP_SUFFIXES: &[&str] = &[
    "-527", "-526", "-S-1-5-9", "-512", "-516", "-518", "-519", "-544", "-551",
];
fn normalize(graph: &mut GraphData, report: &mut AnalysisReport) {
    let domains: Vec<_> = graph
        .nodes
        .values()
        .filter(|n| kind(n, "Domain"))
        .cloned()
        .collect();
    for n in graph.nodes.values_mut() {
        let before = n.clone();
        if kind(n, "Base") && !is_group(n) && GROUP_SUFFIXES.iter().any(|s| n.objectid.ends_with(s))
        {
            n.labels.insert("Group".into());
        }
        if !n.properties.contains_key("name")
            && let Some((sid, _)) = n.objectid.rsplit_once('-')
            && let Some(d) = domains.iter().find(|d| d.objectid == sid)
            && let Some(name) = text(d, "name")
        {
            n.properties
                .insert("name".into(), json!(format!("({name}) {}", n.objectid)));
            n.properties.insert("domainsid".into(), json!(sid));
        }
        if *n != before {
            report.nodes_updated += 1;
        }
    }
    let definitions = [
        ("-513", "DOMAIN USERS"),
        ("-515", "DOMAIN COMPUTERS"),
        ("-S-1-1-0", "EVERYONE"),
        ("-S-1-5-11", "AUTHENTICATED USERS"),
        ("-S-1-5-2", "NETWORK"),
        ("-S-1-5-15", "THIS ORGANIZATION"),
        ("-S-1-5-65-1", "THIS ORGANIZATION CERTIFICATE"),
        ("-S-1-18-1", "AUTHENTICATION AUTHORITY ASSERTED IDENTITY"),
        ("-S-1-18-4", "KEY TRUST"),
        ("-S-1-18-5", "MFA KEY PROPERTY"),
        ("-S-1-5-64-10", "NTLM AUTHENTICATION"),
        ("-S-1-5-64-14", "SCHANNEL AUTHENTICATION"),
    ];
    let mut jobs = vec![];
    for d in domains
        .into_iter()
        .filter(|d| flag(d, "collected") == Some(true))
    {
        let (Some(name), Some(sid)) = (text(&d, "name"), text(&d, "domainsid")) else {
            continue;
        };
        let mut ids = BTreeMap::new();
        for (suffix, label) in definitions {
            let id = format!(
                "{}{suffix}",
                if suffix == "-513" || suffix == "-515" {
                    sid
                } else {
                    name
                }
            );
            if let Some(n) = graph.nodes.get_mut(&id) {
                if n.labels.insert("Group".into()) {
                    report.nodes_updated += 1;
                }
            } else {
                graph.upsert_node(Node {
                    objectid: id.clone(),
                    labels: BTreeSet::from(["Base".into(), "Group".into()]),
                    properties: serde_json::from_value(
                        json!({"name":format!("{label}@{name}"),"domainsid":sid,"domain":name}),
                    )
                    .unwrap(),
                });
                report.nodes_created += 1;
            }
            ids.insert(suffix, id);
        }
        for (a, b) in [
            ("-513", "-S-1-5-11"),
            ("-515", "-S-1-5-11"),
            ("-S-1-5-11", "-S-1-1-0"),
        ] {
            push(&mut jobs, &ids[a], &ids[b], "MemberOf");
        }
        for (suffix, _) in &definitions[4..] {
            push(
                &mut jobs,
                &ids["-S-1-1-0"],
                &ids[suffix],
                "ClaimSpecialIdentity",
            );
        }
        let guest = format!("{sid}-501");
        if let Some(n) = graph.nodes.get(&guest) {
            push(&mut jobs, &guest, &ids["-S-1-1-0"], "MemberOf");
            if flag(n, "enabled") == Some(true) {
                push(&mut jobs, &ids["-S-1-1-0"], &guest, "ClaimSpecialIdentity");
            }
        }
    }
    apply(graph, jobs, report);
}

fn basic(index: &Index<'_>, options: &AnalysisOptions) -> Jobs {
    let mut jobs = vec![];
    for d in index
        .nodes("Domain")
        .into_iter()
        .filter(|d| flag(d, "collected") == Some(true))
    {
        let Some(sid) = text(d, "domainsid") else {
            continue;
        };
        let changes = index.incoming(&d.objectid, &["GetChanges"]);
        for source in index.cross(&[
            changes.clone(),
            index.incoming(&d.objectid, &["GetChangesAll"]),
        ]) {
            push(&mut jobs, &source, &d.objectid, "DCSync");
        }
        let laps = index.cross(&[
            changes,
            index.incoming(&d.objectid, &["GetChangesInFilteredSet"]),
        ]);
        for n in index
            .nodes("Computer")
            .into_iter()
            .filter(|n| text(n, "domainsid") == Some(sid) && flag(n, "haslaps") == Some(true))
        {
            for source in &laps {
                push(&mut jobs, source, &n.objectid, "SyncLAPSPassword");
            }
        }
        if let Some(holder) = index.nodes("Container").into_iter().find(|n| {
            text(n, "domainsid") == Some(sid)
                && text(n, "distinguishedname")
                    .is_some_and(|s| s.starts_with("CN=ADMINSDHOLDER,CN=SYSTEM,"))
        }) {
            for target in index.graph.nodes.values().filter(|n| {
                (kind(n, "User") || kind(n, "Group") || kind(n, "Computer"))
                    && text(n, "domainsid") == Some(sid)
                    && flag(n, "adminsdholderprotected") == Some(true)
            }) {
                push(
                    &mut jobs,
                    &holder.objectid,
                    &target.objectid,
                    "ProtectAdminGroups",
                );
            }
        }
        if let Some(netbios) = text(d, "netbios") {
            for target_domain in
                index.outgoing(&d.objectid, &["SameForestTrust", "CrossForestTrust"])
            {
                let Some(target_sid) = index
                    .node(&target_domain)
                    .and_then(|n| text(n, "domainsid"))
                else {
                    continue;
                };
                if let Some(account) = index.nodes("User").into_iter().find(|n| {
                    text(n, "domainsid") == Some(target_sid)
                        && text(n, "samaccountname") == Some(format!("{netbios}$").as_str())
                }) {
                    push(&mut jobs, &d.objectid, &account.objectid, "HasTrustKeys");
                }
            }
        }
    }
    for computer in index.nodes("Computer") {
        let groups = index.incoming(&computer.objectid, &["LocalToComputer"]);
        // CE fetches one group for each suffix. Prefer the computer-scoped
        // collection identifier when a DC also has a domain builtin group.
        let local_group = |suffix: &str| {
            groups
                .iter()
                .find(|id| **id == format!("{}{suffix}", computer.objectid))
                .or_else(|| groups.iter().find(|id| id.ends_with(suffix)))
        };
        for (suffix, edge_kind) in [
            ("-544", "AdminTo"),
            ("-580", "CanPSRemote"),
            ("-562", "ExecuteDCOM"),
        ] {
            if let Some(group) = local_group(suffix) {
                for member in index.incoming(group, &["MemberOfLocalGroup"]) {
                    push(&mut jobs, &member, &computer.objectid, edge_kind);
                }
            }
        }
        let Some(rdp) = local_group("-555") else {
            continue;
        };
        let ril = index.incoming(&computer.objectid, &["RemoteInteractiveLogonRight"]);
        let ura_enabled = options.enforce_ura || flag(computer, "hasura") == Some(true);
        let dau = groups
            .iter()
            .filter(|_| options.restrict_citrix)
            .find(|id| {
                index
                    .node(id)
                    .filter(|n| kind(n, "ADLocalGroup"))
                    .and_then(|n| text(n, "name"))
                    .is_some_and(|n| n.to_uppercase().starts_with("DIRECT ACCESS USERS"))
            });
        let eligible = if let Some(dau) = dau {
            if ura_enabled {
                index.cross(&[singleton(rdp), singleton(dau), ril])
            } else {
                index.cross(&[singleton(rdp), singleton(dau)])
            }
        } else if !ura_enabled || ril.contains(rdp) {
            index.incoming(rdp, &["MemberOfLocalGroup"])
        } else {
            let members = index.members(rdp);
            let mut eligible = Set::new();
            for id in ril {
                if members.contains(&id) {
                    eligible.insert(id);
                } else {
                    eligible.extend(index.members(&id).intersection(&members).cloned());
                }
            }
            eligible
        };
        for id in eligible {
            if id != computer.objectid {
                push(&mut jobs, &id, &computer.objectid, "CanRDP");
            }
        }
    }
    jobs
}

fn ownership(index: &Index<'_>) -> Jobs {
    let enforced: BTreeSet<_> = index
        .nodes("Domain")
        .into_iter()
        .filter(|n| text(n, "dsheuristics").and_then(|s| s.as_bytes().get(28)) == Some(&b'1'))
        .filter_map(|n| text(n, "domainsid").map(str::to_owned))
        .collect();
    let admins: Set = index
        .graph
        .nodes
        .values()
        .filter(|n| n.objectid.ends_with("-512") || n.objectid.ends_with("-519"))
        .flat_map(|n| index.members(&n.objectid))
        .collect();
    let mut jobs = vec![];
    for e in index
        .graph
        .edges
        .values()
        .filter(|e| e.kind == "OwnsRaw" || e.kind == "WriteOwnerRaw")
    {
        let Some(target) = index.node(&e.target) else {
            continue;
        };
        let blocked = text(target, "domainsid").is_some_and(|sid| enforced.contains(sid))
            && computer_derived(target);
        if !blocked || e.kind == "OwnsRaw" && admins.contains(&e.source) {
            push(
                &mut jobs,
                &e.source,
                &e.target,
                if e.kind == "OwnsRaw" {
                    "Owns"
                } else {
                    "WriteOwner"
                },
            );
        }
    }
    jobs
}

fn tag_tier_zero(graph: &mut GraphData, report: &mut AnalysisReport) {
    // Default AD selectors from the v9.8.0 migration manifest, then the
    // child/parent expansion in analysis/agt.go. Custom selectors are separate.
    let index = Index::new(graph);
    let group_suffixes = [
        "S-1-5-32-544",
        "S-1-5-32-548",
        "S-1-5-32-549",
        "S-1-5-32-550",
        "S-1-5-32-551",
        "S-1-5-32-559",
        "S-1-5-32-562",
        "S-1-5-32-569",
        "-512",
        "-516",
        "-517",
        "-518",
        "-519",
        "-526",
        "-527",
        "-557",
        "-1-5-9",
    ];
    let group_names = [
        "EXCHANGE TRUSTED SUBSYSTEM@",
        "EXCHANGE WINDOWS PERMISSIONS@",
        "DNSADMINS@",
    ];
    let mut seeds = Set::new();
    for n in graph.nodes.values() {
        let selected = [
            "Domain",
            "NTAuthStore",
            "RootCA",
            "AIACA",
            "EnterpriseCA",
            "CertTemplate",
            "Site",
        ]
        .iter()
        .any(|k| kind(n, k))
            || kind(n, "Group")
                && (group_suffixes.iter().any(|s| n.objectid.ends_with(s))
                    || text(n, "name")
                        .is_some_and(|s| group_names.iter().any(|prefix| s.starts_with(prefix))))
            || kind(n, "User") && (n.objectid.ends_with("-500") || n.objectid.ends_with("-502"))
            || kind(n, "Container")
                && text(n, "distinguishedname").is_some_and(|s| {
                    index.nodes("Domain").iter().any(|d| {
                        text(d, "distinguishedname")
                            .is_some_and(|dn| s == format!("CN=ADMINSDHOLDER,CN=SYSTEM,{dn}"))
                    })
                })
            || kind(n, "Computer")
                && (flag(n, "isreadonlydc") == Some(true)
                    || text(n, "samaccountname") == Some("AZUREADSSOACC$")
                    || !index.outgoing(&n.objectid, &["HostsCAService"]).is_empty()
                    || index
                        .outgoing(&n.objectid, &["MemberOf"])
                        .iter()
                        .any(|g| g.ends_with("-521")))
            || kind(n, "SiteServer")
                && index
                    .outgoing(&n.objectid, &["ServerIs"])
                    .iter()
                    .any(|computer| !index.outgoing(computer, &["DCFor"]).is_empty());
        if selected {
            seeds.insert(n.objectid.clone());
        }
    }
    let tier_zero = expand_asset_group(graph, &seeds, true, true);
    for n in graph.nodes.values_mut() {
        let before = n.clone();
        // TagAssetGroupsAndTierZero first clears legacy system_tags for every
        // entity, then the selected tier-zero tag writes admin_tier_0 again.
        if tier_zero.contains(&n.objectid) {
            n.properties
                .insert("system_tags".into(), json!("admin_tier_0"));
            n.labels.insert("Tag_Tier_Zero".into());
        } else {
            n.properties.remove("system_tags");
            n.labels.remove("Tag_Tier_Zero");
        }
        if *n != before {
            report.nodes_updated += 1;
            *report.counts_by_rule.entry("TierZero".into()).or_default() += 1;
        }
    }
}

/// Expand asset-group selectors using CE's child and parent traversal rules.
/// Parent expansion never feeds back into child expansion, preventing siblings
/// of selected objects from being included merely because their OU is included.
pub fn expand_asset_group(
    graph: &GraphData,
    seeds: &BTreeSet<String>,
    children: bool,
    parents: bool,
) -> BTreeSet<String> {
    let index = Index::new(graph);
    let mut tier_zero: Set = seeds
        .iter()
        .filter(|id| graph.nodes.contains_key(*id))
        .cloned()
        .collect();
    if children {
        for id in seeds {
            if let Some(n) = index.node(id) {
                if kind(n, "Group") {
                    tier_zero.extend(index.reach(id, &["MemberOf"], true));
                }
                if kind(n, "OU") || kind(n, "Container") {
                    tier_zero.extend(index.reach(id, &["Contains"], false));
                }
            }
        }
    }
    if parents {
        // Parent expansion must not turn an entire containing OU into child seeds.
        for id in tier_zero.clone() {
            let mut ou_parents = singleton(&id);
            let mut queue = VecDeque::from([id.clone()]);
            while let Some(current) = queue.pop_front() {
                for parent in index.incoming(&current, &["Contains"]) {
                    if index.node(&parent).is_some_and(|n| kind(n, "OU"))
                        && ou_parents.insert(parent.clone())
                    {
                        queue.push_back(parent);
                    }
                }
            }
            for parent in &ou_parents {
                tier_zero.extend(
                    index
                        .incoming(parent, &["GPLink"])
                        .into_iter()
                        .filter(|id| index.node(id).is_some_and(|n| kind(n, "GPO"))),
                );
            }
            tier_zero.extend(ou_parents);
            if index
                .node(&id)
                .is_some_and(|n| flag(n, "isaclprotected") == Some(false))
            {
                let mut visited = singleton(&id);
                let mut queue = VecDeque::from([id]);
                while let Some(current) = queue.pop_front() {
                    for parent in index.incoming(&current, &["Contains"]) {
                        if index.node(&parent).is_some_and(|n| kind(n, "Container"))
                            && visited.insert(parent.clone())
                        {
                            tier_zero.insert(parent.clone());
                            queue.push_back(parent);
                        }
                    }
                }
            }
        }
    }
    tier_zero
}
