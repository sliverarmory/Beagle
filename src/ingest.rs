// Copyright 2023-2026 Specter Ops, Inc. and Beagle contributors.
// SPDX-License-Identifier: Apache-2.0
// Conversion rules adapted from BloodHound CE v9.8.0, commit 1759e16,
// packages/go/ein/{ad.go,incoming_models.go} and services/graphify/convertors.go.
// See https://www.apache.org/licenses/LICENSE-2.0 .
// This module intentionally keeps input provenance separate from graph properties.

use crate::model::{Edge, GraphData, Node, Properties};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImportReport {
    pub upstream: String,
    pub ingested_at: String,
    pub files: Vec<SourceFile>,
    pub records: usize,
    pub nodes: usize,
    pub edges: usize,
    pub counts_by_type: BTreeMap<String, usize>,
    pub warnings: Vec<String>,
    /// Complete original records, including collection failure diagnostics and
    /// fields not projected into BloodHound's graph. Consumers may archive this
    /// report independently; graph snapshots contain only graph properties.
    pub source_records: Vec<SourceRecord>,
    /// Input fields intentionally not interpreted by the upstream graph converter.
    /// They remain available for diagnostics and future schema migrations.
    pub retained_fields: Vec<RetainedFields>,
    /// Explicit null updates must remove prior properties when merging batches.
    #[serde(default)]
    pub property_deletions: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    pub edge_property_deletions: Vec<EdgePropertyDeletion>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EdgePropertyDeletion {
    pub source: String,
    pub target: String,
    pub kind: String,
    pub property: String,
}

/// Merge an import while applying explicit-null removals. Deletions precede the
/// final incoming values, so repeated records obey their original update order.
pub fn apply_import(existing: &mut GraphData, incoming: &GraphData, report: &ImportReport) {
    for (id, properties) in &report.property_deletions {
        if let Some(node) = existing.nodes.get_mut(id) {
            for property in properties {
                node.properties.remove(property);
            }
        }
    }
    for deletion in &report.edge_property_deletions {
        let key = crate::model::EdgeKey(
            deletion.source.clone(),
            deletion.target.clone(),
            deletion.kind.clone(),
        );
        if let Some(edge) = existing.edges.get_mut(&key) {
            edge.properties.remove(&deletion.property);
        }
    }
    for node in incoming.nodes.values() {
        existing.upsert_node(node.clone());
    }
    for edge in incoming.edges.values() {
        existing.upsert_edge(edge.clone());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: String,
    pub sha256: String,
    pub metadata: Value,
    pub records: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetainedFields {
    pub source: String,
    pub record: usize,
    pub objectid: String,
    pub fields: Properties,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceRecord {
    pub source: String,
    pub index: usize,
    pub data: Value,
}

/// Import SharpHound schema versions 5 and 6. Input order is deterministic;
/// directories are recursive and ZIP members are read without extracting files.
/// All files are validated before returning a graph; errors never return a partial graph.
pub fn ingest_paths(paths: &[PathBuf]) -> Result<(GraphData, ImportReport)> {
    ingest_paths_with_existing(paths, &GraphData::default())
}

/// Import a new batch, resolving distinguished-name references against the
/// retained graph as well as this batch. Returns only incoming entities/edges;
/// callers merge these into `existing`. Existing-only timestamps are untouched.
pub fn ingest_paths_with_existing(
    paths: &[PathBuf],
    existing: &GraphData,
) -> Result<(GraphData, ImportReport)> {
    ensure!(!paths.is_empty(), "at least one input path is required");
    let mut inputs = BTreeSet::new();
    let mut report = ImportReport {
        upstream: "BloodHound CE v9.8.0 (1759e16)".into(),
        ingested_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        ..Default::default()
    };
    for path in paths {
        discover(path, &mut inputs, &mut report)?;
    }
    ensure!(!inputs.is_empty(), "no SharpHound JSON or ZIP inputs found");
    let mut graph = GraphData::default();
    let mut deferred = Vec::new();
    for path in inputs {
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        if extension(&path) == "zip" {
            let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
                .with_context(|| format!("opening ZIP {}", path.display()))?;
            let mut names: Vec<_> = (0..zip.len())
                .map(|i| {
                    let f = zip.by_index(i)?;
                    Ok((f.name().to_owned(), i, f.is_dir()))
                })
                .collect::<Result<_>>()?;
            names.sort();
            for (name, index, directory) in names {
                if directory {
                    continue;
                }
                let source = format!("{}!{}", path.display(), name);
                if extension(Path::new(&name)) != "json" {
                    report.warnings.push(format!(
                        "ZIP member is not JSON and was not imported: {source}"
                    ));
                    continue;
                }
                let mut data = Vec::new();
                zip.by_index(index)?.read_to_end(&mut data)?;
                import_document(&source, &data, &mut graph, &mut report, &mut deferred)?;
            }
        } else {
            import_document(
                &path.display().to_string(),
                &bytes,
                &mut graph,
                &mut report,
                &mut deferred,
            )?;
        }
    }
    // DN references can precede the objects they reference or occur in another file.
    let mut dns: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // New properties override retained properties, while a reference-only stub
    // must not hide an existing object's distinguished name.
    let mut known_names: BTreeMap<String, String> = BTreeMap::new();
    for n in existing.nodes.values().chain(graph.nodes.values()) {
        if let Some(dn) = n
            .properties
            .get("distinguishedname")
            .and_then(Value::as_str)
        {
            known_names.insert(n.objectid.clone(), dn.to_uppercase());
        }
    }
    for (id, properties) in &report.property_deletions {
        if properties.contains("distinguishedname")
            && !graph.nodes.get(id).is_some_and(|n| {
                n.properties
                    .get("distinguishedname")
                    .is_some_and(Value::is_string)
            })
        {
            known_names.remove(id);
        }
    }
    for (id, dn) in known_names {
        dns.entry(dn).or_default().push(id);
    }
    for (dn, group) in deferred {
        if let Some(ids) = dns.get(&dn) {
            ensure!(
                ids.len() == 1,
                "ambiguous distinguished-name membership reference {dn}"
            );
            edge(
                &mut graph,
                &ids[0],
                "Base",
                &group,
                "Group",
                "MemberOf",
                props(json!({"isacl":false,"isprimarygroup":false})),
            )?;
        } else {
            bail!(
                "unresolved distinguished-name membership reference {dn} in group {group}; supply the corresponding object collection"
            );
        }
    }
    ensure!(
        !report.files.is_empty(),
        "no SharpHound JSON documents found"
    );
    for n in graph.nodes.values_mut() {
        n.properties
            .insert("lastseen".into(), json!(report.ingested_at));
    }
    for e in graph.edges.values_mut() {
        e.properties
            .insert("lastseen".into(), json!(report.ingested_at));
    }
    report.nodes = graph.nodes.len();
    report.edges = graph.edges.len();
    Ok((graph, report))
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn discover(path: &Path, inputs: &mut BTreeSet<PathBuf>, report: &mut ImportReport) -> Result<()> {
    let info =
        fs::symlink_metadata(path).with_context(|| format!("inspecting {}", path.display()))?;
    ensure!(
        !info.file_type().is_symlink(),
        "symlink input is not followed: {}",
        path.display()
    );
    if info.is_dir() {
        let mut children = fs::read_dir(path)?
            .map(|e| e.map(|x| x.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        children.sort();
        for child in children {
            if child.is_dir() || matches!(extension(&child).as_str(), "json" | "zip") {
                discover(&child, inputs, report)?;
            } else {
                report.warnings.push(format!(
                    "Non-collection file was not imported: {}",
                    child.display()
                ));
            }
        }
    } else {
        ensure!(
            info.is_file(),
            "input is not a regular file: {}",
            path.display()
        );
        ensure!(
            matches!(extension(path).as_str(), "json" | "zip"),
            "unsupported input extension: {}",
            path.display()
        );
        inputs.insert(path.canonicalize()?);
    }
    Ok(())
}

fn field<'a>(v: &'a Value, name: &str) -> &'a Value {
    v.as_object()
        .and_then(|m| {
            m.get(name).or_else(|| {
                m.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v)
            })
        })
        .unwrap_or(&Value::Null)
}
fn text(v: &Value, name: &str) -> Result<String> {
    match field(v, name) {
        Value::Null => Ok(String::new()),
        Value::String(s) => Ok(s.clone()),
        _ => bail!("{name} must be a string"),
    }
}
fn required(v: &Value, name: &str) -> Result<String> {
    let s = text(v, name)?;
    ensure!(!s.is_empty(), "{name} must be a nonempty string");
    Ok(s)
}
fn boolean(v: &Value, name: &str) -> Result<bool> {
    match field(v, name) {
        Value::Null => Ok(false),
        Value::Bool(b) => Ok(*b),
        _ => bail!("{name} must be a boolean"),
    }
}
fn list<'a>(v: &'a Value, name: &str) -> Result<&'a [Value]> {
    match field(v, name) {
        Value::Null => Ok(&[]),
        Value::Array(a) => Ok(a),
        _ => bail!("{name} must be an array"),
    }
}
fn object(v: &Value, name: &str) -> Result<Properties> {
    match field(v, name) {
        Value::Null => Ok(Properties::new()),
        Value::Object(m) => Ok(m.clone()),
        _ => bail!("{name} must be an object"),
    }
}

// The upstream Go decoder reads Properties as map[string]any, so every number
// there (including array elements) is float64. Typed fields outside Properties
// and converter-generated integer properties must retain their integer types.
fn decode_property_numbers(value: &mut Value) -> Result<()> {
    match value {
        Value::Number(number) => {
            *number = serde_json::Number::from_f64(
                number
                    .as_f64()
                    .context("property number exceeds float64 range")?,
            )
            .context("property number is not finite")?;
        }
        Value::Array(values) => {
            for value in values {
                decode_property_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                decode_property_numbers(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn props(v: Value) -> Properties {
    v.as_object().unwrap().clone()
}
fn nonacl() -> Properties {
    props(json!({"isacl":false}))
}
fn kind(name: &str) -> Result<&'static str> {
    const KINDS: &[&str] = &[
        "Base",
        "User",
        "Computer",
        "Group",
        "GPO",
        "OU",
        "Container",
        "Domain",
        "ADLocalGroup",
        "ADLocalUser",
        "AIACA",
        "RootCA",
        "EnterpriseCA",
        "NTAuthStore",
        "CertTemplate",
        "IssuancePolicy",
        "Site",
        "SiteServer",
        "SiteSubnet",
    ];
    if name.is_empty()
        || name.eq_ignore_ascii_case("Unknown")
        || name.eq_ignore_ascii_case("Configuration")
    {
        return Ok("Base");
    }
    KINDS
        .iter()
        .copied()
        .find(|k| k.eq_ignore_ascii_case(name))
        .with_context(|| format!("unknown AD object type {name:?}"))
}
fn principal(v: &Value) -> Result<(String, String)> {
    ensure!(v.is_object(), "typed principal must be an object");
    Ok((
        required(v, "ObjectIdentifier")?.to_uppercase(),
        kind(&text(v, "ObjectType")?)?.into(),
    ))
}
fn edge(
    g: &mut GraphData,
    source: &str,
    sk: &str,
    target: &str,
    tk: &str,
    rel: &str,
    p: Properties,
) -> Result<()> {
    ensure!(
        !source.is_empty() && !target.is_empty(),
        "empty endpoint for {rel} relationship"
    );
    let s = source.to_uppercase();
    let t = target.to_uppercase();
    g.ensure_node(&s, sk);
    g.ensure_node(&t, tk);
    g.upsert_edge(Edge {
        source: s,
        target: t,
        kind: rel.into(),
        properties: p,
        derived: false,
    });
    Ok(())
}
fn add_node(g: &mut GraphData, id: &str, label: &str, mut p: Properties) -> Result<()> {
    for key in ["name", "operatingsystem", "distinguishedname"] {
        if let Some(v) = p.get_mut(key)
            && !v.is_null()
        {
            *v = Value::String(
                v.as_str()
                    .with_context(|| format!("{key} must be a string"))?
                    .to_uppercase(),
            );
        }
    }
    p.remove("reconcile");
    // Neo4j SET removes null-valued properties. Do not invent stringified nulls.
    let id = id.to_uppercase();
    if let Some(n) = g.nodes.get_mut(&id) {
        for (k, v) in &p {
            if v.is_null() {
                n.properties.remove(k);
            }
        }
    }
    p.retain(|_, v| !v.is_null());
    g.upsert_node(Node {
        objectid: id,
        labels: BTreeSet::from(["Base".into(), label.into()]),
        properties: p,
    });
    Ok(())
}

fn import_document(
    source: &str,
    bytes: &[u8],
    g: &mut GraphData,
    report: &mut ImportReport,
    deferred: &mut Vec<(String, String)>,
) -> Result<()> {
    let sha256 = hex::encode(Sha256::digest(bytes));
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let document: Value =
        serde_json::from_slice(bytes).with_context(|| format!("decoding {source}"))?;
    let meta = field(&document, "meta");
    ensure!(meta.is_object(), "{source}: missing meta object");
    let t = required(meta, "type")?.to_ascii_lowercase();
    if field(meta, "version").is_null() {
        // The pinned CE's own v5 fixtures omit version for domain/container/GPO
        // files. Its non-computer decoders do not gate on version either.
        ensure!(
            t != "computers",
            "{source}: computer collection requires meta.version 5 or 6"
        );
        report.warnings.push(format!(
            "{source}: meta.version is absent; using CE's legacy non-computer decoder"
        ));
    } else {
        let version = field(meta, "version")
            .as_u64()
            .with_context(|| format!("{source}: meta.version must be an integer"))?;
        ensure!(
            matches!(version, 5 | 6),
            "{source}: unsupported SharpHound version {version}; supported versions: 5, 6"
        );
    }
    let label = match t.as_str() {
        "users" => "User",
        "groups" => "Group",
        "computers" => "Computer",
        "domains" => "Domain",
        "gpos" => "GPO",
        "ous" => "OU",
        "containers" => "Container",
        "aiacas" => "AIACA",
        "rootcas" => "RootCA",
        "enterprisecas" => "EnterpriseCA",
        "ntauthstores" => "NTAuthStore",
        "certtemplates" => "CertTemplate",
        "issuancepolicies" => "IssuancePolicy",
        "sites" => "Site",
        "siteservers" => "SiteServer",
        "sitesubnets" => "SiteSubnet",
        "sessions" => "Session",
        _ => bail!(
            "{source}: unsupported collection type {t:?}; this importer handles CE AD object/session collections, not Azure, OpenGraph, deletion deltas or standalone localgroups"
        ),
    };
    ensure!(
        field(&document, "data").is_array(),
        "{source}: data must be an array"
    );
    let records = list(&document, "data")?;
    if let Some(n) = field(meta, "count").as_u64() {
        if n != records.len() as u64 {
            report.warnings.push(format!("{source}: meta.count={n} differs from actual data length {}; all records were processed",records.len()));
        }
    } else if !field(meta, "count").is_null() {
        bail!("{source}: meta.count must be a nonnegative integer");
    }
    for (i, record) in records.iter().enumerate() {
        let result = if label == "Session" {
            session(g, record, true)
        } else {
            convert(g, record, label, source, i, report, deferred)
        };
        result.with_context(|| format!("{source}: {t} record {}", i + 1))?;
        report.source_records.push(SourceRecord {
            source: source.into(),
            index: i + 1,
            data: record.clone(),
        });
    }
    report.records += records.len();
    *report.counts_by_type.entry(t).or_default() += records.len();
    report.files.push(SourceFile {
        path: source.into(),
        sha256,
        metadata: meta.clone(),
        records: records.len(),
    });
    Ok(())
}

fn convert(
    g: &mut GraphData,
    v: &Value,
    label: &str,
    source: &str,
    index: usize,
    report: &mut ImportReport,
    deferred: &mut Vec<(String, String)>,
) -> Result<()> {
    ensure!(v.is_object(), "record must be an object");
    validate_record(v)?;
    let id = required(v, "ObjectIdentifier")?.to_uppercase();
    let mut p = object(v, "Properties")?;
    for value in p.values_mut() {
        decode_property_numbers(value)?;
    }
    p.insert("lastcollected".into(), json!(report.ingested_at));
    let aces = list(v, "Aces")?;
    for ace in aces {
        if matches!(text(ace, "RightName")?.as_str(), "Owns" | "OwnsRaw") {
            p.insert("ownersid".into(), json!(required(ace, "PrincipalSID")?));
            break;
        }
    }
    if matches!(label, "Domain" | "OU" | "Container" | "Site")
        && !list(v, "InheritanceHashes")?.is_empty()
    {
        p.insert(
            "inheritancehashes".into(),
            field(v, "InheritanceHashes").clone(),
        );
    }
    if label == "Domain" {
        domain_properties(&mut p, report, &id);
    }
    if label == "Computer" {
        computer_properties(v, &mut p)?;
    }
    if label == "EnterpriseCA" {
        ca_properties(v, &mut p)?;
    }
    if label == "GPO" {
        gpo_properties(&mut p);
    }
    if label == "IssuancePolicy" && !text(field(v, "GroupLink"), "ObjectIdentifier")?.is_empty() {
        let (target, tk) = principal(field(v, "GroupLink"))?;
        edge(g, &id, label, &target, &tk, "OIDGroupLink", nonacl())?;
        p.insert(
            "grouplinkid".into(),
            json!(text(field(v, "GroupLink"), "ObjectIdentifier")?),
        );
    }
    for (key, value) in &p {
        if value.is_null() {
            report
                .property_deletions
                .entry(id.clone())
                .or_default()
                .insert(key.clone());
        }
    }
    add_node(g, &id, label, p.clone())?;
    if !matches!(label, "SiteServer" | "SiteSubnet") {
        acl(g, aces, &id, label, &p)?;
    }
    if !matches!(label, "GPO" | "Domain")
        && !text(field(v, "ContainedBy"), "ObjectIdentifier")?.is_empty()
    {
        let (container, ck) = principal(field(v, "ContainedBy"))?;
        edge(g, &container, &ck, &id, label, "Contains", nonacl())?;
    }
    if matches!(label, "Domain" | "OU" | "Container" | "Site") {
        for child in list(v, "ChildObjects")? {
            let (target, tk) = principal(child)?;
            edge(g, &id, label, &target, &tk, "Contains", nonacl())?;
        }
    }
    if matches!(label, "Domain" | "OU" | "Site") {
        for link in list(v, "Links")? {
            edge(
                g,
                &required(link, "Guid")?,
                "GPO",
                &id,
                label,
                "GPLink",
                props(json!({"isacl":false,"enforced":boolean(link,"IsEnforced")?})),
            )?;
        }
    }
    for (field_name, rel, reverse) in [
        ("AllowedToDelegate", "AllowedToDelegate", false),
        ("AllowedToAct", "AllowedToAct", true),
        ("HasSIDHistory", "HasSIDHistory", false),
        ("DumpSMSAPassword", "DumpSMSAPassword", false),
    ] {
        if match field_name {
            "HasSIDHistory" => !matches!(label, "User" | "Computer" | "Group"),
            "AllowedToDelegate" => !matches!(label, "User" | "Computer"),
            _ => label != "Computer",
        } {
            continue;
        }
        for target in list(v, field_name)? {
            let (tid, tk) = principal(target)?;
            if reverse {
                edge(g, &tid, &tk, &id, label, rel, nonacl())?;
            } else {
                edge(g, &id, label, &tid, &tk, rel, nonacl())?;
            }
        }
    }
    if matches!(label, "User" | "Computer") {
        let pg = text(v, "PrimaryGroupSID")?;
        if !pg.is_empty() {
            edge(
                g,
                &id,
                label,
                &pg,
                "Group",
                "MemberOf",
                props(json!({"isacl":false,"isprimarygroup":true})),
            )?;
        }
        let ds = text(v, "DomainSID")?;
        let isdc = label == "Computer" && boolean(v, "IsDC")? && !ds.is_empty();
        if isdc {
            edge(g, &id, label, &ds, "Domain", "DCFor", nonacl())?;
        } else {
            let unconstrained = match p.get("unconstraineddelegation") {
                Some(Value::Bool(b)) => *b,
                Some(_) => false,
                None => boolean(v, "UnconstrainedDelegation")?,
            };
            let domain = p.get("domainsid").and_then(Value::as_str).unwrap_or(&ds);
            if unconstrained && !domain.is_empty() {
                edge(g, &id, label, domain, "Domain", "CoerceToTGT", nonacl())?;
            }
        }
    }
    if label == "Group" {
        for member in list(v, "Members")? {
            let (mid, mk) = principal(member)?;
            if mid.starts_with("DN=") {
                deferred.push((mid, id.clone()));
            } else {
                edge(
                    g,
                    &mid,
                    &mk,
                    &id,
                    label,
                    "MemberOf",
                    props(json!({"isacl":false,"isprimarygroup":false})),
                )?;
            }
        }
    }
    if label == "User" {
        for spn in list(v, "SPNTargets")? {
            let rel = required(spn, "Service")?;
            ensure!(
                rel == "SQLAdmin",
                "unsupported SPN service relationship {rel:?}"
            );
            let port = field(spn, "Port")
                .as_i64()
                .context("SPN Port must be an integer")?;
            edge(
                g,
                &id,
                label,
                &required(spn, "ComputerSID")?,
                "Computer",
                &rel,
                props(json!({"isacl":true,"port":port})),
            )?;
        }
    }
    if label == "Computer" {
        for api in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
            let data = field(v, api);
            if boolean(data, "Collected")? {
                for s in list(data, "Results")? {
                    session(g, s, false)?;
                }
            }
        }
        for group in list(v, "LocalGroups")? {
            local_group(g, group, &id)?;
        }
        for right in list(v, "UserRights")? {
            if !boolean(right, "Collected")? || list(right, "Results")?.is_empty() {
                continue;
            }
            if text(right, "Privilege")? == "SeRemoteInteractiveLogonRight" {
                for actor in list(right, "Results")? {
                    let (aid, ak) = principal(actor)?;
                    edge(
                        g,
                        &aid,
                        &ak,
                        &id,
                        label,
                        "RemoteInteractiveLogonRight",
                        nonacl(),
                    )?;
                }
                g.nodes
                    .get_mut(&id)
                    .unwrap()
                    .properties
                    .insert("hasura".into(), json!(true));
            } else {
                report.warnings.push(format!("{id}: UserRights privilege {:?} is retained but not interpreted by BloodHound CE",text(right,"Privilege")?));
            }
        }
    }
    if matches!(label, "Domain" | "OU") {
        gpo_changes(g, field(v, "GPOChanges"))?;
    }
    if label == "Domain" {
        trusts(g, list(v, "Trusts")?, &id, report)?;
    }
    if label == "SiteServer" && !text(field(v, "ServerIs"), "ObjectIdentifier")?.is_empty() {
        let (tid, tk) = principal(field(v, "ServerIs"))?;
        edge(g, &id, label, &tid, &tk, "ServerIs", nonacl())?;
    }
    if matches!(label, "RootCA" | "NTAuthStore") {
        let ds = text(v, "DomainSID")?;
        if !ds.is_empty() {
            edge(
                g,
                &id,
                label,
                &ds,
                "Domain",
                if label == "RootCA" {
                    "RootCAFor"
                } else {
                    "NTAuthStoreFor"
                },
                nonacl(),
            )?;
        }
    }
    if label == "EnterpriseCA" {
        ca_relationships(g, v, &id, &p)?;
    }
    retain_auxiliary(v, source, index, &id, report);
    Ok(())
}

const ACL_KINDS: &[&str] = &[
    "AllExtendedRights",
    "ForceChangePassword",
    "AddMember",
    "AddAllowedToAct",
    "GenericAll",
    "WriteDacl",
    "WriteOwner",
    "GenericWrite",
    "ReadLAPSPassword",
    "ReadGMSAPassword",
    "Owns",
    "AddSelf",
    "WriteSPN",
    "AddKeyCredentialLink",
    "GetChanges",
    "GetChangesAll",
    "GetChangesInFilteredSet",
    "WriteAccountRestrictions",
    "WriteGPLink",
    "SyncLAPSPassword",
    "DCSync",
    "ManageCertificates",
    "ManageCA",
    "Enroll",
    "WritePKIEnrollmentFlag",
    "WritePKINameFlag",
    "WriteOwnerLimitedRights",
    "OwnsLimitedRights",
    "WriteAltSecurityIdentities",
    "WritePublicInformation",
];

fn acl(
    g: &mut GraphData,
    aces: &[Value],
    target: &str,
    tk: &str,
    target_props: &Properties,
) -> Result<()> {
    let mut owner: Option<(String, String)> = None;
    let mut writers = Vec::new();
    let mut owner_privs = Vec::new();
    let mut inherited_privs = Vec::new();
    for ace in aces {
        ensure!(ace.is_object(), "ACE must be an object");
        let sid = required(ace, "PrincipalSID")?.to_uppercase();
        let ak = kind(&text(ace, "PrincipalType")?)?.to_owned();
        let right = required(ace, "RightName")?;
        ensure!(
            ACL_KINDS.contains(&right.as_str()),
            "unknown or non-ACL RightName {right:?}"
        );
        let inherited = boolean(ace, "IsInherited")?;
        let hash = text(ace, "InheritanceHash")?;
        if sid == target {
            continue;
        }
        if right == "Owns" {
            owner = Some((sid, ak));
        } else if right == "WriteOwner" {
            writers.push((sid, ak, inherited, hash));
        } else if sid.ends_with("S-1-3-4") {
            owner_privs.push(right.clone());
            if inherited {
                inherited_privs.push(right);
            }
        } else {
            edge(
                g,
                &sid,
                &ak,
                target,
                tk,
                &right,
                props(json!({"isacl":true,"isinherited":inherited,"inheritancehash":hash})),
            )?;
        }
    }
    let inherited_owner = target_props
        .get("doesanyinheritedacegrantownerrights")
        .and_then(Value::as_bool)
        == Some(true);
    let any_owner = target_props
        .get("doesanyacegrantownerrights")
        .and_then(Value::as_bool)
        == Some(true);
    if !owner_privs.is_empty() {
        if let Some((sid, ak)) = &owner {
            edge(
                g,
                sid,
                ak,
                target,
                tk,
                "OwnsLimitedRights",
                props(json!({"isacl":true,"isinherited":false,"privileges":owner_privs})),
            )?;
        }
        if inherited_privs.is_empty() && inherited_owner {
            return Ok(());
        }
        for (sid, ak, inherit, hash) in writers {
            let mut p = props(json!({"isacl":true,"isinherited":inherit,"inheritancehash":hash}));
            let rel = if inherited_privs.is_empty() {
                "WriteOwnerRaw"
            } else {
                p.insert("privileges".into(), json!(inherited_privs));
                "WriteOwnerLimitedRights"
            };
            edge(g, &sid, &ak, target, tk, rel, p)?;
        }
    } else {
        if any_owner && inherited_owner {
            return Ok(());
        }
        if !any_owner && let Some((sid, ak)) = owner {
            edge(
                g,
                &sid,
                &ak,
                target,
                tk,
                "OwnsRaw",
                props(json!({"isacl":true,"isinherited":false})),
            )?;
        }
        for (sid, ak, inherit, hash) in writers {
            edge(
                g,
                &sid,
                &ak,
                target,
                tk,
                "WriteOwnerRaw",
                props(json!({"isacl":true,"isinherited":inherit,"inheritancehash":hash})),
            )?;
        }
    }
    Ok(())
}

fn session(g: &mut GraphData, v: &Value, standalone: bool) -> Result<()> {
    ensure!(v.is_object(), "session must be an object");
    let p = if standalone {
        let n = if field(v, "LogonType").is_null() {
            0
        } else {
            field(v, "LogonType")
                .as_i64()
                .context("LogonType must be an integer")?
        };
        props(json!({"logontype":n}))
    } else {
        nonacl()
    };
    edge(
        g,
        &required(v, "ComputerSID")?,
        "Computer",
        &required(v, "UserSID")?,
        "User",
        "HasSession",
        p,
    )
}

fn local_group(g: &mut GraphData, v: &Value, computer: &str) -> Result<()> {
    ensure!(v.is_object(), "local group must be an object");
    if !boolean(v, "Collected")? {
        return Ok(());
    }
    let name = text(v, "Name")?;
    let members = list(v, "Results")?;
    if members.is_empty() && !name.to_uppercase().starts_with("DIRECT ACCESS USERS") {
        return Ok(());
    }
    let id = required(v, "ObjectIdentifier")?;
    if name != "IGNOREME" {
        add_node(g, &id, "ADLocalGroup", props(json!({"name":name})))?;
    }
    edge(
        g,
        &id,
        "ADLocalGroup",
        computer,
        "Computer",
        "LocalToComputer",
        nonacl(),
    )?;
    for m in members {
        let (mid, mk) = principal(m)?;
        edge(
            g,
            &mid,
            &mk,
            &id,
            "ADLocalGroup",
            "MemberOfLocalGroup",
            nonacl(),
        )?;
    }
    for n in list(v, "LocalNames")? {
        add_node(
            g,
            &required(n, "ObjectIdentifier")?,
            "Base",
            props(json!({"name":required(n,"PrincipalName")?})),
        )?;
    }
    Ok(())
}

fn gpo_changes(g: &mut GraphData, v: &Value) -> Result<()> {
    for computer in list(v, "AffectedComputers")? {
        let (cid, _) = principal(computer)?;
        for (key, rid) in [
            ("LocalAdmins", "544"),
            ("RemoteDesktopUsers", "555"),
            ("DcomUsers", "562"),
            ("PSRemoteUsers", "580"),
        ] {
            let members = list(v, key)?;
            if members.is_empty() {
                continue;
            }
            let gid = format!("{cid}-{rid}");
            edge(
                g,
                &gid,
                "ADLocalGroup",
                &cid,
                "Computer",
                "LocalToComputer",
                nonacl(),
            )?;
            for m in members {
                let (mid, mk) = principal(m)?;
                edge(
                    g,
                    &mid,
                    &mk,
                    &gid,
                    "ADLocalGroup",
                    "MemberOfLocalGroup",
                    nonacl(),
                )?;
            }
        }
    }
    Ok(())
}

fn trusts(
    g: &mut GraphData,
    values: &[Value],
    domain: &str,
    report: &mut ImportReport,
) -> Result<()> {
    for v in values {
        let target = required(v, "TargetDomainSid")?;
        add_node(
            g,
            &target,
            "Domain",
            props(json!({"name":required(v,"TargetDomainName")?,"domainsid":target})),
        )?;
        let tt = required(v, "TrustType")?;
        let direction = required(v, "TrustDirection")?;
        ensure!(
            ["Disabled", "Inbound", "Outbound", "Bidirectional"].contains(&direction.as_str()),
            "invalid TrustDirection {direction:?}"
        );
        let attr = match field(v, "TrustAttributes") {
            Value::String(s) => s.parse::<i64>().ok(),
            Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|n| n as i64)),
            _ => None,
        };
        let rel = if ["ParentChild", "TreeRoot", "CrossLink"].contains(&tt.as_str()) {
            "SameForestTrust"
        } else {
            "CrossForestTrust"
        };
        let transitive = boolean(v, "IsTransitive")?;
        let delegate = boolean(v, "TGTDelegationEnabled")?;
        let filter = boolean(v, "SidFilteringEnabled")?;
        if matches!(direction.as_str(), "Inbound" | "Bidirectional") {
            let mut p = props(json!({"isacl":false,"trusttype":tt,"transitive":transitive}));
            if let Some(attr) = attr {
                p.insert("trustattributesinbound".into(), json!(attr));
                p.insert("tgtdelegation".into(), json!(delegate));
            } else {
                delete_edge_property(g, report, &target, domain, rel, "trustattributesinbound");
            }
            edge(g, &target, "Domain", domain, "Domain", rel, p)?;
            if rel == "CrossForestTrust" && delegate {
                edge(
                    g,
                    &target,
                    "Domain",
                    domain,
                    "Domain",
                    "AbuseTGTDelegation",
                    props(json!({"isacl":false,"trusttype":tt})),
                )?;
            }
        }
        if matches!(direction.as_str(), "Outbound" | "Bidirectional") {
            let mut p = props(
                json!({"isacl":false,"spoofsidhistoryblocked":filter,"trusttype":tt,"transitive":transitive}),
            );
            if let Some(attr) = attr {
                p.insert("trustattributesoutbound".into(), json!(attr));
            } else {
                delete_edge_property(g, report, domain, &target, rel, "trustattributesoutbound");
            }
            edge(g, domain, "Domain", &target, "Domain", rel, p)?;
            if rel == "CrossForestTrust" && !filter {
                edge(
                    g,
                    &target,
                    "Domain",
                    domain,
                    "Domain",
                    "SpoofSIDHistory",
                    props(json!({"isacl":false,"trusttype":tt})),
                )?;
            }
        }
    }
    Ok(())
}

fn delete_edge_property(
    g: &mut GraphData,
    report: &mut ImportReport,
    source: &str,
    target: &str,
    kind: &str,
    property: &str,
) {
    let (source, target) = (source.to_uppercase(), target.to_uppercase());
    let key = crate::model::EdgeKey(source.clone(), target.clone(), kind.into());
    if let Some(edge) = g.edges.get_mut(&key) {
        edge.properties.remove(property);
    }
    report.edge_property_deletions.push(EdgePropertyDeletion {
        source,
        target,
        kind: kind.into(),
        property: property.into(),
    });
}

fn domain_properties(p: &mut Properties, report: &mut ImportReport, id: &str) {
    for key in [
        "machineaccountquota",
        "minpwdlength",
        "pwdproperties",
        "pwdhistorylength",
        "lockoutthreshold",
    ] {
        if let Some(value) = p.get(key) {
            let int = match value {
                Value::String(s) => s.parse::<i64>().ok(),
                Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|n| n as i64)),
                _ => None,
            };
            if let Some(int) = int {
                p.insert(key.into(), json!(int));
            } else {
                report.warnings.push(format!(
                    "{id}: invalid domain property {key}={value} removed as in BloodHound CE"
                ));
                p.insert(key.into(), Value::Null);
            }
        }
    }
    let key = "expirepasswordsonsmartcardonlyaccounts";
    if let Some(v) = p.get(key) {
        let b = match v {
            Value::Bool(b) => Some(*b),
            Value::String(s) => match s.as_str() {
                "true" | "True" | "TRUE" | "1" | "t" | "T" => Some(true),
                "false" | "False" | "FALSE" | "0" | "f" | "F" => Some(false),
                _ => None,
            },
            _ => None,
        };
        if let Some(b) = b {
            p.insert(key.into(), json!(b));
        } else {
            report.warnings.push(format!(
                "{id}: invalid domain property {key}={v} removed as in BloodHound CE"
            ));
            p.insert(key.into(), Value::Null);
        }
    }
}

fn gpo_properties(p: &mut Properties) {
    if let Some(v) = p.get("gpostatus") {
        let raw = v
            .as_str()
            .map(str::to_owned)
            .or_else(|| v.as_f64().map(|value| value.to_string()))
            .unwrap_or_else(|| v.to_string())
            .trim()
            .to_owned();
        let pretty = match raw.as_str() {
            "0" => "Enabled",
            "1" => "User Configuration Disabled",
            "2" => "Computer Configuration Disabled",
            "3" => "Disabled",
            _ => "GPO Status does not exist",
        };
        p.insert("gpostatusraw".into(), json!(raw));
        p.insert("gpostatus".into(), json!(pretty));
    }
}

fn computer_properties(v: &Value, p: &mut Properties) -> Result<()> {
    let web = field(v, "IsWebClientRunning");
    if boolean(web, "Collected")? {
        p.insert("webclientrunning".into(), json!(boolean(web, "Result")?));
    }
    let smb = field(v, "SmbInfo");
    if boolean(smb, "Collected")? {
        p.insert(
            "smbsigning".into(),
            json!(boolean(field(smb, "Result"), "SigningEnabled")?),
        );
    }
    let ntlm = field(v, "NTLMRegistryData");
    if boolean(ntlm, "Collected")? {
        for (input, output, conversion) in [
            ("RestrictSendingNtlmTraffic", "restrictoutboundntlm", 2),
            (
                "RestrictReceivingNTLMTraffic",
                "restrictreceivingntmltraffic",
                2,
            ),
            ("RequireSecuritySignature", "requiresecuritysignature", 1),
            ("EnableSecuritySignature", "enablesecuritysignature", 1),
            ("NtlmMinClientSec", "ntlmminclientsec", 0),
            ("NtlmMinServerSec", "ntlmminserversec", 0),
            ("LmCompatibilityLevel", "lmcompatibilitylevel", 0),
            ("UseMachineId", "usemachineid", 1),
            ("ClientAllowedNTLMServers", "clientallowedntlmservers", 3),
        ] {
            let value = field(field(ntlm, "Result"), input);
            let result = if value.is_null() {
                Value::Null
            } else if conversion == 3 {
                ensure!(
                    value.is_array() && value.as_array().unwrap().iter().all(Value::is_string),
                    "{input} must be a string array"
                );
                value.clone()
            } else {
                let n = value
                    .as_u64()
                    .with_context(|| format!("{input} must be an unsigned integer"))?;
                match conversion {
                    1 => json!(n != 0),
                    2 => json!(n == 2),
                    _ => json!(n),
                }
            };
            p.insert(output.into(), result);
        }
    }
    for (old, new) in [
        ("ldapenabled", "ldapavailable"),
        ("ldapsenabled", "ldapsavailable"),
    ] {
        if let Some(value) = p.remove(old) {
            p.insert(new.into(), value);
        }
    }
    let mut dc_props = Properties::new();
    let dc = field(v, "DCRegistryData");
    let maps = field(dc, "CertificateMappingMethods");
    if boolean(maps, "Collected")? {
        let n = field(maps, "Value")
            .as_i64()
            .context("CertificateMappingMethods.Value must be an integer")?;
        dc_props.insert("certificatemappingmethodsraw".into(), json!(n));
        let mut pretty = Vec::new();
        if n == -1 {
            pretty.push("Registry value does not exist");
        } else {
            for (flag, name) in [
                (1, "0x01: One-to-one (subject/issuer)"),
                (2, "0x02: Many-to-one (issuer certificate)"),
                (4, "0x04: User principal name (UPN/SAN)"),
                (8, "0x08: Kerberos service-for-user (S4U) certificate"),
                (
                    16,
                    "0x10: Kerberos service-for-user (S4U) explicit certificate",
                ),
            ] {
                if n & flag != 0 {
                    pretty.push(name);
                }
            }
        }
        if !pretty.is_empty() {
            dc_props.insert("certificatemappingmethods".into(), json!(pretty));
        } else {
            dc_props.insert("certificatemappingmethods".into(), Value::Null);
        }
    }
    let binding = field(dc, "StrongCertificateBindingEnforcement");
    if boolean(binding, "Collected")? {
        let n = field(binding, "Value")
            .as_i64()
            .context("StrongCertificateBindingEnforcement.Value must be an integer")?;
        dc_props.insert("strongcertificatebindingenforcementraw".into(), json!(n));
        if let Some(pretty) = match n {
            -1 => Some("Registry value does not exist"),
            0 => Some("Disabled"),
            1 => Some("Compatibility mode"),
            2 => Some("Full enforcement mode"),
            _ => None,
        } {
            dc_props.insert("strongcertificatebindingenforcement".into(), json!(pretty));
        }
    }
    let netlogon = field(dc, "VulnerableNetlogonSecurityDescriptor");
    let collected = boolean(netlogon, "Collected")?;
    dc_props.insert(
        "vulnerablenetlogonsecuritydescriptorcollected".into(),
        json!(collected),
    );
    if collected {
        dc_props.insert(
            "vulnerablenetlogonsecuritydescriptor".into(),
            json!(text(netlogon, "Value")?),
        );
    }
    dc_props.extend(std::mem::take(p));
    *p = dc_props;
    Ok(())
}

fn ca_properties(v: &Value, p: &mut Properties) -> Result<()> {
    let mut http = Vec::new();
    let mut https = Vec::new();
    let mut collected = false;
    for ep in list(v, "HttpEnrollmentEndpoints")? {
        if !boolean(ep, "Collected")? {
            continue;
        }
        collected = true;
        let r = field(ep, "Result");
        let url = required(r, "Url")?;
        if boolean(r, "ADCSWebEnrollmentHTTP")? {
            http.push(url.clone());
        }
        if boolean(r, "ADCSWebEnrollmentHTTPS")? && !boolean(r, "ADCSWebEnrollmentEPA")? {
            https.push(url);
        }
    }
    if collected {
        p.insert(
            "hasvulnerableendpoint".into(),
            json!(!http.is_empty() || !https.is_empty()),
        );
    }
    if !http.is_empty() {
        p.insert("httpenrollmentendpoints".into(), json!(http));
    }
    if !https.is_empty() {
        p.insert("httpsenrollmentendpoints".into(), json!(https));
    }
    let registry = field(v, "CARegistryData");
    let restrictions = field(registry, "EnrollmentAgentRestrictions");
    if boolean(restrictions, "Collected")? {
        p.insert(
            "hasenrollmentagentrestrictions".into(),
            json!(!list(restrictions, "Restrictions")?.is_empty()),
        );
    }
    for (input, key) in [
        ("IsUserSpecifiesSanEnabled", "isuserspecifiessanenabled"),
        ("RoleSeparationEnabled", "roleseparationenabled"),
    ] {
        let item = field(registry, input);
        if boolean(item, "Collected")? {
            p.insert(key.into(), json!(boolean(item, "Value")?));
        }
    }
    Ok(())
}

fn ca_relationships(g: &mut GraphData, v: &Value, id: &str, p: &Properties) -> Result<()> {
    let mut templates = Vec::new();
    for template in list(v, "EnabledCertTemplates")? {
        let (tid, _) = principal(template)?;
        templates.push(tid.clone());
        edge(
            g,
            &tid,
            "CertTemplate",
            id,
            "EnterpriseCA",
            "PublishedTo",
            nonacl(),
        )?;
    }
    let host = text(v, "HostingComputer")?;
    if !host.is_empty() {
        edge(
            g,
            &host,
            "Computer",
            id,
            "EnterpriseCA",
            "HostsCAService",
            nonacl(),
        )?;
    }
    let registry = field(v, "CARegistryData");
    let restrictions = field(registry, "EnrollmentAgentRestrictions");
    if boolean(restrictions, "Collected")? {
        for r in list(restrictions, "Restrictions")? {
            if text(r, "AccessType")? != "AccessAllowedCallback" {
                continue;
            }
            let (aid, ak) = principal(field(r, "Agent"))?;
            let ts = if boolean(r, "AllTemplates")? {
                templates.clone()
            } else {
                vec![principal(field(r, "Template"))?.0]
            };
            for t in ts {
                edge(
                    g,
                    &aid,
                    &ak,
                    &t,
                    "CertTemplate",
                    "DelegatedEnrollmentAgent",
                    nonacl(),
                )?;
            }
        }
    }
    let security = field(registry, "CASecurity");
    if boolean(security, "Collected")? {
        let mut combined = Vec::new();
        for ace in list(security, "Data")? {
            if text(ace, "PrincipalType")? != "ADLocalGroup" && text(ace, "RightName")? != "Owns" {
                combined.push(ace.clone());
            }
        }
        for ace in list(v, "Aces")? {
            if text(ace, "PrincipalSID")? == host
                || !["ManageCA", "ManageCertificates", "Enroll"]
                    .contains(&text(ace, "RightName")?.as_str())
            {
                combined.push(ace.clone());
            }
        }
        acl(g, &combined, id, "EnterpriseCA", p)?;
    }
    Ok(())
}

fn validate_record(v: &Value) -> Result<()> {
    for key in [
        "IsDeleted",
        "IsACLProtected",
        "IsDC",
        "UnconstrainedDelegation",
    ] {
        boolean(v, key)?;
    }
    for key in [
        "Properties",
        "ContainedBy",
        "Sessions",
        "PrivilegedSessions",
        "RegistrySessions",
        "DCRegistryData",
        "Status",
        "SmbInfo",
        "IsWebClientRunning",
        "NTLMRegistryData",
        "CARegistryData",
        "GPOChanges",
        "GroupLink",
        "ServerIs",
    ] {
        let value = field(v, key);
        ensure!(
            value.is_null() || value.is_object(),
            "{key} must be an object or null"
        );
    }
    for key in [
        "Aces",
        "AllowedToDelegate",
        "AllowedToAct",
        "DumpSMSAPassword",
        "HasSIDHistory",
        "LocalGroups",
        "UserRights",
        "ChildObjects",
        "Members",
        "Links",
        "Trusts",
        "SPNTargets",
        "EnabledCertTemplates",
        "HttpEnrollmentEndpoints",
    ] {
        list(v, key)?;
    }
    for key in ["Sessions", "PrivilegedSessions", "RegistrySessions"] {
        let api = field(v, key);
        boolean(api, "Collected")?;
        list(api, "Results")?;
    }
    for (key, children) in [
        (
            "CARegistryData",
            &[
                "CASecurity",
                "EnrollmentAgentRestrictions",
                "IsUserSpecifiesSanEnabled",
                "RoleSeparationEnabled",
            ][..],
        ),
        (
            "DCRegistryData",
            &[
                "CertificateMappingMethods",
                "StrongCertificateBindingEnforcement",
                "VulnerableNetlogonSecurityDescriptor",
            ][..],
        ),
    ] {
        for child in children {
            let api = field(field(v, key), child);
            ensure!(
                api.is_null() || api.is_object(),
                "{key}.{child} must be an object or null"
            );
            boolean(api, "Collected")?;
        }
    }
    for key in ["NTLMRegistryData", "SmbInfo"] {
        let value = field(field(v, key), "Result");
        ensure!(
            value.is_null() || value.is_object(),
            "{key}.Result must be an object or null"
        );
        boolean(field(v, key), "Collected")?;
    }
    for key in ["LocalGroups", "UserRights", "HttpEnrollmentEndpoints"] {
        for api in list(v, key)? {
            ensure!(api.is_object(), "{key} entry must be an object");
            boolean(api, "Collected")?;
        }
    }
    for value in list(v, "InheritanceHashes")? {
        ensure!(
            value.is_string(),
            "InheritanceHashes entries must be strings"
        );
    }
    Ok(())
}

fn retain_auxiliary(v: &Value, source: &str, record: usize, id: &str, report: &mut ImportReport) {
    const CONSUMED: &[&str] = &[
        "ObjectIdentifier",
        "Properties",
        "Aces",
        "ContainedBy",
        "InheritanceHashes",
        "AllowedToDelegate",
        "AllowedToAct",
        "DumpSMSAPassword",
        "HasSIDHistory",
        "PrimaryGroupSID",
        "DomainSID",
        "IsDC",
        "UnconstrainedDelegation",
        "Members",
        "SPNTargets",
        "Sessions",
        "PrivilegedSessions",
        "RegistrySessions",
        "LocalGroups",
        "ChildObjects",
        "Links",
        "Trusts",
        "GPOChanges",
        "GroupLink",
        "ServerIs",
        "SmbInfo",
        "IsWebClientRunning",
        "NTLMRegistryData",
        "DCRegistryData",
        "CARegistryData",
        "EnabledCertTemplates",
        "HostingComputer",
        "HttpEnrollmentEndpoints",
    ];
    let fields: Properties = v
        .as_object()
        .unwrap()
        .iter()
        .filter(|(key, _)| !CONSUMED.iter().any(|k| k.eq_ignore_ascii_case(key)))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // Known upstream diagnostics are retained without warnings. New schema fields are explicit.
    for key in fields.keys() {
        if !["IsDeleted", "IsACLProtected", "Status", "UserRights"]
            .iter()
            .any(|k| k.eq_ignore_ascii_case(key))
        {
            report.warnings.push(format!("{source}: record {} ({id}): unrecognized field {key:?} retained without graph interpretation",record+1));
        }
    }
    if !fields.is_empty() {
        report.retained_fields.push(RetainedFields {
            source: source.into(),
            record: record + 1,
            objectid: id.into(),
            fields,
        });
    }
}
