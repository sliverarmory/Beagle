//! Bounded, versioned stdio transport for trusted desktop hosts.
//!
//! The host owns authorization and process deadlines. This module owns framing,
//! request validation and one database connection; it never evaluates shell text.

use anyhow::{Result, bail};
use beagle::{
    AssetGroupConfiguration, Beagle, ExportKind, ImportMode, IngestOptions, PathOptions,
    PathSelection, SnapshotImportOptions, SystemTag,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

const REQUEST_BYTES: usize = 1_048_576;
const RESPONSE_BYTES: usize = 33_554_432;
const MAX_REQUEST_ID: u64 = 9_007_199_254_740_991;
const OPERATIONS: &[&str] = &[
    "open",
    "stats",
    "query",
    "savedQuery",
    "catalog",
    "savedQueryInfo",
    "entity",
    "ingest",
    "analyze",
    "tag",
    "compose",
    "export",
    "paths",
    "shutdown",
    "importSnapshot",
    "exportToFile",
    "backup",
    "cleanup",
    "getAssetGroups",
    "previewAssetGroups",
    "applyAssetGroups",
    "relayTargets",
    "closeDatabase",
    "setImportHistoryRetention",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u64,
    command: Command,
}

#[derive(Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Command {
    Open {
        database: String,
        query_timeout_ms: u64,
    },
    CloseDatabase {},
    SetImportHistoryRetention {
        limit: usize,
    },
    Stats {},
    Query {
        cypher: String,
        parameters: Map<String, Value>,
    },
    SavedQuery {
        id: String,
        parameters: Map<String, Value>,
    },
    Catalog {},
    SavedQueryInfo {
        id: String,
    },
    Entity {
        objectid: String,
    },
    Ingest {
        paths: Vec<String>,
        analyze: bool,
        #[serde(default)]
        mode: ImportMode,
        #[serde(default)]
        history_limit: Option<usize>,
        #[serde(default)]
        compact_reports: bool,
    },
    Analyze {
        #[serde(default)]
        compact_reports: bool,
    },
    ImportSnapshot {
        path: String,
        analyze: bool,
        #[serde(default)]
        compact_reports: bool,
    },
    ExportToFile {
        path: String,
        #[serde(default)]
        kind: ExportKind,
    },
    Backup {
        path: String,
    },
    Cleanup {
        kinds: Vec<String>,
    },
    GetAssetGroups {},
    PreviewAssetGroups {
        configuration: AssetGroupConfiguration,
    },
    ApplyAssetGroups {
        configuration: AssetGroupConfiguration,
    },
    RelayTargets {
        source: String,
        target: String,
        kind: String,
    },
    Tag {
        objectid: String,
        tag: SystemTag,
        enabled: bool,
    },
    Compose {
        source: String,
        target: String,
        kind: String,
    },
    Export {},
    Paths {
        source: String,
        target: String,
        all: bool,
        max_hops: u32,
    },
    Shutdown {},
}

#[derive(Clone, Copy, Debug, Serialize)]
struct ProtocolError {
    code: &'static str,
    message: &'static str,
}
impl ProtocolError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}
const INVALID_INPUT: ProtocolError =
    ProtocolError::new("invalid_input", "Invalid helper command input.");
const OPERATION_FAILED: ProtocolError = ProtocolError::new(
    "operation_failed",
    "Beagle could not complete the operation.",
);
const RESPONSE_TOO_LARGE: ProtocolError = ProtocolError::new(
    "response_too_large",
    "Beagle response exceeds the 32 MiB limit; narrow the request.",
);

type OperationResult = std::result::Result<Value, ProtocolError>;

pub fn run_stdio() -> Result<()> {
    match serve(&mut io::stdin().lock(), &mut io::stdout().lock()) {
        Ok(true) => Ok(()),
        Ok(false) => bail!("Beagle helper protocol failed"),
        Err(_) => bail!("Beagle helper transport failed"),
    }
}

fn serve(input: &mut impl BufRead, output: &mut impl Write) -> io::Result<bool> {
    write_message(
        output,
        &json!({
            "type": "ready", "protocol": 1, "name": "beagle", "version": env!("CARGO_PKG_VERSION"),
            "operations": OPERATIONS,
            "limits": {"requestBytes": REQUEST_BYTES, "responseBytes": RESPONSE_BYTES},
        }),
    )?;
    let mut engine = None;
    let mut previous_id = 0;
    let mut frame = Vec::with_capacity(8_192);
    loop {
        match read_frame(input, &mut frame) {
            Ok(false) => return Ok(true),
            Ok(true) => {}
            Err(error) => return fatal(output, error),
        }
        let request: Request = match serde_json::from_slice(&frame) {
            Ok(request) => request,
            Err(_) => {
                return fatal(
                    output,
                    ProtocolError::new("invalid_request", "Invalid helper request envelope."),
                );
            }
        };
        if request.id <= previous_id || request.id > MAX_REQUEST_ID {
            return fatal(
                output,
                ProtocolError::new(
                    "invalid_request_id",
                    "Request IDs must be increasing positive safe integers.",
                ),
            );
        }
        previous_id = request.id;
        let shutdown = matches!(request.command, Command::Shutdown {});
        let response = match execute(&mut engine, request.command) {
            Ok(value) => json!({"type": "response", "id": request.id, "ok": true, "value": value}),
            Err(error) => error_response(request.id, error),
        };
        // Serialize completely before touching stdout. An oversized result must
        // not leave a partial frame in front of the following error response.
        match encode_message(&response, RESPONSE_BYTES) {
            Ok(bytes) => {
                output.write_all(&bytes)?;
                output.flush()?;
            }
            Err(_) => write_message(output, &error_response(request.id, RESPONSE_TOO_LARGE))?,
        }
        if shutdown {
            return Ok(true);
        }
    }
}

fn fatal(output: &mut impl Write, error: ProtocolError) -> io::Result<bool> {
    write_message(output, &json!({"type": "fatal", "error": error}))?;
    Ok(false)
}

fn error_response(id: u64, error: ProtocolError) -> Value {
    json!({"type": "response", "id": id, "ok": false, "error": error})
}

/// The framing limit includes the newline. Inspect each input chunk before
/// copying it, and never grow the retained frame capacity past that limit.
fn read_frame(
    input: &mut impl BufRead,
    frame: &mut Vec<u8>,
) -> std::result::Result<bool, ProtocolError> {
    frame.clear();
    loop {
        let chunk = input
            .fill_buf()
            .map_err(|_| ProtocolError::new("input_error", "Could not read helper input."))?;
        if chunk.is_empty() {
            return if frame.is_empty() {
                Ok(false)
            } else {
                Err(ProtocolError::new(
                    "truncated_request",
                    "Helper input ended before the request newline.",
                ))
            };
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(chunk.len(), |index| index + 1);
        if count > REQUEST_BYTES - frame.len()
            || (newline.is_none() && count == REQUEST_BYTES - frame.len())
        {
            return Err(ProtocolError::new(
                "request_too_large",
                "Helper request exceeds the 1 MiB limit.",
            ));
        }
        reserve_bounded(frame, count, REQUEST_BYTES)
            .map_err(|_| ProtocolError::new("input_error", "Could not buffer helper input."))?;
        frame.extend_from_slice(&chunk[..count]);
        input.consume(count);
        if newline.is_some() {
            return Ok(true);
        }
    }
}

fn reserve_bounded(bytes: &mut Vec<u8>, count: usize, limit: usize) -> io::Result<()> {
    let needed = bytes
        .len()
        .checked_add(count)
        .filter(|size| *size <= limit)
        .ok_or_else(|| io::Error::other("Frame limit reached"))?;
    if needed > bytes.capacity() {
        let capacity = needed.next_power_of_two().min(limit);
        bytes
            .try_reserve_exact(capacity - bytes.len())
            .map_err(|_| io::Error::other("Could not allocate frame"))?;
    }
    Ok(())
}

struct BoundedOutput {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        reserve_bounded(&mut self.bytes, bytes.len(), self.limit)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_message(value: &impl Serialize, limit: usize) -> io::Result<Vec<u8>> {
    let mut output = BoundedOutput {
        bytes: Vec::with_capacity(8_192.min(limit)),
        limit: limit.saturating_sub(1),
    };
    serde_json::to_writer(&mut output, value).map_err(io::Error::other)?;
    reserve_bounded(&mut output.bytes, 1, limit)?;
    output.bytes.push(b'\n');
    Ok(output.bytes)
}

fn write_message(output: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    output.write_all(&encode_message(value, RESPONSE_BYTES)?)?;
    output.flush()
}

fn valid_text(value: &str, max: usize, multiline: bool) -> bool {
    !value.trim().is_empty()
        && value.encode_utf16().count() <= max
        && !value.chars().any(|c| {
            (c <= '\u{1f}' || c == '\u{7f}') && !(multiline && matches!(c, '\n' | '\r' | '\t'))
        })
}

fn valid_path(value: &str) -> bool {
    valid_text(value, 4_096, false) && Path::new(value).is_absolute()
}

fn valid_parameters(parameters: &Map<String, Value>) -> bool {
    fn visit(value: &Value, depth: usize, entries: &mut usize) -> bool {
        *entries += 1;
        if depth > 32 || *entries > 100_000 {
            return false;
        }
        match value {
            Value::Array(values) => values.iter().all(|value| visit(value, depth + 1, entries)),
            Value::Object(values) => values
                .values()
                .all(|value| visit(value, depth + 1, entries)),
            Value::String(value) => value.encode_utf16().count() <= 1_000_000,
            _ => true,
        }
    }
    let mut entries = 1;
    parameters
        .values()
        .all(|value| visit(value, 1, &mut entries))
        && encode_message(parameters, 65_537).is_ok()
}

fn valid_configuration(configuration: &AssetGroupConfiguration) -> bool {
    let mut labels = std::collections::BTreeSet::new();
    configuration.groups.len() <= 32
        && encode_message(configuration, 262_145).is_ok()
        && configuration.groups.iter().all(|group| {
            valid_text(&group.label, 128, false)
                && group.label.starts_with("Tag_")
                && group.label.len() > 4
                && group
                    .label
                    .chars()
                    .all(|value| value.is_ascii_alphanumeric() || value == '_')
                && labels.insert(&group.label)
                && group.priority <= 1_000_000
                && group.seeds.len() <= 128
                && group.exclusions.len() <= 1024
                && group.exclusions.iter().all(|id| valid_text(id, 512, false))
                && group.seeds.iter().all(|seed| match seed {
                    beagle::asset_groups::Seed::Objectid(id) => valid_text(id, 512, false),
                    beagle::asset_groups::Seed::Cypher(cypher) => valid_text(cypher, 65_536, true),
                })
        })
}

fn validate(command: &Command) -> bool {
    match command {
        Command::Open {
            database,
            query_timeout_ms,
        } => {
            (database == ":memory:" || valid_path(database))
                && (1..=120_000).contains(query_timeout_ms)
        }
        Command::Query { cypher, parameters } => {
            valid_text(cypher, 65_536, true) && valid_parameters(parameters)
        }
        Command::SavedQuery { id, parameters } => {
            valid_text(id, 512, false) && valid_parameters(parameters)
        }
        Command::SavedQueryInfo { id } => valid_text(id, 512, false),
        Command::Entity { objectid } | Command::Tag { objectid, .. } => {
            valid_text(objectid, 512, false)
        }
        Command::Ingest {
            paths,
            history_limit,
            ..
        } => {
            (1..=100).contains(&paths.len())
                && paths.iter().all(|path| valid_path(path))
                && history_limit.is_none_or(|limit| [10, 25, 50, 100].contains(&limit))
        }
        Command::SetImportHistoryRetention { limit } => [10, 25, 50, 100].contains(limit),
        Command::Compose {
            source,
            target,
            kind,
        }
        | Command::RelayTargets {
            source,
            target,
            kind,
        } => {
            valid_text(source, 512, false)
                && valid_text(target, 512, false)
                && valid_text(kind, 128, false)
        }
        Command::Paths {
            source,
            target,
            max_hops,
            ..
        } => {
            valid_text(source, 512, false)
                && valid_text(target, 512, false)
                && (1..=64).contains(max_hops)
        }
        Command::ImportSnapshot { path, .. }
        | Command::ExportToFile { path, .. }
        | Command::Backup { path } => valid_path(path),
        Command::Cleanup { kinds } => {
            !kinds.is_empty()
                && kinds.len() <= 4
                && kinds.iter().all(|kind| {
                    matches!(
                        kind.as_str(),
                        "HasSession"
                            | "LocalToComputer"
                            | "MemberOfLocalGroup"
                            | "RemoteInteractiveLogonRight"
                    )
                })
        }
        Command::PreviewAssetGroups { configuration }
        | Command::ApplyAssetGroups { configuration } => valid_configuration(configuration),
        _ => true,
    }
}

fn execute(engine: &mut Option<Beagle>, command: Command) -> OperationResult {
    if !validate(&command) {
        return Err(INVALID_INPUT);
    }
    match command {
        Command::Open {
            database,
            query_timeout_ms,
        } => {
            if engine.is_some() {
                return Err(ProtocolError::new(
                    "database_already_open",
                    "This helper already owns a database.",
                ));
            }
            let mut opened = Beagle::open(database).map_err(|_| OPERATION_FAILED)?;
            opened.set_query_timeout(Duration::from_millis(query_timeout_ms));
            *engine = Some(opened);
            Ok(Value::Null)
        }
        Command::CloseDatabase {} => {
            drop(engine.take());
            Ok(Value::Null)
        }
        Command::Catalog {} => Beagle::query_catalog()
            .into_iter()
            .map(|entry| {
                let id = entry
                    .get("guid")
                    .and_then(Value::as_str)
                    .ok_or(OPERATION_FAILED)?;
                Beagle::saved_query(id).map_err(|_| OPERATION_FAILED)
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map(Value::Array),
        Command::SavedQueryInfo { id } => Beagle::saved_query(&id).map_err(|_| OPERATION_FAILED),
        Command::Shutdown {} => Ok(Value::Null),
        command => {
            let engine = engine.as_mut().ok_or(ProtocolError::new(
                "database_not_open",
                "Open a database before this operation.",
            ))?;
            execute_open(engine, command).map_err(|_| OPERATION_FAILED)
        }
    }
}

fn execute_open(engine: &mut Beagle, command: Command) -> Result<Value> {
    Ok(match command {
        Command::Stats {} => engine.stats()?,
        Command::SetImportHistoryRetention { limit } => {
            engine.set_import_history_retention(limit)?
        }
        Command::Query { cypher, parameters } => {
            engine.query(&cypher, &Value::Object(parameters))?
        }
        Command::SavedQuery { id, parameters } => {
            engine.query_saved(&id, &Value::Object(parameters))?
        }
        Command::Entity { objectid } => engine.entity(&objectid)?,
        Command::Ingest {
            paths,
            analyze,
            mode,
            history_limit,
            compact_reports,
        } => {
            let outcome = engine.ingest_with_history_retention(
                &paths.into_iter().map(PathBuf::from).collect::<Vec<_>>(),
                IngestOptions { analyze, mode },
                history_limit,
            )?;
            if compact_reports {
                compact_ingest(outcome)?
            } else {
                serde_json::to_value(outcome)?
            }
        }
        Command::Analyze { compact_reports } => {
            let outcome = engine.analyze(None)?;
            if compact_reports {
                compact_analysis_outcome(outcome)?
            } else {
                serde_json::to_value(outcome)?
            }
        }
        Command::ImportSnapshot {
            path,
            analyze,
            compact_reports,
        } => {
            let metadata = fs::symlink_metadata(&path)?;
            anyhow::ensure!(
                metadata.is_file() && metadata.len() <= SNAPSHOT_BYTES,
                "Snapshot exceeds file limits"
            );
            let snapshot = serde_json::from_reader(File::open(path)?.take(SNAPSHOT_BYTES + 1))?;
            let outcome = engine.import_snapshot(snapshot, SnapshotImportOptions { analyze })?;
            let mut value = serde_json::to_value(outcome)?;
            if compact_reports {
                compact_analysis_value(&mut value);
            }
            value
        }
        Command::ExportToFile { path, kind } => {
            let snapshot = engine.export(kind)?;
            let ((), bytes) = private_output(&path, |file| {
                serde_json::to_writer(
                    &mut LimitedFile {
                        file,
                        bytes: 0,
                        limit: SNAPSHOT_BYTES,
                    },
                    &snapshot,
                )?;
                Ok(())
            })?;
            json!({"nodes":snapshot.nodes.len(),"edges":snapshot.edges.len(),"bytes":bytes})
        }
        Command::Backup { path } => {
            let ((), bytes) = private_output(&path, |_file| engine.store().backup_to(&path))?;
            json!({"bytes":bytes})
        }
        Command::Cleanup { kinds } => {
            let mut value = engine.cleanup_relationships(&kinds)?;
            compact_analysis_value(&mut value);
            value
        }
        Command::GetAssetGroups {} => serde_json::to_value(engine.asset_group_configuration()?)?,
        Command::PreviewAssetGroups { configuration } => {
            compact_selection(engine.preview_asset_groups(&configuration)?)?
        }
        Command::ApplyAssetGroups { configuration } => {
            compact_analysis_outcome(engine.apply_asset_groups_with_analysis(&configuration)?)?
        }
        Command::RelayTargets {
            source,
            target,
            kind,
        } => {
            let nodes = engine.relay_targets(&source, &target, &kind)?;
            json!({"columns":["target"],"rows":nodes.into_iter().map(|node| json!({"target":node})).collect::<Vec<_>>()})
        }
        Command::Tag {
            objectid,
            tag,
            enabled,
        } => serde_json::to_value(engine.tag(&objectid, tag, enabled)?)?,
        Command::Compose {
            source,
            target,
            kind,
        } => serde_json::to_value(engine.compose(&source, &target, &kind)?)?,
        Command::Export {} => serde_json::to_value(engine.export(ExportKind::Current)?)?,
        Command::Paths {
            source,
            target,
            all,
            max_hops,
        } => engine.paths(
            &source,
            &target,
            PathOptions {
                selection: if all {
                    PathSelection::AllShortest
                } else {
                    PathSelection::Shortest
                },
                max_hops: Some(max_hops),
            },
        )?,
        Command::Open { .. }
        | Command::CloseDatabase {}
        | Command::Catalog {}
        | Command::SavedQueryInfo { .. }
        | Command::Shutdown {} => unreachable!(),
    })
}

const SNAPSHOT_BYTES: u64 = 1024 * 1024 * 1024;

/// The host publishes this create-new staging file only after a verified reply.
/// Killing the helper may leave a partial staging file; the host owns cleanup.
fn private_output<T>(
    path: &str,
    operation: impl FnOnce(&mut File) -> Result<T>,
) -> Result<(T, u64)> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let result = (|| {
        let value = operation(&mut file)?;
        file.sync_all()?;
        Ok((value, file.metadata()?.len()))
    })();
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}
struct LimitedFile<'a> {
    file: &'a mut File,
    bytes: u64,
    limit: u64,
}
impl Write for LimitedFile<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.limit - self.bytes {
            return Err(io::Error::other("Snapshot exceeds 1 GiB limit"));
        }
        let written = self.file.write(bytes)?;
        self.bytes += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn bounded_text(value: &str, length: usize) -> String {
    value.chars().take(length).collect()
}

fn compact_ingest(mut outcome: beagle::IngestOutcome) -> Result<Value> {
    let report = &mut outcome.ingest;
    let mut quality = Map::new();
    for category in [
        "Sessions",
        "PrivilegedSessions",
        "RegistrySessions",
        "LocalGroups",
    ] {
        let (mut collected, mut failed, mut unknown, mut omitted) =
            (0usize, 0usize, 0usize, 0usize);
        let mut reasons = std::collections::BTreeMap::<String, usize>::new();
        for record in &report.source_records {
            if let Some(probe) = record.data.get(category) {
                // LocalGroups records one independent probe per local group.
                // Missing fields and empty arrays mean no reported probes (zero),
                // while a present probe without Collected is explicitly unknown.
                let values = if category == "LocalGroups" {
                    probe
                        .as_array()
                        .map(Vec::as_slice)
                        .unwrap_or(std::slice::from_ref(probe))
                } else {
                    std::slice::from_ref(probe)
                };
                for value in values {
                    let success = value.get("Collected").and_then(Value::as_bool);
                    match success {
                        Some(true) => collected += 1,
                        Some(false) => failed += 1,
                        None => unknown += 1,
                    }
                    if success == Some(false) {
                        let reason = bounded_text(
                            value
                                .get("FailureReason")
                                .and_then(Value::as_str)
                                .filter(|reason| !reason.is_empty())
                                .unwrap_or("Unspecified"),
                            512,
                        );
                        if reasons.contains_key(&reason) || reasons.len() < 100 {
                            *reasons.entry(reason).or_default() += 1;
                        } else {
                            omitted += 1;
                        }
                    }
                }
            }
        }
        quality.insert(category.into(), json!({"collected":collected,"failed":failed,"unknown":unknown,"failureReasons":reasons,"failureReasonsTruncated":omitted}));
    }
    let counts = json!({"sourceRecordsCount":report.source_records.len(),"retainedFieldsCount":report.retained_fields.len(),"propertyDeletionsCount":report.property_deletions.len(),"edgePropertyDeletionsCount":report.edge_property_deletions.len(),"warningsTruncated":report.warnings.len().saturating_sub(200),"filesTruncated":report.files.len().saturating_sub(1000),"collectionQuality":quality});
    report.source_records.clear();
    report.retained_fields.clear();
    report.property_deletions.clear();
    report.edge_property_deletions.clear();
    report.warnings.truncate(200);
    for warning in &mut report.warnings {
        *warning = bounded_text(warning, 2048);
    }
    report.files.truncate(1000);
    for file in &mut report.files {
        file.path = bounded_text(&file.path, 4096);
        file.metadata = Value::Object(
            file.metadata
                .as_object()
                .into_iter()
                .flatten()
                .take(32)
                .filter_map(|(key, value)| {
                    if ![
                        "type",
                        "version",
                        "count",
                        "methods",
                        "collectorversion",
                        "timestamp",
                    ]
                    .contains(&key.as_str())
                        || !matches!(
                            value,
                            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
                        )
                    {
                        return None;
                    }
                    Some((
                        key.clone(),
                        match value {
                            Value::String(value) => Value::String(bounded_text(value, 1024)),
                            other => other.clone(),
                        },
                    ))
                })
                .collect(),
        );
    }
    let mut value = serde_json::to_value(outcome)?;
    let ingest = value["ingest"].as_object_mut().unwrap();
    for field in [
        "source_records",
        "retained_fields",
        "property_deletions",
        "edge_property_deletions",
    ] {
        ingest.remove(field);
    }
    ingest.extend(counts.as_object().unwrap().clone());
    compact_analysis_value(&mut value);
    Ok(value)
}
fn compact_analysis_outcome(outcome: beagle::AnalysisOutcome) -> Result<Value> {
    let mut value = serde_json::to_value(outcome)?;
    compact_analysis_value(&mut value);
    Ok(value)
}
fn compact_analysis_value(value: &mut Value) {
    if let Some(analysis) = value.get_mut("analysis").and_then(Value::as_object_mut) {
        let mut omitted = 0;
        if let Some(ambiguities) = analysis
            .get_mut("local_group_ambiguities")
            .and_then(Value::as_array_mut)
        {
            let original = std::mem::take(ambiguities);
            let mut bytes = 0;
            for ambiguity in original {
                if ambiguities.len() >= 100 {
                    omitted += 1;
                    continue;
                }
                match encode_message(&ambiguity, 65_536) {
                    Ok(encoded) if bytes + encoded.len() <= 2 * 1024 * 1024 => {
                        bytes += encoded.len();
                        ambiguities.push(ambiguity);
                    }
                    _ => omitted += 1,
                }
            }
        }
        analysis.insert("diagnostics_truncated".into(), json!(omitted));
    }
    if let Some(selection) = value
        .get_mut("asset_groups")
        .filter(|value| !value.is_null())
        && let Ok(report) = serde_json::from_value::<beagle::SelectionReport>(selection.clone())
        && let Ok(compact) = compact_selection(report)
    {
        *selection = compact;
    }
}
fn compact_selection(report: beagle::SelectionReport) -> Result<Value> {
    let mut value = serde_json::to_value(report)?;
    let mut counts = Map::new();
    let mut truncated = false;
    if let Some(selected) = value["selected"].as_object_mut() {
        for (label, ids) in selected {
            if let Some(ids) = ids.as_array_mut() {
                counts.insert(label.clone(), json!(ids.len()));
                truncated |= ids.len() > 100;
                ids.truncate(100);
            }
        }
    }
    let missing_total = value["missing_objectids"].as_array().map_or(0, Vec::len);
    if let Some(missing) = value["missing_objectids"].as_array_mut() {
        missing.truncate(100);
    }
    value["counts"] = Value::Object(counts);
    value["missing_total"] = json!(missing_total);
    value["truncated"] = json!(truncated || missing_total > 100);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn input_limit_counts_newline_before_copying_chunk() {
        let mut exact = vec![b' '; REQUEST_BYTES];
        exact[REQUEST_BYTES - 1] = b'\n';
        for chunk_size in [1, 31, 8_192, REQUEST_BYTES + 1] {
            let mut input = BufReader::with_capacity(chunk_size, Cursor::new(&exact));
            let mut frame = Vec::new();
            assert!(read_frame(&mut input, &mut frame).unwrap());
            assert_eq!(frame.len(), REQUEST_BYTES);
            assert!(frame.capacity() <= REQUEST_BYTES);
        }
        let oversize = vec![b'x'; REQUEST_BYTES + 1];
        let mut frame = Vec::new();
        assert_eq!(
            read_frame(&mut Cursor::new(oversize), &mut frame)
                .unwrap_err()
                .code,
            "request_too_large"
        );
        assert!(frame.len() < REQUEST_BYTES);
        assert!(frame.capacity() <= REQUEST_BYTES);
    }

    #[test]
    fn output_limit_counts_json_escaping_and_newline() {
        let value = json!({"text": "\n\"\\"});
        let expected = serde_json::to_vec(&value).unwrap();
        let encoded = encode_message(&value, expected.len() + 1).unwrap();
        assert_eq!(&encoded[..expected.len()], expected);
        assert_eq!(encoded.last(), Some(&b'\n'));
        assert!(encode_message(&value, expected.len()).is_err());
        let oversized = Value::String("x".repeat(RESPONSE_BYTES));
        assert!(encode_message(&oversized, RESPONSE_BYTES).is_err());
    }

    #[test]
    fn parameter_limits_reject_deep_and_large_payloads() {
        let mut nested = json!(true);
        for _ in 0..32 {
            nested = json!([nested]);
        }
        assert!(!valid_parameters(
            json!({"value": nested}).as_object().unwrap()
        ));
        assert!(!valid_parameters(
            json!({"value": "x".repeat(65_536)}).as_object().unwrap()
        ));
        assert!(valid_parameters(
            json!({"__proto__": {"polluted": true}, "x": [null, 1]})
                .as_object()
                .unwrap()
        ));
    }
    #[test]
    fn compact_diagnostics_omit_oversized_entries_with_explicit_count() {
        let oversized =
            json!({"computer":"HOST","candidate_groups":{"GROUP":["x".repeat(70_000)]}});
        let small = json!({"computer":"HOST","candidate_groups":{"GROUP":["USER"]}});
        let mut value = json!({"analysis":{"local_group_ambiguities":[oversized,small.clone()]}});
        compact_analysis_value(&mut value);
        assert_eq!(value["analysis"]["local_group_ambiguities"], json!([small]));
        assert_eq!(value["analysis"]["diagnostics_truncated"], 1);
    }

    #[test]
    fn failed_file_write_removes_only_its_new_staging_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("snapshot.json");
        let result = private_output(path.to_str().unwrap(), |file| {
            LimitedFile {
                file,
                bytes: 0,
                limit: 3,
            }
            .write_all(b"four")?;
            Ok(())
        });
        assert!(result.is_err());
        assert!(!path.exists());
        fs::write(&path, b"existing").unwrap();
        assert!(private_output(path.to_str().unwrap(), |_file| Ok(())).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"existing");
    }

    #[test]
    fn rules_limits_apply_even_when_a_rule_is_disabled() {
        let mut value = json!({"type":"previewAssetGroups","configuration":{"groups":[{"label":"Tag_Test","seeds":[{"type":"cypher","value":"RETURN 1"}],"enabled":false,"priority":1_000_001}]}});
        assert!(!validate(
            &serde_json::from_value::<Command>(value.clone()).unwrap()
        ));
        value["configuration"]["groups"][0]["priority"] = json!(0);
        assert!(validate(
            &serde_json::from_value::<Command>(value.clone()).unwrap()
        ));
        value["configuration"]["groups"][0]["seeds"][0]["value"] = json!("x".repeat(65_537));
        assert!(!validate(
            &serde_json::from_value::<Command>(value).unwrap()
        ));
    }
}
