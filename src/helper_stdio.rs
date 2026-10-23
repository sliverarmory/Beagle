//! Bounded, versioned stdio transport for trusted desktop hosts.
//!
//! The host owns authorization and process deadlines. This module owns framing,
//! request validation and one database connection; it never evaluates shell text.

use anyhow::{Result, bail};
use beagle::{Beagle, ExportKind, IngestOptions, PathOptions, PathSelection, SystemTag};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    io::{self, BufRead, Write},
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
    },
    Analyze {},
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
        Command::Ingest { paths, .. } => {
            (1..=100).contains(&paths.len()) && paths.iter().all(|path| valid_path(path))
        }
        Command::Compose {
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
        Command::Query { cypher, parameters } => {
            engine.query(&cypher, &Value::Object(parameters))?
        }
        Command::SavedQuery { id, parameters } => {
            engine.query_saved(&id, &Value::Object(parameters))?
        }
        Command::Entity { objectid } => engine.entity(&objectid)?,
        Command::Ingest { paths, analyze } => serde_json::to_value(engine.ingest(
            &paths.into_iter().map(PathBuf::from).collect::<Vec<_>>(),
            IngestOptions {
                analyze,
                ..Default::default()
            },
        )?)?,
        Command::Analyze {} => serde_json::to_value(engine.analyze(None)?)?,
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
        | Command::Catalog {}
        | Command::SavedQueryInfo { .. }
        | Command::Shutdown {} => unreachable!(),
    })
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
}
