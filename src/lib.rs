//! Beagle's in-process Active Directory graph analysis library.
//!
//! [`Beagle`] provides the same ingestion, analysis, tagging, and query workflows
//! used by the standalone CLI. Inputs and reports are Rust values; no subprocess,
//! command-line parsing, or standard-I/O protocol is needed. SQLite, GraphQLite,
//! and PCRE2 are statically linked into the consuming application.
//!
//! ```
//! use beagle::{Beagle, ExportKind, GraphSnapshot, SnapshotImportOptions};
//! use serde_json::json;
//!
//! let mut beagle = Beagle::open(":memory:")?;
//! beagle.import_snapshot(GraphSnapshot::default(), SnapshotImportOptions::default())?;
//! let result = beagle.query("RETURN $value AS value", &json!({"value": 42}))?;
//! assert_eq!(result["rows"][0]["value"], 42);
//! assert!(beagle.export(ExportKind::Current)?.nodes.is_empty());
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! The lower-level [`Store`] and graph-processing modules remain available for
//! consumers that need finer control. Operations are synchronous; use a worker
//! thread for lengthy work in a GUI. This crate exposes a Rust API, not a stable
//! C ABI. The standalone binary also provides a JSON-lines `serve-stdio` mode.

pub mod analysis;
pub mod asset_groups;
mod backend;
pub mod composition;
pub mod engine;
pub mod ingest;
pub mod model;
pub mod query;
pub mod store;

pub use analysis::{AnalysisOptions, AnalysisReport};
pub use asset_groups::{Configuration as AssetGroupConfiguration, SelectionReport};
pub use engine::{
    AnalysisOutcome, Beagle, ExportKind, ImportMode, IngestOptions, IngestOutcome, PathOptions,
    PathSelection, SnapshotImportOptions, SnapshotImportOutcome, SystemTag, TagOutcome,
};
pub use ingest::ImportReport;
pub use model::{Edge, GraphData, GraphSnapshot, Node, Properties};
pub use store::Store;
