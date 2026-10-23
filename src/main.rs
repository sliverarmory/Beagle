mod helper_stdio;

use anyhow::{Context, Result, bail};
use beagle::{
    Beagle, ExportKind, GraphSnapshot, ImportMode, IngestOptions, PathOptions, PathSelection,
    SnapshotImportOptions, SystemTag, analysis, asset_groups,
};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
};

#[derive(Parser)]
#[command(
    version,
    about = "Headless Active Directory graph analysis using Rust and GraphQLite"
)]
struct Cli {
    /// Print embedded desktop runtime build provenance without opening a database.
    #[arg(long, exclusive = true)]
    build_info: bool,
    #[arg(long, global = true, default_value = "beagle.db")]
    db: PathBuf,
    #[arg(long, global = true, default_value_t = 30)]
    query_timeout: u64,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    /// Import SharpHound JSON, ZIP or directories. Repeated imports merge by identity.
    Ingest {
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        #[arg(long)]
        analyze: bool,
        #[arg(long)]
        replace: bool,
    },
    /// Rebuild derived relationships from the retained raw collection.
    Analyze {
        #[arg(long)]
        options: Option<PathBuf>,
    },
    /// Apply and persist objectid/Cypher asset-group selectors and exclusions.
    AssetGroups { file: PathBuf },
    /// Execute read-only Cypher, a file, or an official saved query.
    Query {
        cypher: Option<String>,
        #[arg(long, conflicts_with_all=["cypher","saved"])]
        file: Option<PathBuf>,
        #[arg(long, conflicts_with = "cypher")]
        saved: Option<String>,
        #[arg(long, default_value = "{}")]
        params: String,
    },
    /// List official AD queries, or show one by name or GUID.
    Queries { name: Option<String> },
    /// Validate Cypher syntax and semantics without executing it.
    Validate { cypher: String },
    /// Export canonical graph JSON; raw returns the pre-analysis collection.
    Export {
        #[arg(long)]
        raw: bool,
    },
    /// Import canonical graph JSON (useful for reproducible comparisons).
    ImportSnapshot {
        file: PathBuf,
        #[arg(long)]
        analyze: bool,
    },
    /// Node/relationship counts and backend capabilities.
    Stats,
    /// Look up an entity by its BloodHound object ID.
    Entity { objectid: String },
    /// Search entity names and object IDs.
    Search {
        term: String,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Find shortest attack paths between two object IDs.
    Paths {
        #[arg(long)]
        source: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        max_hops: Option<u32>,
    },
    /// Explain a derived edge using its underlying BloodHound relationships.
    Compose {
        #[arg(long)]
        source: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        kind: String,
    },
    /// List intermediate NTLM relay targets for a derived relationship.
    RelayTargets {
        #[arg(long)]
        source: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        kind: String,
    },
    /// Set or remove an owned/admin_tier_0 system tag.
    Tag {
        objectid: String,
        tag: String,
        #[arg(long)]
        remove: bool,
    },
    /// Process JSON lines with op=query/validate/export/stats; one JSON reply per line.
    ServeStdio,
    /// Run the bounded, persistent desktop-helper protocol over private stdio.
    HelperStdio,
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", json!({"error":format!("{error:#}")}));
        std::process::exit(1);
    }
}
fn print(value: &Value) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}
fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.build_info {
        return print(&json!({
            "name": "beagle",
            "version": env!("CARGO_PKG_VERSION"),
            "protocol": 1,
            "beagleRevision": env!("BEAGLE_BUILD_REVISION"),
            "target": env!("BEAGLE_BUILD_TARGET"),
        }));
    }
    let command = cli.command.context("a command is required")?;
    if matches!(command, Command::HelperStdio) {
        return helper_stdio::run_stdio();
    }
    if let Command::Queries { name } = &command {
        return print(&match name {
            Some(name) => Beagle::saved_query(name)?,
            None => json!(Beagle::query_catalog()),
        });
    }
    let mut beagle = Beagle::open(&cli.db)?;
    beagle.set_query_timeout(std::time::Duration::from_secs(cli.query_timeout));
    let result = match command {
        Command::Ingest {
            inputs,
            analyze,
            replace,
        } => serde_json::to_value(beagle.ingest(
            &inputs,
            IngestOptions {
                mode: if replace {
                    ImportMode::Replace
                } else {
                    ImportMode::Merge
                },
                analyze,
            },
        )?)?,
        Command::Analyze { options } => {
            let options: Option<analysis::AnalysisOptions> = options
                .map(|path| -> Result<_> {
                    Ok(serde_json::from_reader(std::fs::File::open(path)?)?)
                })
                .transpose()?;
            serde_json::to_value(beagle.analyze(options.as_ref())?)?
        }
        Command::AssetGroups { file } => {
            let config: asset_groups::Configuration =
                serde_json::from_reader(std::fs::File::open(file)?)?;
            serde_json::to_value(beagle.apply_asset_groups(&config)?)?
        }
        Command::Query {
            cypher,
            file,
            saved,
            params,
        } => {
            let params: Value = serde_json::from_str(&params).context("parse --params")?;
            if let Some(file) = file {
                beagle.query(&std::fs::read_to_string(file)?, &params)?
            } else if let Some(saved) = saved {
                beagle.query_saved(&saved, &params)?
            } else {
                beagle.query(
                    &cypher.context("provide CYPHER, --file, or --saved")?,
                    &params,
                )?
            }
        }
        Command::Queries { .. } | Command::HelperStdio => unreachable!(),
        Command::Validate { cypher } => beagle.validate(&cypher)?,
        Command::Export { raw } => serde_json::to_value(beagle.export(if raw {
            ExportKind::Raw
        } else {
            ExportKind::Current
        })?)?,
        Command::ImportSnapshot { file, analyze } => {
            let snapshot: GraphSnapshot = serde_json::from_reader(std::fs::File::open(file)?)?;
            serde_json::to_value(
                beagle.import_snapshot(snapshot, SnapshotImportOptions { analyze })?,
            )?
        }
        Command::Stats => beagle.stats()?,
        Command::Entity { objectid } => beagle.entity(&objectid)?,
        Command::Search { term, limit } => beagle.search(&term, limit)?,
        Command::Paths {
            source,
            target,
            all,
            max_hops,
        } => {
            if max_hops.is_some_and(|n| n == 0 || n > i32::MAX as u32) {
                bail!("--max-hops must be between 1 and 2147483647");
            }
            beagle.paths(
                &source,
                &target,
                PathOptions {
                    selection: if all {
                        PathSelection::AllShortest
                    } else {
                        PathSelection::Shortest
                    },
                    max_hops,
                },
            )?
        }
        Command::Tag {
            objectid,
            tag,
            remove,
        } => {
            let tag = match tag.as_str() {
                "owned" => SystemTag::Owned,
                "admin_tier_0" => SystemTag::AdminTierZero,
                _ => bail!("supported tags: owned, admin_tier_0"),
            };
            serde_json::to_value(beagle.tag(&objectid, tag, !remove)?)?
        }
        Command::Compose {
            source,
            target,
            kind,
        } => serde_json::to_value(beagle.compose(&source, &target, &kind)?)?,
        Command::RelayTargets {
            source,
            target,
            kind,
        } => serde_json::to_value(beagle.relay_targets(&source, &target, &kind)?)?,
        Command::ServeStdio => {
            for line in io::stdin().lock().lines() {
                let response = (|| -> Result<Value> {
                    let input: Value = serde_json::from_str(&line?)?;
                    match input["op"].as_str() {
                        Some("query") => beagle.query(
                            input["query"].as_str().context("query required")?,
                            input.get("params").unwrap_or(&json!({})),
                        ),
                        Some("validate") => {
                            beagle.validate(input["query"].as_str().context("query required")?)
                        }
                        Some("export") => {
                            Ok(serde_json::to_value(beagle.export(ExportKind::Current)?)?)
                        }
                        Some("stats") => beagle.stats(),
                        _ => bail!("unsupported op"),
                    }
                })();
                print(&match response {
                    Ok(value) => json!({"value": value}),
                    Err(error) => json!({"error": format!("{error:#}")}),
                })?;
            }
            return Ok(());
        }
    };
    print(&result)
}
