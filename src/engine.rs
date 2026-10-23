//! In-process application API shared by library consumers and the CLI.

use crate::{
    GraphData, GraphSnapshot, Node, Store, analysis, asset_groups, composition, ingest, query,
};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::Path, path::PathBuf, str::FromStr, time::Duration};

/// A graph database with Beagle's ingestion, analysis, and query workflows.
///
/// SQLite, GraphQLite, and PCRE2 are linked into the consumer at build time. No
/// Beagle subprocess or external GraphQLite shared library is needed. Operations
/// run synchronously on the calling thread; GUI applications should run lengthy
/// imports and analysis on a worker thread.
///
/// Each instance owns one [`Store`]. Open a separate instance for independently
/// owned connections, and use [`Self::set_query_timeout`] to bound Cypher work.
pub struct Beagle {
    store: Store,
}

/// How an imported SharpHound batch relates to the retained raw collection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportMode {
    /// Merge records by object identity and preserve the import history.
    #[default]
    Merge,
    /// Replace the retained collection and reset its import history.
    Replace,
}

/// Settings for [`Beagle::ingest`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IngestOptions {
    pub mode: ImportMode,
    /// Rebuild derived relationships and reapply persisted asset groups.
    pub analyze: bool,
}

/// An import's provenance and the resulting graph size.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestOutcome {
    pub ingest: ingest::ImportReport,
    pub analysis: Option<analysis::AnalysisReport>,
    pub asset_groups: Option<asset_groups::SelectionReport>,
    pub nodes: usize,
    pub edges: usize,
}

/// Analysis results and the effective settings persisted for future operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisOutcome {
    pub analysis: analysis::AnalysisReport,
    pub options: analysis::AnalysisOptions,
    pub asset_groups: Option<asset_groups::SelectionReport>,
}

/// Settings for replacing the graph with a canonical snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SnapshotImportOptions {
    /// Analyze the supplied snapshot using persisted settings and asset groups.
    pub analyze: bool,
}

/// The resulting graph size and optional processing reports for a snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotImportOutcome {
    pub nodes: usize,
    pub edges: usize,
    pub analysis: Option<analysis::AnalysisReport>,
    pub asset_groups: Option<asset_groups::SelectionReport>,
}

/// Which graph to export.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportKind {
    /// The current graph, including derived relationships and applied tags.
    #[default]
    Current,
    /// The retained collection before analysis and applied tag overrides.
    Raw,
}

/// How many shortest attack paths to return.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathSelection {
    #[default]
    Shortest,
    AllShortest,
}

/// Settings for [`Beagle::paths`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathOptions {
    pub selection: PathSelection,
    /// Optional bound from 1 through 2,147,483,647 inclusive.
    pub max_hops: Option<u32>,
}

/// A supported manual system tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemTag {
    #[serde(rename = "owned")]
    Owned,
    #[serde(rename = "admin_tier_0")]
    AdminTierZero,
}

impl SystemTag {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owned => "owned",
            Self::AdminTierZero => "admin_tier_0",
        }
    }
}

impl FromStr for SystemTag {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "owned" => Ok(Self::Owned),
            "admin_tier_0" => Ok(Self::AdminTierZero),
            _ => bail!("supported tags: owned, admin_tier_0"),
        }
    }
}

/// A persisted manual tag override.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagOutcome {
    pub objectid: String,
    pub tag: SystemTag,
    pub enabled: bool,
}

impl Beagle {
    /// Open or create a database. `":memory:"` creates an in-memory database.
    pub fn open(database: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            store: Store::open(database)?,
        })
    }

    /// Create an isolated in-memory graph database.
    pub fn in_memory() -> Result<Self> {
        Self::open(":memory:")
    }

    /// Adopt an existing database connection without reopening it.
    pub fn from_store(store: Store) -> Self {
        Self { store }
    }

    /// Access the low-level database API, for example to inspect import history.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Return the owned low-level database connection.
    pub fn into_store(self) -> Store {
        self.store
    }

    /// Bound Cypher execution and asset-group selectors. The default is 30 seconds.
    pub fn set_query_timeout(&mut self, timeout: Duration) {
        self.store.set_query_timeout(timeout);
    }

    /// Import SharpHound JSON files, ZIP archives, or directories.
    ///
    /// Input validation and processing finish before the new graph is committed.
    /// Merge mode applies explicit-null removals and resolves incoming references
    /// against the retained collection. Manual tag overrides are reapplied in
    /// both modes, even when analysis is disabled.
    pub fn ingest(&mut self, inputs: &[PathBuf], options: IngestOptions) -> Result<IngestOutcome> {
        self.ingest_with_history_retention(inputs, options, None)
    }

    /// Atomically import and optionally update the persisted source-report policy.
    /// Existing callers retain their configured policy, or the legacy unlimited
    /// policy until an explicit retention limit is chosen.
    pub fn ingest_with_history_retention(
        &mut self,
        inputs: &[PathBuf],
        options: IngestOptions,
        history_limit: Option<usize>,
    ) -> Result<IngestOutcome> {
        if let Some(limit) = history_limit {
            crate::store::validate_import_history_limit(limit)?;
        }
        let replace = options.mode == ImportMode::Replace;
        let mut graph = if replace {
            GraphData::default()
        } else {
            self.store.raw_graph()?
        };
        let (incoming, ingest) = ingest::ingest_paths_with_existing(inputs, &graph)?;
        ingest::apply_import(&mut graph, &incoming, &ingest);
        let raw = graph.clone();
        if options.analyze && !replace {
            self.store.retain_previous_ownership(&mut graph)?;
        }
        let analysis_options = self.analysis_options()?;
        let analysis = if options.analyze {
            Some(analysis::analyze_with_options(
                &mut graph,
                &analysis_options,
            )?)
        } else {
            None
        };
        let asset_groups = if options.analyze {
            self.store.apply_saved_asset_groups(&mut graph)?
        } else {
            None
        };
        self.store.apply_manual_tags(&mut graph)?;
        let outcome = IngestOutcome {
            ingest,
            analysis,
            asset_groups,
            nodes: graph.nodes.len(),
            edges: graph.edges.len(),
        };
        self.store.save_import_with_retention(
            &graph,
            &raw,
            &serde_json::to_value(&outcome)?,
            replace,
            history_limit,
        )?;
        Ok(outcome)
    }

    /// Persist a source-report retention limit and prune only archived reports.
    /// The retained raw graph, manual tags and asset-group configuration remain.
    pub fn set_import_history_retention(&mut self, limit: usize) -> Result<Value> {
        self.store.set_import_history_retention(limit)
    }

    /// Rebuild derived relationships from the retained raw graph.
    ///
    /// `None` reuses the last persisted analysis settings, or the defaults when
    /// none exist. Explicit settings become the defaults for subsequent imports,
    /// analysis, and asset-group updates after a successful commit.
    pub fn analyze(
        &mut self,
        options: Option<&analysis::AnalysisOptions>,
    ) -> Result<AnalysisOutcome> {
        let mut graph = self.store.raw_graph()?;
        self.store.retain_previous_ownership(&mut graph)?;
        let options = match options {
            Some(options) => options.clone(),
            None => self.analysis_options()?,
        };
        let analysis = analysis::analyze_with_options(&mut graph, &options)?;
        let asset_groups = self.store.apply_saved_asset_groups(&mut graph)?;
        self.store.apply_manual_tags(&mut graph)?;
        let outcome = AnalysisOutcome {
            analysis,
            options,
            asset_groups,
        };
        self.store.save(
            &graph,
            None,
            Some(("last_analysis", &serde_json::to_value(&outcome)?)),
        )?;
        Ok(outcome)
    }

    /// Remove selected collected links and atomically rebuild derived state.
    /// Original import history remains an archive; retained raw graph is updated.
    pub fn cleanup_relationships(&mut self, kinds: &[String]) -> Result<Value> {
        if kinds.is_empty()
            || kinds.len() > 4
            || kinds.iter().any(|kind| {
                !matches!(
                    kind.as_str(),
                    "HasSession"
                        | "LocalToComputer"
                        | "MemberOfLocalGroup"
                        | "RemoteInteractiveLogonRight"
                )
            })
        {
            bail!("unsupported collected relationship cleanup");
        }
        let mut graph = self.store.raw_graph()?;
        let before = graph.edges.len();
        graph.edges.retain(|_, edge| !kinds.contains(&edge.kind));
        let removed = before - graph.edges.len();
        let raw = graph.clone();
        let options = self.analysis_options()?;
        let analysis = analysis::analyze_with_options(&mut graph, &options)?;
        let asset_groups = self.store.apply_saved_asset_groups(&mut graph)?;
        self.store.apply_manual_tags(&mut graph)?;
        let outcome = json!({"removedEdges":removed,"kinds":kinds,"analysis":analysis,"options":options,"asset_groups":asset_groups,"nodes":graph.nodes.len(),"edges":graph.edges.len()});
        self.store
            .save(&graph, Some(&raw), Some(("last_cleanup", &outcome)))?;
        Ok(outcome)
    }

    /// Return persisted analysis settings, or defaults for a new database.
    pub fn analysis_options(&self) -> Result<analysis::AnalysisOptions> {
        Ok(self
            .store
            .metadata("last_analysis")?
            .and_then(|value| value.get("options").cloned())
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default())
    }

    /// Read saved rule settings without changing the current graph.
    pub fn asset_group_configuration(&self) -> Result<asset_groups::Configuration> {
        Ok(self
            .store
            .metadata("asset_groups")?
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default())
    }

    /// Evaluate a configuration against the same staged graph used by apply.
    /// Neither graph data nor saved settings are changed. Manual tag overrides
    /// apply after these rule selections when a configuration is committed.
    pub fn preview_asset_groups(
        &self,
        configuration: &asset_groups::Configuration,
    ) -> Result<asset_groups::SelectionReport> {
        let mut graph = self.store.raw_graph()?;
        self.store.retain_previous_ownership(&mut graph)?;
        analysis::analyze_with_options(&mut graph, &self.analysis_options()?)?;
        self.store.apply_asset_groups(&mut graph, configuration)
    }

    /// Reanalyze the retained collection and apply and persist asset groups.
    ///
    /// Selectors execute against the staged graph. A failed selector does not
    /// commit a partial graph or replace the saved configuration.
    pub fn apply_asset_groups(
        &mut self,
        configuration: &asset_groups::Configuration,
    ) -> Result<asset_groups::SelectionReport> {
        Ok(self
            .apply_asset_groups_with_analysis(configuration)?
            .asset_groups
            .expect("applying asset groups always returns a selection report"))
    }

    /// Apply rules and return the diagnostics from that same analysis pass.
    pub fn apply_asset_groups_with_analysis(
        &mut self,
        configuration: &asset_groups::Configuration,
    ) -> Result<AnalysisOutcome> {
        let mut graph = self.store.raw_graph()?;
        self.store.retain_previous_ownership(&mut graph)?;
        let options = self.analysis_options()?;
        let analysis = analysis::analyze_with_options(&mut graph, &options)?;
        let report = self.store.apply_asset_groups(&mut graph, configuration)?;
        self.store.apply_manual_tags(&mut graph)?;
        self.store.save(
            &graph,
            None,
            Some(("asset_groups", &serde_json::to_value(configuration)?)),
        )?;
        Ok(AnalysisOutcome {
            analysis,
            options,
            asset_groups: Some(report),
        })
    }

    /// Replace the current and raw graph with a canonical snapshot.
    ///
    /// When analysis is enabled, persisted asset groups and manual tag overrides
    /// are applied after analysis. Otherwise, the supplied graph is stored as-is.
    /// Snapshot imports preserve the existing import history and configuration.
    pub fn import_snapshot(
        &mut self,
        snapshot: GraphSnapshot,
        options: SnapshotImportOptions,
    ) -> Result<SnapshotImportOutcome> {
        let mut graph = GraphData::from_snapshot(snapshot);
        let raw = graph.clone();
        let analysis = if options.analyze {
            Some(analysis::analyze_with_options(
                &mut graph,
                &self.analysis_options()?,
            )?)
        } else {
            None
        };
        let asset_groups = if options.analyze {
            let groups = self.store.apply_saved_asset_groups(&mut graph)?;
            self.store.apply_manual_tags(&mut graph)?;
            groups
        } else {
            None
        };
        self.store.save(&graph, Some(&raw), None)?;
        Ok(SnapshotImportOutcome {
            nodes: graph.nodes.len(),
            edges: graph.edges.len(),
            analysis,
            asset_groups,
        })
    }

    /// Export the selected graph as typed nodes and relationships.
    pub fn export(&self, kind: ExportKind) -> Result<GraphSnapshot> {
        Ok(match kind {
            ExportKind::Current => self.store.graph()?,
            ExportKind::Raw => self.store.raw_graph()?,
        }
        .snapshot())
    }

    /// Execute read-only Cypher with JSON parameters.
    ///
    /// Query results retain GraphQLite's `columns` and `rows` envelope because
    /// their shape depends on the caller's query. Writes are rejected.
    pub fn query(&self, cypher: &str, parameters: &Value) -> Result<Value> {
        self.store.query(cypher, parameters)
    }

    /// Prepare and execute an official saved query by name or GUID.
    pub fn query_saved(&self, name_or_guid: &str, parameters: &Value) -> Result<Value> {
        self.query(&query::prepare_saved(name_or_guid, parameters)?, parameters)
    }

    /// Return the bundled official AD query catalog without opening a database.
    pub fn query_catalog() -> Vec<Value> {
        query::catalog()
    }

    /// Look up an official saved query without opening a database.
    pub fn saved_query(name_or_guid: &str) -> Result<Value> {
        query::saved_query(name_or_guid)
    }

    /// Validate Cypher syntax and semantics without executing it.
    pub fn validate(&self, cypher: &str) -> Result<Value> {
        self.store.validate(cypher)
    }

    /// Return node and relationship counts, labels, and backend capabilities.
    pub fn stats(&self) -> Result<Value> {
        self.store.stats()
    }

    /// Return an entity in the Cypher result envelope, with no rows if absent.
    pub fn entity(&self, objectid: &str) -> Result<Value> {
        self.query(
            "MATCH (n {objectid:$id}) RETURN n",
            &json!({"id": objectid}),
        )
    }

    /// Search names and object IDs, ordered by name, in a Cypher result envelope.
    pub fn search(&self, term: &str, limit: u32) -> Result<Value> {
        self.query(
            "MATCH (n) WHERE toUpper(n.name) CONTAINS toUpper($term) OR toUpper(n.objectid) CONTAINS toUpper($term) RETURN n ORDER BY n.name LIMIT $limit",
            &json!({"term": term, "limit": limit}),
        )
    }

    /// Find shortest attack paths between two BloodHound object IDs.
    pub fn paths(&self, source: &str, target: &str, options: PathOptions) -> Result<Value> {
        if options
            .max_hops
            .is_some_and(|n| n == 0 || n > i32::MAX as u32)
        {
            bail!("max_hops must be between 1 and 2147483647");
        }
        let hops = options
            .max_hops
            .map(|n| format!("1..{n}"))
            .unwrap_or_default();
        let function = match options.selection {
            PathSelection::Shortest => "shortestPath",
            PathSelection::AllShortest => "allShortestPaths",
        };
        self.query(
            &format!("MATCH p={function}((s {{objectid:$source}})-[:AD_ATTACK_PATHS*{hops}]->(t {{objectid:$target}})) RETURN p"),
            &json!({"source": source, "target": target}),
        )
    }

    /// Set or remove a supported system tag and persist the manual override.
    pub fn tag(&mut self, objectid: &str, tag: SystemTag, enabled: bool) -> Result<TagOutcome> {
        self.store.tag(objectid, tag.as_str(), enabled)?;
        Ok(TagOutcome {
            objectid: objectid.to_owned(),
            tag,
            enabled,
        })
    }

    /// Explain an existing edge using its underlying BloodHound relationships.
    pub fn compose(&self, source: &str, target: &str, kind: &str) -> Result<GraphSnapshot> {
        composition::compose(&self.store.graph()?, source, target, kind)
    }

    /// Return intermediate relay target nodes for an existing derived edge.
    pub fn relay_targets(&self, source: &str, target: &str, kind: &str) -> Result<Vec<Node>> {
        composition::relay_targets(&self.store.graph()?, source, target, kind)
    }
}
