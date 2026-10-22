//! Persistent GraphQLite graph, with a raw collection snapshot for repeatable analysis.
use crate::model::{Edge, GraphData, Node};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path, time::Duration};

pub struct Store {
    conn: Connection,
    query_timeout: Duration,
}

impl Store {
    pub fn open(database: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(database).context("open database")?;
        conn.busy_timeout(Duration::from_secs(30))?;
        crate::backend::initialize(&conn)?;
        conn.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS bh_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);")?;
        let store = Self {
            conn,
            query_timeout: Duration::from_secs(30),
        };
        store.execute("MATCH (n) RETURN count(n) AS count", &json!({}))?;
        Ok(store)
    }

    pub fn capabilities(&self) -> Result<Value> {
        let value: String = self
            .conn
            .query_row("SELECT cypher_capabilities()", [], |row| row.get(0))?;
        Ok(serde_json::from_str(&value)?)
    }

    pub fn set_query_timeout(&mut self, timeout: Duration) {
        self.query_timeout = timeout;
    }

    /// Evaluate selectors against a staged graph, before its atomic publication.
    pub fn apply_asset_groups(
        &self,
        graph: &mut GraphData,
        config: &crate::asset_groups::Configuration,
    ) -> Result<crate::asset_groups::SelectionReport> {
        let mut stage = Self::open(":memory:")?;
        stage.query_timeout = self.query_timeout;
        stage.save(graph, None, None)?;
        crate::asset_groups::apply(graph, config, |query| stage.query(query, &json!({})))
    }

    pub fn apply_saved_asset_groups(
        &self,
        graph: &mut GraphData,
    ) -> Result<Option<crate::asset_groups::SelectionReport>> {
        self.metadata("asset_groups")?
            .map(|value| self.apply_asset_groups(graph, &serde_json::from_value(value)?))
            .transpose()
    }

    /// CE refreshes ownership after ADCS; retain its previous derived ownership
    /// until that stage runs, including the documented first/second-pass behavior.
    pub fn retain_previous_ownership(&self, graph: &mut GraphData) -> Result<()> {
        for edge in self
            .graph()?
            .edges
            .into_values()
            .filter(|e| e.derived && matches!(e.kind.as_str(), "Owns" | "WriteOwner"))
        {
            if graph.nodes.contains_key(&edge.source) && graph.nodes.contains_key(&edge.target) {
                graph.upsert_edge(edge);
            }
        }
        Ok(())
    }

    pub fn apply_manual_tags(&self, graph: &mut GraphData) -> Result<()> {
        if let Some(overrides) = self.metadata("manual_tags")? {
            let overrides: std::collections::BTreeMap<
                String,
                std::collections::BTreeMap<String, bool>,
            > = serde_json::from_value(overrides)?;
            for (objectid, tags) in overrides {
                if let Some(node) = graph.nodes.get_mut(&objectid) {
                    for (tag, enabled) in tags {
                        set_tag(node, &tag, enabled);
                    }
                }
            }
        }
        Ok(())
    }

    fn execute(&self, query: &str, parameters: &Value) -> Result<Value> {
        if !parameters.is_object() {
            bail!("Cypher parameters must be a JSON object");
        }
        let value: Option<String> = self
            .conn
            .query_row(
                "SELECT cypher(?1, ?2)",
                params![query, parameters.to_string()],
                |row| row.get(0),
            )
            .with_context(|| format!("execute Cypher: {query}"))?;
        let value: Value = match value {
            None => json!([]),
            Some(text) => serde_json::from_str(&text)
                .with_context(|| format!("invalid GraphQLite response: {text}"))?,
        };
        if let Some(error) = value.get("error") {
            bail!("GraphQLite: {error}");
        }
        Ok(value)
    }

    /// BloodHound custom queries are read-only. SQLite's authorizer enforces this
    /// on the statements actually executed, including nested Cypher operations.
    pub fn query(&self, query: &str, parameters: &Value) -> Result<Value> {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        let expanded = crate::query::expand_shortcuts(query)?;
        let started = std::time::Instant::now();
        let timeout = self.query_timeout;
        self.conn
            .progress_handler(10_000, Some(move || started.elapsed() >= timeout));
        self.conn
            .authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Insert { .. }
                | AuthAction::Update { .. }
                | AuthAction::Delete { .. }
                | AuthAction::DropTable { .. }
                | AuthAction::DropIndex { .. }
                | AuthAction::AlterTable { .. }
                | AuthAction::Attach { .. }
                | AuthAction::Detach { .. }
                | AuthAction::CreateTable { .. }
                | AuthAction::CreateIndex { .. }
                | AuthAction::CreateTrigger { .. }
                | AuthAction::DropTrigger { .. }
                | AuthAction::CreateView { .. }
                | AuthAction::DropView { .. } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
        let result = (|| -> Result<Value> {
            if !parameters.is_object() {
                bail!("Cypher parameters must be a JSON object");
            }
            let text: String = self
                .conn
                .query_row(
                    "SELECT cypher_result(?1,?2)",
                    params![expanded, parameters.to_string()],
                    |row| row.get(0),
                )
                .context("execute read-only Cypher")?;
            Ok(serde_json::from_str(&text)?)
        })();
        self.conn.progress_handler(0, None::<fn() -> bool>);
        self.conn
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        result
    }

    pub fn validate(&self, query: &str) -> Result<Value> {
        let expanded = crate::query::expand_shortcuts(query)?;
        let text: String =
            self.conn
                .query_row("SELECT cypher_validate(?1)", [&expanded], |row| row.get(0))?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn metadata(&self, key: &str) -> Result<Option<Value>> {
        use rusqlite::OptionalExtension;
        let text: Option<String> = self
            .conn
            .query_row("SELECT value FROM bh_metadata WHERE key=?1", [key], |row| {
                row.get(0)
            })
            .optional()?;
        text.map(|v| serde_json::from_str(&v).map_err(Into::into))
            .transpose()
    }

    /// Accepted import reports in order, including original collector records
    /// and unconsumed fields. Databases created before history support retain
    /// their latest report as the first entry on the next incremental import.
    pub fn import_history(&self) -> Result<Vec<Value>> {
        match self.metadata("import_history")? {
            Some(value) => serde_json::from_value(value).context("decode import history"),
            None => Ok(self.metadata("last_import")?.into_iter().collect()),
        }
    }

    fn put_metadata(&self, key: &str, value: &Value) -> Result<()> {
        self.conn.execute("INSERT INTO bh_metadata(key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key,value.to_string()])?;
        Ok(())
    }

    pub fn raw_graph(&self) -> Result<GraphData> {
        match self.metadata("raw_graph")? {
            Some(value) => Ok(GraphData::from_snapshot(serde_json::from_value(value)?)),
            None => self.graph(),
        }
    }

    pub fn graph(&self) -> Result<GraphData> {
        let mut graph = GraphData::default();
        let nodes = self.execute("MATCH (n) RETURN n.objectid AS objectid, labels(n) AS labels, properties(n) AS properties", &json!({}))?;
        for n in nodes.as_array().context("node query response")? {
            graph.upsert_node(Node {
                objectid: n["objectid"]
                    .as_str()
                    .context("node missing objectid")?
                    .into(),
                labels: serde_json::from_value(n["labels"].clone())?,
                properties: serde_json::from_value(n["properties"].clone())?,
            });
        }
        let derived: BTreeSet<(String, String, String)> = self
            .metadata("derived")?
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();
        let edges = self.execute("MATCH (s)-[r]->(t) RETURN s.objectid AS source, t.objectid AS target, type(r) AS kind, properties(r) AS properties", &json!({}))?;
        for r in edges.as_array().context("edge query response")? {
            let mut edge: Edge = serde_json::from_value(r.clone())?;
            edge.derived =
                derived.contains(&(edge.source.clone(), edge.target.clone(), edge.kind.clone()));
            graph.upsert_edge(edge);
        }
        Ok(graph)
    }

    /// Replace the materialized graph and associated provenance atomically.
    /// The raw snapshot is supplied on import and retained across analysis runs.
    pub fn save(
        &self,
        graph: &GraphData,
        raw: Option<&GraphData>,
        report: Option<(&str, &Value)>,
    ) -> Result<()> {
        self.save_impl(graph, raw, report, None)
    }

    /// Publish an imported graph, its raw snapshot and complete provenance in
    /// one transaction. Replacement starts a new history; incremental imports
    /// retain every previously accepted report. `last_import` stays the latest.
    pub fn save_import(
        &self,
        graph: &GraphData,
        raw: &GraphData,
        report: &Value,
        replace: bool,
    ) -> Result<()> {
        self.save_impl(
            graph,
            Some(raw),
            Some(("last_import", report)),
            Some(replace),
        )
    }

    fn save_impl(
        &self,
        graph: &GraphData,
        raw: Option<&GraphData>,
        report: Option<(&str, &Value)>,
        reset_import_history: Option<bool>,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let history = reset_import_history
            .map(|reset| -> Result<Vec<Value>> {
                let mut history = if reset {
                    Vec::new()
                } else {
                    self.import_history()?
                };
                history.push(report.expect("save_import supplies its report").1.clone());
                Ok(history)
            })
            .transpose()?;
        self.execute("MATCH (n) DETACH DELETE n", &json!({}))?;
        for (objectid, node) in &graph.nodes {
            if node.objectid.is_empty() {
                bail!("empty objectid");
            }
            if objectid != &node.objectid
                || node.properties.get("objectid").and_then(Value::as_str)
                    != Some(node.objectid.as_str())
            {
                bail!("inconsistent node objectid: {}", node.objectid);
            }
            let labels = node
                .labels
                .iter()
                .map(|v| identifier(v))
                .collect::<Result<Vec<_>>>()?
                .join(":");
            let labels = if labels.is_empty() {
                String::new()
            } else {
                format!(":{labels}")
            };
            self.execute(
                &format!("CREATE (n{labels}) SET n += $properties"),
                &json!({"properties":node.properties}),
            )?;
        }
        for edge in graph.edges.values() {
            if !graph.nodes.contains_key(&edge.source) || !graph.nodes.contains_key(&edge.target) {
                bail!(
                    "edge {} has missing endpoint {} -> {}",
                    edge.kind,
                    edge.source,
                    edge.target
                );
            }
            self.execute(&format!("MATCH (s {{objectid:$source}}), (t {{objectid:$target}}) CREATE (s)-[r:{}]->(t) SET r += $properties",identifier(&edge.kind)?), &json!({"source":edge.source,"target":edge.target,"properties":edge.properties}))?;
        }
        let derived: Vec<_> = graph
            .edges
            .values()
            .filter(|e| e.derived)
            .map(|e| (&e.source, &e.target, &e.kind))
            .collect();
        self.put_metadata("derived", &json!(derived))?;
        self.put_metadata("schema_version", &json!(1))?;
        if let Some(raw) = raw {
            self.put_metadata("raw_graph", &serde_json::to_value(raw.snapshot())?)?;
        }
        if let Some((key, value)) = report {
            self.put_metadata(key, value)?;
        }
        if let Some(history) = history {
            self.put_metadata("import_history", &json!(history))?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn stats(&self) -> Result<Value> {
        let graph = self.graph()?;
        let mut labels = std::collections::BTreeMap::<String, usize>::new();
        let mut kinds = std::collections::BTreeMap::<String, usize>::new();
        for node in graph.nodes.values() {
            for label in &node.labels {
                *labels.entry(label.clone()).or_default() += 1;
            }
        }
        for edge in graph.edges.values() {
            *kinds.entry(edge.kind.clone()).or_default() += 1;
        }
        Ok(
            json!({"nodes":graph.nodes.len(),"edges":graph.edges.len(),"labels":labels,"relationships":kinds,"capabilities":self.capabilities()?}),
        )
    }

    pub fn tag(&self, objectid: &str, tag: &str, enabled: bool) -> Result<()> {
        if !matches!(tag, "owned" | "admin_tier_0") {
            bail!("supported tags: owned, admin_tier_0");
        }
        let mut graph = self.graph()?;
        let node = graph.nodes.get_mut(objectid).context("unknown objectid")?;
        set_tag(node, tag, enabled);
        let mut overrides: std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<String, bool>,
        > = self
            .metadata("manual_tags")?
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();
        overrides
            .entry(objectid.into())
            .or_default()
            .insert(tag.into(), enabled);
        self.save(
            &graph,
            None,
            Some(("manual_tags", &serde_json::to_value(overrides)?)),
        )
    }
}

fn set_tag(node: &mut Node, tag: &str, enabled: bool) {
    let tags = node
        .properties
        .get("system_tags")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut tags: BTreeSet<String> = tags.split_whitespace().map(str::to_string).collect();
    if enabled {
        tags.insert(tag.into());
    } else {
        tags.remove(tag);
    }
    node.properties.insert(
        "system_tags".into(),
        json!(tags.into_iter().collect::<Vec<_>>().join(" ")),
    );
    let label = if tag == "owned" {
        "Tag_Owned"
    } else {
        "Tag_Tier_Zero"
    };
    if enabled {
        node.labels.insert(label.into());
    } else {
        node.labels.remove(label);
    }
}

fn identifier(value: &str) -> Result<String> {
    if value.is_empty()
        || value
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '_'))
    {
        bail!("invalid graph kind: {value:?}");
    }
    Ok(format!("`{value}`"))
}
