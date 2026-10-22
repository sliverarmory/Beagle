use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Properties = Map<String, Value>;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Node {
    pub objectid: String,
    pub labels: BTreeSet<String>,
    pub properties: Properties,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Edge {
    pub source: String,
    pub target: String,
    pub kind: String,
    #[serde(default)]
    pub properties: Properties,
    #[serde(default)]
    pub derived: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeKey(pub String, pub String, pub String);

#[derive(Clone, Debug, Default)]
pub struct GraphData {
    pub nodes: BTreeMap<String, Node>,
    pub edges: BTreeMap<EdgeKey, Edge>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

impl GraphData {
    pub fn upsert_node(&mut self, mut node: Node) {
        node.properties
            .insert("objectid".into(), Value::String(node.objectid.clone()));
        self.nodes
            .entry(node.objectid.clone())
            .and_modify(|existing| {
                existing.labels.extend(node.labels.clone());
                existing.properties.extend(node.properties.clone());
            })
            .or_insert(node);
    }

    pub fn ensure_node(&mut self, objectid: &str, kind: &str) {
        if objectid.is_empty() {
            return;
        }
        let mut labels = BTreeSet::from(["Base".into()]);
        if !kind.is_empty() && kind != "Unknown" {
            labels.insert(kind.to_owned());
        }
        self.upsert_node(Node {
            objectid: objectid.into(),
            labels,
            properties: Properties::new(),
        });
    }

    pub fn upsert_edge(&mut self, edge: Edge) -> bool {
        let key = EdgeKey(edge.source.clone(), edge.target.clone(), edge.kind.clone());
        if let Some(existing) = self.edges.get_mut(&key) {
            existing.properties.extend(edge.properties);
            existing.derived &= edge.derived;
            false
        } else {
            self.edges.insert(key, edge);
            true
        }
    }

    pub fn snapshot(&self) -> GraphSnapshot {
        GraphSnapshot {
            nodes: self.nodes.values().cloned().collect(),
            edges: self.edges.values().cloned().collect(),
        }
    }

    pub fn from_snapshot(snapshot: GraphSnapshot) -> Self {
        let mut graph = Self::default();
        for node in snapshot.nodes {
            graph.upsert_node(node);
        }
        for edge in snapshot.edges {
            graph.upsert_edge(edge);
        }
        graph
    }
}
