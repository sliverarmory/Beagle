//! NTLM edge explanations and relay targets from pinned ad/ntlm.go.
use super::*;

pub(super) fn adcs(i: &Index<'_>, source: &str, target: &str) -> Result<Vec<Path>> {
    let sid = text(i.node(source), "domainsid").context("relay source has no domainsid")?;
    let domain = i
        .graph
        .nodes
        .get(sid)
        .filter(|n| kind(n, "Base"))
        .context("relay source domain not found")?;
    let roots = i.special_roots(target);
    Ok(combine_ca(
        i,
        template_paths(
            i,
            &roots,
            Some(&domain.objectid),
            ENROLL,
            relay_template,
            None,
            true,
        ),
        ca_paths(i, &roots, Some(&domain.objectid), false),
    ))
}

fn eligible_smb_terminal(node: &Node, sid: &str) -> bool {
    !kind(node, "User")
        && text(node, "domainsid") == Some(sid)
        && flag(node, "restrictoutboundntlm", false)
}

/// CE's SMB routines use dawgs/ops.Traversal, whose PathFilter is applied only
/// after all accepted descendants are exhausted. Computer/User nodes stop
/// descent; an intermediate group is not itself a completed composition path.
fn smb_paths(i: &Index<'_>, source: &str, target: &str, global_visited: bool) -> Result<Vec<Path>> {
    let sid = text(i.node(source), "domainsid").context("relay source has no domainsid")?;
    let mut todo = vec![Path {
        nodes: vec![target.to_owned()],
        edges: vec![],
    }];
    let mut visited = Set::new();
    let mut out = vec![];
    while let Some(path) = todo.pop() {
        let work = i.work.get() + 1;
        i.work.set(work);
        if work > 2_000_000 || path.nodes.len() > 4096 {
            i.exceeded.set(true);
            break;
        }
        let current = i.node(i.last(&path));
        let stop_at_principal =
            path.nodes.len() > 1 && (kind(current, "Computer") || kind(current, "User"));
        // AcyclicTraverseTerminals uses a global expansion bitmap. TraversePaths
        // instead rejects cycles on each path and retains distinct valid paths.
        let expand = !global_visited || visited.insert(current.objectid.clone());
        let mut descendants = 0;
        if !stop_at_principal && expand {
            for edge in i.incoming.get(&current.objectid).into_iter().flatten() {
                if !["MemberOf", "AdminTo"].contains(&edge.kind.as_str())
                    || !global_visited && path.nodes.contains(&edge.source)
                {
                    continue;
                }
                let mut next = path.clone();
                next.nodes.push(edge.source.clone());
                next.edges.push(EdgeKey(
                    edge.source.clone(),
                    edge.target.clone(),
                    edge.kind.clone(),
                ));
                todo.push(next);
                descendants += 1;
            }
        }
        if descendants == 0 && !path.edges.is_empty() && eligible_smb_terminal(current, sid) {
            out.push(path);
        }
    }
    Ok(out)
}

pub(super) fn smb(i: &Index<'_>, source: &str, target: &str) -> Result<Vec<Path>> {
    smb_paths(i, source, target, false)
}

/// Return relay target nodes, preserving CE's kind-specific filters.
pub(super) fn relay_targets(
    graph: &GraphData,
    source: &str,
    target: &str,
    kind_name: &str,
) -> Result<Vec<Node>> {
    require_edge(graph, source, target, kind_name)?;
    let i = Index::new(graph);
    let mut ids = Set::new();
    match kind_name {
        "CoerceAndRelayNTLMToLDAP" | "CoerceAndRelayNTLMToLDAPS" => {
            let sid = text(i.node(source), "domainsid").context("relay source has no domainsid")?;
            let secure = kind_name.ends_with("LDAPS");
            for n in graph.nodes.values() {
                if kind(n, "Computer")
                    && flag(n, "isdc", true)
                    && text(n, "domainsid") == Some(sid)
                    && flag(
                        n,
                        if secure {
                            "ldapsavailable"
                        } else {
                            "ldapavailable"
                        },
                        true,
                    )
                    && flag(n, if secure { "ldapsepa" } else { "ldapsigning" }, false)
                {
                    ids.insert(n.objectid.clone());
                }
            }
        }
        "CoerceAndRelayNTLMToADCS" => {
            for p in adcs(&i, source, target)? {
                for id in p.nodes {
                    let n = i.node(&id);
                    if kind(n, "EnterpriseCA") && flag(n, "hasvulnerableendpoint", true) {
                        ids.insert(id);
                    }
                }
            }
        }
        "CoerceAndRelayNTLMToSMB" => {
            for p in smb_paths(&i, source, target, true)? {
                let id = i.last(&p);
                if id != target {
                    ids.insert(id.to_owned());
                }
            }
        }
        _ => {}
    }
    if i.exceeded.get() {
        bail!("relay-target traversal exceeded its work limit; no partial result returned");
    }
    Ok(ids.into_iter().map(|id| i.node(&id).clone()).collect())
}
