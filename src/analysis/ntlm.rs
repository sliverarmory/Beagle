//! Native implementation of ad/ntlm.go. Missing collection flags fail closed.
use super::*;

pub(super) fn analyze(index: &Index<'_>) -> Jobs {
    let mut jobs = vec![];
    let auth: BTreeMap<_, _> = index
        .nodes("Group")
        .into_iter()
        .filter(|n| n.objectid.ends_with("-S-1-5-11"))
        .filter_map(|n| text(n, "domainsid").map(|sid| (sid.to_owned(), n.objectid.clone())))
        .collect();
    let domains: BTreeMap<_, _> = index
        .nodes("Domain")
        .into_iter()
        .filter_map(|n| text(n, "domainsid").map(|sid| (sid.to_owned(), n)))
        .collect();
    let protected: BTreeMap<_, _> = index
        .nodes("Group")
        .into_iter()
        .filter(|n| n.objectid.ends_with("-525"))
        .filter_map(|n| {
            text(n, "domainsid").map(|sid| (sid.to_owned(), index.members(&n.objectid)))
        })
        .collect();
    let old_levels = [
        "2000 Mixed/Native",
        "2003 Interim",
        "2003",
        "2008",
        "2008 R2",
        "2012",
    ];
    let unprotected: Set = index
        .nodes("Computer")
        .into_iter()
        .filter(|n| {
            let Some(sid) = text(n, "domainsid") else {
                return false;
            };
            let Some(domain) = domains.get(sid) else {
                return false;
            };
            auth.contains_key(sid)
                && flag(n, "restrictoutboundntlm") == Some(false)
                && (!protected
                    .get(sid)
                    .is_some_and(|set| set.contains(&n.objectid))
                    || text(domain, "functionallevel").is_some_and(|s| old_levels.contains(&s)))
        })
        .map(|n| n.objectid.clone())
        .collect();
    for computer in index.nodes("Computer") {
        let Some(sid) = text(computer, "domainsid") else {
            continue;
        };
        let Some(auth) = auth.get(sid) else { continue };
        if flag(computer, "smbsigning") == Some(false) {
            let admins: Set = index
                .incoming(&computer.objectid, &["AdminTo"])
                .iter()
                .flat_map(|id| {
                    if index.node(id).is_some_and(|n| kind(n, "Group")) {
                        index.members(id)
                    } else {
                        singleton(id)
                    }
                })
                .collect();
            if admins
                .intersection(&unprotected)
                .any(|id| id != &computer.objectid)
            {
                push(
                    &mut jobs,
                    auth,
                    &computer.objectid,
                    "CoerceAndRelayNTLMToSMB",
                );
            }
        }
        if unprotected.contains(&computer.objectid)
            && flag(computer, "webclientrunning") == Some(true)
        {
            for (edge, available, secure) in [
                ("CoerceAndRelayNTLMToLDAP", "ldapavailable", "ldapsigning"),
                ("CoerceAndRelayNTLMToLDAPS", "ldapsavailable", "ldapsepa"),
            ] {
                if index.graph.nodes.values().any(|dc| {
                    dc.objectid != computer.objectid
                        && text(dc, "domainsid") == Some(sid)
                        && flag(dc, "isdc") == Some(true)
                        && flag(dc, available) == Some(true)
                        && flag(dc, secure) == Some(false)
                }) {
                    push(&mut jobs, auth, &computer.objectid, edge);
                }
            }
        }
    }
    for ca in index.nodes("EnterpriseCA") {
        if flag(ca, "hasvulnerableendpoint") != Some(true) {
            continue;
        }
        let domains = adcs::chains(index, ca, true);
        if domains.is_empty() {
            continue;
        }
        for ct_id in index.incoming(&ca.objectid, &["PublishedTo"]) {
            let Some(ct) = index
                .node(&ct_id)
                .filter(|n| kind(n, "CertTemplate") && adcs::relay_template(n))
            else {
                continue;
            };
            let victims = adcs::victims(index, ct, ca);
            for domain in &domains {
                let Some(sid) = index.node(domain).and_then(|n| text(n, "domainsid")) else {
                    continue;
                };
                let Some(auth) = auth.get(sid) else { continue };
                for victim in victims.intersection(&unprotected) {
                    push(&mut jobs, auth, victim, "CoerceAndRelayNTLMToADCS");
                }
            }
        }
    }
    jobs
}
