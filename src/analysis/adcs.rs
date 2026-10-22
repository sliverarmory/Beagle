//! ADCS stages translated from analysis/ad/{adcs,esc*,adcscache}.go.
use super::*;

const AGENT: &str = "1.3.6.1.4.1.311.20.2.1";
const ANY: &str = "2.5.29.37.0";
const ENROLL: &[&str] = &["Enroll", "GenericAll", "AllExtendedRights"];
const CONTROL: &[&str] = &["Owns", "GenericAll", "WriteDacl", "WriteOwner"];

pub(super) fn preprocess(index: &Index<'_>) -> Jobs {
    let mut jobs = vec![];
    let cas: Vec<_> = index
        .graph
        .nodes
        .values()
        .filter(|n| kind(n, "EnterpriseCA") || kind(n, "RootCA") || kind(n, "AIACA"))
        .collect();
    for store in index.nodes("NTAuthStore") {
        if let Some(thumbprints) = strings(store, "certthumbprints") {
            for ca in &cas {
                if kind(ca, "EnterpriseCA")
                    && text(ca, "certthumbprint")
                        .is_some_and(|t| !t.is_empty() && thumbprints.contains(&t))
                {
                    push(&mut jobs, &ca.objectid, &store.objectid, "TrustedForNTAuth");
                }
            }
        }
    }
    for ca in &cas {
        if let Some(chain) = strings(ca, "certchain")
            && let Some(parent) = chain.get(1)
        {
            for other in &cas {
                if text(other, "certthumbprint") == Some(parent) {
                    push(&mut jobs, &ca.objectid, &other.objectid, "IssuedSignedBy");
                }
            }
        }
        if kind(ca, "EnterpriseCA")
            && let Some(thumb) = text(ca, "certthumbprint").filter(|s| !s.is_empty())
        {
            for other in &cas {
                if (kind(other, "RootCA") || kind(other, "AIACA"))
                    && text(other, "certthumbprint") == Some(thumb)
                {
                    push(&mut jobs, &ca.objectid, &other.objectid, "EnterpriseCAFor");
                }
            }
        }
    }
    for ct in index.nodes("CertTemplate") {
        if let (Some(policies), Some(domain)) = (
            strings(ct, "certificatepolicy"),
            text(ct, "domainsid").filter(|s| !s.is_empty()),
        ) {
            for policy in index.nodes("IssuancePolicy") {
                if text(policy, "domainsid") == Some(domain)
                    && text(policy, "certtemplateoid")
                        .or_else(|| text(policy, "certificatepolicyoid"))
                        .is_some_and(|p| policies.contains(&p))
                {
                    push(
                        &mut jobs,
                        &ct.objectid,
                        &policy.objectid,
                        "ExtendedByPolicy",
                    );
                }
            }
        }
    }
    jobs
}

pub(super) fn chains(index: &Index<'_>, ca: &Node, require_host: bool) -> Set {
    if require_host {
        let forest = index.domain(ca).map(|d| index.forest(&d.objectid));
        let valid_host = index
            .incoming(&ca.objectid, &["HostsCAService"])
            .iter()
            .filter_map(|id| index.node(id))
            .any(|host| {
                kind(host, "Computer")
                    && flag(host, "enabled") == Some(true)
                    && forest
                        .as_ref()
                        .is_none_or(|f| index.domain(host).is_some_and(|d| f.contains(&d.objectid)))
            });
        if !valid_host {
            return Set::new();
        }
    }
    let root = index.reach(
        &ca.objectid,
        &["IssuedSignedBy", "EnterpriseCAFor", "RootCAFor"],
        false,
    );
    let auth: Set = index
        .outgoing(&ca.objectid, &["TrustedForNTAuth"])
        .iter()
        .flat_map(|id| index.outgoing(id, &["NTAuthStoreFor"]))
        .collect();
    root.intersection(&auth)
        .filter(|id| index.node(id).is_some_and(|n| kind(n, "Domain")))
        .cloned()
        .collect()
}
fn root_domains(index: &Index<'_>, ct: &Node) -> Set {
    index
        .outgoing(&ct.objectid, &["PublishedTo"])
        .iter()
        .flat_map(|ca| {
            index.reach(
                ca,
                &["IssuedSignedBy", "EnterpriseCAFor", "RootCAFor"],
                false,
            )
        })
        .filter(|id| index.node(id).is_some_and(|n| kind(n, "Domain")))
        .collect()
}
fn published<'a>(index: &Index<'a>, ca: &str) -> Vec<&'a Node> {
    index
        .incoming(ca, &["PublishedTo"])
        .iter()
        .filter_map(|id| index.node(id))
        .filter(|n| kind(n, "CertTemplate"))
        .collect()
}

pub(super) fn enroll_on_behalf(index: &Index<'_>) -> Jobs {
    let mut jobs = vec![];
    let templates = index.nodes("CertTemplate");
    let links: BTreeMap<_, _> = templates
        .iter()
        .map(|t| (t.objectid.clone(), root_domains(index, t)))
        .collect();
    for ca in index.nodes("EnterpriseCA") {
        let domains = chains(index, ca, false);
        for start in published(index, &ca.objectid) {
            let Some(ekus) = strings(start, "effectiveekus") else {
                continue;
            };
            for end in &templates {
                let Some(version) = number(end, "schemaversion") else {
                    continue;
                };
                let eligible = if version == 1.0 {
                    ekus.is_empty() || ekus.contains(&AGENT) || ekus.contains(&ANY)
                } else if version >= 2.0 {
                    start.objectid != end.objectid
                        && ekus.contains(&AGENT)
                        && !ekus.contains(&ANY)
                        && number(end, "authorizedsignatures").is_some_and(|n| n >= 1.0)
                        && strings(end, "applicationpolicies").is_some_and(|p| p.contains(&AGENT))
                } else {
                    false
                };
                if eligible && !domains.is_disjoint(&links[&end.objectid]) {
                    push(
                        &mut jobs,
                        &start.objectid,
                        &end.objectid,
                        "EnrollOnBehalfOf",
                    );
                }
            }
        }
    }
    jobs
}

fn signature_gate(ct: &Node) -> bool {
    matches!((number(ct,"schemaversion"),number(ct,"authorizedsignatures")),(Some(v),Some(s)) if v<=1.0||s<=0.0)
}
fn no_approval(ct: &Node) -> bool {
    flag(ct, "requiresmanagerapproval") == Some(false)
}
fn authentication(ct: &Node) -> bool {
    flag(ct, "authenticationenabled") == Some(true)
}
fn schannel(ct: &Node) -> bool {
    if ct.properties.contains_key("schannelauthenticationenabled") {
        return flag(ct, "schannelauthenticationenabled") == Some(true);
    }
    strings(ct, "effectiveekus")
        .is_some_and(|e| e.is_empty() || e.contains(&"1.3.6.1.5.5.7.3.2") || e.contains(&ANY))
}
pub(super) fn relay_template(ct: &Node) -> bool {
    no_approval(ct)
        && authentication(ct)
        && number(ct, "schemaversion")
            .is_some_and(|v| v <= 1.0 || number(ct, "authorizedsignatures") == Some(0.0))
}
fn dns_filter(index: &Index<'_>, mut principals: Set, ct: &Node) -> Set {
    if flag(ct, "subjectaltrequiredns") != Some(false)
        || flag(ct, "subjectaltrequiredomaindns") != Some(false)
    {
        principals.retain(|id| {
            index
                .node(id)
                .is_none_or(|n| !kind(n, "User") || computer_derived(n))
        });
    }
    principals
}
fn special_enrollment(index: &Index<'_>, set: &Set) -> bool {
    set.iter().any(|id| {
        index.special(id)
            || index.node(id).is_some_and(|n| kind(n, "Group"))
                && index
                    .incoming(id, &["MemberOf"])
                    .iter()
                    .any(|member| index.special(member))
    })
}
pub(super) fn victims(index: &Index<'_>, ct: &Node, ca: &Node) -> Set {
    let a = index.incoming(&ct.objectid, ENROLL);
    let b = index.incoming(&ca.objectid, &["Enroll"]);
    let ea: Set = index
        .expand(&a)
        .into_iter()
        .filter(|id| index.node(id).is_some_and(|n| !kind(n, "Group")))
        .collect();
    let eb: Set = index
        .expand(&b)
        .into_iter()
        .filter(|id| index.node(id).is_some_and(|n| !kind(n, "Group")))
        .collect();
    match (special_enrollment(index, &a), special_enrollment(index, &b)) {
        (false, false) => ea.intersection(&eb).cloned().collect(),
        (true, false) => eb,
        (false, true) => ea,
        (true, true) => ea.union(&eb).cloned().collect(),
    }
}
fn attackers(index: &Index<'_>, victims: Set, scenario_b: bool) -> Set {
    let kinds = if scenario_b {
        &[
            "GenericAll",
            "GenericWrite",
            "Owns",
            "WriteOwner",
            "WriteDacl",
        ][..]
    } else {
        &[
            "GenericAll",
            "GenericWrite",
            "Owns",
            "WriteOwner",
            "WriteDacl",
            "WritePublicInformation",
        ][..]
    };
    victims
        .iter()
        .filter(|id| !scenario_b || index.node(id).is_some_and(|n| kind(n, "Computer")))
        .flat_map(|id| index.incoming(id, kinds))
        .filter(|id| {
            index
                .node(id)
                .is_some_and(|n| kind(n, "Group") || kind(n, "User") || kind(n, "Computer"))
        })
        .collect()
}
fn weak_mapping(index: &Index<'_>, domain: &str, upn: bool) -> bool {
    index
        .forest(domain)
        .iter()
        .flat_map(|id| index.incoming(id, &["DCFor"]))
        .filter_map(|id| index.node(&id))
        .filter(|n| kind(n, "Computer"))
        .any(|dc| {
            if upn {
                number(dc, "certificatemappingmethodsraw")
                    .is_some_and(|v| v >= 0.0 && (v as i64) & 4 == 4)
            } else {
                number(dc, "strongcertificatebindingenforcementraw")
                    .is_some_and(|v| v == -1.0 || v == 0.0 || v == 1.0)
            }
        })
}
fn targets(jobs: &mut Jobs, principals: Set, domains: &Set, edge_kind: &str) {
    for source in principals {
        for target in domains {
            push(jobs, &source, target, edge_kind);
        }
    }
}

pub(super) fn analyze(index: &Index<'_>) -> Jobs {
    let mut jobs = vec![];
    for ca in index.nodes("EnterpriseCA") {
        let domains = chains(index, ca, true);
        if domains.is_empty() {
            continue;
        }
        let eca_enroll = index.incoming(&ca.objectid, &["Enroll"]);
        for host in index.incoming(&ca.objectid, &["HostsCAService"]) {
            if index.node(&host).is_some_and(|n| kind(n, "Computer")) {
                targets(&mut jobs, singleton(&host), &domains, "GoldenCert");
            }
        }
        for ct in published(index, &ca.objectid) {
            let ct_enroll = index.incoming(&ct.objectid, ENROLL);
            let enrollers = index.cross(&[ct_enroll.clone(), eca_enroll.clone()]);
            if no_approval(ct)
                && authentication(ct)
                && flag(ct, "enrolleesuppliessubject") == Some(true)
                && signature_gate(ct)
            {
                targets(&mut jobs, enrollers.clone(), &domains, "ADCSESC1");
            }
            if flag(ct, "enrolleesuppliessubject").is_some()
                && flag(ct, "requiresmanagerapproval").is_some()
            {
                let enroll_only = index.incoming(&ct.objectid, &["Enroll", "AllExtendedRights"]);
                let name = index.incoming(&ct.objectid, &["WritePKINameFlag"]);
                let enrollment = index.incoming(&ct.objectid, &["WritePKIEnrollmentFlag"]);
                let mut control =
                    index.cross(&[eca_enroll.clone(), index.incoming(&ct.objectid, CONTROL)]);
                control.extend(index.cross(&[
                    eca_enroll.clone(),
                    index.incoming(&ct.objectid, &["GenericWrite"]),
                    enroll_only.clone(),
                ]));
                if authentication(ct) && signature_gate(ct) {
                    control.extend(index.cross(&[
                        eca_enroll.clone(),
                        enroll_only.clone(),
                        name.clone(),
                        enrollment.clone(),
                    ]));
                    if flag(ct, "enrolleesuppliessubject") == Some(true) {
                        control.extend(index.cross(&[
                            eca_enroll.clone(),
                            enroll_only.clone(),
                            enrollment,
                        ]));
                    }
                    if no_approval(ct) {
                        control.extend(index.cross(&[eca_enroll.clone(), enroll_only, name]));
                    }
                }
                targets(&mut jobs, control, &domains, "ADCSESC4");
            }
            if no_approval(ct) && signature_gate(ct) {
                if flag(ca, "isuserspecifiessanenabledcollected") == Some(true)
                    && flag(ca, "isuserspecifiessanenabled") == Some(true)
                {
                    let filtered = dns_filter(index, enrollers.clone(), ct);
                    if authentication(ct) && flag(ct, "nosecurityextension") == Some(true) {
                        targets(&mut jobs, filtered.clone(), &domains, "ADCSESC6a");
                    }
                    if schannel(ct) {
                        let upn = domains
                            .iter()
                            .filter(|d| weak_mapping(index, d, true))
                            .cloned()
                            .collect();
                        targets(&mut jobs, filtered, &upn, "ADCSESC6b");
                    }
                }
                if flag(ct, "enrolleesuppliessubject") == Some(false) {
                    for scenario_b in [false, true] {
                        let san = if scenario_b {
                            flag(ct, "subjectaltrequiredns") == Some(true)
                        } else {
                            matches!((flag(ct,"subjectaltrequireupn"),flag(ct,"subjectaltrequirespn")),(Some(a),Some(b)) if a||b)
                        };
                        if !san {
                            continue;
                        }
                        let victim_set = if scenario_b {
                            victims(index, ct, ca)
                        } else {
                            dns_filter(index, victims(index, ct, ca), ct)
                        };
                        let attackers = attackers(index, victim_set, scenario_b);
                        if authentication(ct) && flag(ct, "nosecurityextension") == Some(true) {
                            let weak = domains
                                .iter()
                                .filter(|d| weak_mapping(index, d, false))
                                .cloned()
                                .collect();
                            targets(
                                &mut jobs,
                                attackers.clone(),
                                &weak,
                                if scenario_b { "ADCSESC9b" } else { "ADCSESC9a" },
                            );
                        }
                        if schannel(ct) {
                            let upn = domains
                                .iter()
                                .filter(|d| weak_mapping(index, d, true))
                                .cloned()
                                .collect();
                            targets(
                                &mut jobs,
                                attackers,
                                &upn,
                                if scenario_b {
                                    "ADCSESC10b"
                                } else {
                                    "ADCSESC10a"
                                },
                            );
                        }
                    }
                }
                if authentication(ct) {
                    let filtered = dns_filter(index, enrollers.clone(), ct);
                    for policy in index.outgoing(&ct.objectid, &["ExtendedByPolicy"]) {
                        for group in index.outgoing(&policy, &["OIDGroupLink"]) {
                            if !index.node(&group).is_some_and(|n| kind(n, "Group")) {
                                continue;
                            }
                            let ancestors =
                                index.reach(&group, &["Contains", "SameForestTrust"], true);
                            if !ancestors.is_disjoint(&domains) {
                                for source in &filtered {
                                    push(&mut jobs, source, &group, "ADCSESC13");
                                }
                            }
                        }
                    }
                }
            }
            if authentication(ct) && no_approval(ct) {
                let restrictions = match flag(ca, "enrollmentagentrestrictionscollected") {
                    Some(false) => Some(false),
                    Some(true) => flag(ca, "hasenrollmentagentrestrictions"),
                    None => None,
                };
                if let Some(restrictions) = restrictions {
                    for start_id in index.incoming(&ct.objectid, &["EnrollOnBehalfOf"]) {
                        let Some(start) = index.node(&start_id).filter(|n| kind(n, "CertTemplate"))
                        else {
                            continue;
                        };
                        let start_valid = no_approval(start)
                            && number(start, "schemaversion").is_some_and(|v| {
                                v == 1.0
                                    || v > 1.0
                                        && number(start, "authorizedsignatures")
                                            .is_some_and(|s| s <= 0.0)
                            });
                        if !start_valid {
                            continue;
                        }
                        for ca1 in index.outgoing(&start.objectid, &["PublishedTo"]) {
                            let mut permissions = vec![
                                index.incoming(&start.objectid, ENROLL),
                                ct_enroll.clone(),
                                index.incoming(&ca1, &["Enroll"]),
                                eca_enroll.clone(),
                            ];
                            if restrictions {
                                permissions.push(
                                    index.incoming(&ct.objectid, &["DelegatedEnrollmentAgent"]),
                                );
                            }
                            targets(
                                &mut jobs,
                                dns_filter(index, index.cross(&permissions), start),
                                &domains,
                                "ADCSESC3",
                            );
                        }
                    }
                }
            }
        }
    }
    jobs
}
