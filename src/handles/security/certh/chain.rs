//! `chain.info`: finds the leaf certificates of a bundle and every path from
//! each leaf through the bundle and the trust anchors, linking certificates
//! by issuer name and signature. A path that ends at a trust anchor is
//! reported as trusted only when rustls-webpki validates it.

use serde_json::{Value, json};
use x509_parser::prelude::*;

use super::errors::{CResult, CertError};
use super::trust;

/// Where a certificate came from.
#[derive(Clone)]
pub struct Node {
    pub der: Vec<u8>,
    /// "target_bundle", "system", "mount" or "inline".
    pub source: &'static str,
    /// Index in the target bundle, for bundle certificates.
    pub index: Option<usize>,
    pub anchor: bool,
}

pub struct Options {
    pub max_depth: usize,
    pub max_paths: usize,
    pub include_raw_subjects: bool,
    pub include_raw_issuers: bool,
    pub include_cert_refs: bool,
}

/// One path: indices into the node list, leaf first.
struct Path {
    nodes: Vec<usize>,
    end: End,
}

enum End {
    /// The last node is a trust anchor.
    Anchor,
    /// The last node is self-signed but not a trust anchor.
    UntrustedRoot,
    /// No issuer of the last node was found (or max_depth was reached).
    Missing(String),
}

/// Where a trust anchor came from ("system", "mount" or "inline").
fn anchor_source(node: &Node, anchors: &[(Vec<u8>, &'static str)]) -> &'static str {
    anchors
        .iter()
        .find(|(a, _)| *a == node.der)
        .map(|(_, s)| *s)
        .unwrap_or(node.source)
}

fn parse(der: &[u8]) -> Option<X509Certificate<'_>> {
    X509Certificate::from_der(der).ok().map(|(_, c)| c)
}

/// True if `child` names `parent` as issuer and `parent`'s key verifies it.
fn issued_by(child: &X509Certificate, parent: &X509Certificate) -> bool {
    child.issuer().as_raw() == parent.subject().as_raw()
        && matches!(
            super::verify_cert_signed_by(child, parent.public_key()),
            super::SignatureCheck::Valid
        )
}

fn self_signed(c: &X509Certificate) -> bool {
    super::is_self_issued(c) && issued_by(c, c)
}

fn name_json(name: &X509Name, raw: bool) -> Value {
    let mut v = json!({
        "common_name": name.iter_common_name().next().and_then(|a| a.as_str().ok()),
    });
    if raw {
        v["raw_dn"] = json!(name.to_string());
    }
    v
}

fn key_json(c: &X509Certificate) -> Value {
    let k = super::describe_spki(c.public_key());
    let algorithm = match k.algorithm.as_str() {
        "rsa" => "RSA".to_string(),
        "ecdsa" => "ECDSA".to_string(),
        "ed25519" => "Ed25519".to_string(),
        other => other.to_string(),
    };
    json!({
        "algorithm": algorithm,
        "rsa_bits": if k.algorithm == "rsa" { k.bits } else { None },
        "ecdsa_curve": k.curve,
    })
}

fn fingerprints(der: &[u8]) -> Value {
    json!({ "sha256": super::fingerprint("sha256", der) })
}

/// Builds the chain report for the bundle certificates `bundle` (DER, in
/// file order) and trust anchors `anchors` (DER, with their source).
pub fn report(
    target: &str,
    encoding: &str,
    bundle: &[Vec<u8>],
    anchors: &[(Vec<u8>, &'static str)],
    now: u64,
    opts: &Options,
) -> CResult<Value> {
    // Every certificate once: bundle certificates first; an anchor that is
    // also in the bundle marks the bundle entry as an anchor.
    let mut nodes: Vec<Node> = Vec::new();
    for (i, der) in bundle.iter().enumerate() {
        let anchor_src = anchors.iter().find(|(a, _)| a == der).map(|(_, s)| *s);
        nodes.push(Node {
            der: der.clone(),
            source: "target_bundle",
            index: Some(i),
            anchor: anchor_src.is_some(),
        });
    }
    for (der, src) in anchors {
        if !nodes.iter().any(|n| &n.der == der) {
            nodes.push(Node {
                der: der.clone(),
                source: src,
                index: None,
                anchor: true,
            });
        }
    }
    let parsed: Vec<X509Certificate> = nodes
        .iter()
        .map(|n| {
            parse(&n.der).ok_or_else(|| {
                CertError::failed("cert.parse_failed", "a certificate could not be parsed")
            })
        })
        .collect::<CResult<_>>()?;

    // Leaf candidates: bundle certificates that issue no other bundle
    // certificate (all of them if every one issues another).
    let in_bundle: Vec<usize> = (0..bundle.len()).collect();
    let mut leaves: Vec<usize> = in_bundle
        .iter()
        .copied()
        .filter(|&i| {
            !in_bundle
                .iter()
                .any(|&j| j != i && issued_by(&parsed[j], &parsed[i]))
        })
        .collect();
    if leaves.is_empty() {
        leaves = in_bundle.clone();
    }

    // Depth-first search for every path from each leaf.
    let mut paths: Vec<Path> = Vec::new();
    let limit = 1000;
    for &leaf in &leaves {
        let mut stack: Vec<Vec<usize>> = vec![vec![leaf]];
        while let Some(path) = stack.pop() {
            if paths.len() >= limit {
                break;
            }
            let cur = *path.last().unwrap_or(&leaf);
            let c = &parsed[cur];
            if nodes[cur].anchor {
                paths.push(Path {
                    nodes: path,
                    end: End::Anchor,
                });
                continue;
            }
            if self_signed(c) {
                paths.push(Path {
                    nodes: path,
                    end: End::UntrustedRoot,
                });
                continue;
            }
            if path.len() >= opts.max_depth {
                paths.push(Path {
                    nodes: path,
                    end: End::Missing(format!("max_depth={} reached", opts.max_depth)),
                });
                continue;
            }
            let issuers: Vec<usize> = (0..nodes.len())
                .filter(|j| !path.contains(j) && issued_by(c, &parsed[*j]))
                .collect();
            if issuers.is_empty() {
                paths.push(Path {
                    nodes: path,
                    end: End::Missing(format!("issuer {} not found", c.issuer())),
                });
                continue;
            }
            // Pushed in reverse so the first issuer is explored first.
            for j in issuers.into_iter().rev() {
                let mut p = path.clone();
                p.push(j);
                stack.push(p);
            }
        }
    }

    // Describe and rank each path.
    let mut chains: Vec<(u32, Value)> = Vec::new();
    for path in &paths {
        let leaf = path.nodes[0];
        let last = *path.nodes.last().unwrap_or(&leaf);
        let root = &parsed[last];
        let (status, reason, score, gaps) = match &path.end {
            End::Anchor => {
                if path.nodes.len() == 1 {
                    (
                        "trusted",
                        "The certificate is itself a trust anchor".to_string(),
                        100,
                        vec![],
                    )
                } else {
                    let inter: Vec<Vec<u8>> = path.nodes[1..path.nodes.len() - 1]
                        .iter()
                        .map(|i| nodes[*i].der.clone())
                        .collect();
                    match trust::validate(
                        &nodes[leaf].der,
                        &inter,
                        std::slice::from_ref(&nodes[last].der),
                        now,
                        trust::Eku::Any,
                    ) {
                        Ok(_) => (
                            "trusted",
                            format!(
                                "Validated to trust anchor {} ({})",
                                root.subject(),
                                anchor_source(&nodes[last], anchors)
                            ),
                            100,
                            vec![],
                        ),
                        Err(e) => {
                            let (code, _, msg) = trust::describe_error(&e);
                            (
                                "invalid",
                                format!(
                                    "Ends at trust anchor {}, but {msg} ({code})",
                                    root.subject()
                                ),
                                20,
                                vec![],
                            )
                        }
                    }
                }
            }
            End::UntrustedRoot if path.nodes.len() == 1 => (
                "self_signed_untrusted",
                "Self-signed certificate that is not a trust anchor".to_string(),
                50,
                vec![],
            ),
            End::UntrustedRoot => (
                "untrusted_root",
                format!(
                    "Ends at self-signed root {} that is not a trust anchor",
                    root.subject()
                ),
                30,
                vec![],
            ),
            End::Missing(gap) => (
                "incomplete",
                format!("Incomplete chain: {gap}"),
                10,
                vec![gap.clone()],
            ),
        };
        let n = path.nodes.len();
        let hops: Vec<Value> = path
            .nodes
            .iter()
            .enumerate()
            .map(|(pos, &i)| {
                let c = &parsed[i];
                let role = if pos == 0 && n > 1 {
                    "leaf"
                } else if pos == n - 1 && (nodes[i].anchor || self_signed(c)) {
                    "root"
                } else if pos == 0 {
                    "leaf"
                } else {
                    "intermediate"
                };
                let (is_ca, path_len) = super::basic_constraints_of(c);
                let mut hop = json!({
                    "position": pos,
                    "role": role,
                    "source": nodes[i].source,
                    "is_trust_anchor": nodes[i].anchor,
                    "subject": name_json(c.subject(), opts.include_raw_subjects),
                    "issuer": name_json(c.issuer(), opts.include_raw_issuers),
                    "is_ca": is_ca,
                    "path_len": path_len,
                    "ski": c.extensions().iter().find_map(|e| match e.parsed_extension() {
                        ParsedExtension::SubjectKeyIdentifier(id) => Some(super::colon_hex(id.0)),
                        _ => None,
                    }),
                    "aki": c.extensions().iter().find_map(|e| match e.parsed_extension() {
                        ParsedExtension::AuthorityKeyIdentifier(a) =>
                            a.key_identifier.as_ref().map(|id| super::colon_hex(id.0)),
                        _ => None,
                    }),
                    "public_key": key_json(c),
                    "validity": {
                        "not_before": super::asn1_time_rfc3339(&c.validity().not_before),
                        "not_after": super::asn1_time_rfc3339(&c.validity().not_after),
                    },
                    "fingerprints": fingerprints(&nodes[i].der),
                });
                if opts.include_cert_refs {
                    hop["cert_ref"] = match nodes[i].index {
                        Some(idx) => json!(format!("cert://{target}#{idx}")),
                        None => Value::Null,
                    };
                }
                hop
            })
            .collect();
        let mut notes = Vec::new();
        if n == 1 && matches!(path.end, End::UntrustedRoot) {
            notes.push("Self-signed certificate".to_string());
        }
        let lc = &parsed[leaf];
        chains.push((
            score + if (2..=4).contains(&n) { 10 } else { 5 },
            json!({
                "length": n,
                "trust_status": status,
                "reason": reason,
                "leaf": {
                    "index_in_target": nodes[leaf].index,
                    "subject": name_json(lc.subject(), opts.include_raw_subjects),
                    "fingerprints": fingerprints(&nodes[leaf].der),
                },
                "root": {
                    "subject": name_json(root.subject(), opts.include_raw_subjects),
                    "is_self_signed": self_signed(root),
                    "is_trust_anchor": nodes[last].anchor,
                    "trust_source": if nodes[last].anchor {
                        anchor_source(&nodes[last], anchors)
                    } else {
                        "none"
                    },
                },
                "hops": hops,
                "gaps": gaps,
                "notes": notes,
            }),
        ));
    }
    // Best first (stable, so equal scores keep the search order).
    chains.sort_by_key(|c| std::cmp::Reverse(c.0));
    let total = chains.len();
    let mut warnings = Vec::new();
    if paths.len() >= limit {
        warnings.push(format!("Stopped after {limit} candidate paths"));
    }
    if total > opts.max_paths {
        warnings.push(format!(
            "{total} chains found; showing the best {} (max_paths)",
            opts.max_paths
        ));
    }
    let chains: Vec<Value> = chains
        .into_iter()
        .take(opts.max_paths)
        .enumerate()
        .map(|(id, (_, mut c))| {
            c["id"] = json!(id);
            c["source"] = json!(if id == 0 { "primary" } else { "alternative" });
            c
        })
        .collect();

    let leaf_candidates: Vec<Value> = leaves
        .iter()
        .map(|&i| {
            json!({
                "index": nodes[i].index,
                "subject": name_json(parsed[i].subject(), opts.include_raw_subjects),
                "is_ca": super::is_ca_cert(&parsed[i]),
                "fingerprints": fingerprints(&nodes[i].der),
            })
        })
        .collect();

    Ok(json!({
        "ok": true,
        "target": format!("cert://{target}"),
        "encoding": encoding,
        "anchors_loaded": anchors.len(),
        "leaf_candidates": leaf_candidates,
        "chains": chains,
        "warnings": warnings,
    }))
}

/// The text form of a chain report.
pub fn text(report: &Value) -> String {
    let s = |v: &Value| v.as_str().unwrap_or("(none)").to_string();
    let mut out = format!(
        "Target: {}\nEncoding: {}\nTrust anchors loaded: {}\n\n",
        s(&report["target"]),
        s(&report["encoding"]),
        report["anchors_loaded"]
    );
    out.push_str("Leaf Candidates:\n");
    for c in report["leaf_candidates"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "  [{}] CN={}\n",
            c["index"],
            s(&c["subject"]["common_name"])
        ));
    }
    out.push('\n');
    for chain in report["chains"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "Chain {} (length={})\n  Trust Status : {}\n  Reason       : {}\n",
            chain["id"],
            chain["length"],
            s(&chain["trust_status"]),
            s(&chain["reason"])
        ));
        for hop in chain["hops"].as_array().into_iter().flatten() {
            let role = match hop["role"].as_str() {
                Some("leaf") => "Leaf",
                Some("root") => "Root",
                _ => "Intermediate",
            };
            let k = &hop["public_key"];
            let mut key = s(&k["algorithm"]);
            if let Some(b) = k["rsa_bits"].as_u64() {
                key.push_str(&format!(" {b}-bit"));
            }
            if let Some(c) = k["ecdsa_curve"].as_str() {
                key.push_str(&format!(" {c}"));
            }
            if hop["is_ca"] == true {
                key.push_str(", CA");
            }
            out.push_str(&format!(
                "  [{}] {role} ({}{})\n      Subject : CN={}\n      Issuer  : CN={}\n      Key     : {key}\n",
                hop["position"],
                s(&hop["source"]),
                if hop["is_trust_anchor"] == true { ", trust anchor" } else { "" },
                s(&hop["subject"]["common_name"]),
                s(&hop["issuer"]["common_name"]),
            ));
        }
        out.push('\n');
    }
    out.push_str("Warnings:\n");
    let warnings = report["warnings"].as_array().cloned().unwrap_or_default();
    if warnings.is_empty() {
        out.push_str("  (none)\n");
    }
    for w in warnings {
        out.push_str(&format!("  {}\n", s(&w)));
    }
    out
}
