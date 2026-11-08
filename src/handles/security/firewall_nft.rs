//! nftables specifics of `rules.add`: finding the live table and chain a
//! rule goes into, and the family match an inet table needs.

use super::*;

/// A chain of the live ruleset, with its hook when it is a base chain.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct NftChain {
    /// `ip`, `ip6`, `inet`, ...
    pub family: String,
    pub table: String,
    pub chain: String,
    /// `filter`, `nat`, `route` (base chains only).
    pub kind: Option<String>,
    /// `input`, `output`, `forward`, `prerouting`, `postrouting`.
    pub hook: Option<String>,
}

/// The chains of an `nft list ruleset` listing, in order.
pub(crate) fn parse_nft_chains(ruleset: &str) -> Vec<NftChain> {
    let mut chains: Vec<NftChain> = Vec::new();
    let mut table: Option<(String, String)> = None;
    for line in ruleset.lines() {
        let line = line.trim();
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["table", family, name, ..] => {
                table = Some((family.to_string(), name.to_string()));
            }
            ["chain", name, ..] => {
                if let Some((family, t)) = &table {
                    chains.push(NftChain {
                        family: family.clone(),
                        table: t.clone(),
                        chain: name.to_string(),
                        kind: None,
                        hook: None,
                    });
                }
            }
            _ => {}
        }
        // `type filter hook input priority filter; policy accept;`, on its
        // own line or inside a one-line chain definition.
        if let Some(pos) = words.iter().position(|w| *w == "type") {
            if let (Some(kind), Some(hook)) = (
                words.get(pos + 1),
                words
                    .iter()
                    .position(|w| *w == "hook")
                    .and_then(|h| words.get(h + 1)),
            ) {
                if let Some(last) = chains.last_mut() {
                    if last.hook.is_none() && (words[0] == "type" || words[0] == "chain") {
                        last.kind = Some(kind.to_string());
                        last.hook = Some(hook.trim_end_matches(';').to_string());
                    }
                }
            }
        }
    }
    chains
}

/// The nft table family a normalized rule family stands for.
pub(crate) fn nft_table_family(family: &str) -> &str {
    match family {
        "ipv4" => "ip",
        "ipv6" => "ip6",
        other => other,
    }
}

/// The nft address family keyword (`ip`/`ip6`) for an address.
pub(crate) fn nft_addr_family(addr: &str) -> &'static str {
    if address_family(addr) == "ipv6" {
        "ip6"
    } else {
        "ip"
    }
}

/// `meta nfproto` value a rule spec needs: a one-family rule in an inet
/// table without an address (an address already implies its family).
pub(crate) fn nft_nfproto(spec: &FirewallRuleSpec) -> Option<&'static str> {
    if spec.nft_family.as_deref() != Some("inet")
        || normalize_address(spec.saddr.as_ref()).is_some()
        || normalize_address(spec.daddr.as_ref()).is_some()
    {
        return None;
    }
    match spec.family.as_str() {
        "ipv4" => Some("ipv4"),
        "ipv6" => Some("ipv6"),
        _ => None,
    }
}

/// The `meta nfproto` restriction of a listed rule, from its raw line.
pub(crate) fn raw_nfproto(raw: &str) -> Option<&'static str> {
    if raw.contains("meta nfproto ipv4") {
        Some("ipv4")
    } else if raw.contains("meta nfproto ipv6") {
        Some("ipv6")
    } else {
        None
    }
}

impl FirewallHandle {
    /// Puts each nftables rule spec into a live chain: the given table and
    /// chain, or else the first base chain of the right type hooked on the
    /// requested direction, preferring an inet table over ip/ip6. A
    /// `family=any` request whose two rules land in the same inet chain
    /// becomes one rule there. A NAT rule with no NAT chain to go into (and
    /// no table/chain given) goes into resh's own `inet resh` table; the
    /// commands that create it are returned with the specs.
    pub(super) async fn resolve_nft_targets(
        &self,
        specs: Vec<FirewallRuleSpec>,
        opts: &RulesAddOptions,
    ) -> Result<(Vec<FirewallRuleSpec>, Vec<Vec<String>>)> {
        let (code, out, err) =
            run_command_with_timeout("nft", &["list", "ruleset"], opts.timeout_ms).await?;
        if code != 0 {
            return Err(FirewallError::CommandFailed {
                command: "nft list ruleset".to_string(),
                code,
                stderr: err.trim().to_string(),
            }
            .into());
        }
        let mut chains = parse_nft_chains(&out);
        let mut setup: Vec<Vec<String>> = Vec::new();
        let nat = matches!(
            opts.action.as_str(),
            "masquerade" | "snat" | "dnat" | "redirect"
        ) || matches!(opts.direction.as_str(), "prerouting" | "postrouting");
        let kind = if nat { "nat" } else { "filter" };
        let needs_own_chain = |chains: &[NftChain]| {
            nat && opts.table.is_none()
                && opts.chain.is_none()
                && !chains.iter().any(|c| {
                    c.kind.as_deref() == Some("nat")
                        && c.hook.as_deref() == Some(opts.direction.as_str())
                        && matches!(c.family.as_str(), "inet" | "ip" | "ip6")
                })
        };
        if needs_own_chain(&chains) {
            let priority = match opts.direction.as_str() {
                "prerouting" | "output" => "dstnat",
                _ => "srcnat",
            };
            let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<String>>();
            setup.push(words(&["nft", "add", "table", "inet", "resh"]));
            setup.push(words(&[
                "nft",
                "add",
                "chain",
                "inet",
                "resh",
                &opts.direction,
                "{",
                "type",
                "nat",
                "hook",
                &opts.direction,
                "priority",
                priority,
                ";",
                "}",
            ]));
            chains.push(NftChain {
                family: "inet".to_string(),
                table: "resh".to_string(),
                chain: opts.direction.clone(),
                kind: Some("nat".to_string()),
                hook: Some(opts.direction.clone()),
            });
        }
        let pick = |family: &str| -> Option<NftChain> {
            let families: &[&str] = match family {
                "ipv4" => &["inet", "ip"],
                "ipv6" => &["inet", "ip6"],
                _ => &["inet"],
            };
            families.iter().find_map(|f| {
                chains
                    .iter()
                    .find(|c| {
                        c.family == *f
                            && opts.table.as_ref().is_none_or(|t| c.table == *t)
                            && match &opts.chain {
                                Some(chain) => c.chain == *chain,
                                None => {
                                    c.hook.as_deref() == Some(opts.direction.as_str())
                                        && c.kind.as_deref() == Some(kind)
                                }
                            }
                    })
                    .cloned()
            })
        };
        let place = |mut spec: FirewallRuleSpec, chain: &NftChain| {
            spec.table = Some(chain.table.clone());
            spec.chain = Some(chain.chain.clone());
            spec.nft_family = Some(chain.family.clone());
            spec
        };

        if specs.len() == 2 {
            if let (Some(a), Some(b)) = (pick(&specs[0].family), pick(&specs[1].family)) {
                if a == b && a.family == "inet" {
                    let mut one = specs[0].clone();
                    one.family = "any".to_string();
                    one.saddr = None;
                    one.daddr = None;
                    return Ok((vec![place(one, &a)], setup));
                }
            }
        }
        let placed = specs
            .into_iter()
            .map(|spec| match pick(&spec.family) {
                Some(chain) => Ok(place(spec, &chain)),
                None => Err(FirewallError::ChainNotFound {
                    message: format!(
                        "no nftables chain for this rule: wanted {} in an inet or {} table{}; \
                         create the table and chain, or give table= and chain=",
                        match &opts.chain {
                            Some(c) => format!("chain {c}"),
                            None => format!("a {kind} chain hooked on {}", opts.direction),
                        },
                        nft_table_family(&spec.family),
                        opts.table
                            .as_ref()
                            .map(|t| format!(" named {t}"))
                            .unwrap_or_default()
                    ),
                }
                .into()),
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((placed, setup))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULESET: &str = "table inet filter { # handle 1
\tchain input { # handle 1
\t\ttype filter hook input priority filter; policy accept;
\t\ttcp dport 22 accept # handle 4
\t}
\tchain allowed { # handle 2
\t}
}
table ip nat { # handle 2
\tchain POSTROUTING { type nat hook postrouting priority srcnat; policy accept; }
}
table ip6 filter {
\tchain INPUT {
\t\ttype filter hook input priority 0; policy drop;
\t}
}
";

    #[test]
    fn chains_and_hooks_are_read_from_the_listing() {
        let chains = parse_nft_chains(RULESET);
        let summary: Vec<(String, String, String, Option<String>, Option<String>)> = chains
            .into_iter()
            .map(|c| (c.family, c.table, c.chain, c.kind, c.hook))
            .collect();
        let s = |v: &str| v.to_string();
        assert_eq!(
            summary,
            vec![
                (
                    s("inet"),
                    s("filter"),
                    s("input"),
                    Some(s("filter")),
                    Some(s("input"))
                ),
                (s("inet"), s("filter"), s("allowed"), None, None),
                (
                    s("ip"),
                    s("nat"),
                    s("POSTROUTING"),
                    Some(s("nat")),
                    Some(s("postrouting"))
                ),
                (
                    s("ip6"),
                    s("filter"),
                    s("INPUT"),
                    Some(s("filter")),
                    Some(s("input"))
                ),
            ]
        );
    }

    #[test]
    fn nfproto_only_for_one_family_in_inet_without_address() {
        let mut spec = FirewallRuleSpec {
            backend: "nftables".into(),
            family: "ipv4".into(),
            table: None,
            chain: None,
            direction: "input".into(),
            action: "accept".into(),
            proto: None,
            sport: None,
            dport: None,
            saddr: Some("0.0.0.0/0".into()),
            daddr: Some("0.0.0.0/0".into()),
            in_iface: None,
            out_iface: None,
            zone: None,
            log_prefix: None,
            rate_limit: None,
            comment: None,
            to: None,
            nft_family: Some("inet".into()),
        };
        assert_eq!(nft_nfproto(&spec), Some("ipv4"));
        spec.saddr = Some("10.0.0.0/8".into());
        assert_eq!(nft_nfproto(&spec), None);
        spec.saddr = None;
        spec.nft_family = Some("ip".into());
        assert_eq!(nft_nfproto(&spec), None);
        assert_eq!(
            raw_nfproto("meta nfproto ipv6 tcp dport 22 accept"),
            Some("ipv6")
        );
        assert_eq!(nft_addr_family("2001:db8::/32"), "ip6");
        assert_eq!(nft_addr_family("10.0.0.1"), "ip");
    }
}
