//! NAT targets: the `to=<addr>[:port]` of a dnat or snat rule.
//!
//! The value must be one address (IPv4, or IPv6 in brackets when a port
//! follows) with an optional port or port range in plain decimal, so it
//! can only ever be the single token it claims to be in an iptables,
//! nft or firewalld command (see the R4-02/R5-03 validation).

use super::is_canonical_decimal;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A parsed `to` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NatTarget {
    pub addr: IpAddr,
    /// A port (`8080`) or range (`8080-8090`).
    pub port: Option<String>,
}

fn valid_port(p: &str) -> bool {
    let number = |s: &str| {
        is_canonical_decimal(s)
            .then(|| s.parse::<u16>().ok())
            .flatten()
            .filter(|n| *n != 0)
    };
    match p.split_once('-') {
        Some((lo, hi)) => number(lo).zip(number(hi)).is_some_and(|(l, h)| l <= h),
        None => number(p).is_some(),
    }
}

/// Parses `1.2.3.4`, `1.2.3.4:8080`, `2001:db8::1`, `[2001:db8::1]` or
/// `[2001:db8::1]:8080` (ports may be ranges `low-high`). Anything else is
/// `None`.
pub(crate) fn parse_to(value: &str) -> Option<NatTarget> {
    if value.len() > 64 {
        return None;
    }
    let (addr, port) = if let Some(rest) = value.strip_prefix('[') {
        let (addr, after) = rest.split_once(']')?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        (IpAddr::V6(addr.parse::<Ipv6Addr>().ok()?), port)
    } else if let Ok(addr) = value.parse::<IpAddr>() {
        (addr, None)
    } else {
        let (addr, port) = value.rsplit_once(':')?;
        (IpAddr::V4(addr.parse::<Ipv4Addr>().ok()?), Some(port))
    };
    if port.is_some_and(|p| !valid_port(p)) {
        return None;
    }
    Some(NatTarget {
        addr,
        port: port.map(str::to_string),
    })
}

impl NatTarget {
    /// `ipv4` or `ipv6`.
    pub fn family(&self) -> &'static str {
        if self.addr.is_ipv6() { "ipv6" } else { "ipv4" }
    }

    /// The form iptables, nft and resh print: `addr`, `addr:port`, or
    /// `[v6addr]:port`.
    pub fn render(&self) -> String {
        match (&self.addr, &self.port) {
            (IpAddr::V6(a), Some(p)) => format!("[{a}]:{p}"),
            (a, Some(p)) => format!("{a}:{p}"),
            (a, None) => a.to_string(),
        }
    }
}

/// True when two `to` values name the same target (or both are absent).
pub(crate) fn same_to(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => match (parse_to(a), parse_to(b)) {
            (Some(a), Some(b)) => a == b,
            _ => a == b,
        },
        _ => false,
    }
}

/// The NAT target of an nft rule (`dnat ip to 10.0.0.5:8080`,
/// `snat to 192.0.2.1`), read from the rule text before any comment.
pub(crate) fn nft_rule_to(line: &str) -> Option<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let at = words.iter().position(|w| *w == "dnat" || *w == "snat")?;
    let mut i = at + 1;
    if matches!(words.get(i), Some(&"ip") | Some(&"ip6")) {
        i += 1;
    }
    (words.get(i) == Some(&"to"))
        .then(|| words.get(i + 1).map(|v| v.to_string()))
        .flatten()
}

/// The value of `key="value"` in a firewalld rich rule.
pub(crate) fn rich_attr(rule: &str, key: &str) -> Option<String> {
    let needle = format!(" {key}=\"");
    let start = format!(" {rule}").find(&needle)? + needle.len() - 1;
    let rest = &rule[start..];
    rest.find('"').map(|end| rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_values_are_one_address_and_an_optional_port() {
        for (given, rendered, family) in [
            ("10.0.0.5", "10.0.0.5", "ipv4"),
            ("10.0.0.5:8080", "10.0.0.5:8080", "ipv4"),
            ("10.0.0.5:8080-8090", "10.0.0.5:8080-8090", "ipv4"),
            ("2001:db8::5", "2001:db8::5", "ipv6"),
            ("[2001:db8::5]", "2001:db8::5", "ipv6"),
            ("[2001:db8::5]:443", "[2001:db8::5]:443", "ipv6"),
        ] {
            let t = parse_to(given).unwrap_or_else(|| panic!("{given}"));
            assert_eq!(t.render(), rendered);
            assert_eq!(t.family(), family);
        }
        for bad in [
            "",
            "host.example",
            "10.0.0.5:0",
            "10.0.0.5:080",
            "10.0.0.5:65536",
            "10.0.0.5:90-80",
            "10.0.0.5:80;flush ruleset",
            "10.0.0.5 :80",
            "10.0.0.0/8",
            "2001:db8::5:80x",
            "[2001:db8::5]80",
            "[10.0.0.5]:80",
            "10.0.0.5:8080\"",
            "010.0.0.5",
        ] {
            assert!(parse_to(bad).is_none(), "{bad:?} accepted");
        }
        assert!(same_to(Some("[2001:db8::5]"), Some("2001:db8::5")));
        assert!(!same_to(Some("10.0.0.5:80"), Some("10.0.0.5")));
    }

    #[test]
    fn targets_are_read_from_listings() {
        assert_eq!(
            nft_rule_to("meta nfproto ipv4 tcp dport 80 dnat ip to 10.0.0.5:8080").as_deref(),
            Some("10.0.0.5:8080")
        );
        assert_eq!(
            nft_rule_to("snat to 192.0.2.1").as_deref(),
            Some("192.0.2.1")
        );
        assert_eq!(nft_rule_to("masquerade"), None);
        let rich = "rule family=\"ipv4\" forward-port port=\"80\" protocol=\"tcp\" \
                    to-port=\"8080\" to-addr=\"10.0.0.5\"";
        assert_eq!(rich_attr(rich, "to-addr").as_deref(), Some("10.0.0.5"));
        assert_eq!(rich_attr(rich, "to-port").as_deref(), Some("8080"));
        assert_eq!(rich_attr(rich, "port").as_deref(), Some("80"));
        assert_eq!(rich_attr(rich, "nope"), None);
    }
}
