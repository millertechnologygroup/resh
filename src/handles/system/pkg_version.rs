//! Package version ordering as the package managers define it, used by
//! `restore` to tell an upgrade from a downgrade:
//! - `dpkg`: Debian's algorithm (`dpkg --compare-versions`), for apt;
//! - `rpm_evr`: rpm's `[epoch:]version[-release]` with `rpmvercmp` (also what
//!   pacman's `vercmp` implements), for dnf, yum and pacman;
//! - `apk`: Alpine's version format, for apk.

use std::cmp::Ordering;

/// Splits `[epoch:]rest` into a numeric epoch (0 when absent) and the rest.
fn split_epoch(v: &str) -> (u64, &str) {
    match v.split_once(':') {
        Some((e, rest)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => {
            (e.parse().unwrap_or(u64::MAX), rest)
        }
        _ => (0, v),
    }
}

/// Debian version comparison: epoch, then upstream version, then revision.
pub(crate) fn dpkg(a: &str, b: &str) -> Ordering {
    let (ea, ra) = split_epoch(a);
    let (eb, rb) = split_epoch(b);
    let split = |s: &str| -> (String, String) {
        match s.rfind('-') {
            Some(i) => (s[..i].to_string(), s[i + 1..].to_string()),
            None => (s.to_string(), String::new()),
        }
    };
    let (ua, va) = split(ra);
    let (ub, vb) = split(rb);
    ea.cmp(&eb)
        .then_with(|| verrevcmp(&ua, &ub))
        .then_with(|| verrevcmp(&va, &vb))
}

/// The weight of a non-digit character in dpkg's ordering: `~` sorts before
/// everything (even the end), letters before other characters.
fn dpkg_order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(b'~') => -1,
        Some(c) => c as i32 + 256,
    }
}

fn verrevcmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        let mut first_diff = 0i32;
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let ac = dpkg_order(a.get(i).copied());
            let bc = dpkg_order(b.get(j).copied());
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while i < a.len() && a[i] == b'0' {
            i += 1;
        }
        while j < b.len() && b[j] == b'0' {
            j += 1;
        }
        while i < a.len() && a[i].is_ascii_digit() && j < b.len() && b[j].is_ascii_digit() {
            if first_diff == 0 {
                first_diff = a[i] as i32 - b[j] as i32;
            }
            i += 1;
            j += 1;
        }
        if i < a.len() && a[i].is_ascii_digit() {
            return Ordering::Greater;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }
    Ordering::Equal
}

/// rpm comparison of `[epoch:]version[-release]`.
pub(crate) fn rpm_evr(a: &str, b: &str) -> Ordering {
    let (ea, ra) = split_epoch(a);
    let (eb, rb) = split_epoch(b);
    let split = |s: &str| -> (String, Option<String>) {
        match s.rfind('-') {
            Some(i) => (s[..i].to_string(), Some(s[i + 1..].to_string())),
            None => (s.to_string(), None),
        }
    };
    let (va, la) = split(ra);
    let (vb, lb) = split(rb);
    ea.cmp(&eb)
        .then_with(|| rpmvercmp(&va, &vb))
        .then_with(|| match (la, lb) {
            (Some(la), Some(lb)) => rpmvercmp(&la, &lb),
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
        })
}

/// rpm's `rpmvercmp`: alternating numeric and alphabetic segments; numbers
/// beat letters, `~` sorts before everything, `^` after the end only.
pub(crate) fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    let sep = |c: u8| !c.is_ascii_alphanumeric() && c != b'~' && c != b'^';
    while i < a.len() || j < b.len() {
        while i < a.len() && sep(a[i]) {
            i += 1;
        }
        while j < b.len() && sep(b[j]) {
            j += 1;
        }
        let (ca, cb) = (a.get(i).copied(), b.get(j).copied());
        if ca == Some(b'~') || cb == Some(b'~') {
            if ca != Some(b'~') {
                return Ordering::Greater;
            }
            if cb != Some(b'~') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if ca == Some(b'^') || cb == Some(b'^') {
            if ca.is_none() {
                return Ordering::Less;
            }
            if cb.is_none() {
                return Ordering::Greater;
            }
            if ca != Some(b'^') {
                return Ordering::Greater;
            }
            if cb != Some(b'^') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if ca.is_none() || cb.is_none() {
            break;
        }
        let (si, sj) = (i, j);
        let numeric = a[i].is_ascii_digit();
        if numeric {
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
        } else {
            while i < a.len() && a[i].is_ascii_alphabetic() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_alphabetic() {
                j += 1;
            }
        }
        if sj == j {
            // Segments of different types: a number is newer than letters.
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let (mut sa, mut sb) = (&a[si..i], &b[sj..j]);
        if numeric {
            while sa.first() == Some(&b'0') {
                sa = &sa[1..];
            }
            while sb.first() == Some(&b'0') {
                sb = &sb[1..];
            }
            let by_len = sa.len().cmp(&sb.len());
            if by_len != Ordering::Equal {
                return by_len;
            }
        }
        let by_text = sa.cmp(sb);
        if by_text != Ordering::Equal {
            return by_text;
        }
    }
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Ordering::Equal,
        (false, _) => Ordering::Greater,
        _ => Ordering::Less,
    }
}

/// pacman's `vercmp` (libalpm): `[epoch:]version[-release]`, the release
/// compared only when both have one, and an older `rpmvercmp` without `~`
/// and `^` in which a trailing letter segment is older (`1.0a < 1.0`).
pub(crate) fn pacman(a: &str, b: &str) -> Ordering {
    let (ea, ra) = split_epoch(a);
    let (eb, rb) = split_epoch(b);
    let split = |s: &str| -> (String, Option<String>) {
        match s.rfind('-') {
            Some(i) => (s[..i].to_string(), Some(s[i + 1..].to_string())),
            None => (s.to_string(), None),
        }
    };
    let (va, la) = split(ra);
    let (vb, lb) = split(rb);
    ea.cmp(&eb)
        .then_with(|| alpm_rpmvercmp(&va, &vb))
        .then_with(|| match (la, lb) {
            (Some(la), Some(lb)) => alpm_rpmvercmp(&la, &lb),
            _ => Ordering::Equal,
        })
}

fn alpm_rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        let (pi, pj) = (i, j);
        while i < a.len() && !a[i].is_ascii_alphanumeric() {
            i += 1;
        }
        while j < b.len() && !b[j].is_ascii_alphanumeric() {
            j += 1;
        }
        if i >= a.len() || j >= b.len() {
            break;
        }
        if i - pi != j - pj {
            return (i - pi).cmp(&(j - pj));
        }
        let (si, sj) = (i, j);
        let numeric = a[i].is_ascii_digit();
        if numeric {
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
        } else {
            while i < a.len() && a[i].is_ascii_alphabetic() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_alphabetic() {
                j += 1;
            }
        }
        if sj == j {
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let (mut sa, mut sb) = (&a[si..i], &b[sj..j]);
        if numeric {
            while sa.first() == Some(&b'0') {
                sa = &sa[1..];
            }
            while sb.first() == Some(&b'0') {
                sb = &sb[1..];
            }
            let by_len = sa.len().cmp(&sb.len());
            if by_len != Ordering::Equal {
                return by_len;
            }
        }
        let by_text = sa.cmp(sb);
        if by_text != Ordering::Equal {
            return by_text;
        }
    }
    let (ra, rb) = (a.get(i).copied(), b.get(j).copied());
    match (ra, rb) {
        (None, None) => Ordering::Equal,
        // A remaining letter segment is older; anything else is newer.
        (None, Some(c)) if !c.is_ascii_alphabetic() => Ordering::Less,
        (Some(c), _) if c.is_ascii_alphabetic() => Ordering::Less,
        _ => Ordering::Greater,
    }
}

/// Alpine's version order:`.`-separated numbers, an optional letter,
/// `_suffix[N]` parts (`alpha`, `beta`, `pre`, `rc` before the plain
/// version; `cvs`, `svn`, `git`, `hg`, `p` after), `~hash` (ignored) and
/// `-rN`.
pub(crate) fn apk(a: &str, b: &str) -> Ordering {
    apk_parse(a).cmp(&apk_parse(b))
}

type ApkKey = (Vec<u64>, u8, Vec<(u8, u64)>, u64);

fn apk_parse(v: &str) -> ApkKey {
    let (main, release) = match v.rsplit_once("-r") {
        Some((m, r)) if !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit()) => {
            (m, r.parse().unwrap_or(u64::MAX))
        }
        _ => (v, 0),
    };
    let main = main.split('~').next().unwrap_or(main);
    let mut parts = main.splitn(2, '_');
    let base = parts.next().unwrap_or("");
    let suffixes = parts.next().unwrap_or("");
    let letter = base
        .bytes()
        .last()
        .filter(u8::is_ascii_alphabetic)
        .unwrap_or(0);
    let digits = if letter != 0 {
        &base[..base.len() - 1]
    } else {
        base
    };
    let numbers = digits.split('.').map(|n| n.parse().unwrap_or(0)).collect();
    // Suffix ranks around the plain version (rank 4, also the terminator).
    let mut sufs: Vec<(u8, u64)> = suffixes
        .split('_')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let name: String = s.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
            let num = s[name.len()..].parse().unwrap_or(0);
            let rank = match name.as_str() {
                "alpha" => 0,
                "beta" => 1,
                "pre" => 2,
                "rc" => 3,
                "cvs" => 5,
                "svn" => 6,
                "git" => 7,
                "hg" => 8,
                "p" => 9,
                _ => 4,
            };
            (rank, num)
        })
        .collect();
    sufs.push((4, 0));
    (numbers, letter, sufs, release)
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::{Equal, Greater, Less};

    // Each expectation was checked against the managers' own tools
    // (`dpkg --compare-versions`, `rpmdev-vercmp`/`vercmp`, `apk version -t`)
    // in Debian, Fedora, Arch and Alpine containers.
    #[test]
    fn dpkg_order() {
        for (a, b, want) in [
            ("1.0", "1.0", Equal),
            ("1.0", "1.1", Less),
            ("1.0~rc1", "1.0", Less),
            ("1.0", "1.0+deb12u1", Less),
            ("1:0.9", "2.0", Greater),
            ("8.5.0-2ubuntu10", "8.5.0-2ubuntu10.16", Less),
            ("7.88.1-10+deb12u5", "7.88.1-10+deb12u15", Less),
            ("1.10", "1.9", Greater),
            ("1.0a", "1.0", Greater),
            ("2:4.1-1", "2:4.1-1", Equal),
            ("1.0-1", "1.0", Greater),
        ] {
            assert_eq!(dpkg(a, b), want, "{a} vs {b}");
            assert_eq!(dpkg(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn rpm_order() {
        for (a, b, want) in [
            ("1.0-1.fc42", "1.0-1.fc42", Equal),
            ("1.0-1.fc42", "1.0-2.fc42", Less),
            ("1.10-1", "1.9-1", Greater),
            ("1:1.0-1", "2.0-1", Greater),
            ("1.0~rc1-1", "1.0-1", Less),
            ("1.0^git1-1", "1.0-1", Greater),
            ("1.0a-1", "1.0-1", Greater),
            ("1.7.1-3", "1.7.1-10", Less),
            ("6.6.1-2", "6.6.1-2", Equal),
            ("1.0", "1.0-5", Less),
        ] {
            assert_eq!(rpm_evr(a, b), want, "{a} vs {b}");
            assert_eq!(rpm_evr(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn pacman_order() {
        for (a, b, want) in [
            ("1.0-1.fc42", "1.0-2.fc42", Less),
            ("1.10-1", "1.9-1", Greater),
            ("1:1.0-1", "2.0-1", Greater),
            ("1.0~rc1-1", "1.0-1", Greater),
            ("1.0^git1-1", "1.0-1", Greater),
            ("1.0a-1", "1.0-1", Less),
            ("1.7.1-3", "1.7.1-10", Less),
            ("6.6.1-2", "6.6.1-2", Equal),
            ("1.0", "1.0-5", Equal),
        ] {
            assert_eq!(pacman(a, b), want, "{a} vs {b}");
            assert_eq!(pacman(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn apk_order() {
        for (a, b, want) in [
            ("1.7.1-r0", "1.7.1-r10", Less),
            ("1.0_rc1", "1.0", Less),
            ("1.0_p1", "1.0", Greater),
            ("1.8.2-r0", "1.7.1-r0", Greater),
            ("1.0a", "1.0", Greater),
            ("1.0.1", "1.0", Greater),
            ("1.37.0-r31", "1.37.0-r31", Equal),
            ("1.0_alpha1", "1.0_beta1", Less),
        ] {
            assert_eq!(apk(a, b), want, "{a} vs {b}");
            assert_eq!(apk(b, a), want.reverse(), "{b} vs {a}");
        }
    }
}
