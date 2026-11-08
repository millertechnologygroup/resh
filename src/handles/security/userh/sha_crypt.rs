//! SHA-crypt (`$5$` SHA-256 and `$6$` SHA-512), as specified by Ulrich
//! Drepper ("Unix crypt using SHA-256 and SHA-512") and implemented by glibc
//! and libxcrypt. Used to hash new passwords for `chpasswd -e` and to verify
//! old passwords read from the shadow file.

use sha2::{Digest, Sha256, Sha512};

const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ROUNDS_DEFAULT: u32 = 5000;
const ROUNDS_MIN: u32 = 1000;
const ROUNDS_MAX: u32 = 999_999_999;
const SALT_MAX: usize = 16;

/// The two SHA-crypt variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Sha256,
    Sha512,
}

impl Variant {
    fn prefix(self) -> &'static str {
        match self {
            Variant::Sha256 => "$5$",
            Variant::Sha512 => "$6$",
        }
    }

    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        match self {
            Variant::Sha256 => {
                let mut h = Sha256::new();
                for p in parts {
                    h.update(p);
                }
                h.finalize().to_vec()
            }
            Variant::Sha512 => {
                let mut h = Sha512::new();
                for p in parts {
                    h.update(p);
                }
                h.finalize().to_vec()
            }
        }
    }

    /// The final encoding: groups of three bytes in the order the
    /// specification gives, each written as four characters, then the
    /// remaining bytes.
    fn encode(self, d: &[u8]) -> String {
        let mut out = String::new();
        let mut put = |b2: u8, b1: u8, b0: u8, n: usize| {
            let mut w = (u32::from(b2) << 16) | (u32::from(b1) << 8) | u32::from(b0);
            for _ in 0..n {
                out.push(ALPHABET[(w & 0x3f) as usize] as char);
                w >>= 6;
            }
        };
        match self {
            Variant::Sha512 => {
                const ORDER: [(usize, usize, usize); 21] = [
                    (0, 21, 42),
                    (22, 43, 1),
                    (44, 2, 23),
                    (3, 24, 45),
                    (25, 46, 4),
                    (47, 5, 26),
                    (6, 27, 48),
                    (28, 49, 7),
                    (50, 8, 29),
                    (9, 30, 51),
                    (31, 52, 10),
                    (53, 11, 32),
                    (12, 33, 54),
                    (34, 55, 13),
                    (56, 14, 35),
                    (15, 36, 57),
                    (37, 58, 16),
                    (59, 17, 38),
                    (18, 39, 60),
                    (40, 61, 19),
                    (62, 20, 41),
                ];
                for (a, b, c) in ORDER {
                    put(d[a], d[b], d[c], 4);
                }
                put(0, 0, d[63], 2);
            }
            Variant::Sha256 => {
                const ORDER: [(usize, usize, usize); 10] = [
                    (0, 10, 20),
                    (21, 1, 11),
                    (12, 22, 2),
                    (3, 13, 23),
                    (24, 4, 14),
                    (15, 25, 5),
                    (6, 16, 26),
                    (27, 7, 17),
                    (18, 28, 8),
                    (9, 19, 29),
                ];
                for (a, b, c) in ORDER {
                    put(d[a], d[b], d[c], 4);
                }
                put(0, d[31], d[30], 3);
            }
        }
        out
    }
}

/// `n` bytes taken by repeating `block`.
fn repeat_to(block: &[u8], n: usize) -> Vec<u8> {
    block.iter().copied().cycle().take(n).collect()
}

/// The encoded SHA-crypt digest of `password` with `salt` and `rounds`.
fn crypt_raw(variant: Variant, password: &[u8], salt: &[u8], rounds: u32) -> String {
    let p = password;
    let s = salt;
    let b = variant.digest(&[p, s, p]);

    let mut a_input: Vec<u8> = Vec::new();
    a_input.extend_from_slice(p);
    a_input.extend_from_slice(s);
    a_input.extend(repeat_to(&b, p.len()));
    let mut n = p.len();
    while n > 0 {
        if n & 1 == 1 {
            a_input.extend_from_slice(&b);
        } else {
            a_input.extend_from_slice(p);
        }
        n >>= 1;
    }
    let mut a = variant.digest(&[&a_input]);

    let dp = variant.digest(&[&p.repeat(p.len())]);
    let p_seq = repeat_to(&dp, p.len());

    let ds = variant.digest(&[&s.repeat(16 + usize::from(a[0]))]);
    let s_seq = repeat_to(&ds, s.len());

    for i in 0..rounds {
        let mut parts: Vec<&[u8]> = Vec::with_capacity(4);
        parts.push(if i & 1 == 1 { &p_seq } else { &a });
        if i % 3 != 0 {
            parts.push(&s_seq);
        }
        if i % 7 != 0 {
            parts.push(&p_seq);
        }
        parts.push(if i & 1 == 1 { &a } else { &p_seq });
        a = variant.digest(&parts);
    }
    variant.encode(&a)
}

/// The parts of a stored SHA-crypt hash: `(variant, rounds, salt, encoded
/// digest)`, or `None` for anything else.
fn parse(stored: &str) -> Option<(Variant, u32, &str, &str)> {
    let (variant, rest) = match stored.strip_prefix("$6$") {
        Some(r) => (Variant::Sha512, r),
        None => (Variant::Sha256, stored.strip_prefix("$5$")?),
    };
    let (rounds, rest) = match rest.strip_prefix("rounds=") {
        Some(r) => {
            let (num, rest) = r.split_once('$')?;
            let n: u64 = num.parse().ok()?;
            let n = n.clamp(u64::from(ROUNDS_MIN), u64::from(ROUNDS_MAX)) as u32;
            (n, rest)
        }
        None => (ROUNDS_DEFAULT, rest),
    };
    let (salt, digest) = rest.split_once('$')?;
    // A stored hash always carries the salt as the algorithm truncated it.
    if salt.len() > SALT_MAX || salt.contains(':') {
        return None;
    }
    let want = match variant {
        Variant::Sha256 => 43,
        Variant::Sha512 => 86,
    };
    if digest.len() != want || !digest.bytes().all(|c| ALPHABET.contains(&c)) {
        return None;
    }
    Some((variant, rounds, salt, digest))
}

/// True if `stored` is a well-formed `$5$` or `$6$` hash.
pub fn is_sha_crypt(stored: &str) -> bool {
    parse(stored).is_some()
}

/// Hashes `password` with a fresh random salt and the default rounds.
pub fn hash(variant: Variant, password: &str) -> Result<String, String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut raw = [0u8; SALT_MAX];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| "cannot generate a random salt".to_string())?;
    let salt: String = raw
        .iter()
        .map(|b| ALPHABET[usize::from(*b) & 0x3f] as char)
        .collect();
    Ok(hash_with_salt(variant, password, &salt, None))
}

/// Hashes `password` with `salt` (truncated to 16 characters) and
/// `rounds` (`None` for the default 5000, written without `rounds=`).
pub fn hash_with_salt(variant: Variant, password: &str, salt: &str, rounds: Option<u32>) -> String {
    let salt = &salt[..salt.len().min(SALT_MAX)];
    let r = rounds
        .map(|r| r.clamp(ROUNDS_MIN, ROUNDS_MAX))
        .unwrap_or(ROUNDS_DEFAULT);
    let digest = crypt_raw(variant, password.as_bytes(), salt.as_bytes(), r);
    match rounds {
        Some(_) => format!("{}rounds={}${}${}", variant.prefix(), r, salt, digest),
        None => format!("{}{}${}", variant.prefix(), salt, digest),
    }
}

/// Verifies `password` against a stored `$5$`/`$6$` hash. `None` when
/// `stored` is not a SHA-crypt hash.
pub fn verify(password: &str, stored: &str) -> Option<bool> {
    let (variant, rounds, salt, digest) = parse(stored)?;
    let computed = crypt_raw(variant, password.as_bytes(), salt.as_bytes(), rounds);
    Some(constant_time_eq(computed.as_bytes(), digest.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors from Drepper's specification, checked against `openssl passwd -5/-6`.
    #[test]
    fn specification_vectors() {
        assert_eq!(
            hash_with_salt(Variant::Sha512, "Hello world!", "saltstring", None),
            "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu\
             esI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
        );
        assert_eq!(
            hash_with_salt(
                Variant::Sha512,
                "Hello world!",
                "saltstringsaltstring",
                Some(10000)
            ),
            "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/\
             UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
        );
        assert_eq!(
            hash_with_salt(Variant::Sha256, "Hello world!", "saltstring", None),
            "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"
        );
        // A salt longer than 16 characters is truncated.
        assert_eq!(
            hash_with_salt(
                Variant::Sha256,
                "Hello world!",
                "saltstringsaltstring",
                None
            ),
            "$5$saltstringsaltst$a5C8Ofk71MUIoKve2QuP9FMl.dwNgseF5tR1LGAL7iB"
        );
        assert_eq!(
            hash_with_salt(
                Variant::Sha256,
                "Hello world!",
                "saltstringsaltstring",
                Some(10000)
            ),
            "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"
        );
    }

    #[test]
    fn hash_and_verify_round_trip() {
        for v in [Variant::Sha256, Variant::Sha512] {
            let h = hash(v, "S3cr3t pw").unwrap();
            assert!(is_sha_crypt(&h), "{h}");
            assert_eq!(verify("S3cr3t pw", &h), Some(true));
            assert_eq!(verify("S3cr3t pX", &h), Some(false));
            assert_eq!(verify("", &h), Some(false));
        }
        let explicit = hash_with_salt(Variant::Sha512, "pw", "abc", Some(5000));
        assert!(explicit.starts_with("$6$rounds=5000$abc$"));
        assert_eq!(verify("pw", &explicit), Some(true));
    }

    #[test]
    fn foreign_and_malformed_hashes_are_not_sha_crypt() {
        for bad in [
            "",
            "!",
            "*",
            "$1$abc$def",
            "$y$j9T$abc$def",
            "$2b$12$abcdefghijklmnopqrstuuJ8V8sQJ2zWQ9fSNWZFx7zU8pdZ0zU5i",
            "$6$salt",
            "$6$salt$short",
            "$6$rounds=x$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
        ] {
            assert!(!is_sha_crypt(bad), "{bad}");
            assert_eq!(verify("pw", bad), None, "{bad}");
        }
    }
}
