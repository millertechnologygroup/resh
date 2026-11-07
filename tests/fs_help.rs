//! `resh fs --help` and `resh fs <verb> --help`: golden snapshots, the
//! approved layout, and usage lines that list exactly the options each verb
//! accepts. Regenerate the goldens with `UPDATE_GOLDEN=1`.

use resh::core::parse::parse_stage;
use std::path::PathBuf;

const VERBS: &[&str] = &[
    "list-mounts",
    "usage",
    "snapshot",
    "quota",
    "quota_summary",
    "mount",
    "unmount",
    "umount",
    "resize",
    "check",
    "fsck",
];

const FILTERS: &[&str] = &[
    "include_mountpoints",
    "exclude_mountpoints",
    "include_types",
    "exclude_types",
    "include_sources",
    "exclude_sources",
];

/// The options each verb accepts, as documented in fs.md.
fn options(verb: &str) -> Vec<&'static str> {
    let mut o: Vec<&str> = match verb {
        "list-mounts" => vec![
            "paths",
            "include_readonly",
            "include_readwrite",
            "include_pseudo",
            "include_loop",
            "include_network",
            "normalize_paths",
            "resolve_labels",
            "resolve_fs_features",
            "timeout_ms",
        ],
        "usage" => vec![
            "mode",
            "paths",
            "units",
            "human_readable",
            "include_inodes",
            "include_readonly",
            "normalize_paths",
            "threshold_used_percent_min",
            "threshold_used_percent_max",
            "timeout_ms",
        ],
        "snapshot" => vec![
            "format",
            "include_usage",
            "include_inodes",
            "include_fs_metadata",
            "include_os_metadata",
            "normalize_paths",
            "timeout_ms",
        ],
        "quota" | "quota_summary" => vec![
            "subject",
            "subject_type",
            "all_subjects",
            "units",
            "include_space",
            "include_inodes",
            "include_grace",
            "resolve_uid_gid",
            "timeout_ms",
        ],
        "mount" => vec![
            "target",
            "source",
            "type",
            "options",
            "read_only",
            "bind",
            "remount",
            "network",
            "create_target",
            "make_parents",
            "fail_if_mounted",
            "dry_run",
            "timeout_ms",
        ],
        "unmount" | "umount" => vec![
            "target",
            "by",
            "force",
            "lazy",
            "detach_children",
            "fail_if_not_mounted",
            "dry_run",
            "timeout_ms",
        ],
        "resize" => vec![
            "target",
            "size",
            "delta",
            "by",
            "size_units",
            "mode",
            "allow_shrink",
            "min_free_space_percent",
            "manage_underlying_volume",
            "volume_resize_only",
            "filesystem_resize_only",
            "require_unmounted_for_shrink",
            "force",
            "dry_run",
            "timeout_ms",
        ],
        "check" | "fsck" => vec![
            "target",
            "by",
            "filesystem_type",
            "mode",
            "allow_repair",
            "aggressiveness",
            "allow_online_check",
            "require_unmounted_for_repair",
            "skip_if_mounted",
            "force",
            "btrfs_use_scrub",
            "btrfs_allow_offline_check",
            "dry_run",
            "timeout_ms",
        ],
        other => panic!("unknown verb {other}"),
    };
    if verb == "quota" {
        o.push("path");
    }
    if matches!(verb, "list-mounts" | "usage" | "snapshot" | "quota_summary") {
        o.extend(FILTERS);
    }
    o.sort();
    o
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = assert_cmd::cargo::cargo_bin_cmd!("resh")
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn golden(name: &str, actual: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.txt"));
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing golden {}", path.display()));
    assert_eq!(actual, expected, "golden {name} differs");
}

fn assert_plain_text(out: &str) {
    assert!(out.is_ascii(), "non-ASCII output");
    for line in out.lines() {
        assert!(line.len() <= 80, "line over 80 columns: {line:?}");
        assert!(!line.ends_with(' '), "trailing space: {line:?}");
    }
}

#[test]
fn handle_help_matches_golden_and_lists_every_verb() {
    let (code, out, err) = run(&["fs", "--help"]);
    assert_eq!(code, 0);
    assert_eq!(err, "");
    assert_plain_text(&out);
    golden("fs_help", &out);
    assert!(out.starts_with("Handle: fs\n"));
    assert!(out.contains("Usage:\n  resh fs://<alias>.<verb>"));
    let listed: Vec<&str> = out
        .split("Available Verbs:\n")
        .nth(1)
        .unwrap()
        .split("\n\n")
        .next()
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    let mut listed_sorted = listed.clone();
    listed_sorted.sort();
    let mut verbs = VERBS.to_vec();
    verbs.sort();
    assert_eq!(listed_sorted, verbs);
    // The help verb prints the same text.
    let (code, via_verb, _) = run(&["fs://local.help"]);
    assert_eq!(code, 0);
    assert_eq!(via_verb, out);
}

#[test]
fn every_verb_help_is_accurate() {
    for verb in VERBS {
        let (code, out, err) = run(&["fs", verb, "--help"]);
        assert_eq!(code, 0, "{verb}");
        assert_eq!(err, "", "{verb}");
        assert_plain_text(&out);
        golden(&format!("fs_{}_help", verb.replace('-', "_")), &out);

        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "Handle: fs");
        assert_eq!(lines[1], format!("Verb: {verb}"));
        assert!(lines[2].starts_with("Definition: "));
        let pos = |label: &str| {
            out.find(label)
                .unwrap_or_else(|| panic!("{verb}: no {label}"))
        };
        assert!(pos("\nUsage:\n") < pos("\nExample:\n"));
        assert!(pos("\nExample:\n") < pos("\nExample Output:\n"));

        // The usage lists exactly the accepted options.
        let usage = out
            .split("Usage:\n")
            .nth(1)
            .unwrap()
            .split("\n\n")
            .next()
            .unwrap();
        let mut in_usage: Vec<&str> = usage
            .split(|c: char| c == '[' || c.is_whitespace())
            .filter_map(|w| w.split_once('=').map(|(k, _)| k))
            .collect();
        in_usage.sort();
        assert_eq!(in_usage, options(verb), "usage of {verb}");

        // The example is a valid stage for this verb, with known options.
        let example = out
            .split("Example:\n")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .trim();
        let words: Vec<&str> = example.split_whitespace().collect();
        assert_eq!(words[0], "resh");
        let stage = words.iter().find(|w| w.starts_with("fs://")).unwrap();
        let parsed = parse_stage(stage).unwrap();
        assert_eq!(parsed.verb, *verb);
        for arg in words.iter().skip_while(|w| !w.starts_with("fs://")).skip(1) {
            let key = arg.split_once('=').unwrap().0;
            assert!(options(verb).contains(&key), "{verb} example uses {key}");
        }

        // The help verb prints the same text for this verb.
        let (_, via_verb, _) = run(&["fs://local.help", &format!("verb={verb}")]);
        assert_eq!(via_verb, out, "{verb}");
    }
}

#[test]
fn every_accepted_option_is_recognised_and_others_are_refused() {
    for verb in VERBS {
        for opt in options(verb) {
            // An unreadable timeout_ms makes every verb stop before it does
            // anything; the refusal must be about that, not about `opt`.
            let mut args = vec![format!("fs://local.{verb}"), "timeout_ms=soon".to_string()];
            if opt != "timeout_ms" {
                args.push(format!("{opt}=x"));
            }
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let (code, _, err) = run(&args);
            assert_eq!(code, 2, "{verb} {opt}: {err}");
            assert!(
                !err.contains("unknown argument"),
                "{verb} does not accept its documented option {opt}: {err}"
            );
        }
        let (code, _, err) = run(&[&format!("fs://local.{verb}"), "no_such_option=1"]);
        assert_eq!(code, 2, "{verb}");
        assert!(
            err.contains("unknown argument \"no_such_option\""),
            "{verb}: {err}"
        );
    }
}
