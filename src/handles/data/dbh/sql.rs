//! A small SQL lexer: enough to count the statements in a string (so `query`,
//! `exec` and each `transaction` item run exactly one statement) and to find
//! the CHECK constraints in a SQLite `CREATE TABLE` text.
//!
//! It knows each dialect's quoting and comments: `'...'` strings (`''`
//! escape; backslash escapes in MySQL strings and PostgreSQL `E'...'`),
//! `"..."` (identifiers, or strings with backslash escapes in MySQL),
//! `` `...` `` (MySQL, SQLite) and `[...]` (SQLite) identifiers, `--` and
//! `/* */` comments (nested in PostgreSQL), `#` comments (MySQL) and
//! PostgreSQL `$tag$...$tag$` bodies. A `BEGIN ... END` block in a
//! `CREATE TRIGGER/PROCEDURE/FUNCTION/EVENT` statement does not end at its
//! inner semicolons.

use super::Driver;

/// One lexical token. Quoted text and comments keep their delimiters.
#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    /// A keyword or bare identifier (as written).
    Word(String),
    /// A quoted identifier or string, delimiters included.
    Quoted(String),
    /// Any other single character (operators, parentheses, `;`).
    Punct(char),
}

/// Splits `sql` into tokens, dropping whitespace and comments. Fails on an
/// unterminated string, identifier, comment or dollar-quoted body.
pub fn tokens(sql: &str, driver: Driver) -> Result<Vec<Tok>, String> {
    Ok(spanned(sql, driver)?.into_iter().map(|(t, _)| t).collect())
}

/// Like [`tokens`], with each token's start and end as character indices.
fn spanned(sql: &str, driver: Driver) -> Result<Vec<(Tok, (usize, usize))>, String> {
    let c: Vec<char> = sql.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let n = c.len();
    let word_char = |ch: char| ch.is_alphanumeric() || ch == '_' || ch == '$';
    while i < n {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch == '-' && c.get(i + 1) == Some(&'-') || ch == '#' && driver == Driver::Mysql {
            while i < n && c[i] != '\n' {
                i += 1;
            }
        } else if ch == '/' && c.get(i + 1) == Some(&'*') {
            let nested = driver == Driver::Postgres;
            let mut depth = 1;
            i += 2;
            while depth > 0 {
                if i >= n {
                    return Err("unterminated /* comment".into());
                }
                if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else if nested && c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else if ch == '\'' || ch == '"' || ch == '`' || (ch == '[' && driver == Driver::Sqlite) {
            let close = if ch == '[' { ']' } else { ch };
            // Backslash escapes: MySQL strings ('...' and "..."), and
            // PostgreSQL E'...' strings.
            let pg_e = driver == Driver::Postgres
                && ch == '\''
                && i > 0
                && matches!(c[i - 1], 'e' | 'E')
                && (i < 2 || !word_char(c[i - 2]));
            let backslash = (driver == Driver::Mysql && ch != '`') || pg_e;
            let start = i;
            i += 1;
            loop {
                if i >= n {
                    return Err(format!("unterminated {ch}...{close} quote"));
                }
                if backslash && c[i] == '\\' {
                    i += 2;
                    continue;
                }
                if c[i] == close {
                    // A doubled delimiter is an escaped one (not for [...]).
                    if close != ']' && c.get(i + 1) == Some(&close) {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            // The E of E'...' was read as a word just before; fold it in.
            if pg_e {
                if let Some((Tok::Word(w), _)) = out.last() {
                    if w.eq_ignore_ascii_case("e") {
                        out.pop();
                    }
                }
            }
            out.push((Tok::Quoted(c[start..i].iter().collect()), (start, i)));
        } else if ch == '$'
            && driver == Driver::Postgres
            && (i == 0 || !word_char(c[i - 1]))
            && dollar_tag(&c, i).is_some()
        {
            let tag = dollar_tag(&c, i).unwrap();
            let start = i;
            i += tag.len();
            loop {
                if i >= n {
                    return Err(format!(
                        "unterminated {} body",
                        tag.iter().collect::<String>()
                    ));
                }
                if c[i..].starts_with(&tag) {
                    i += tag.len();
                    break;
                }
                i += 1;
            }
            out.push((Tok::Quoted(c[start..i].iter().collect()), (start, i)));
        } else if word_char(ch) {
            let start = i;
            while i < n && word_char(c[i]) {
                i += 1;
            }
            out.push((Tok::Word(c[start..i].iter().collect()), (start, i)));
        } else {
            out.push((Tok::Punct(ch), (i, i + 1)));
            i += 1;
        }
    }
    Ok(out)
}

/// The `$tag$` opening at `i` (`$$` or `$name$`), as characters.
fn dollar_tag(c: &[char], i: usize) -> Option<Vec<char>> {
    let mut j = i + 1;
    while j < c.len() && (c[j].is_alphanumeric() || c[j] == '_') {
        j += 1;
    }
    if j < c.len() && c[j] == '$' && !c.get(i + 1).is_some_and(|d| d.is_ascii_digit()) {
        Some(c[i..=j].to_vec())
    } else {
        None
    }
}

fn is_word(t: &Tok, w: &str) -> bool {
    matches!(t, Tok::Word(x) if x.eq_ignore_ascii_case(w))
}

/// The number of statements in `sql` (empty statements between semicolons
/// are not counted).
pub fn statement_count(sql: &str, driver: Driver) -> Result<usize, String> {
    let toks = tokens(sql, driver)?;
    let mut count = 0;
    let mut current: Vec<&Tok> = Vec::new();
    let mut depth = 0usize;
    for (k, t) in toks.iter().enumerate() {
        if *t == Tok::Punct(';') && depth == 0 {
            if !current.is_empty() {
                count += 1;
            }
            current.clear();
            continue;
        }
        // Compound bodies of stored routines and triggers.
        let routine = current.first().is_some_and(|f| is_word(f, "create"))
            && current.iter().any(|w| {
                ["trigger", "procedure", "function", "event"]
                    .iter()
                    .any(|k| is_word(w, k))
            });
        if routine {
            if is_word(t, "begin") || (depth > 0 && is_word(t, "case")) {
                // `END CASE` closes a CASE opened earlier; do not reopen.
                let after_end = k > 0 && is_word(&toks[k - 1], "end");
                if !after_end {
                    depth += 1;
                }
            } else if is_word(t, "end") && depth > 0 {
                let next = toks.get(k + 1);
                let closes_other = next.is_some_and(|n| {
                    ["if", "loop", "while", "repeat"]
                        .iter()
                        .any(|w| is_word(n, w))
                });
                if !closes_other {
                    depth -= 1;
                }
            }
        }
        current.push(t);
    }
    if !current.is_empty() {
        count += 1;
    }
    Ok(count)
}

/// Checks that `sql` is exactly one statement (a trailing `;` is allowed).
pub fn single_statement(sql: &str, driver: Driver, what: &str) -> Result<(), String> {
    match statement_count(sql, driver) {
        Err(e) => Err(format!("{what}: {e}")),
        Ok(0) => Err(format!("{what} is empty")),
        Ok(1) => Ok(()),
        Ok(n) => Err(format!(
            "{what} holds {n} statements; give one statement (use transaction \
             statements=[...] to run several)"
        )),
    }
}

/// The CHECK constraints in a SQLite `CREATE TABLE` statement, as
/// `(name, expression)`; `name` is set when written as
/// `CONSTRAINT <name> CHECK (...)`.
pub fn sqlite_checks(create_sql: &str) -> Vec<(Option<String>, String)> {
    let Ok(toks) = spanned(create_sql, Driver::Sqlite) else {
        return Vec::new();
    };
    let chars: Vec<char> = create_sql.chars().collect();
    let mut out = Vec::new();
    for (k, (t, _)) in toks.iter().enumerate() {
        if !is_word(t, "check") || toks.get(k + 1).map(|x| &x.0) != Some(&Tok::Punct('(')) {
            continue;
        }
        let open = toks[k + 1].1.1;
        let mut depth = 0;
        let mut close = None;
        for (t, (s, _)) in &toks[k + 1..] {
            match t {
                Tok::Punct('(') => depth += 1,
                Tok::Punct(')') => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(*s);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else { continue };
        let expr: String = chars[open..close].iter().collect();
        let name = if k >= 2 && is_word(&toks[k - 2].0, "constraint") {
            match &toks[k - 1].0 {
                Tok::Word(w) => Some(w.clone()),
                Tok::Quoted(q) => Some(unquote(q)),
                Tok::Punct(_) => None,
            }
        } else {
            None
        };
        out.push((name, expr.trim().to_string()));
    }
    out
}

/// A quoted identifier without its delimiters.
fn unquote(q: &str) -> String {
    let inner = &q[1..q.len() - 1];
    match q.chars().next() {
        Some('"') => inner.replace("\"\"", "\""),
        Some('`') => inner.replace("``", "`"),
        Some('\'') => inner.replace("''", "'"),
        _ => inner.to_string(),
    }
}

/// `name` as a SQLite identifier: double-quoted, inner quotes doubled.
pub fn quote_sqlite_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// The trigger timing and events of a SQLite `CREATE TRIGGER` text.
pub fn sqlite_trigger_parts(sql: &str) -> (Option<String>, Vec<String>) {
    let Ok(toks) = tokens(sql, Driver::Sqlite) else {
        return (None, Vec::new());
    };
    let mut timing = None;
    let mut events = Vec::new();
    for (k, t) in toks.iter().enumerate() {
        if is_word(t, "on") || is_word(t, "begin") {
            break;
        }
        if is_word(t, "before") {
            timing = Some("BEFORE".to_string());
        } else if is_word(t, "after") {
            timing = Some("AFTER".to_string());
        } else if is_word(t, "instead") && toks.get(k + 1).is_some_and(|n| is_word(n, "of")) {
            timing = Some("INSTEAD OF".to_string());
        } else if ["insert", "update", "delete"].iter().any(|e| is_word(t, e)) {
            if let Tok::Word(w) = t {
                events.push(w.to_ascii_uppercase());
            }
        }
    }
    (timing.or(Some("BEFORE".to_string())), events)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(sql: &str, d: Driver) -> usize {
        statement_count(sql, d).unwrap()
    }

    #[test]
    fn counts_statements_outside_quotes_and_comments() {
        for d in [Driver::Postgres, Driver::Mysql, Driver::Sqlite] {
            assert_eq!(count("SELECT 1", d), 1);
            assert_eq!(count("SELECT 1;", d), 1);
            assert_eq!(count("SELECT 1; ; ", d), 1);
            assert_eq!(count("SELECT 1; SELECT 2", d), 2);
            assert_eq!(count("SELECT 'a;b'", d), 1);
            assert_eq!(count("SELECT 'it''s; ok'", d), 1);
            assert_eq!(count("SELECT 1 -- ; DROP TABLE x\n", d), 1);
            assert_eq!(count("SELECT /* ; */ 1", d), 1);
            assert_eq!(count("", d), 0);
            assert_eq!(count(" ; -- only a comment", d), 0);
        }
        assert_eq!(count(r#"SELECT "a;b" FROM t"#, Driver::Postgres), 1);
        assert_eq!(count("SELECT `a;b` FROM t", Driver::Mysql), 1);
        assert_eq!(count("SELECT [a;b] FROM t", Driver::Sqlite), 1);
    }

    #[test]
    fn dialect_escapes() {
        // MySQL: backslash escapes the quote, so the string continues.
        assert_eq!(count(r"SELECT 'a\'; DROP TABLE t; --'", Driver::Mysql), 1);
        // Standard strings: the backslash is literal and the string ends.
        assert_eq!(count(r"SELECT 'a\'; DROP TABLE t", Driver::Sqlite), 2);
        assert_eq!(count(r"SELECT 'a\'; DROP TABLE t", Driver::Postgres), 2);
        // PostgreSQL E'' strings use backslash escapes.
        assert_eq!(count(r"SELECT E'a\'; b'", Driver::Postgres), 1);
        // # is a comment only in MySQL.
        assert_eq!(count("SELECT 1 # ; x\n", Driver::Mysql), 1);
        // PostgreSQL comments nest.
        assert_eq!(count("SELECT /* a /* ; */ ; */ 1", Driver::Postgres), 1);
        // Dollar-quoted bodies.
        let f = "CREATE FUNCTION f() RETURNS int AS $body$ SELECT 1; SELECT 2; $body$ \
                 LANGUAGE sql";
        assert_eq!(count(f, Driver::Postgres), 1);
        assert_eq!(count("SELECT $$a;b$$", Driver::Postgres), 1);
        // $1 is a parameter, not a dollar quote.
        assert_eq!(count("SELECT $1; SELECT $2", Driver::Postgres), 2);
    }

    #[test]
    fn trigger_bodies_are_one_statement() {
        let t = "CREATE TRIGGER trg AFTER INSERT ON a BEGIN \
                 UPDATE b SET n = n + 1; \
                 INSERT INTO c VALUES (CASE WHEN 1 THEN 2 END); END";
        assert_eq!(count(t, Driver::Sqlite), 1);
        assert_eq!(count(&format!("{t}; SELECT 1"), Driver::Sqlite), 2);
        let p = "CREATE PROCEDURE p() BEGIN IF 1 THEN SELECT 1; END IF; \
                 CASE WHEN 1 THEN SELECT 2; END CASE; END";
        assert_eq!(count(p, Driver::Mysql), 1);
        // BEGIN outside a routine is a statement of its own.
        assert_eq!(count("BEGIN; SELECT 1; COMMIT", Driver::Sqlite), 3);
    }

    #[test]
    fn unterminated_text_is_an_error() {
        for (sql, d) in [
            ("SELECT 'x", Driver::Sqlite),
            ("SELECT \"x", Driver::Postgres),
            ("SELECT /* x", Driver::Mysql),
            ("SELECT $$x", Driver::Postgres),
        ] {
            assert!(statement_count(sql, d).is_err(), "{sql}");
        }
        assert!(single_statement("SELECT 'x", Driver::Sqlite, "sql").is_err());
        assert!(
            single_statement("SELECT 1; SELECT 2", Driver::Sqlite, "sql")
                .unwrap_err()
                .contains("2 statements")
        );
        assert!(
            single_statement(";", Driver::Sqlite, "sql")
                .unwrap_err()
                .contains("empty")
        );
    }

    #[test]
    fn sqlite_check_constraints() {
        let sql = "CREATE TABLE t (a INTEGER CHECK (a > 0), b TEXT, \
                   CONSTRAINT b_len CHECK (length(b) < 10), \
                   CONSTRAINT \"q x\" CHECK (a <> 'x(y)'))";
        let checks = sqlite_checks(sql);
        assert_eq!(
            checks,
            vec![
                (None, "a > 0".to_string()),
                (Some("b_len".to_string()), "length(b) < 10".to_string()),
                (Some("q x".to_string()), "a <> 'x(y)'".to_string()),
            ]
        );
    }

    #[test]
    fn sqlite_trigger_timing_and_events() {
        assert_eq!(
            sqlite_trigger_parts("CREATE TRIGGER t AFTER UPDATE OF a ON x BEGIN SELECT 1; END"),
            (Some("AFTER".into()), vec!["UPDATE".to_string()])
        );
        assert_eq!(
            sqlite_trigger_parts("CREATE TRIGGER t INSTEAD OF DELETE ON v BEGIN SELECT 1; END"),
            (Some("INSTEAD OF".into()), vec!["DELETE".to_string()])
        );
        assert_eq!(quote_sqlite_ident("a\"b"), "\"a\"\"b\"");
    }
}
