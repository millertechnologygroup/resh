//! Connecting: the DSN, TLS settings, one connection per run, the deadline
//! that covers connecting and the work, and cancelling a statement on the
//! server when that deadline passes.

use super::{DbError, Driver};
use sqlx::Connection;
use std::time::{Duration, Instant};

/// `tls_mode=` values. Only `verify_ca` and `verify_full` check the
/// server's certificate; the others encrypt (if at all) without
/// authenticating the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Disable,
    Allow,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl TlsMode {
    pub const NAMES: &'static str = "disable, allow, prefer, require, verify_ca or verify_full";

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "disable" => TlsMode::Disable,
            "allow" => TlsMode::Allow,
            "prefer" => TlsMode::Prefer,
            "require" => TlsMode::Require,
            "verify_ca" => TlsMode::VerifyCa,
            "verify_full" => TlsMode::VerifyFull,
            _ => return None,
        })
    }

    pub fn verifies(self) -> bool {
        matches!(self, TlsMode::VerifyCa | TlsMode::VerifyFull)
    }

    fn postgres(self) -> sqlx::postgres::PgSslMode {
        use sqlx::postgres::PgSslMode as M;
        match self {
            TlsMode::Disable => M::Disable,
            TlsMode::Allow => M::Allow,
            TlsMode::Prefer => M::Prefer,
            TlsMode::Require => M::Require,
            TlsMode::VerifyCa => M::VerifyCa,
            TlsMode::VerifyFull => M::VerifyFull,
        }
    }

    /// MySQL has no `allow`; the argument check refuses it first.
    fn mysql(self) -> sqlx::mysql::MySqlSslMode {
        use sqlx::mysql::MySqlSslMode as M;
        match self {
            TlsMode::Disable => M::Disabled,
            TlsMode::Allow | TlsMode::Prefer => M::Preferred,
            TlsMode::Require => M::Required,
            TlsMode::VerifyCa => M::VerifyCa,
            TlsMode::VerifyFull => M::VerifyIdentity,
        }
    }
}

/// The environment variable read when `dsn=` is not given.
pub fn env_var(alias: &str) -> String {
    format!("DB_{}_DSN", alias.to_ascii_uppercase().replace('-', "_"))
}

/// Removes the secrets of a DSN (its password, wherever it appears, and the
/// DSN itself) from text before it is printed.
#[derive(Debug, Default, Clone)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    pub fn for_dsn(dsn: &str) -> Self {
        let mut secrets = vec![dsn.to_string()];
        if let Ok(url) = url::Url::parse(dsn) {
            if let Some(p) = url.password() {
                secrets.push(p.to_string());
                if let Ok(d) = percent_encoding::percent_decode_str(p).decode_utf8() {
                    secrets.push(d.into_owned());
                }
            }
            for (k, v) in url.query_pairs() {
                if matches!(k.as_ref(), "password" | "sslpassword") {
                    secrets.push(v.into_owned());
                }
            }
        }
        secrets.retain(|s| !s.is_empty());
        // Longest first, so a password inside the DSN does not break the
        // DSN's own replacement.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        Self { secrets }
    }

    pub fn scrub(&self, text: &str) -> String {
        let mut out = text.to_string();
        for s in &self.secrets {
            out = out.replace(s.as_str(), "***");
        }
        out
    }
}

/// Checks the DSN's form for `driver` without echoing it.
pub fn check_dsn(driver: Driver, dsn: &str) -> Result<(), DbError> {
    let invalid = |m: String| DbError::usage_code("invalid_dsn", m);
    if driver == Driver::Sqlite {
        if !dsn.starts_with("sqlite:") {
            return Err(invalid(
                "a sqlite DSN starts with sqlite: (for example sqlite:app.db or \
                 sqlite::memory:)"
                    .into(),
            ));
        }
        return Ok(());
    }
    let url = url::Url::parse(dsn).map_err(|e| {
        invalid(format!(
            "the DSN is not a valid URL ({e}); percent-encode special characters in the \
             user name and password ($ as %24, @ as %40, # as %23, % as %25) and quote the \
             DSN in single quotes"
        ))
    })?;
    let ok = match driver {
        Driver::Postgres => matches!(url.scheme(), "postgres" | "postgresql"),
        Driver::Mysql => matches!(url.scheme(), "mysql" | "mariadb"),
        Driver::Sqlite => true,
    };
    if !ok {
        let expected = match driver {
            Driver::Postgres => "postgresql:// or postgres://",
            _ => "mysql:// or mariadb://",
        };
        return Err(invalid(format!(
            "the DSN scheme {:?} does not match driver {}; expected {expected}",
            url.scheme(),
            driver.name()
        )));
    }
    Ok(())
}

/// The certificates of a `ca_file=` PEM file, checked to hold at least one
/// valid certificate. Returns the file's bytes.
pub fn load_ca_file(path: &str) -> Result<Vec<u8>, String> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("bad certificate in {path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no PEM certificate in {path}"));
    }
    for c in &certs {
        webpki_check(c).map_err(|e| format!("bad certificate in {path}: {e}"))?;
    }
    Ok(bytes)
}

fn webpki_check(c: &rustls::pki_types::CertificateDer<'_>) -> Result<(), String> {
    let mut store = rustls::RootCertStore::empty();
    store.add(c.clone()).map_err(|e| e.to_string())
}

/// What to connect to and how.
#[derive(Debug, Clone)]
pub enum Spec {
    Pg(sqlx::postgres::PgConnectOptions),
    My(sqlx::mysql::MySqlConnectOptions),
    Lite(sqlx::sqlite::SqliteConnectOptions),
}

impl Spec {
    /// Builds the connect options. `tls_mode` overrides the DSN's SSL
    /// mode; `ca_pem` adds trusted CA certificates (verification stays on).
    pub fn new(
        driver: Driver,
        dsn: &str,
        tls_mode: Option<TlsMode>,
        ca_pem: Option<Vec<u8>>,
        timeout: Duration,
    ) -> Result<Self, DbError> {
        use std::str::FromStr;
        let bad = |e: sqlx::Error| {
            DbError::usage_code("invalid_dsn", format!("the DSN cannot be used: {e}"))
        };
        Ok(match driver {
            Driver::Postgres => {
                let mut o = sqlx::postgres::PgConnectOptions::from_str(dsn).map_err(bad)?;
                if let Some(m) = tls_mode {
                    o = o.ssl_mode(m.postgres());
                }
                if let Some(pem) = ca_pem {
                    o = o.ssl_root_cert_from_pem(pem);
                }
                Spec::Pg(o.application_name("resh"))
            }
            Driver::Mysql => {
                let mut o = sqlx::mysql::MySqlConnectOptions::from_str(dsn).map_err(bad)?;
                if let Some(m) = tls_mode {
                    o = o.ssl_mode(m.mysql());
                }
                if let Some(pem) = ca_pem {
                    o = o.ssl_ca_from_pem(pem);
                }
                Spec::My(o)
            }
            Driver::Sqlite => {
                let o = sqlx::sqlite::SqliteConnectOptions::from_str(dsn).map_err(bad)?;
                // Waiting for a lock counts against the same deadline.
                Spec::Lite(o.busy_timeout(timeout))
            }
        })
    }
}

/// One open connection.
pub enum Conn {
    Pg(sqlx::postgres::PgConnection),
    My(sqlx::mysql::MySqlConnection),
    Lite(sqlx::sqlite::SqliteConnection),
}

/// A connection and what is needed to stop its work at the deadline.
pub struct Session {
    pub conn: Conn,
    pub ctl: Control,
}

/// The deadline of a session, and its server-side id and connect options
/// for cancelling a statement from a second connection.
pub struct Control {
    server_id: Option<u64>,
    spec: Spec,
    pub deadline: Instant,
    timeout: Duration,
}

/// Classifies a connect failure.
pub fn connect_error(e: sqlx::Error) -> DbError {
    match &e {
        sqlx::Error::Tls(_) => {
            DbError::new("tls_failed", format!("TLS with the server failed: {e}"))
        }
        sqlx::Error::Database(d) if d.code().is_some_and(|c| c.starts_with("28")) => {
            DbError::new("auth_failed", format!("the server refused the login: {e}"))
        }
        sqlx::Error::Configuration(_) => {
            DbError::usage_code("invalid_dsn", format!("the DSN cannot be used: {e}"))
        }
        _ => DbError::new("connect_failed", format!("cannot connect: {e}")),
    }
}

/// True if `e` is a TLS failure (some arrive wrapped as I/O errors).
fn is_tls(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Tls(_) => true,
        sqlx::Error::Io(io) => {
            let s = io.to_string().to_ascii_lowercase();
            s.contains("certificate") || s.contains("tls") || s.contains("handshake")
        }
        _ => false,
    }
}

impl Session {
    /// Connects within `timeout`, which also bounds the work done on the
    /// session afterwards (`deadline`).
    pub async fn open(spec: Spec, timeout: Duration) -> Result<Self, DbError> {
        let deadline = Instant::now() + timeout;
        let connect = async {
            let res: Result<(Conn, Option<u64>), sqlx::Error> = match &spec {
                Spec::Pg(o) => {
                    let mut c = sqlx::postgres::PgConnection::connect_with(o).await?;
                    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                        .fetch_one(&mut c)
                        .await?;
                    Ok((Conn::Pg(c), Some(pid as u64)))
                }
                Spec::My(o) => {
                    let mut c = sqlx::mysql::MySqlConnection::connect_with(o).await?;
                    let id: u64 = sqlx::query_scalar("SELECT CONNECTION_ID()")
                        .fetch_one(&mut c)
                        .await?;
                    Ok((Conn::My(c), Some(id)))
                }
                Spec::Lite(o) => {
                    let mut c = sqlx::sqlite::SqliteConnection::connect_with(o).await?;
                    // Interrupts a running statement once the deadline passes.
                    c.lock_handle()
                        .await?
                        .set_progress_handler(1000, move || Instant::now() < deadline);
                    Ok((Conn::Lite(c), None))
                }
            };
            res
        };
        match tokio::time::timeout_at(deadline.into(), connect).await {
            Err(_) => Err(DbError::timeout(format!(
                "connecting did not finish within timeout_ms={}",
                timeout.as_millis()
            ))),
            Ok(Err(e)) if is_tls(&e) => Err(DbError::new(
                "tls_failed",
                format!("TLS with the server failed: {e}"),
            )),
            Ok(Err(e)) => Err(connect_error(e)),
            Ok(Ok((conn, server_id))) => Ok(Self {
                conn,
                ctl: Control {
                    server_id,
                    spec,
                    deadline,
                    timeout,
                },
            }),
        }
    }
}

impl Control {
    pub fn timeout_ms(&self) -> u128 {
        self.timeout.as_millis()
    }

    /// Runs `work` until the deadline. When the deadline passes first, the
    /// work is dropped and its statement stopped on the server; `what`
    /// names the work in the timeout message (exit 124).
    pub async fn within<T>(
        &self,
        what: &str,
        work: impl std::future::Future<Output = Result<T, DbError>>,
    ) -> Result<T, DbError> {
        match tokio::time::timeout_at(self.deadline.into(), work).await {
            Ok(Err(e)) if e.code == "interrupted" => Err(DbError::timeout(format!(
                "{what} did not finish within timeout_ms={}; the statement was interrupted",
                self.timeout_ms()
            ))),
            Ok(r) => r,
            Err(_) => {
                let how = self.cancel().await;
                Err(DbError::timeout(format!(
                    "{what} did not finish within timeout_ms={}; {how}",
                    self.timeout_ms()
                )))
            }
        }
    }

    /// Stops the statement that was running when the deadline passed: a
    /// cancel on PostgreSQL (`pg_cancel_backend`) or `KILL QUERY` on MySQL,
    /// sent on a second connection. SQLite's progress handler has already
    /// interrupted it. Returns a sentence for the error message.
    pub async fn cancel(&self) -> String {
        let Some(id) = self.server_id else {
            return "the statement was interrupted".into();
        };
        let grace = Instant::now() + Duration::from_secs(5);
        let attempt = async {
            match &self.spec {
                Spec::Pg(o) => {
                    let mut c = sqlx::postgres::PgConnection::connect_with(o).await?;
                    let ok: bool = sqlx::query_scalar("SELECT pg_cancel_backend($1)")
                        .bind(id as i32)
                        .fetch_one(&mut c)
                        .await?;
                    let _ = c.close().await;
                    Ok::<bool, sqlx::Error>(ok)
                }
                Spec::My(o) => {
                    let mut c = sqlx::mysql::MySqlConnection::connect_with(o).await?;
                    // The id is the server's integer connection id.
                    sqlx::raw_sql(&format!("KILL QUERY {id}"))
                        .execute(&mut c)
                        .await?;
                    let _ = c.close().await;
                    Ok(true)
                }
                Spec::Lite(_) => Ok(true),
            }
        };
        match tokio::time::timeout_at(grace.into(), attempt).await {
            Ok(Ok(true)) => "the statement was cancelled on the server".into(),
            Ok(Ok(false)) => "the server found no statement to cancel".into(),
            Ok(Err(e)) => format!("cancelling it on the server failed: {e}"),
            Err(_) => "cancelling it on the server did not finish within 5 s".into(),
        }
    }
}
