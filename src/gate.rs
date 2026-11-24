//! Socket auth shared by the Room and Mailbox objects.
//!
//! Both run the same sequence on the first frame: the per-object R9 limiter,
//! `auth::verify`, a WebID length cap and the per-object jti replay table
//! (ruling R2). Both also close sockets that send no auth within 5 s (or
//! whose verification is still running 20 s after open), through the object
//! alarm. Each object keeps its own tables (`SCHEMA`) in its own SQLite
//! storage, created lazily (`Schema`) so an object can drop all of its
//! storage once it holds nothing worth keeping.
//!
//! Logs carry a tag, counts and error codes only, never tokens, proofs, URLs
//! or WebIDs.

use std::cell::Cell;

use serde::Deserialize;
use worker::{console_log, Date, Result, SqlStorage, State, WebSocket};

use crate::auth::{self, AuthError, Verified};
use crate::frames::{ErrorCode, ServerFrame};
use crate::limits::{
    RateLimiter, AUTH_TIMEOUT_MS, CLEANUP_DELAY_MS, JTI_KEEP, VERIFY_TIMEOUT_MS, WINDOW_MS,
};
use crate::profile::FetchDirectory;

/// Tables every object that authenticates sockets needs.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS jti(jti TEXT PRIMARY KEY, exp INTEGER);
CREATE TABLE IF NOT EXISTS auth_hits(at INTEGER);
";

/// A verified WebID longer than this (UTF-8 bytes) is refused with
/// `auth_failed`, which keeps socket attachments inside their 2 KB limit.
pub const MAX_WEBID_BYTES: usize = 512;
/// An upgrade whose Host is longer than this gets HTTP 400, for the same
/// reason (the host is kept in the attachment to rebuild `htu`).
pub const MAX_HOST_BYTES: usize = 255;

pub fn webid_ok(webid: &str) -> bool {
    webid.len() <= MAX_WEBID_BYTES
}

pub fn host_ok(host: &str) -> bool {
    !host.is_empty() && host.len() <= MAX_HOST_BYTES
}

/// The host to rebuild `htu` from: the Host header, else the request URL's
/// host and port. None (HTTP 400) when missing or longer than
/// `MAX_HOST_BYTES`.
pub fn upgrade_host(header: Option<String>, url: &worker::Url) -> Option<String> {
    let host = match header {
        Some(h) if !h.is_empty() => h,
        _ => match (url.host_str(), url.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_string(),
            _ => return None,
        },
    };
    host_ok(&host).then_some(host)
}

/// Lazily created tables. `delete_all` drops the whole database, so the
/// tables are created on first use rather than once in `new`, and created
/// again after a wipe.
pub struct Schema {
    ddl: &'static [&'static str],
    ready: Cell<bool>,
}

impl Schema {
    pub fn new(ddl: &'static [&'static str]) -> Self {
        Self {
            ddl,
            ready: Cell::new(false),
        }
    }

    /// The object's SQL storage, with the tables created if needed.
    pub fn sql(&self, state: &State) -> SqlStorage {
        let sql = state.storage().sql();
        if !self.ready.get() {
            let ok = self.ddl.iter().all(|d| sql.exec(d, None).is_ok());
            self.ready.set(ok);
        }
        sql
    }

    /// Drop every table and row this object holds (and its alarm). The
    /// tables come back on the next `sql`.
    pub async fn wipe(&self, state: &State, tag: &str) -> Result<()> {
        self.ready.set(false);
        state.storage().delete_all().await?;
        state.storage().delete_alarm().await?;
        // A request served during those awaits may have made the tables again.
        self.ready.set(false);
        console_log!("{} storage wiped", tag);
        Ok(())
    }
}

/// True while `ws` is still one of the object's open sockets. A socket the
/// alarm or the client closed during an await is not.
pub fn is_open(state: &State, ws: &WebSocket) -> bool {
    let raw: &worker::web_sys::WebSocket = ws.as_ref();
    raw.ready_state() == worker::web_sys::WebSocket::OPEN
        && state.get_websockets().iter().any(|s| s == ws)
}

/// Close `ws` with 1011 after an internal error (storage, serialization,
/// stub). Only the tag is logged, never the error text. Clients treat any
/// close as "fall back to polling".
pub fn internal_error(ws: &WebSocket, tag: &str) {
    console_log!("{} internal_error", tag);
    let _ = ws.close(Some(1011), Some("internal_error"));
}

#[derive(Deserialize)]
struct N {
    n: i64,
}

#[derive(Deserialize)]
struct At {
    at: i64,
}

pub fn now_ms() -> i64 {
    Date::now().as_millis() as i64
}

fn auth_reason(e: &AuthError) -> &'static str {
    match e {
        AuthError::Malformed => "malformed",
        AuthError::BadSignature => "bad_signature",
        AuthError::Expired => "expired",
        AuthError::ProofMismatch => "proof_mismatch",
        AuthError::ProofStale => "proof_stale",
        AuthError::IssuerNotTrusted => "issuer_not_trusted",
        AuthError::Fetch(_) => "fetch",
    }
}

/// Send `error` with `code`, then close with the matching close code.
pub fn fail(ws: &WebSocket, code: ErrorCode, tag: &str) {
    console_log!("{} error {}", tag, code.as_str());
    let _ = ws.send_with_str(ServerFrame::Error(code).to_json());
    let _ = ws.close(Some(code.close()), Some(code.as_str()));
}

/// R9: at most 30 verifications per rolling 60 s per object, persisted so
/// hibernation does not reset the window.
pub fn auth_allowed(sql: &SqlStorage, now: i64) -> Result<bool> {
    let cutoff = now - WINDOW_MS;
    sql.exec("DELETE FROM auth_hits WHERE at <= ?", vec![cutoff.into()])?;
    let hits: Vec<At> = sql.exec("SELECT at FROM auth_hits", None)?.to_array()?;
    let mut rl = RateLimiter::auths(hits.into_iter().map(|h| h.at).collect());
    if !rl.allow(now) {
        return Ok(false);
    }
    sql.exec("INSERT INTO auth_hits(at) VALUES (?)", vec![now.into()])?;
    Ok(true)
}

/// Record a proof jti. False when it was seen before (replay).
pub fn take_jti(sql: &SqlStorage, jti: &str, exp: i64, now_s: i64) -> Result<bool> {
    sql.exec("DELETE FROM jti WHERE exp < ?", vec![now_s.into()])?;
    let seen: N = sql
        .exec(
            "SELECT COUNT(*) AS n FROM jti WHERE jti = ?",
            vec![jti.to_string().into()],
        )?
        .one()?;
    if seen.n > 0 {
        return Ok(false);
    }
    sql.exec(
        "INSERT INTO jti(jti, exp) VALUES (?, ?)",
        vec![jti.to_string().into(), exp.into()],
    )?;
    sql.exec(
        "DELETE FROM jti WHERE rowid NOT IN (SELECT rowid FROM jti ORDER BY rowid DESC LIMIT ?)",
        vec![JTI_KEEP.into()],
    )?;
    Ok(true)
}

/// The shared auth sequence: R9 limiter (before any directory fetch),
/// `verify`, WebID length cap, jti replay check. `Ok(Err(code))` means the
/// caller sends `code` and closes; `Ok(Ok(v))` is a fresh verified identity.
pub async fn verify_socket(
    sql: &SqlStorage,
    dir: &FetchDirectory,
    token: &str,
    proof: &str,
    htu: &str,
    now: i64,
    tag: &str,
) -> Result<std::result::Result<Verified, ErrorCode>> {
    if !auth_allowed(sql, now)? {
        return Ok(Err(ErrorCode::RateLimited));
    }
    let verified = match auth::verify(token, proof, htu, now / 1000, dir).await {
        Ok(v) => v,
        Err(e) => {
            console_log!("{} auth refused {}", tag, auth_reason(&e));
            return Ok(Err(ErrorCode::AuthFailed));
        }
    };
    if !webid_ok(&verified.webid) {
        return Ok(Err(ErrorCode::AuthFailed));
    }
    if !take_jti(sql, &verified.jti, verified.exp, now_ms() / 1000)? {
        console_log!("{} auth refused replay", tag);
        return Ok(Err(ErrorCode::AuthFailed));
    }
    Ok(Ok(verified))
}

/// Arm the 5 s auth timeout alarm for a fresh socket, unless one is already
/// due sooner (a later cleanup or expiry alarm is pulled in; the alarm body
/// re-arms it).
pub async fn arm_auth_timeout(state: &State) -> Result<()> {
    let due = now_ms() + AUTH_TIMEOUT_MS;
    match state.storage().get_alarm().await? {
        Some(t) if t <= due => {}
        _ => state.storage().set_alarm(AUTH_TIMEOUT_MS).await?,
    }
    Ok(())
}

/// Arm a cleanup alarm `CLEANUP_DELAY_MS` out unless one is already set.
pub async fn arm_cleanup(state: &State) -> Result<()> {
    if state.storage().get_alarm().await?.is_none() {
        state.storage().set_alarm(CLEANUP_DELAY_MS).await?;
    }
    Ok(())
}

/// When an unauthenticated socket opened at `opened` is closed: 5 s after
/// open, or 20 s while its verification is in flight (`pending`).
pub fn auth_deadline(opened: i64, pending: bool) -> i64 {
    opened
        + if pending {
            VERIFY_TIMEOUT_MS
        } else {
            AUTH_TIMEOUT_MS
        }
}

/// Alarm body: close unauthenticated sockets past their `auth_deadline`, and
/// re-arm while unauthenticated sockets remain. `unauthed` returns a
/// socket's `(opened, pending)` when it is not authenticated, None otherwise.
/// Returns true when no open socket is left, so the caller may drop storage
/// that holds nothing worth keeping.
pub async fn auth_alarm(
    state: &State,
    unauthed: impl Fn(&WebSocket) -> Option<(i64, bool)>,
    tag: &str,
) -> Result<bool> {
    let now = now_ms();
    let mut closed = 0;
    let mut live = 0;
    let mut next: Option<i64> = None;
    for ws in state.get_websockets() {
        if !is_open(state, &ws) {
            continue;
        }
        let Some((opened, pending)) = unauthed(&ws) else {
            live += 1;
            continue;
        };
        let deadline = auth_deadline(opened, pending);
        if deadline <= now {
            fail(&ws, ErrorCode::AuthFailed, tag);
            closed += 1;
        } else {
            live += 1;
            next = Some(next.map_or(deadline, |n| n.min(deadline)));
        }
    }
    if closed > 0 {
        console_log!("{} alarm closed={}", tag, closed);
    }
    if let Some(d) = next {
        state.storage().set_alarm(d - now).await?;
    }
    Ok(live == 0)
}

/// How long after the last auth attempt the `jti` and `auth_hits` rows still
/// protect something: a proof may carry an `iat` up to 60 s ahead and is
/// accepted until 60 s after that, so its jti matters for 120 s; the R9
/// window is 60 s. One second of margin.
pub const AUTH_ROWS_KEEP_MS: i64 = 2 * auth::PROOF_WINDOW_S * 1000 + 1000;

#[derive(Deserialize)]
struct MaxAt {
    at: Option<i64>,
}

/// For an idle object that holds nothing worth keeping (no members, no
/// items): drop all of its storage, unless an auth attempt was recent enough
/// that its replay and rate limit rows still matter, in which case come back
/// when they stop mattering.
pub async fn sweep_junk(state: &State, schema: &Schema, tag: &str) -> Result<()> {
    let sql = schema.sql(state);
    let last: MaxAt = sql
        .exec("SELECT MAX(at) AS at FROM auth_hits", None)?
        .one()?;
    let now = now_ms();
    match last.at.map(|t| t + AUTH_ROWS_KEEP_MS) {
        Some(until) if until > now => state.storage().set_alarm(until - now).await,
        _ => schema.wipe(state, tag).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webid_cap_is_512_utf8_bytes() {
        let base = "https://a.example/";
        let fit = format!("{base}{}", "x".repeat(MAX_WEBID_BYTES - base.len()));
        assert_eq!(fit.len(), 512);
        assert!(webid_ok(&fit));
        assert!(!webid_ok(&format!("{fit}x")));
        // Bytes, not chars: 255 two byte chars plus the base is over 512.
        let wide = format!("{base}{}", "é".repeat(250));
        assert!(wide.chars().count() < 512 && wide.len() > 512);
        assert!(!webid_ok(&wide));
    }

    #[test]
    fn host_cap_is_255_bytes() {
        assert!(host_ok("relay.example"));
        assert!(host_ok(&"h".repeat(255)));
        assert!(!host_ok(&"h".repeat(256)));
        assert!(!host_ok(""));
    }

    #[test]
    fn upgrade_host_from_header_or_url() {
        let url = worker::Url::parse("https://relay.example:8787/v1/me").unwrap();
        assert_eq!(
            upgrade_host(Some("h.example".into()), &url).as_deref(),
            Some("h.example")
        );
        assert_eq!(
            upgrade_host(None, &url).as_deref(),
            Some("relay.example:8787")
        );
        assert_eq!(
            upgrade_host(Some(String::new()), &url).as_deref(),
            Some("relay.example:8787")
        );
        assert_eq!(upgrade_host(Some("h".repeat(256)), &url), None);
    }

    #[test]
    fn auth_rows_outlive_replay_window() {
        // A proof stamped 60 s ahead is accepted for 120 s from its first use.
        const _: () = assert!(AUTH_ROWS_KEEP_MS > 2 * auth::PROOF_WINDOW_S * 1000);
        const _: () = assert!(AUTH_ROWS_KEEP_MS > WINDOW_MS);
    }

    #[test]
    fn pending_sockets_get_20s() {
        assert_eq!(auth_deadline(1_000, false), 6_000);
        assert_eq!(auth_deadline(1_000, true), 21_000);
        // Longer than the worst case verify: three 5 s fetches.
        assert!(VERIFY_TIMEOUT_MS > 3 * crate::profile::FETCH_TIMEOUT_MS as i64);
    }
}
