//! Socket auth shared by the Room and Mailbox objects.
//!
//! Both run the same sequence on the first frame: the per-object R9 limiter,
//! `auth::verify`, a WebID length cap and the per-object jti replay table
//! (ruling R2). Both also close sockets that send no auth within 5 s, through
//! the object alarm. Each object keeps its own tables (`SCHEMA`) in its own
//! SQLite storage.
//!
//! Logs carry a tag, counts and error codes only, never tokens, proofs, URLs
//! or WebIDs.

use serde::Deserialize;
use worker::{console_log, Date, Response, Result, SqlStorage, State, WebSocket};

use crate::auth::{self, AuthError, Verified};
use crate::frames::{ErrorCode, ServerFrame};
use crate::limits::{RateLimiter, AUTH_TIMEOUT_MS, JTI_KEEP, WINDOW_MS};
use crate::profile::FetchDirectory;

/// Tables every object that authenticates sockets needs.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS jti(jti TEXT PRIMARY KEY, exp INTEGER);
CREATE TABLE IF NOT EXISTS auth_hits(at INTEGER);
";

/// A verified WebID longer than this is refused, which keeps socket
/// attachments well inside their 2 KB limit.
pub const MAX_WEBID_BYTES: usize = 1024;

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
    if verified.webid.len() > MAX_WEBID_BYTES {
        return Ok(Err(ErrorCode::AuthFailed));
    }
    if !take_jti(sql, &verified.jti, verified.exp, now_ms() / 1000)? {
        console_log!("{} auth refused replay", tag);
        return Ok(Err(ErrorCode::AuthFailed));
    }
    Ok(Ok(verified))
}

/// Arm the 5 s auth timeout alarm for a fresh socket unless one is set.
pub async fn arm_auth_timeout(state: &State) -> Result<()> {
    if state.storage().get_alarm().await?.is_none() {
        state.storage().set_alarm(AUTH_TIMEOUT_MS).await?;
    }
    Ok(())
}

/// Alarm body: close sockets still unauthenticated 5 s after opening, and
/// re-arm only while unauthenticated sockets remain. `opened_unauthed`
/// returns a socket's open time when it is not authenticated, None otherwise.
pub async fn auth_alarm(
    state: &State,
    opened_unauthed: impl Fn(&WebSocket) -> Option<i64>,
    tag: &str,
) -> Result<Response> {
    let now = now_ms();
    let mut closed = 0;
    let mut next: Option<i64> = None;
    for ws in state.get_websockets() {
        let Some(opened) = opened_unauthed(&ws) else {
            continue;
        };
        let deadline = opened + AUTH_TIMEOUT_MS;
        if deadline <= now {
            fail(&ws, ErrorCode::AuthFailed, tag);
            closed += 1;
        } else {
            next = Some(next.map_or(deadline, |n| n.min(deadline)));
        }
    }
    if closed > 0 {
        console_log!("{} alarm closed={}", tag, closed);
    }
    if let Some(d) = next {
        state.storage().set_alarm(d - now).await?;
    }
    Response::ok("")
}
