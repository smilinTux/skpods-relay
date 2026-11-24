//! Chat room Durable Object, one per room id.
//!
//! Thin glue over the pure modules: `frames` (parsing), `limits` (rate
//! limits), `fanout` (who gets what) and `auth` (identity). Sockets use the
//! hibernation API, so every piece of per-socket state lives in the socket
//! attachment and every piece of per-room state lives in SQLite.
//!
//! Logs carry counts and error codes only, never tokens, proofs, URLs or
//! WebIDs.

use futures_util::future::join_all;
use serde::{Deserialize, Serialize};
use worker::{
    console_log, durable_object, Date, DurableObject, Env, Headers, Method, Request,
    RequestInit, Response, Result, State, WebSocket, WebSocketIncomingMessage,
    WebSocketPair,
};

use crate::auth::{self, AuthError};
use crate::fanout::{self, SocketView};
use crate::frames::{check_order, parse, ClientFrame, ErrorCode, Kind, ServerFrame};
use crate::ids::{sha256_hex, valid_room_id};
use crate::limits::{RateLimiter, AUTH_TIMEOUT_MS, JTI_KEEP, MAX_MEMBERS, WINDOW_MS};
use crate::mailbox::{QueuedItem, ENQUEUE_URL};
use crate::profile::FetchDirectory;

/// A verified WebID longer than this is refused, which keeps the socket
/// attachment well inside its 2 KB limit.
const MAX_WEBID_BYTES: usize = 1024;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS members(webid TEXT PRIMARY KEY, last_seen INTEGER);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER);
CREATE TABLE IF NOT EXISTS jti(jti TEXT PRIMARY KEY, exp INTEGER);
CREATE TABLE IF NOT EXISTS auth_hits(at INTEGER);
";

/// Per-socket state, kept in the hibernatable attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Attachment {
    authed: bool,
    opened: i64,
    /// Room id and Host header from the upgrade request: a hibernated
    /// message handler has no request to read them from (ruling R7).
    room: String,
    host: String,
    #[serde(default)]
    webid: Option<String>,
    #[serde(default)]
    rl: Option<RateLimiter>,
}

#[derive(Deserialize)]
struct N {
    n: i64,
}

#[derive(Deserialize)]
struct V {
    v: i64,
}

#[derive(Deserialize)]
struct At {
    at: i64,
}

#[derive(Deserialize)]
struct Member {
    webid: String,
}

fn now_ms() -> i64 {
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
fn fail(ws: &WebSocket, code: ErrorCode) {
    console_log!("room error {}", code.as_str());
    let _ = ws.send_with_str(ServerFrame::Error(code).to_json());
    let _ = ws.close(Some(code.close()), Some(code.as_str()));
}

#[durable_object]
pub struct Room {
    state: State,
    env: Env,
    /// One directory per object, so its profile and JWKS cache is shared by
    /// every auth on this room.
    dir: FetchDirectory,
}

impl Room {
    fn sql(&self) -> worker::SqlStorage {
        self.state.storage().sql()
    }

    fn attachment(ws: &WebSocket) -> Option<Attachment> {
        ws.deserialize_attachment::<Attachment>().ok().flatten()
    }

    /// R9: at most 30 verifications per rolling 60 s per object, persisted
    /// so hibernation does not reset the window.
    fn auth_allowed(&self, now: i64) -> Result<bool> {
        let sql = self.sql();
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
    fn take_jti(&self, jti: &str, exp: i64, now_s: i64) -> Result<bool> {
        let sql = self.sql();
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

    /// Upsert the member unless that would make more than 50. False when full.
    fn admit(&self, webid: &str, now: i64) -> Result<bool> {
        let sql = self.sql();
        let known: N = sql
            .exec(
                "SELECT COUNT(*) AS n FROM members WHERE webid = ?",
                vec![webid.to_string().into()],
            )?
            .one()?;
        if known.n == 0 {
            let total: N = sql.exec("SELECT COUNT(*) AS n FROM members", None)?.one()?;
            if total.n >= MAX_MEMBERS {
                return Ok(false);
            }
        }
        self.touch(webid, now)?;
        Ok(true)
    }

    fn touch(&self, webid: &str, now: i64) -> Result<()> {
        self.sql().exec(
            "INSERT INTO members(webid, last_seen) VALUES (?, ?) \
             ON CONFLICT(webid) DO UPDATE SET last_seen = excluded.last_seen",
            vec![webid.to_string().into(), now.into()],
        )?;
        Ok(())
    }

    fn next_seq(&self) -> Result<i64> {
        let v: V = self
            .sql()
            .exec(
                "INSERT INTO meta(k, v) VALUES ('seq', 1) \
                 ON CONFLICT(k) DO UPDATE SET v = v + 1 RETURNING v",
                None,
            )?
            .one()?;
        Ok(v.v)
    }

    async fn authenticate(
        &self,
        ws: &WebSocket,
        mut att: Attachment,
        token: &str,
        proof: &str,
        now: i64,
    ) -> Result<()> {
        if !self.auth_allowed(now)? {
            fail(ws, ErrorCode::RateLimited);
            return Ok(());
        }
        let htu = format!("https://{}/v1/room/{}", att.host, att.room);
        let now_s = now / 1000;
        let verified = match auth::verify(token, proof, &htu, now_s, &self.dir).await {
            Ok(v) => v,
            Err(e) => {
                console_log!("room auth refused {}", auth_reason(&e));
                fail(ws, ErrorCode::AuthFailed);
                return Ok(());
            }
        };
        if verified.webid.len() > MAX_WEBID_BYTES {
            fail(ws, ErrorCode::AuthFailed);
            return Ok(());
        }
        if !self.take_jti(&verified.jti, verified.exp, now_ms() / 1000)? {
            console_log!("room auth refused replay");
            fail(ws, ErrorCode::AuthFailed);
            return Ok(());
        }
        if !self.admit(&verified.webid, now)? {
            fail(ws, ErrorCode::RoomFull);
            return Ok(());
        }
        let ready = ServerFrame::Ready {
            webid: &verified.webid,
        }
        .to_json();
        att.authed = true;
        att.webid = Some(verified.webid);
        att.rl = Some(RateLimiter::frames());
        ws.serialize_attachment(&att)?;
        ws.send_with_str(ready)?;
        console_log!("room auth ok");
        Ok(())
    }

    /// Open sockets with their verified WebIDs.
    fn sockets(&self) -> (Vec<WebSocket>, Vec<Option<String>>) {
        let sockets = self.state.get_websockets();
        let webids = sockets
            .iter()
            .map(|s| Self::attachment(s).filter(|a| a.authed).and_then(|a| a.webid))
            .collect();
        (sockets, webids)
    }

    /// Relay a typing frame (`ping` is None) or a ping to the other members.
    async fn relay(
        &self,
        ws: &WebSocket,
        from: &str,
        room: &str,
        ping: Option<(Kind, String)>,
    ) -> Result<()> {
        let (sockets, webids) = self.sockets();
        let views: Vec<SocketView> = sockets
            .iter()
            .zip(&webids)
            .map(|(s, w)| SocketView {
                is_sender: s == ws,
                webid: w.as_deref(),
            })
            .collect();

        let Some((kind, url)) = ping else {
            let frame = ServerFrame::Typing { from }.to_json();
            let plan = fanout::plan(&views, &[]);
            for i in &plan.live {
                let _ = sockets[*i].send_with_str(&frame);
            }
            return Ok(());
        };

        let seq = self.next_seq()?;
        let at = now_ms();
        let frame = ServerFrame::Ping {
            from,
            kind,
            url: &url,
            seq,
            at,
        }
        .to_json();
        let members: Vec<String> = self
            .sql()
            .exec("SELECT webid FROM members", None)?
            .to_array::<Member>()?
            .into_iter()
            .map(|m| m.webid)
            .collect();
        let plan = fanout::plan(&views, &members);
        for i in &plan.live {
            let _ = sockets[*i].send_with_str(&frame);
        }

        let item = QueuedItem {
            room: room.to_string(),
            from: from.to_string(),
            kind: kind.as_str().to_string(),
            url,
            seq,
            at,
        };
        let body = serde_json::to_string(&item)?;
        let ns = self.env.durable_object("MAILBOX")?;
        let mut forwards = Vec::with_capacity(plan.offline.len());
        for member in &plan.offline {
            let stub = ns.id_from_name(&sha256_hex(member))?.get_stub()?;
            let headers = Headers::new();
            headers.set("content-type", "application/json")?;
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_headers(headers)
                .with_body(Some(body.clone().into()));
            let req = Request::new_with_init(ENQUEUE_URL, &init)?;
            forwards.push(async move { stub.fetch_with_request(req).await });
        }
        let results = join_all(forwards).await;
        let failed = results
            .iter()
            .filter(|r| !matches!(r, Ok(resp) if resp.status_code() == 202))
            .count();
        console_log!(
            "room ping live={} queued={} failed={}",
            plan.live.len(),
            results.len() - failed,
            failed
        );
        Ok(())
    }
}

impl DurableObject for Room {
    fn new(state: State, env: Env) -> Self {
        let _ = state.storage().sql().exec(SCHEMA, None);
        Self {
            state,
            env,
            dir: FetchDirectory::new(),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let room = match url.path().strip_prefix("/v1/room/") {
            Some(id) if valid_room_id(id) => id.to_string(),
            _ => return Response::error("Bad Request", 400),
        };
        let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
        if !upgrade.eq_ignore_ascii_case("websocket") {
            return Response::error("Upgrade Required", 426);
        }
        let host = match req.headers().get("Host")? {
            Some(h) if !h.is_empty() => h,
            _ => match (url.host_str(), url.port()) {
                (Some(h), Some(p)) => format!("{h}:{p}"),
                (Some(h), None) => h.to_string(),
                _ => return Response::error("Bad Request", 400),
            },
        };

        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        let now = now_ms();
        pair.server.serialize_attachment(&Attachment {
            authed: false,
            opened: now,
            room,
            host,
            webid: None,
            rl: None,
        })?;
        if self.state.storage().get_alarm().await?.is_none() {
            self.state.storage().set_alarm(AUTH_TIMEOUT_MS).await?;
        }
        Response::from_websocket(pair.client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let Some(mut att) = Self::attachment(&ws) else {
            fail(&ws, ErrorCode::BadFrame);
            return Ok(());
        };
        let now = now_ms();
        if !att.authed && now - att.opened > AUTH_TIMEOUT_MS {
            fail(&ws, ErrorCode::AuthFailed);
            return Ok(());
        }
        let text = match message {
            WebSocketIncomingMessage::String(s) => s,
            WebSocketIncomingMessage::Binary(_) => {
                fail(&ws, ErrorCode::BadFrame);
                return Ok(());
            }
        };
        let frame = match parse(&text).and_then(|f| check_order(att.authed, &f).map(|_| f)) {
            Ok(f) => f,
            Err(e) => {
                fail(&ws, e.code());
                return Ok(());
            }
        };

        match frame {
            ClientFrame::Auth { token, proof, .. } => {
                self.authenticate(&ws, att, &token, &proof, now).await
            }
            ClientFrame::Ping { .. } | ClientFrame::Typing => {
                let rl = att.rl.get_or_insert_with(RateLimiter::frames);
                if !rl.allow(now) {
                    fail(&ws, ErrorCode::RateLimited);
                    return Ok(());
                }
                ws.serialize_attachment(&att)?;
                let from = att.webid.clone().unwrap_or_default();
                let ping = match frame {
                    ClientFrame::Ping { kind, url } => Some((kind, url)),
                    _ => None,
                };
                self.relay(&ws, &from, &att.room, ping).await
            }
        }
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        if let Some(webid) = Self::attachment(&ws).and_then(|a| a.webid) {
            self.touch(&webid, now_ms())?;
        }
        let _ = ws.close(Some(1000), Some("bye"));
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: worker::Error) -> Result<()> {
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        let now = now_ms();
        let mut closed = 0;
        let mut next: Option<i64> = None;
        for ws in self.state.get_websockets() {
            let Some(a) = Self::attachment(&ws) else {
                continue;
            };
            if a.authed {
                continue;
            }
            let deadline = a.opened + AUTH_TIMEOUT_MS;
            if deadline <= now {
                fail(&ws, ErrorCode::AuthFailed);
                closed += 1;
            } else {
                next = Some(next.map_or(deadline, |n| n.min(deadline)));
            }
        }
        if closed > 0 {
            console_log!("room alarm closed={}", closed);
        }
        // Re-arm only while unauthenticated sockets remain.
        if let Some(d) = next {
            self.state.storage().set_alarm(d - now).await?;
        }
        Response::ok("")
    }
}
