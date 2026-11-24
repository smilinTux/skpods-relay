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
    console_log, durable_object, DurableObject, Env, Headers, Method, Request, RequestInit,
    Response, Result, State, WebSocket, WebSocketIncomingMessage, WebSocketPair,
};

use crate::fanout::{self, forward_due, SocketView};
use crate::frames::{check_order, parse, ClientFrame, ErrorCode, Kind, ServerFrame};
use crate::gate::Schema;
use crate::gate::{self, now_ms};
use crate::ids::{sha256_hex, valid_room_id};
use crate::limits::{RateLimiter, AUTH_TIMEOUT_MS, MAX_MEMBERS};
use crate::mailbox::{QueuedItem, ENQUEUE_URL};
use crate::profile::FetchDirectory;

const TAG: &str = "room";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS members(webid TEXT PRIMARY KEY, last_seen INTEGER, last_forward INTEGER);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER);
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
    /// Set while an auth frame is being verified; a second auth arriving
    /// meanwhile is `bad_frame`, so one socket cannot end up with two
    /// identities.
    #[serde(default)]
    pending: bool,
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
struct Member {
    webid: String,
    last_forward: Option<i64>,
}

fn fail(ws: &WebSocket, code: ErrorCode) {
    gate::fail(ws, code, TAG);
}

#[durable_object]
pub struct Room {
    state: State,
    env: Env,
    /// One directory per object, so its profile and JWKS cache is shared by
    /// every auth on this room.
    dir: FetchDirectory,
    schema: Schema,
}

impl Room {
    fn sql(&self) -> worker::SqlStorage {
        self.schema.sql(&self.state)
    }

    fn member_count(&self) -> Result<i64> {
        let total: N = self
            .sql()
            .exec("SELECT COUNT(*) AS n FROM members", None)?
            .one()?;
        Ok(total.n)
    }

    fn attachment(ws: &WebSocket) -> Option<Attachment> {
        ws.deserialize_attachment::<Attachment>().ok().flatten()
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
        if known.n == 0 && self.member_count()? >= MAX_MEMBERS {
            return Ok(false);
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
        att.pending = true;
        ws.serialize_attachment(&att)?;
        let htu = format!("https://{}/v1/room/{}", att.host, att.room);
        let sql = self.sql();
        let verified =
            match gate::verify_socket(&sql, &self.dir, token, proof, &htu, now, TAG).await? {
                Ok(v) => v,
                Err(code) => {
                    fail(ws, code);
                    return Ok(());
                }
            };
        // The alarm or the client may have closed the socket while the
        // verify was in flight: then there is no one to admit.
        if !gate::is_open(&self.state, ws) {
            console_log!("room auth dropped closed");
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
        att.pending = false;
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
            .map(|s| {
                Self::attachment(s)
                    .filter(|a| a.authed)
                    .and_then(|a| a.webid)
            })
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
        let rows: Vec<Member> = self
            .sql()
            .exec("SELECT webid, last_forward FROM members", None)?
            .to_array()?;
        let members: Vec<String> = rows.iter().map(|m| m.webid.clone()).collect();
        let plan = fanout::plan(&views, &members);
        for i in &plan.live {
            let _ = sockets[*i].send_with_str(&frame);
        }

        let item = QueuedItem {
            room: room.to_string(),
            from: from.to_string(),
            kind,
            url,
            seq: seq as u64,
            at,
        };
        let body = serde_json::to_string(&item)?;
        let ns = self.env.durable_object("MAILBOX")?;
        // R10: at most one forward per (room, member) per 30 s. Stamped on
        // attempt, so a failing mailbox cannot turn every ping into a
        // sub-request either.
        let due: Vec<&str> = plan
            .offline
            .iter()
            .copied()
            .filter(|m| {
                let last = rows
                    .iter()
                    .find(|r| r.webid == *m)
                    .and_then(|r| r.last_forward);
                forward_due(last, at)
            })
            .collect();
        let skipped = plan.offline.len() - due.len();
        for member in &due {
            self.sql().exec(
                "UPDATE members SET last_forward = ? WHERE webid = ?",
                vec![at.into(), member.to_string().into()],
            )?;
        }
        let mut forwards = Vec::with_capacity(due.len());
        for member in &due {
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
            "room ping live={} queued={} failed={} skipped={}",
            plan.live.len(),
            results.len() - failed,
            failed,
            skipped
        );
        Ok(())
    }
}

impl DurableObject for Room {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            dir: FetchDirectory::new(),
            schema: Schema::new(&[SCHEMA, gate::SCHEMA]),
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
        let Some(host) = gate::upgrade_host(req.headers().get("Host")?, &url) else {
            return Response::error("Bad Request", 400);
        };

        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        let att = Attachment {
            authed: false,
            opened: now_ms(),
            room,
            host,
            webid: None,
            rl: None,
            pending: false,
        };
        // Accepted already: a failure here must close the socket, or it
        // would sit open with no attachment or no auth timeout.
        let setup = match pair.server.serialize_attachment(&att) {
            Ok(()) => gate::arm_auth_timeout(&self.state).await,
            Err(e) => Err(e),
        };
        if setup.is_err() {
            gate::internal_error(&pair.server, TAG);
        }
        Response::from_websocket(pair.client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        if self.on_message(&ws, message).await.is_err() {
            gate::internal_error(&ws, TAG);
        }
        Ok(())
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
        // A room nobody was ever admitted to holds only auth rows: let the
        // alarm drop them.
        if self.member_count()? == 0 {
            gate::arm_cleanup(&self.state).await?;
        }
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: worker::Error) -> Result<()> {
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        let idle = gate::auth_alarm(
            &self.state,
            |ws| {
                Self::attachment(ws)
                    .filter(|a| !a.authed)
                    .map(|a| (a.opened, a.pending))
            },
            TAG,
        )
        .await?;
        if idle && self.member_count()? == 0 {
            gate::sweep_junk(&self.state, &self.schema, TAG).await?;
        }
        Response::ok("")
    }
}

impl Room {
    async fn on_message(&self, ws: &WebSocket, message: WebSocketIncomingMessage) -> Result<()> {
        let ws = ws.clone();
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
            ClientFrame::Auth { .. } if att.pending => {
                fail(&ws, ErrorCode::BadFrame);
                Ok(())
            }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{MAX_HOST_BYTES, MAX_WEBID_BYTES};

    #[test]
    fn worst_case_attachment_fits_2kb() {
        let mut rl = RateLimiter::frames();
        let t0 = 1_800_000_000_000;
        while rl.allow(t0 + rl.hits().len() as i64) {}
        let att = Attachment {
            authed: true,
            opened: t0,
            room: "0".repeat(32),
            host: "h".repeat(MAX_HOST_BYTES),
            webid: Some("w".repeat(MAX_WEBID_BYTES)),
            rl: Some(rl),
            pending: true,
        };
        let len = serde_json::to_string(&att).unwrap().len();
        assert!(len < 2048, "attachment is {len} bytes");
    }
}
