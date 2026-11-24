//! Per-WebID mailbox Durable Object, named by `sha256_hex(webid)`.
//!
//! Two ways in, both reached only through the `MAILBOX` namespace:
//!
//! * `POST /internal/enqueue` from a Room stub (ruling R4: the public router
//!   never routes `/internal/*`). While the owner has an authenticated socket
//!   open the item goes straight to every such socket and is not stored;
//!   otherwise it is queued.
//! * `GET /v1/me?w=<hex>`, the owner's socket. After the shared auth sequence
//!   the mailbox checks `sha256_hex(verified webid) == w` (ruling R3), sends
//!   `ready`, then one `queued` frame with the drained queue (even when
//!   empty), then live single-item `queued` frames. The mailbox only sends:
//!   any client frame after auth is `bad_frame`.
//!
//! `Queue` is the pure queue rule set: at most 500 items, oldest dropped
//! first, items older than 7 days dropped on push and on drain, and repeats
//! of the same `(room, url, kind)` collapsed to the newest. The object keeps
//! one row per item in SQLite table `items` and applies `Queue` to it.
//!
//! Logs carry counts and error codes only, never tokens, proofs, URLs or
//! WebIDs.

use serde::{Deserialize, Serialize};
use worker::{
    console_log, durable_object, DurableObject, Env, Method, Request, Response, Result, State,
    WebSocket, WebSocketIncomingMessage, WebSocketPair,
};

use crate::frames::{check_order, parse, ClientFrame, ErrorCode, Kind, ServerFrame};
use crate::gate::{self, now_ms};
use crate::ids::sha256_hex;
use crate::limits::AUTH_TIMEOUT_MS;
use crate::profile::FetchDirectory;
use crate::routes::mailbox_param;

/// Path a Room posts a queued ping to, through the namespace stub only. The
/// public router never routes `/internal/*`.
pub const ENQUEUE_PATH: &str = "/internal/enqueue";
/// Base URL for stub sub-requests; the host is ignored by the runtime.
pub const ENQUEUE_URL: &str = "https://mailbox/internal/enqueue";

/// Most items a mailbox keeps.
pub const MAX_ITEMS: usize = 500;
/// Items older than this are dropped.
pub const MAX_AGE_MS: i64 = 7 * 86_400_000;

const TAG: &str = "mailbox";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS items(
  id INTEGER PRIMARY KEY, room TEXT, sender TEXT, kind TEXT, url TEXT, seq INTEGER, at INTEGER
);
";

/// One queued hint, as sent in a `queued` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedItem {
    pub room: String,
    pub from: String,
    pub kind: Kind,
    pub url: String,
    pub seq: u64,
    pub at: i64,
}

impl QueuedItem {
    fn same_slot(&self, other: &QueuedItem) -> bool {
        self.room == other.room && self.url == other.url && self.kind == other.kind
    }
}

/// The queue rules, oldest item first. Pure code, tested on the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Queue {
    items: Vec<QueuedItem>,
}

impl Queue {
    /// A queue holding `items` as stored, oldest first.
    pub fn from_items(items: Vec<QueuedItem>) -> Self {
        Self { items }
    }

    pub fn items(&self) -> &[QueuedItem] {
        &self.items
    }

    pub fn push(&mut self, item: QueuedItem, now_ms: i64) {
        self.push_tracked(item, now_ms);
    }

    /// `push`, returning the positions (in the queue as it was before the
    /// push) of the items it removed, so storage can delete just those rows.
    pub fn push_tracked(&mut self, item: QueuedItem, now_ms: i64) -> Vec<usize> {
        let cutoff = now_ms - MAX_AGE_MS;
        let mut removed = Vec::new();
        let mut kept = Vec::with_capacity(self.items.len() + 1);
        for (i, old) in self.items.drain(..).enumerate() {
            if old.at < cutoff || old.same_slot(&item) {
                removed.push(i);
            } else {
                kept.push((i, old));
            }
        }
        let excess = (kept.len() + 1).saturating_sub(MAX_ITEMS);
        removed.extend(kept.drain(..excess).map(|(i, _)| i));
        removed.sort_unstable();
        self.items = kept.into_iter().map(|(_, it)| it).collect();
        if item.at >= cutoff {
            self.items.push(item);
        }
        removed
    }

    /// Every unexpired item, oldest first. The queue is empty afterwards.
    pub fn drain(&mut self, now_ms: i64) -> Vec<QueuedItem> {
        let cutoff = now_ms - MAX_AGE_MS;
        let mut items = std::mem::take(&mut self.items);
        items.retain(|i| i.at >= cutoff);
        items
    }
}

/// Per-socket state, kept in the hibernatable attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Attachment {
    authed: bool,
    opened: i64,
    /// The mailbox name the socket dialled (`w`) and its Host header (R7).
    w: String,
    host: String,
    #[serde(default)]
    pending: bool,
}

#[derive(Deserialize)]
struct Row {
    id: i64,
    room: String,
    sender: String,
    kind: String,
    url: String,
    seq: i64,
    at: i64,
}

impl Row {
    fn item(self) -> Option<(i64, QueuedItem)> {
        let item = QueuedItem {
            room: self.room,
            from: self.sender,
            kind: Kind::parse(&self.kind)?,
            url: self.url,
            seq: u64::try_from(self.seq).ok()?,
            at: self.at,
        };
        Some((self.id, item))
    }
}

fn fail(ws: &WebSocket, code: ErrorCode) {
    gate::fail(ws, code, TAG);
}

#[durable_object]
pub struct Mailbox {
    state: State,
    #[allow(dead_code)]
    env: Env,
    dir: FetchDirectory,
}

impl Mailbox {
    fn sql(&self) -> worker::SqlStorage {
        self.state.storage().sql()
    }

    fn attachment(ws: &WebSocket) -> Option<Attachment> {
        ws.deserialize_attachment::<Attachment>().ok().flatten()
    }

    fn authed_sockets(&self) -> Vec<WebSocket> {
        self.state
            .get_websockets()
            .into_iter()
            .filter(|s| Self::attachment(s).is_some_and(|a| a.authed))
            .collect()
    }

    /// Stored items with their row ids, oldest first.
    fn load(&self) -> Result<(Vec<i64>, Queue)> {
        let rows: Vec<Row> = self
            .sql()
            .exec(
                "SELECT id, room, sender, kind, url, seq, at FROM items ORDER BY id",
                None,
            )?
            .to_array()?;
        let (ids, items): (Vec<i64>, Vec<QueuedItem>) =
            rows.into_iter().filter_map(Row::item).unzip();
        Ok((ids, Queue::from_items(items)))
    }

    fn store(&self, item: QueuedItem, now: i64) -> Result<()> {
        let (ids, mut queue) = self.load()?;
        let removed = queue.push_tracked(item.clone(), now);
        let sql = self.sql();
        for i in removed {
            sql.exec("DELETE FROM items WHERE id = ?", vec![ids[i].into()])?;
        }
        if queue.items().last() == Some(&item) {
            sql.exec(
                "INSERT INTO items(room, sender, kind, url, seq, at) VALUES (?, ?, ?, ?, ?, ?)",
                vec![
                    item.room.into(),
                    item.from.into(),
                    item.kind.as_str().into(),
                    item.url.into(),
                    (item.seq as i64).into(),
                    item.at.into(),
                ],
            )?;
        }
        Ok(())
    }

    fn drain(&self, now: i64) -> Result<Vec<QueuedItem>> {
        let (_, mut queue) = self.load()?;
        self.sql().exec("DELETE FROM items", None)?;
        Ok(queue.drain(now))
    }

    async fn enqueue(&self, mut req: Request) -> Result<Response> {
        let item = match req.json::<QueuedItem>().await {
            Ok(item) => item,
            Err(_) => return Response::error("Bad Request", 400),
        };
        let frame = ServerFrame::Queued(std::slice::from_ref(&item)).to_json();
        let live = self
            .authed_sockets()
            .iter()
            .filter(|s| s.send_with_str(&frame).is_ok())
            .count();
        if live == 0 {
            self.store(item, now_ms())?;
        }
        console_log!("mailbox enqueue live={}", live);
        Ok(Response::empty()?.with_status(202))
    }

    async fn upgrade(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let Some(w) = mailbox_param(url.query()) else {
            return Response::error("Bad Request", 400);
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
        pair.server.serialize_attachment(&Attachment {
            authed: false,
            opened: now_ms(),
            w,
            host,
            pending: false,
        })?;
        gate::arm_auth_timeout(&self.state).await?;
        Response::from_websocket(pair.client)
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
        // htu excludes the query string (DPoP, ruling R3).
        let htu = format!("https://{}/v1/me", att.host);
        let sql = self.sql();
        let verified =
            match gate::verify_socket(&sql, &self.dir, token, proof, &htu, now, TAG).await? {
                Ok(v) => v,
                Err(code) => {
                    fail(ws, code);
                    return Ok(());
                }
            };
        if sha256_hex(&verified.webid) != att.w {
            console_log!("mailbox auth refused not_owner");
            fail(ws, ErrorCode::AuthFailed);
            return Ok(());
        }
        att.authed = true;
        att.pending = false;
        ws.serialize_attachment(&att)?;
        ws.send_with_str(
            ServerFrame::Ready {
                webid: &verified.webid,
            }
            .to_json(),
        )?;
        // No await between marking the socket authed and draining, so a
        // forward cannot slip in between and be both stored and missed.
        let items = self.drain(now_ms())?;
        ws.send_with_str(ServerFrame::Queued(&items).to_json())?;
        console_log!("mailbox auth ok drained={}", items.len());
        Ok(())
    }
}

impl DurableObject for Mailbox {
    fn new(state: State, env: Env) -> Self {
        let sql = state.storage().sql();
        let _ = sql.exec(SCHEMA, None);
        let _ = sql.exec(gate::SCHEMA, None);
        Self {
            state,
            env,
            dir: FetchDirectory::new(),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        match (req.method(), req.path().as_str()) {
            (Method::Post, ENQUEUE_PATH) => self.enqueue(req).await,
            (Method::Get, "/v1/me") => self.upgrade(req).await,
            _ => Response::error("Not Found", 404),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let Some(att) = Self::attachment(&ws) else {
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
            // The mailbox only sends.
            ClientFrame::Ping { .. } | ClientFrame::Typing => {
                fail(&ws, ErrorCode::BadFrame);
                Ok(())
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
        let _ = ws.close(Some(1000), Some("bye"));
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: worker::Error) -> Result<()> {
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        gate::auth_alarm(
            &self.state,
            |ws| Self::attachment(ws).filter(|a| !a.authed).map(|a| a.opened),
            TAG,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::Kind;

    const DAY: i64 = 86_400_000;
    const NOW: i64 = 1_800_000_000_000;

    fn item(room: &str, url: &str, kind: Kind, seq: u64, at: i64) -> QueuedItem {
        QueuedItem {
            room: room.into(),
            from: "https://a.example/#me".into(),
            kind,
            url: url.into(),
            seq,
            at,
        }
    }

    fn url(i: usize) -> String {
        format!("https://a.example/m-{i}.ttl")
    }

    #[test]
    fn keeps_500_drops_oldest() {
        let mut q = Queue::default();
        for i in 0..501 {
            q.push(item("r", &url(i), Kind::Message, i as u64, NOW), NOW);
        }
        assert_eq!(q.items().len(), MAX_ITEMS);
        assert_eq!(q.items()[0].url, url(1));
        assert_eq!(q.items()[499].url, url(500));
    }

    #[test]
    fn expires_after_7_days() {
        let mut q = Queue::default();
        q.push(
            item("r", &url(0), Kind::Message, 1, NOW - 7 * DAY - 1),
            NOW - DAY,
        );
        q.push(
            item("r", &url(1), Kind::Message, 2, NOW - 7 * DAY),
            NOW - DAY,
        );
        assert_eq!(q.items().len(), 2);
        // On push: the item just over 7 days old is gone.
        q.push(item("r", &url(2), Kind::Message, 3, NOW), NOW);
        let urls: Vec<&str> = q.items().iter().map(|i| i.url.as_str()).collect();
        assert_eq!(urls, vec![url(1), url(2)]);
        // On drain: one millisecond later the exactly-7-days item is gone too.
        let drained = q.drain(NOW + 1);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].url, url(2));
    }

    #[test]
    fn collapses_same_room_url_kind() {
        let mut q = Queue::default();
        q.push(item("r", &url(0), Kind::Message, 1, NOW), NOW);
        q.push(item("r", &url(0), Kind::Edit, 2, NOW), NOW);
        q.push(item("s", &url(0), Kind::Message, 3, NOW), NOW);
        q.push(item("r", &url(0), Kind::Message, 4, NOW + 5), NOW + 5);
        let got: Vec<(&str, Kind, u64)> = q
            .items()
            .iter()
            .map(|i| (i.room.as_str(), i.kind, i.seq))
            .collect();
        assert_eq!(
            got,
            vec![
                ("r", Kind::Edit, 2),
                ("s", Kind::Message, 3),
                ("r", Kind::Message, 4)
            ]
        );
    }

    #[test]
    fn drain_empties_queue() {
        let mut q = Queue::default();
        q.push(item("r", &url(0), Kind::Message, 1, NOW), NOW);
        q.push(item("r", &url(1), Kind::Join, 2, NOW), NOW);
        assert_eq!(q.drain(NOW).len(), 2);
        assert!(q.items().is_empty());
        assert!(q.drain(NOW).is_empty());
    }

    #[test]
    fn push_reports_removed_positions() {
        let mut q = Queue::from_items(vec![
            item("r", &url(0), Kind::Message, 1, NOW - 8 * DAY),
            item("r", &url(1), Kind::Message, 2, NOW),
            item("r", &url(2), Kind::Message, 3, NOW),
        ]);
        let removed = q.push_tracked(item("r", &url(1), Kind::Message, 4, NOW), NOW);
        assert_eq!(removed, vec![0, 1]);
        let seqs: Vec<u64> = q.items().iter().map(|i| i.seq).collect();
        assert_eq!(seqs, vec![3, 4]);
    }

    #[test]
    fn item_json_matches_wire() {
        let i = item("r", &url(0), Kind::Receipt, 7, NOW);
        let v: serde_json::Value = serde_json::to_value(&i).unwrap();
        assert_eq!(v["kind"], "receipt");
        assert_eq!(v["seq"], 7);
        let back: QueuedItem = serde_json::from_value(v).unwrap();
        assert_eq!(back, i);
    }
}
