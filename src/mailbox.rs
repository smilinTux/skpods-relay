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

use std::ops::Range;

use serde::{Deserialize, Serialize};
use worker::{
    console_log, durable_object, DurableObject, Env, Method, Request, Response, Result, State,
    WebSocket, WebSocketIncomingMessage, WebSocketPair,
};

use crate::frames::{check_order, parse, ClientFrame, ErrorCode, Kind, ServerFrame};
use crate::gate::{self, now_ms, Schema};
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

/// Most serialized bytes per `queued` frame. A drain is split into several
/// frames under this, well inside the runtime's 1 MiB WebSocket message
/// limit (ruling R12: relay-to-client frames have no protocol cap).
pub const FRAME_BUDGET: usize = 256 * 1024;

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
        let mut items = std::mem::take(&mut self.items);
        items.retain(|i| fresh(i.at, now_ms));
        items
    }
}

/// Whether an item stamped `at` is still within 7 days at `now_ms`.
pub fn fresh(at: i64, now_ms: i64) -> bool {
    at >= now_ms - MAX_AGE_MS
}

/// Split `items` into contiguous runs, in order, whose `queued` frame
/// serializes to at most `budget` bytes. Every run holds at least one item
/// (an item larger than the budget goes alone). Empty input gives one empty
/// run, so the empty queue is still sent as one frame.
pub fn split_frames(items: &[QueuedItem], budget: usize) -> Vec<Range<usize>> {
    let overhead = ServerFrame::Queued(&[]).to_json().len();
    let mut frames = Vec::new();
    let mut start = 0;
    let mut len = overhead;
    for (i, item) in items.iter().enumerate() {
        let size = serde_json::to_string(item).map_or(0, |s| s.len());
        let add = if i == start { size } else { size + 1 };
        if i > start && len + add > budget {
            frames.push(start..i);
            start = i;
            len = overhead + size;
        } else {
            len += add;
        }
    }
    frames.push(start..items.len());
    frames
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
struct Oldest {
    at: Option<i64>,
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
    schema: Schema,
}

impl Mailbox {
    fn sql(&self) -> worker::SqlStorage {
        self.schema.sql(&self.state)
    }

    /// Drop expired items; the oldest remaining item's `at`, if any.
    fn prune(&self, now: i64) -> Result<Option<i64>> {
        let sql = self.sql();
        sql.exec(
            "DELETE FROM items WHERE at < ?",
            vec![(now - MAX_AGE_MS).into()],
        )?;
        let oldest: Oldest = sql.exec("SELECT MIN(at) AS at FROM items", None)?.one()?;
        Ok(oldest.at)
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

    /// Send the stored queue to `ws` as one or more `queued` frames (one
    /// empty frame when nothing is queued). Each frame's rows are deleted
    /// only after its send succeeded; on a failed send the rest stays
    /// stored. Synchronous: no await between read, send and delete.
    fn deliver_queue(&self, ws: &WebSocket, now: i64) -> Result<usize> {
        let (ids, queue) = self.load()?;
        let sql = self.sql();
        // Expired rows would be dropped by any drain anyway.
        sql.exec(
            "DELETE FROM items WHERE at < ?",
            vec![(now - MAX_AGE_MS).into()],
        )?;
        let (ids, items): (Vec<i64>, Vec<QueuedItem>) = ids
            .into_iter()
            .zip(queue.items().iter().cloned())
            .filter(|(_, i)| fresh(i.at, now))
            .unzip();
        let mut sent = 0;
        for r in split_frames(&items, FRAME_BUDGET) {
            if ws
                .send_with_str(ServerFrame::Queued(&items[r.clone()]).to_json())
                .is_err()
            {
                console_log!("mailbox drain send failed kept={}", items.len() - sent);
                break;
            }
            if !r.is_empty() {
                // Ids ascend with the queue order, so a frame is one id range.
                sql.exec(
                    "DELETE FROM items WHERE id >= ? AND id <= ?",
                    vec![ids[r.start].into(), ids[r.end - 1].into()],
                )?;
            }
            sent += r.len();
        }
        Ok(sent)
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
            // The alarm keeps stored items to their 7 day expiry.
            gate::arm_cleanup(&self.state).await?;
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
        let Some(host) = gate::upgrade_host(req.headers().get("Host")?, &url) else {
            return Response::error("Bad Request", 400);
        };

        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        let att = Attachment {
            authed: false,
            opened: now_ms(),
            w,
            host,
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
        // The alarm or the client may have closed the socket while the
        // verify was in flight: then nothing is sent or drained.
        if !gate::is_open(&self.state, ws) {
            console_log!("mailbox auth dropped closed");
            return Ok(());
        }
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
        let drained = self.deliver_queue(ws, now_ms())?;
        console_log!("mailbox auth ok drained={}", drained);
        Ok(())
    }
}

impl DurableObject for Mailbox {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            dir: FetchDirectory::new(),
            schema: Schema::new(&[SCHEMA, gate::SCHEMA]),
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
        let _ = ws.close(Some(1000), Some("bye"));
        // Leftover auth rows, or expired items, are dropped by the alarm.
        gate::arm_cleanup(&self.state).await
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
        if idle {
            let now = now_ms();
            match self.prune(now)? {
                // Come back when the oldest item expires.
                Some(at) => {
                    self.state
                        .storage()
                        .set_alarm((at + MAX_AGE_MS - now + 1).max(1))
                        .await?
                }
                None => gate::sweep_junk(&self.state, &self.schema, TAG).await?,
            }
        }
        Response::ok("")
    }
}

impl Mailbox {
    async fn on_message(&self, ws: &WebSocket, message: WebSocketIncomingMessage) -> Result<()> {
        let ws = ws.clone();
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

    fn frame_len(items: &[QueuedItem]) -> usize {
        ServerFrame::Queued(items).to_json().len()
    }

    #[test]
    fn split_keeps_each_frame_under_budget_in_order() {
        let items: Vec<QueuedItem> = (0..500)
            .map(|i| {
                let long = format!("https://a.example/{}/m-{i}.ttl", "x".repeat(3_900));
                item("r", &long, Kind::Message, i as u64, NOW)
            })
            .collect();
        let frames = split_frames(&items, FRAME_BUDGET);
        assert!(frames.len() > 1);
        let mut next = 0;
        for r in &frames {
            assert_eq!(r.start, next, "contiguous, in order");
            assert!(!r.is_empty(), "at least one item per frame");
            assert!(frame_len(&items[r.clone()]) <= FRAME_BUDGET);
            next = r.end;
        }
        assert_eq!(next, items.len(), "every item covered");
    }

    #[test]
    fn split_exact_budget_and_oversize_item() {
        let items: Vec<QueuedItem> = (0..3)
            .map(|i| item("r", &url(i), Kind::Message, i as u64, NOW))
            .collect();
        // A budget of exactly two items' frame fits two, then one.
        let two = frame_len(&items[..2]);
        assert_eq!(split_frames(&items, two), vec![0..2, 2..3]);
        assert_eq!(split_frames(&items, two - 1), vec![0..1, 1..2, 2..3]);
        // An item larger than the budget still goes, alone in its frame.
        assert_eq!(split_frames(&items, 10), vec![0..1, 1..2, 2..3]);
        assert_eq!(split_frames(&items, usize::MAX), vec![0..3]);
    }

    #[test]
    fn worst_case_attachment_fits_2kb() {
        let att = Attachment {
            authed: true,
            opened: NOW,
            w: "a".repeat(64),
            host: "h".repeat(crate::gate::MAX_HOST_BYTES),
            pending: true,
        };
        assert!(serde_json::to_string(&att).unwrap().len() < 2048);
    }

    #[test]
    fn split_empty_gives_one_empty_frame() {
        assert_eq!(split_frames(&[], FRAME_BUDGET), vec![0..0]);
    }
}
