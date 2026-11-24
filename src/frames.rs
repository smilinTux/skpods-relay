//! Wire frames for relay protocol v1 (docs/CHAT-PROTOCOL.md in skpods).
//!
//! Pure code: parsing client frames, building server frames, and the error
//! code to close code table. No Workers APIs here, so it runs under
//! `cargo test` on the host.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::mailbox::QueuedItem;

/// Largest accepted frame, in UTF-8 bytes of the whole text frame.
pub const MAX_FRAME_BYTES: usize = 4096;

/// Wire protocol version carried as `"v":1` in the auth frame.
pub const PROTOCOL_VERSION: u8 = 1;

/// Fields only the relay may set. A client frame carrying any of them is refused.
const RELAY_ONLY_FIELDS: [&str; 3] = ["from", "seq", "at"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Message,
    Edit,
    Delete,
    Receipt,
    Join,
    Leave,
    Archive,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "message" => Kind::Message,
            "edit" => Kind::Edit,
            "delete" => Kind::Delete,
            "receipt" => Kind::Receipt,
            "join" => Kind::Join,
            "leave" => Kind::Leave,
            "archive" => Kind::Archive,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Message => "message",
            Kind::Edit => "edit",
            Kind::Delete => "delete",
            Kind::Receipt => "receipt",
            Kind::Join => "join",
            Kind::Leave => "leave",
            Kind::Archive => "archive",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientFrame {
    Auth { v: u8, token: String, proof: String },
    Ping { kind: Kind, url: String },
    Typing,
}

/// Error codes of the wire contract, each with its close code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    AuthFailed,
    RoomFull,
    TooLarge,
    RateLimited,
    BadFrame,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::AuthFailed => "auth_failed",
            ErrorCode::RoomFull => "room_full",
            ErrorCode::TooLarge => "too_large",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::BadFrame => "bad_frame",
        }
    }

    pub fn close(self) -> u16 {
        match self {
            ErrorCode::AuthFailed => 4401,
            ErrorCode::RoomFull => 4403,
            ErrorCode::TooLarge => 4413,
            ErrorCode::RateLimited => 4429,
            ErrorCode::BadFrame => 4400,
        }
    }

    pub fn from_code(s: &str) -> Option<ErrorCode> {
        Some(match s {
            "auth_failed" => ErrorCode::AuthFailed,
            "room_full" => ErrorCode::RoomFull,
            "too_large" => ErrorCode::TooLarge,
            "rate_limited" => ErrorCode::RateLimited,
            "bad_frame" => ErrorCode::BadFrame,
            _ => return None,
        })
    }
}

/// Why a client frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    TooLarge,
    Bad,
}

impl FrameError {
    pub fn code(self) -> ErrorCode {
        match self {
            FrameError::TooLarge => ErrorCode::TooLarge,
            FrameError::Bad => ErrorCode::BadFrame,
        }
    }

    pub fn close(self) -> u16 {
        self.code().close()
    }
}

fn str_field(obj: &Map<String, Value>, key: &str) -> Result<String, FrameError> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or(FrameError::Bad)
}

/// Parse one client text frame. Refuses frames over 4096 bytes, non-JSON,
/// unknown `t`, auth with `v` other than 1, unknown ping `kind`, a ping `url`
/// that is not https, and any frame carrying `from`, `seq` or `at`.
pub fn parse(text: &str) -> Result<ClientFrame, FrameError> {
    if text.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let value: Value = serde_json::from_str(text).map_err(|_| FrameError::Bad)?;
    let obj = value.as_object().ok_or(FrameError::Bad)?;
    if RELAY_ONLY_FIELDS.iter().any(|k| obj.contains_key(*k)) {
        return Err(FrameError::Bad);
    }
    match obj.get("t").and_then(Value::as_str) {
        Some("auth") => {
            if obj.get("v").and_then(Value::as_u64) != Some(u64::from(PROTOCOL_VERSION)) {
                return Err(FrameError::Bad);
            }
            Ok(ClientFrame::Auth {
                v: PROTOCOL_VERSION,
                token: str_field(obj, "token")?,
                proof: str_field(obj, "proof")?,
            })
        }
        Some("ping") => {
            let kind = obj
                .get("kind")
                .and_then(Value::as_str)
                .and_then(Kind::parse)
                .ok_or(FrameError::Bad)?;
            let url = str_field(obj, "url")?;
            if !is_https_url(&url) {
                return Err(FrameError::Bad);
            }
            Ok(ClientFrame::Ping { kind, url })
        }
        Some("typing") => Ok(ClientFrame::Typing),
        _ => Err(FrameError::Bad),
    }
}

/// `https://` followed by a non-empty host, with no whitespace or control
/// characters anywhere.
fn is_https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    host_end > 0 && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Order rule for a socket: the first frame must be `auth`, and `auth` is
/// never accepted again once the socket is authenticated.
pub fn check_order(authed: bool, frame: &ClientFrame) -> Result<(), FrameError> {
    match (authed, frame) {
        (false, ClientFrame::Auth { .. }) => Ok(()),
        (false, _) => Err(FrameError::Bad),
        (true, ClientFrame::Auth { .. }) => Err(FrameError::Bad),
        (true, _) => Ok(()),
    }
}

/// Frames the relay sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerFrame<'a> {
    Ready {
        webid: &'a str,
    },
    Ping {
        from: &'a str,
        kind: Kind,
        url: &'a str,
        seq: i64,
        at: i64,
    },
    Typing {
        from: &'a str,
    },
    /// Mailbox delivery: the drained queue on connect, or one live item.
    Queued(&'a [QueuedItem]),
    Error(ErrorCode),
}

impl ServerFrame<'_> {
    pub fn to_json(&self) -> String {
        let v = match self {
            ServerFrame::Ready { webid } => json!({"t": "ready", "webid": webid}),
            ServerFrame::Ping {
                from,
                kind,
                url,
                seq,
                at,
            } => json!({
                "t": "ping",
                "from": from,
                "kind": kind.as_str(),
                "url": url,
                "seq": seq,
                "at": at,
            }),
            ServerFrame::Typing { from } => json!({"t": "typing", "from": from}),
            ServerFrame::Queued(items) => json!({"t": "queued", "items": items}),
            ServerFrame::Error(code) => json!({"t": "error", "code": code.as_str()}),
        };
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://alice.pods.example/skpods/v1/chat/c-ab12/m-1.ttl";

    #[test]
    fn parses_each_kind() {
        for k in [
            "message", "edit", "delete", "receipt", "join", "leave", "archive",
        ] {
            let f = parse(&format!(r#"{{"t":"ping","kind":"{k}","url":"{URL}"}}"#)).unwrap();
            assert_eq!(
                f,
                ClientFrame::Ping {
                    kind: Kind::parse(k).unwrap(),
                    url: URL.into()
                }
            );
        }
    }

    #[test]
    fn size_limit_is_utf8_bytes() {
        // 1366 three-byte chars is 4098 bytes but only 1366 chars.
        let pad = "\u{20ac}".repeat(1366);
        let f = format!(r#"{{"t":"typing","x":"{pad}"}}"#);
        assert!(f.chars().count() < MAX_FRAME_BYTES);
        assert_eq!(parse(&f), Err(FrameError::TooLarge));
        // Exactly 4096 bytes is allowed.
        let base = r#"{"t":"typing","x":""}"#;
        let f = format!(
            r#"{{"t":"typing","x":"{}"}}"#,
            "a".repeat(MAX_FRAME_BYTES - base.len())
        );
        assert_eq!(f.len(), MAX_FRAME_BYTES);
        assert_eq!(parse(&f), Ok(ClientFrame::Typing));
    }

    #[test]
    fn refuses_bad_frames() {
        let bad = [
            "not json",
            "[]",
            "\"auth\"",
            r#"{"t":"nope"}"#,
            r#"{"kind":"message"}"#,
            r#"{"t":"auth","token":"a","proof":"b"}"#,
            r#"{"t":"auth","v":"1","token":"a","proof":"b"}"#,
            r#"{"t":"auth","v":1.5,"token":"a","proof":"b"}"#,
            r#"{"t":"auth","v":1,"proof":"b"}"#,
            r#"{"t":"auth","v":1,"token":5,"proof":"b"}"#,
            r#"{"t":"ping","kind":"message"}"#,
            r#"{"t":"ping","kind":"message","url":"https://"}"#,
            r#"{"t":"ping","kind":"message","url":"https:///x"}"#,
            r#"{"t":"ping","kind":"message","url":"HTTPS://a.example/x"}"#,
            r#"{"t":"ping","kind":"message","url":"wss://a.example/x"}"#,
            r#"{"t":"ping","kind":"message","url":"https://a.example/x y"}"#,
            r#"{"t":"typing","from":"https://a.example/#me"}"#,
            r#"{"t":"typing","at":1}"#,
            r#"{"t":"typing","seq":null}"#,
        ];
        for f in bad {
            assert_eq!(parse(f), Err(FrameError::Bad), "{f}");
        }
    }

    #[test]
    fn auth_frame_parses() {
        let f = parse(r#"{"t":"auth","v":1,"token":"tok","proof":"prf"}"#).unwrap();
        assert_eq!(
            f,
            ClientFrame::Auth {
                v: 1,
                token: "tok".into(),
                proof: "prf".into()
            }
        );
    }

    #[test]
    fn order_rule() {
        let auth = parse(r#"{"t":"auth","v":1,"token":"a","proof":"b"}"#).unwrap();
        assert_eq!(check_order(false, &auth), Ok(()));
        assert_eq!(
            check_order(false, &ClientFrame::Typing),
            Err(FrameError::Bad)
        );
        assert_eq!(check_order(true, &auth), Err(FrameError::Bad));
        assert_eq!(check_order(true, &ClientFrame::Typing), Ok(()));
    }
}
