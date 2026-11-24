//! The relay must agree with the shared wire fixtures in
//! `tests/relay-v1.fixtures.json` (copied from the skpods protocol folder).

use serde_json::Value;
use skpods_relay::frames::{parse, ErrorCode, ServerFrame};
use skpods_relay::ids::valid_room_id;
use skpods_relay::limits::RateLimiter;

fn fixtures() -> Vec<Value> {
    let text = include_str!("relay-v1.fixtures.json");
    serde_json::from_str::<Vec<Value>>(text).expect("fixtures parse")
}

#[test]
fn fixtures_match_parser() {
    let mut seen = 0;
    for f in fixtures() {
        if f["direction"] != "client" {
            continue;
        }
        seen += 1;
        let name = f["name"].as_str().unwrap();
        let frame = serde_json::to_string(&f["frame"]).unwrap();
        let valid = f["valid"].as_bool().unwrap();
        let got = parse(&frame);
        assert_eq!(got.is_ok(), valid, "fixture {name}");
        if let Some(close) = f.get("close").and_then(Value::as_u64) {
            let err = got.expect_err(name);
            assert_eq!(
                u64::from(err.close()),
                close,
                "close code for fixture {name}"
            );
        }
    }
    assert!(seen >= 10, "expected the client fixtures, saw {seen}");
}

#[test]
fn server_error_fixtures_match_close_codes() {
    let mut seen = 0;
    for f in fixtures() {
        if f["direction"] != "server" || f["frame"]["t"] != "error" {
            continue;
        }
        seen += 1;
        let code = f["frame"]["code"].as_str().unwrap();
        let ec = ErrorCode::from_code(code).expect(code);
        assert_eq!(ec.as_str(), code);
        assert_eq!(Some(u64::from(ec.close())), f["close"].as_u64(), "{code}");
        let built: Value = serde_json::from_str(&ServerFrame::Error(ec).to_json()).unwrap();
        assert_eq!(built, f["frame"]);
    }
    assert_eq!(seen, 5);
}

#[test]
fn server_frames_match_fixtures() {
    let by_name =
        |n: &str| fixtures().into_iter().find(|f| f["name"] == n).unwrap()["frame"].clone();
    let alice = "https://alice.pods.example/profile/card#me";
    let url = "https://alice.pods.example/skpods/v1/chat/c-ab12/m-1732449600000-x9k2.ttl";

    let ready: Value =
        serde_json::from_str(&ServerFrame::Ready { webid: alice }.to_json()).unwrap();
    assert_eq!(ready, by_name("ready ok"));

    let ping = ServerFrame::Ping {
        from: alice,
        kind: skpods_relay::frames::Kind::Message,
        url,
        seq: 7,
        at: 1732449600000,
    };
    let ping: Value = serde_json::from_str(&ping.to_json()).unwrap();
    assert_eq!(ping, by_name("ping relayed ok"));

    let typing: Value =
        serde_json::from_str(&ServerFrame::Typing { from: alice }.to_json()).unwrap();
    assert_eq!(typing, by_name("typing relayed ok"));
}

#[test]
fn rate_limiter_allows_60_then_blocks() {
    let mut rl = RateLimiter::frames();
    let t = 1_000_000;
    for i in 0..60 {
        assert!(rl.allow(t), "call {i}");
    }
    assert!(!rl.allow(t), "61st call");
    assert!(!rl.allow(t + 59_999), "still inside the window");
    assert!(rl.allow(t + 60_000), "window rolled");
}

#[test]
fn room_id_must_be_32_hex() {
    assert!(valid_room_id("0123456789abcdef0123456789abcdef"));
    assert!(!valid_room_id("0123456789ABCDEF0123456789ABCDEF"));
    assert!(!valid_room_id("0123456789abcdef0123456789abcde"));
    assert!(!valid_room_id("0123456789abcdef0123456789abcdef0"));
    assert!(!valid_room_id("0123456789abcdef0123456789abcdeg"));
    assert!(!valid_room_id(""));
}

#[test]
fn queued_frame_matches_fixture() {
    use skpods_relay::frames::Kind;
    use skpods_relay::mailbox::QueuedItem;
    let want = fixtures()
        .into_iter()
        .find(|f| f["name"] == "queued ok")
        .unwrap()["frame"]
        .clone();
    let items = vec![QueuedItem {
        room: "0123456789abcdef0123456789abcdef".into(),
        from: "https://alice.pods.example/profile/card#me".into(),
        kind: Kind::Message,
        url: "https://alice.pods.example/skpods/v1/chat/c-ab12/m-1732449600000-x9k2.ttl".into(),
        seq: 7,
        at: 1732449600000,
    }];
    let got: Value = serde_json::from_str(&ServerFrame::Queued(&items).to_json()).unwrap();
    assert_eq!(got, want);
    let empty: Value = serde_json::from_str(&ServerFrame::Queued(&[]).to_json()).unwrap();
    assert_eq!(empty, serde_json::json!({"t": "queued", "items": []}));
}
