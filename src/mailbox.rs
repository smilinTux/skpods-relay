//! Per-WebID mailbox Durable Object, named by `sha256_hex(webid)`.
//!
//! Stub for now (ruling R1): it accepts a room's forward and answers 202.
//! Task 4 adds the queue and the `/v1/me` socket.

use serde::{Deserialize, Serialize};
use worker::{durable_object, DurableObject, Env, Method, Request, Response, Result, State};

/// Path a Room posts a queued ping to, through the namespace stub only. The
/// public router never routes `/internal/*`.
pub const ENQUEUE_PATH: &str = "/internal/enqueue";
/// Base URL for stub sub-requests; the host is ignored by the runtime.
pub const ENQUEUE_URL: &str = "https://mailbox/internal/enqueue";

/// One queued hint, as later sent in a `queued` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedItem {
    pub room: String,
    pub from: String,
    pub kind: String,
    pub url: String,
    pub seq: i64,
    pub at: i64,
}

#[durable_object(fetch)]
pub struct Mailbox {
    #[allow(dead_code)]
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for Mailbox {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        if req.method() != Method::Post || req.path() != ENQUEUE_PATH {
            return Response::error("Not Found", 404);
        }
        match req.json::<QueuedItem>().await {
            Ok(_item) => Ok(Response::empty()?.with_status(202)),
            Err(_) => Response::error("Bad Request", 400),
        }
    }
}
