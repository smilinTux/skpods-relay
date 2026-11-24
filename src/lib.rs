//! skpods-relay: a ping relay for SKPods Chat. Later tasks add the router
//! and the Durable Objects; for now every request answers 404.

use worker::{event, Context, Env, Request, Response, Result};

pub mod auth;
pub mod jwk;
pub mod profile;

#[event(fetch)]
async fn fetch(_req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    Response::error("Not Found", 404)
}
