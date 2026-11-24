//! skpods-relay: a ping relay for SKPods Chat.
//!
//! The public router answers only two WebSocket upgrades: `GET /v1/room/:id`,
//! handed to the `Room` Durable Object named by `:id`, and `GET /v1/me?w=<hex>`,
//! handed to the `Mailbox` named by `w`. Everything else is 404.
//! `/internal/*` is reachable only through Durable Object stubs.

use worker::{event, Context, Env, Request, Response, Result};

pub mod auth;
pub mod fanout;
pub mod frames;
pub mod gate;
pub mod ids;
pub mod jwk;
pub mod limits;
pub mod mailbox;
pub mod profile;
pub mod room;
pub mod routes;

use routes::{mailbox_param, route, Route};

fn is_upgrade(req: &Request) -> Result<bool> {
    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    Ok(upgrade.eq_ignore_ascii_case("websocket"))
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let method = req.method().to_string();
    let path = req.path();
    match route(&method, &path) {
        Route::NotFound => Response::error("Not Found", 404),
        Route::BadRoomId => Response::error("Bad Request", 400),
        Route::Room(id) => {
            if !is_upgrade(&req)? {
                return Response::error("Upgrade Required", 426);
            }
            let stub = env.durable_object("ROOM")?.id_from_name(id)?.get_stub()?;
            stub.fetch_with_request(req).await
        }
        Route::Me => {
            let Some(w) = mailbox_param(req.url()?.query()) else {
                return Response::error("Bad Request", 400);
            };
            if !is_upgrade(&req)? {
                return Response::error("Upgrade Required", 426);
            }
            let stub = env
                .durable_object("MAILBOX")?
                .id_from_name(&w)?
                .get_stub()?;
            stub.fetch_with_request(req).await
        }
    }
}
