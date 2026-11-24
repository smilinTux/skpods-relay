//! skpods-relay: a ping relay for SKPods Chat.
//!
//! The public router answers only `GET /v1/room/:id` with a WebSocket
//! upgrade, handed to the `Room` Durable Object named by `:id`. Everything
//! else is 404. `/internal/*` is reachable only through Durable Object stubs.

use worker::{event, Context, Env, Request, Response, Result};

pub mod auth;
pub mod fanout;
pub mod frames;
pub mod ids;
pub mod jwk;
pub mod limits;
pub mod mailbox;
pub mod profile;
pub mod room;
pub mod routes;

use routes::{route, Route};

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let method = req.method().to_string();
    let path = req.path();
    match route(&method, &path) {
        Route::NotFound => Response::error("Not Found", 404),
        Route::BadRoomId => Response::error("Bad Request", 400),
        Route::Room(id) => {
            let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
            if !upgrade.eq_ignore_ascii_case("websocket") {
                return Response::error("Upgrade Required", 426);
            }
            let stub = env.durable_object("ROOM")?.id_from_name(id)?.get_stub()?;
            stub.fetch_with_request(req).await
        }
    }
}
