//! Public routing table. Only `GET /v1/room/:id` and `GET /v1/me?w=<hex>`
//! are reachable from outside; every other path, `/internal/*` included, is
//! 404.

use crate::ids::{valid_mailbox_name, valid_room_id};

#[derive(Debug, PartialEq, Eq)]
pub enum Route<'a> {
    Room(&'a str),
    BadRoomId,
    /// `/v1/me`; the mailbox name comes from the query, see `mailbox_param`.
    Me,
    NotFound,
}

pub fn route<'a>(method: &str, path: &'a str) -> Route<'a> {
    if method != "GET" {
        return Route::NotFound;
    }
    if path == "/v1/me" {
        return Route::Me;
    }
    match path.strip_prefix("/v1/room/") {
        Some(id) if !id.contains('/') => {
            if valid_room_id(id) {
                Route::Room(id)
            } else {
                Route::BadRoomId
            }
        }
        _ => Route::NotFound,
    }
}

/// The mailbox name from a `/v1/me` query: exactly one `w`, 64 lowercase
/// hex characters (ruling R3). None means 400.
pub fn mailbox_param(query: Option<&str>) -> Option<String> {
    let mut found = None;
    for pair in query?.split('&') {
        if let Some(("w", v)) = pair.split_once('=') {
            if found.is_some() {
                return None;
            }
            found = Some(v);
        }
    }
    found.filter(|w| valid_mailbox_name(w)).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn routes_only_rooms() {
        assert_eq!(route("GET", &format!("/v1/room/{ID}")), Route::Room(ID));
        assert_eq!(route("GET", "/v1/room/XYZ"), Route::BadRoomId);
        assert_eq!(route("GET", "/v1/room/"), Route::BadRoomId);
        assert_eq!(route("POST", &format!("/v1/room/{ID}")), Route::NotFound);
        assert_eq!(route("GET", &format!("/v1/room/{ID}/x")), Route::NotFound);
        assert_eq!(route("GET", "/internal/enqueue"), Route::NotFound);
        assert_eq!(route("POST", "/internal/enqueue"), Route::NotFound);
        assert_eq!(route("GET", "/v1/me/x"), Route::NotFound);
        assert_eq!(route("GET", "/"), Route::NotFound);
    }

    #[test]
    fn routes_mailbox_by_w() {
        let w = "ab".repeat(32);
        assert_eq!(route("GET", "/v1/me"), Route::Me);
        assert_eq!(route("POST", "/v1/me"), Route::NotFound);
        assert_eq!(route("GET", "/v1/me/"), Route::NotFound);
        assert_eq!(mailbox_param(Some(&format!("w={w}"))), Some(w.clone()));
        assert_eq!(mailbox_param(Some(&format!("x=1&w={w}"))), Some(w.clone()));
        assert_eq!(mailbox_param(None), None);
        assert_eq!(mailbox_param(Some("")), None);
        assert_eq!(mailbox_param(Some("w=abc")), None);
        assert_eq!(
            mailbox_param(Some(&format!("w={}", w.to_uppercase()))),
            None
        );
        // Exactly one w: a second one is refused rather than guessed.
        assert_eq!(mailbox_param(Some(&format!("w={w}&w={w}"))), None);
    }
}
