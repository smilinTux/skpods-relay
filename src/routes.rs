//! Public routing table. Only `GET /v1/room/:id` is reachable from outside;
//! every other path, `/internal/*` included, is 404.

use crate::ids::valid_room_id;

#[derive(Debug, PartialEq, Eq)]
pub enum Route<'a> {
    Room(&'a str),
    BadRoomId,
    NotFound,
}

pub fn route<'a>(method: &str, path: &'a str) -> Route<'a> {
    if method != "GET" {
        return Route::NotFound;
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
        assert_eq!(route("GET", "/v1/me"), Route::NotFound);
        assert_eq!(route("GET", "/"), Route::NotFound);
    }
}
