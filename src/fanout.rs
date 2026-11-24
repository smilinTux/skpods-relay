//! Who gets a relayed frame. Pure code, tested on the host.

/// One open socket as the room sees it: whether it is the sender's own
/// socket, and its verified WebID once authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketView<'a> {
    pub is_sender: bool,
    pub webid: Option<&'a str>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fanout<'a> {
    /// Indices into the socket list that get the frame live.
    pub live: Vec<usize>,
    /// Stored members with no authenticated socket open; their mailbox gets
    /// the ping queued.
    pub offline: Vec<&'a str>,
}

/// Every other authenticated socket gets the frame live (including the
/// sender's other devices). Every stored member with no authenticated socket
/// open is offline.
pub fn plan<'a>(sockets: &[SocketView<'_>], members: &'a [String]) -> Fanout<'a> {
    let live = sockets
        .iter()
        .enumerate()
        .filter(|(_, s)| !s.is_sender && s.webid.is_some())
        .map(|(i, _)| i)
        .collect();
    let offline = members
        .iter()
        .map(String::as_str)
        .filter(|m| !sockets.iter().any(|s| s.webid == Some(*m)))
        .collect();
    Fanout { live, offline }
}

/// A room forwards to an offline member's mailbox at most once per this
/// long (ruling R10); later pings inside the window are dropped for that
/// member, who re-polls on reconnect anyway.
pub const FORWARD_EVERY_MS: i64 = 30_000;

/// Whether a member last forwarded at `last` (epoch ms) may be forwarded
/// again at `now`. A `last` in the future (clock step) counts as due.
pub fn forward_due(last: Option<i64>, now: i64) -> bool {
    match last {
        None => true,
        Some(t) => t > now || now - t >= FORWARD_EVERY_MS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_live_and_offline() {
        let a = "https://a.example/#me";
        let b = "https://b.example/#me";
        let c = "https://c.example/#me";
        let sockets = [
            SocketView {
                is_sender: true,
                webid: Some(a),
            },
            SocketView {
                is_sender: false,
                webid: Some(a),
            },
            SocketView {
                is_sender: false,
                webid: None,
            },
            SocketView {
                is_sender: false,
                webid: Some(b),
            },
        ];
        let members = vec![a.to_string(), b.to_string(), c.to_string()];
        let f = plan(&sockets, &members);
        assert_eq!(f.live, vec![1, 3]);
        assert_eq!(f.offline, vec![c]);
    }

    #[test]
    fn unauthenticated_socket_does_not_count_as_online() {
        let a = "https://a.example/#me";
        let sockets = [SocketView {
            is_sender: false,
            webid: None,
        }];
        let members = vec![a.to_string()];
        let f = plan(&sockets, &members);
        assert!(f.live.is_empty());
        assert_eq!(f.offline, vec![a]);
    }

    #[test]
    fn forwards_at_most_once_per_30s() {
        let now = 1_000_000;
        assert!(forward_due(None, now));
        assert!(!forward_due(Some(now), now));
        assert!(!forward_due(Some(now - FORWARD_EVERY_MS + 1), now));
        assert!(forward_due(Some(now - FORWARD_EVERY_MS), now));
        // A clock step backwards does not block forwards forever.
        assert!(forward_due(Some(now + 5 * FORWARD_EVERY_MS), now));
    }
}
