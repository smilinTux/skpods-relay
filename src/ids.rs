//! Identifiers used to name Durable Objects.

use sha2::{Digest, Sha256};

/// A room id is 32 lowercase hex characters (a random 128-bit capability).
pub fn valid_room_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Lowercase hex SHA-256 of `s`. A mailbox is named by `sha256_hex(webid)`.
pub fn sha256_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A mailbox name: 64 lowercase hex characters.
pub fn valid_mailbox_name(w: &str) -> bool {
    w.len() == 64 && w.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(valid_mailbox_name(&sha256_hex("https://a.example/#me")));
        assert!(!valid_mailbox_name("abc"));
    }
}
