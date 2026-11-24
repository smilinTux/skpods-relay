//! Limits of the relay, and a rolling-window rate limiter.
//!
//! Pure code, tested on the host.

use serde::{Deserialize, Serialize};

/// Most distinct members a room stores.
pub const MAX_MEMBERS: i64 = 50;
/// An unauthenticated socket is closed after this long.
pub const AUTH_TIMEOUT_MS: i64 = 5_000;
/// A socket whose auth verification is still in flight is closed this long
/// after opening. A verify makes up to three 5 s fetches.
pub const VERIFY_TIMEOUT_MS: i64 = 20_000;
/// Delay before the alarm that drops an idle object's leftover storage.
pub const CLEANUP_DELAY_MS: i64 = 10_000;
/// Frames per socket per window.
pub const FRAMES_PER_WINDOW: usize = 60;
/// Auth verifications per object per window (ruling R9).
pub const AUTHS_PER_WINDOW: usize = 30;
/// Rolling window for both limiters.
pub const WINDOW_MS: i64 = 60_000;
/// How many proof jtis a room remembers. With at most 30 verifications a
/// minute this covers far more than the 60 s proof window.
pub const JTI_KEEP: i64 = 1_000;

/// Sliding log limiter: at most `max` events in any `window_ms` span.
/// Serializable so it can live in a hibernatable socket attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimiter {
    max: usize,
    window_ms: i64,
    hits: Vec<i64>,
}

impl RateLimiter {
    pub fn new(max: usize, window_ms: i64) -> Self {
        Self {
            max,
            window_ms,
            hits: Vec::new(),
        }
    }

    /// 60 frames per rolling 60 s, the per-socket limit.
    pub fn frames() -> Self {
        Self::new(FRAMES_PER_WINDOW, WINDOW_MS)
    }

    /// 30 auth verifications per rolling 60 s, the per-object limit, seeded
    /// with earlier hits (for example ones read back from storage).
    pub fn auths(hits: Vec<i64>) -> Self {
        let mut rl = Self::new(AUTHS_PER_WINDOW, WINDOW_MS);
        rl.hits = hits;
        rl.hits.sort_unstable();
        rl
    }

    /// Record an event at `now_ms` if the window has room; false otherwise.
    pub fn allow(&mut self, now_ms: i64) -> bool {
        let cutoff = now_ms - self.window_ms;
        self.hits.retain(|&t| t > cutoff);
        if self.hits.len() >= self.max {
            return false;
        }
        self.hits.push(now_ms);
        true
    }

    pub fn hits(&self) -> &[i64] {
        &self.hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolling_not_fixed_window() {
        let mut rl = RateLimiter::new(2, 1_000);
        assert!(rl.allow(0));
        assert!(rl.allow(900));
        assert!(!rl.allow(999));
        // The hit at 0 has aged out, the one at 900 has not.
        assert!(rl.allow(1_000));
        assert!(!rl.allow(1_500));
        assert!(rl.allow(1_900));
    }

    #[test]
    fn auth_limiter_is_30_and_keeps_seed() {
        let mut rl = RateLimiter::auths((0..29).collect());
        assert!(rl.allow(100));
        assert!(!rl.allow(100));
        assert_eq!(rl.hits().len(), 30);
        // Rejected calls do not extend the window.
        assert!(rl.allow(60_001));
    }
}
