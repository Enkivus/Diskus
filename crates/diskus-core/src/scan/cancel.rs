//! Cooperative cancellation for long-running scans.
//!
//! A scan can be tens of millions of entries deep. The user must be able to stop
//! it instantly, so the walker holds a clone of this token and checks it every
//! few hundred entries. `AtomicBool` rather than a channel because the check sits
//! in the innermost loop and must be a single uncontended load.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A cheap, thread-safe cancellation flag.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A fresh, un-cancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. Idempotent and safe from any thread.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_uncancelled() {
        let t = CancelToken::new();
        assert!(!t.is_cancelled());
    }

    #[test]
    fn cancel_is_visible_through_clones() {
        let t = CancelToken::new();
        let clone = t.clone();
        t.cancel();
        assert!(clone.is_cancelled(), "clones share the same flag");
    }

    #[test]
    fn cancel_is_idempotent() {
        let t = CancelToken::new();
        t.cancel();
        t.cancel();
        assert!(t.is_cancelled());
    }

    #[test]
    fn cancel_is_visible_across_threads() {
        let t = CancelToken::new();
        let worker = t.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            worker.cancel();
        });
        handle.join().expect("join");
        assert!(t.is_cancelled());
    }
}
