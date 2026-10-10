//! Filesystem scanning: traversal, cancellation and platform knowledge.

pub mod cancel;
pub mod platform;
pub mod walker;

pub use cancel::CancelToken;
pub use platform::{default_roots, is_system_path, user_profiles, volumes};
pub use walker::{FnObserver, Progress, ScanObserver, SilentObserver, WalkError};
