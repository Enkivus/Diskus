//! Application state shared across Tauri commands.
//!
//! The design constraint: a scan can run for minutes and produce a result
//! holding millions of nodes. So:
//!
//! * The *running* scan holds only a cancellation token and live counters.
//!   Nothing large is locked.
//! * Completed results live behind an [`RwLock`] keyed by scan id, so the UI can
//!   fetch a tree while a new scan starts.
//! * At most [`MAX_RETAINED_SCANS`] results are kept. Older ones are evicted;
//!   holding a dozen multi-hundred-megabyte results would exhaust memory on a
//!   machine that is, by definition, short on space.

use diskus_core::config::ScanConfig;
use diskus_core::detect;
use diskus_core::model::{Finding, ScanResult, ScanSummary, UserProfile, Volume};
use diskus_core::scan::CancelToken;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tauri::Emitter;

/// How many finished scans to keep in memory before evicting the oldest.
pub const MAX_RETAINED_SCANS: usize = 2;

/// Shared application state, managed by Tauri.
pub struct AppState {
    scans: RwLock<ScanStore>,
    next_id: AtomicU64,
    /// The currently running scan, if any. Only one runs at a time: two
    /// simultaneous full-filesystem walks would fight for the same disk.
    running: RwLock<Option<Arc<RunningScan>>>,
}

/// A scan that finished, plus everything derived from it.
pub struct CompletedScan {
    /// The filesystem walk.
    pub result: Arc<ScanResult>,
    /// Detection output.
    pub findings: Arc<Vec<Finding>>,
    /// Rollups for the dashboard and reports.
    pub summary: Arc<ScanSummary>,
    /// Sequence number, used to evict the oldest.
    pub sequence: u64,
}

/// Live counters for the running scan.
pub struct RunningScan {
    /// Identifier, matching the completed scan it will produce.
    pub id: String,
    /// Handle the UI calls to abort.
    pub cancel: CancelToken,
    /// True once the walk has finished and detection has begun.
    pub finished_walking: AtomicBool,
    /// Index into [`Self::SCAN_PHASES`].
    pub phase: AtomicU64,
}

impl RunningScan {
    /// Ordered pipeline phases shown in the UI's status line.
    pub const SCAN_PHASES: [&'static str; 4] = ["walking", "hashing", "detecting", "done"];

    /// Current phase name.
    #[must_use]
    pub fn phase_name(&self) -> &'static str {
        let index = self.phase.load(Ordering::Relaxed) as usize;
        Self::SCAN_PHASES.get(index).copied().unwrap_or("walking")
    }

    /// Whether the walk phase has finished.
    #[must_use]
    pub fn is_walking_done(&self) -> bool {
        self.finished_walking.load(Ordering::Relaxed)
    }
}

/// A snapshot of the running scan's status, safe to send across the IPC boundary.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScanStatusSnapshot {
    /// Identifier of the running scan.
    pub scan_id: String,
    /// Pipeline phase name.
    pub phase: String,
    /// Whether the walk has finished.
    pub walking_done: bool,
}

/// Finished scans, keyed by id, ordered by recency.
#[derive(Default)]
struct ScanStore {
    by_id: HashMap<String, Arc<CompletedScan>>,
    next_sequence: u64,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            scans: RwLock::new(ScanStore::default()),
            next_id: AtomicU64::new(1),
            running: RwLock::new(None),
        }
    }
}

impl AppState {
    /// Allocate the next scan identifier.
    pub fn new_scan_id(&self) -> String {
        format!("scan-{}", self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Claim the single scan slot.
    ///
    /// Fails when a scan is already running, which the UI surfaces rather than
    /// silently queueing: a user who presses Scan twice wants to know, not to
    /// wait an unknown time for a second pass.
    ///
    /// # Errors
    /// Returns the id of the scan already in flight.
    pub fn begin_scan(&self, id: &str) -> Result<Arc<RunningScan>, String> {
        let mut running = self.write_running();
        if let Some(current) = running.as_ref() {
            return Err(current.id.clone());
        }
        let scan = Arc::new(RunningScan {
            id: id.to_string(),
            cancel: CancelToken::new(),
            finished_walking: AtomicBool::new(false),
            phase: AtomicU64::new(0),
        });
        *running = Some(Arc::clone(&scan));
        Ok(scan)
    }

    /// The running scan, if it is the one named by `id`.
    #[must_use]
    pub fn running_scan(&self, id: &str) -> Option<Arc<RunningScan>> {
        let running = self.read_running();
        running.as_ref().filter(|s| s.id == id).map(Arc::clone)
    }

    /// A snapshot of the running scan's status, whatever its id.
    #[must_use]
    pub fn any_running(&self) -> Option<ScanStatusSnapshot> {
        let running = self.read_running();
        running.as_ref().map(|s| ScanStatusSnapshot {
            scan_id: s.id.clone(),
            phase: s.phase_name().to_string(),
            walking_done: s.is_walking_done(),
        })
    }

    /// Release the slot only if it is still held by `id`.
    ///
    /// The id check is what makes [`ScanGuard`] safe: a scan that finishes late
    /// cannot cancel a newer scan that has already claimed the slot.
    pub fn end_scan_for(&self, id: &str) {
        let mut running = self.write_running();
        if running.as_ref().is_some_and(|current| current.id == id) {
            if let Some(current) = running.take() {
                current.cancel.cancel();
            }
        }
    }

    /// Abort a specific scan.
    pub fn cancel_scan(&self, id: &str) -> bool {
        let running = self.read_running();
        match running.as_ref() {
            Some(current) if current.id == id => {
                current.cancel.cancel();
                true
            }
            _ => false,
        }
    }

    /// Read the running-slot lock, recovering from poisoning.
    ///
    /// Every access goes through here. A poisoned lock used to be handled three
    /// different ways in this file — silently ignored in one place, panicked on
    /// in another — and the silent path was the one that left the slot wedged so
    /// the app could never scan again.
    fn read_running(&self) -> std::sync::RwLockReadGuard<'_, Option<Arc<RunningScan>>> {
        self.running.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Write the running-slot lock, recovering from poisoning.
    fn write_running(&self) -> std::sync::RwLockWriteGuard<'_, Option<Arc<RunningScan>>> {
        match self.running.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!("scan slot lock was poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }

    /// Record a finished scan, evicting the oldest if the store is full.
    pub fn store_scan(
        &self,
        id: &str,
        result: ScanResult,
        findings: Vec<Finding>,
    ) -> Arc<CompletedScan> {
        let summary = detect::summarise(&findings, result.total_bytes, result.elapsed_ms);

        let mut store = self.scans.write().unwrap_or_else(|e| e.into_inner());
        let sequence = store.next_sequence;
        store.next_sequence += 1;

        let completed = Arc::new(CompletedScan {
            result: Arc::new(result),
            findings: Arc::new(findings),
            summary: Arc::new(summary),
            sequence,
        });
        store.by_id.insert(id.to_string(), Arc::clone(&completed));

        while store.by_id.len() > MAX_RETAINED_SCANS && store.by_id.len() > 1 {
            if let Some(oldest) = store
                .by_id
                .iter()
                .min_by_key(|(_, s)| s.sequence)
                .map(|(k, _)| k.clone())
            {
                store.by_id.remove(&oldest);
                log::debug!("evicted scan {oldest}");
            } else {
                break;
            }
        }

        completed
    }

    /// Look up a finished scan.
    #[must_use]
    pub fn get_scan(&self, id: &str) -> Option<Arc<CompletedScan>> {
        self.scans.read().ok()?.by_id.get(id).map(Arc::clone)
    }

    /// The most recently completed scan.
    #[must_use]
    pub fn latest_scan(&self) -> Option<Arc<CompletedScan>> {
        let store = self.scans.read().ok()?;
        store
            .by_id
            .iter()
            .max_by_key(|(_, s)| s.sequence)
            .map(|(_, s)| Arc::clone(s))
    }

    /// Mounted volumes.
    #[must_use]
    pub fn volumes(&self) -> Vec<Volume> {
        diskus_core::scan::volumes()
    }

    /// Discovered user profiles.
    #[must_use]
    pub fn user_profiles(&self) -> Vec<UserProfile> {
        diskus_core::scan::user_profiles()
    }

    /// Volumes enriched with usage attributed from a finished scan.
    #[must_use]
    pub fn volumes_for(&self, scan: Option<&CompletedScan>) -> Vec<Volume> {
        let mut volumes = self.volumes();
        let Some(scan) = scan else { return volumes };

        for volume in &mut volumes {
            // Attribute a scanned root to the volume that contains it.
            if let Some(root) = scan
                .result
                .roots
                .iter()
                .find(|r| r.starts_with(&volume.mount_point))
            {
                if let Some(node) = scan.result.nodes.iter().find(|n| n.path == *root) {
                    volume.available_bytes =
                        Some(volume.total_bytes.unwrap_or(0).saturating_sub(node.size));
                }
            }
        }
        volumes
    }

    /// Profiles annotated with the sizes a finished scan observed.
    #[must_use]
    pub fn profiles_for(&self, scan: Option<&CompletedScan>) -> Vec<UserProfile> {
        let mut profiles = self.user_profiles();
        let Some(scan) = scan else { return profiles };

        for profile in &mut profiles {
            if let Some(node) = scan.result.nodes.iter().find(|n| n.path == profile.path) {
                profile.size = Some(node.size);
                profile.total_bytes =
                    diskus_core::scan::platform::volume_total_bytes(&profile.path);
            }
        }
        profiles
    }
}

/// Releases the single scan slot on drop, however the scan ends.
///
/// Only one scan runs at a time, so the slot is a resource that must be released
/// on every path — including panics. Previously an unwind skipped the explicit
/// `end_scan()` calls and left the slot occupied forever, after which every
/// `start_scan` failed with "a scan is already running" and the app could never
/// scan again without a restart.
pub struct ScanGuard {
    id: String,
}

impl ScanGuard {
    /// Take ownership of the running-slot release.
    #[must_use]
    pub fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        // The state is reachable through a thread-local handle installed by
        // `install`, so a panic anywhere in the pipeline still unwinds through a
        // release.
        let Some(state) = current_state() else { return };
        state.end_scan_for(&self.id);
    }
}

thread_local! {
    static CURRENT_STATE: std::cell::RefCell<Option<Arc<AppState>>> =
        const { std::cell::RefCell::new(None) };
}

/// Remember the active state on this thread so [`ScanGuard`] can find it.
pub fn install(state: Arc<AppState>) {
    CURRENT_STATE.with(|slot| *slot.borrow_mut() = Some(state));
}

/// The state installed on this thread, if any.
fn current_state() -> Option<Arc<AppState>> {
    CURRENT_STATE.with(|slot| slot.borrow().clone())
}

/// Emit an event to every window.
pub fn emit_to_all<S: serde::Serialize + Clone>(app: &tauri::AppHandle, event: &str, payload: S) {
    if let Err(err) = app.emit(event, payload) {
        log::warn!("failed emitting {event}: {err}");
    }
}

/// A small wrapper so commands can return a consistent error shape.
///
/// Tauri requires every error type to serialise; a plain `String` would be shown
/// to the user verbatim, so every failure carries a human message.
#[derive(Debug, serde::Serialize)]
pub struct CommandError {
    /// Human-readable explanation.
    pub message: String,
}

impl CommandError {
    /// Build an error with a formatted message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<String> for CommandError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for CommandError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

/// Result alias used by every command.
pub type CommandResult<T> = Result<T, CommandError>;

/// Emit a scan-fatal error to the UI and release the scan slot.
pub fn fail_scan<S: serde::Serialize + Clone>(
    app: &tauri::AppHandle,
    id: &str,
    state: &AppState,
    message: &str,
) -> CommandResult<S> {
    log::error!("scan {id} failed: {message}");
    state.end_scan_for(id);
    emit_to_all(
        app,
        "scan://error",
        ScanErrorPayload {
            message: message.to_string(),
        },
    );
    Err(CommandError::new(message))
}

/// Payload for the `scan://error` event.
#[derive(serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScanErrorPayload {
    /// What went wrong, in words a user can act on.
    pub message: String,
}

/// Default configuration, with roots filled in.
#[must_use]
pub fn default_config() -> ScanConfig {
    ScanConfig {
        roots: diskus_core::scan::default_roots(),
        ..ScanConfig::default()
    }
}

/// The treemap tree for a scan.
#[must_use]
pub fn tree_for(
    scan: &CompletedScan,
    options: &diskus_core::viz::VizOptions,
) -> diskus_core::viz::VizNode {
    diskus_core::viz::build_tree(&scan.result, options)
}
