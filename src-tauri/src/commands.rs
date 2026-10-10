//! The Tauri command surface.
//!
//! Two rules govern this module:
//!
//! * **Nothing long-running is awaited on the UI thread.** `start_scan` returns a
//!   scan id immediately and does the work on a blocking thread, reporting back
//!   through events. A scan of a large volume takes minutes; blocking the command
//!   would freeze the window for the duration.
//! * **No command has any way to reach the network.** There is no HTTP client in
//!   the dependency graph, and nothing here adds one.

use crate::state::{
    AppState, CommandError, CommandResult, CompletedScan, ScanStatusSnapshot, emit_to_all,
    fail_scan,
};
use diskus_core::config::{ExportRequest, ScanConfig};
use diskus_core::detect;
use diskus_core::model::{Finding, ScanResult, UserProfile, Volume};
use diskus_core::scan::walker::{FnObserver, Progress, walk};
use diskus_core::scan::{user_profiles, volumes};
use diskus_core::viz::{self, VizNode, VizOptions};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tauri::{AppHandle, Manager, State};

/// Default configuration with platform roots filled in.
#[tauri::command]
pub fn get_default_config() -> ScanConfig {
    crate::state::default_config()
}

/// Mounted volumes, with free and total space.
#[tauri::command]
pub fn list_volumes() -> Vec<Volume> {
    volumes()
}

/// User home directories found on this machine.
#[tauri::command]
pub fn list_user_profiles() -> Vec<UserProfile> {
    user_profiles()
}

/// Payload for `scan://started`.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StartedPayload {
    /// Scan identifier.
    pub scan_id: String,
    /// Roots being walked.
    pub roots: Vec<String>,
}

/// Begin a scan and return its id straight away.
///
/// The walk happens on a blocking thread and reports through events, so this
/// never blocks the window.
#[tauri::command]
pub fn start_scan(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    config: ScanConfig,
) -> CommandResult<String> {
    let id = state.new_scan_id();

    if let Err(current) = state.begin_scan(&id) {
        return Err(CommandError::new(format!(
            "A scan is already running ({current}). Stop it before starting another."
        )));
    }
    let running = match state.running_scan(&id) {
        Some(running) => running,
        None => {
            // The slot was claimed a moment ago; failing here without releasing
            // it would wedge the app permanently.
            state.end_scan_for(&id);
            return Err(CommandError::new(
                "Could not start the scan. Please try again.",
            ));
        }
    };

    emit_to_all(
        &app,
        "scan://started",
        StartedPayload {
            scan_id: id.clone(),
            roots: config
                .roots
                .iter()
                .map(|r| r.to_string_lossy().to_string())
                .collect(),
        },
    );

    let handle = app.clone();
    let scan_id = id.clone();
    let cancel = running.cancel.clone();

    // `spawn_blocking` runs on Tauri's blocking pool. A full-filesystem walk is
    // exactly the kind of blocking work it exists for.
    tauri::async_runtime::spawn_blocking(move || {
        run_scan(handle, scan_id, config, cancel);
    });

    Ok(id)
}

/// The actual scan pipeline: walk, then detect, then publish.
fn run_scan(
    app: AppHandle,
    scan_id: String,
    config: ScanConfig,
    cancel: diskus_core::scan::CancelToken,
) {
    let state = app.state::<Arc<AppState>>();

    // Released on every exit path *including* an unwind. Without this a panic
    // anywhere below left the single scan slot occupied forever, and every
    // subsequent scan failed with "a scan is already running".
    let _guard = crate::state::ScanGuard::new(&scan_id);

    // ---- Phase 1: walk -----------------------------------------------------
    // The observer must be `'static`, so each closure takes its own clone of the
    // handle rather than borrowing the one the pipeline is running under.
    let progress_app = app.clone();
    let directory_app = app.clone();
    let observer = FnObserver::new(
        move |p: &Progress| emit_to_all(&progress_app, "scan://progress", ProgressPayload::from(p)),
        move |node: &diskus_core::model::ScanNode| {
            emit_to_all(
                &directory_app,
                "scan://directory",
                DirectoryPayload::from(node),
            )
        },
    );

    let mut result: ScanResult = match walk(&config, &cancel, &observer) {
        Ok(result) => result,
        Err(err) => {
            let _ = fail_scan::<()>(&app, &scan_id, &state, &err.to_string());
            return;
        }
    };
    result.id = scan_id.clone();

    if let Some(running) = state.running_scan(&scan_id) {
        running.finished_walking.store(true, Ordering::Relaxed);
        running.phase.store(1, Ordering::Relaxed);
    }

    // ---- Phase 2: detect --------------------------------------------------
    // Duplicate detection reads file contents to hash them, which is the only
    // I/O-heavy phase after the walk. The UI is told so it can say why this
    // takes a while instead of appearing to hang.
    // Detection is cancellable too: hashing duplicates is the only phase that
    // can run for minutes, and the Stop button has to work during it.
    let started = std::time::Instant::now();
    let findings: Vec<Finding> = detect::run_all_cancellable(&result, &config, &cancel);
    log::info!(
        "detection produced {} findings in {:?}",
        findings.len(),
        started.elapsed()
    );

    if cancel.is_cancelled() {
        log::info!("scan {scan_id} cancelled before results were published");
        emit_to_all(&app, "scan://cancelled", CancelledPayload { scan_id });
        return;
    }

    // ---- Phase 3: publish -------------------------------------------------
    let completed = state.store_scan(&scan_id, result, findings);
    if let Some(running) = state.running_scan(&scan_id) {
        running.phase.store(3, Ordering::Relaxed);
    }

    emit_to_all(
        &app,
        "scan://complete",
        CompletePayload {
            scan_id: scan_id.clone(),
            total_bytes: completed.result.total_bytes,
            total_files: completed.result.total_files,
            total_dirs: completed.result.total_dirs,
            elapsed_ms: completed.result.elapsed_ms,
            finding_count: completed.findings.len(),
            total_reclaimable: completed.summary.total_reclaimable,
            truncated: completed.result.truncated.clone(),
            denied_paths: completed.result.denied_paths.len(),
            errors_skipped: completed.result.errors_skipped,
        },
    );
}

/// Ask the running scan to stop.
///
/// Returns whether a matching scan was actually running, so the UI can warn if
/// the id is stale rather than silently doing nothing.
#[tauri::command]
pub fn cancel_scan(state: State<'_, Arc<AppState>>, scan_id: String) -> bool {
    state.cancel_scan(&scan_id)
}

/// Whether a scan is currently running, and which phase it is in.
#[tauri::command]
pub fn scan_status(state: State<'_, Arc<AppState>>) -> Option<ScanStatusSnapshot> {
    state.any_running()
}

/// Run detection again against a stored scan, without re-walking the filesystem.
///
/// Useful after changing a threshold: re-detecting is seconds, re-scanning is
/// minutes.
#[tauri::command]
pub fn rerun_detect(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    scan_id: String,
    config: ScanConfig,
) -> CommandResult<DetectResult> {
    let Some(scan) = state.get_scan(&scan_id) else {
        return Err(CommandError::new(
            "That scan is no longer available. Run a new scan.",
        ));
    };

    emit_to_all(
        &app,
        "detect://started",
        DetectStarted {
            scan_id: scan_id.clone(),
        },
    );
    let findings = detect::run_all_cancellable(
        &scan.result,
        &config,
        &diskus_core::scan::CancelToken::new(),
    );
    let summary = detect::summarise(&findings, scan.result.total_bytes, scan.result.elapsed_ms);
    Ok(DetectResult { findings, summary })
}

/// Findings and rollups from a detection run.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DetectResult {
    /// Every finding, already sorted most-urgent first.
    pub findings: Vec<Finding>,
    /// Aggregate numbers for the dashboard.
    pub summary: diskus_core::model::ScanSummary,
}

/// Payload for `detect://started`.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DetectStarted {
    /// Scan the detection is running against.
    pub scan_id: String,
}

/// Everything the dashboard needs for a completed scan, in one round trip.
#[tauri::command]
pub fn get_results(
    state: State<'_, Arc<AppState>>,
    scan_id: Option<String>,
) -> CommandResult<ResultsPayload> {
    let scan = match scan_id {
        Some(id) => state
            .get_scan(&id)
            .ok_or_else(|| CommandError::new("That scan is no longer available."))?,
        None => state
            .latest_scan()
            .ok_or_else(|| CommandError::new("No scan has been run yet."))?,
    };

    Ok(ResultsPayload::build(&scan, &state))
}

/// The dashboard's complete data set.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResultsPayload {
    /// Which scan this describes.
    pub scan_id: String,
    /// Findings, sorted.
    pub findings: Vec<Finding>,
    /// Rollups.
    pub summary: diskus_core::model::ScanSummary,
    /// Volumes, with usage attributed.
    pub volumes: Vec<Volume>,
    /// User profiles, with observed sizes.
    pub profiles: Vec<UserProfile>,
    /// Treemap tree.
    pub tree: VizNode,
    /// Largest individual files.
    pub top_files: Vec<viz::TopFile>,
    /// Walk statistics.
    pub stats: ScanStats,
}

impl ResultsPayload {
    fn build(scan: &Arc<CompletedScan>, state: &AppState) -> Self {
        let tree = crate::state::tree_for(scan, &VizOptions::default());
        let top_files = viz::top_files(&scan.result, 200);
        Self {
            scan_id: scan.result.id.clone(),
            findings: scan.findings.as_ref().clone(),
            summary: scan.summary.as_ref().clone(),
            volumes: state.volumes_for(Some(scan)),
            profiles: state.profiles_for(Some(scan)),
            tree,
            top_files,
            stats: ScanStats {
                total_bytes: scan.result.total_bytes,
                total_on_disk: scan.result.total_on_disk(),
                total_files: scan.result.total_files,
                total_dirs: scan.result.total_dirs,
                elapsed_ms: scan.result.elapsed_ms,
                denied_paths: scan.result.denied_paths.len(),
                errors_skipped: scan.result.errors_skipped,
                truncated: scan.result.truncated.clone(),
                cancelled: scan.result.cancelled,
                roots: scan
                    .result
                    .roots
                    .iter()
                    .map(|r| r.to_string_lossy().to_string())
                    .collect(),
            },
        }
    }
}

/// Walk statistics, surfaced so the UI can be honest about what it saw.
#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanStats {
    /// Bytes seen.
    pub total_bytes: u64,
    /// Bytes actually allocated.
    pub total_on_disk: u64,
    /// Files counted.
    pub total_files: u64,
    /// Directories counted.
    pub total_dirs: u64,
    /// Walk duration.
    pub elapsed_ms: u64,
    /// Paths the OS refused to read.
    pub denied_paths: usize,
    /// Entries skipped without a known path.
    pub errors_skipped: u64,
    /// Present when itemisation was trimmed.
    pub truncated: Option<String>,
    /// Whether the user aborted the walk.
    pub cancelled: bool,
    /// Roots scanned.
    pub roots: Vec<String>,
}

/// Progress event forwarded to the UI.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProgressPayload {
    /// Files counted.
    pub files: u64,
    /// Directories counted.
    pub dirs: u64,
    /// Bytes seen.
    pub bytes: u64,
    /// Path currently being read.
    pub current_path: String,
    /// Elapsed milliseconds.
    pub elapsed_ms: u64,
}

impl From<&Progress> for ProgressPayload {
    fn from(p: &Progress) -> Self {
        Self {
            files: p.files,
            dirs: p.dirs,
            bytes: p.bytes,
            current_path: p.current_path.clone(),
            elapsed_ms: p.elapsed_ms,
        }
    }
}

/// Live directory event forwarded to the UI.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryPayload {
    /// Path of the directory.
    pub path: String,
    /// Final path component.
    pub name: String,
    /// Depth below the scan root.
    pub depth: u16,
    /// Size accumulated so far.
    pub size: u64,
    /// Bytes allocated so far.
    pub on_disk: u64,
}

impl From<&diskus_core::model::ScanNode> for DirectoryPayload {
    fn from(n: &diskus_core::model::ScanNode) -> Self {
        Self {
            path: n.path.to_string_lossy().to_string(),
            name: n.name.clone(),
            depth: n.depth,
            size: n.size,
            on_disk: n.on_disk,
        }
    }
}

/// Payload for `scan://complete`.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CompletePayload {
    /// Which scan finished.
    pub scan_id: String,
    /// Bytes scanned.
    pub total_bytes: u64,
    /// Files scanned.
    pub total_files: u64,
    /// Directories scanned.
    pub total_dirs: u64,
    /// Walk duration.
    pub elapsed_ms: u64,
    /// Findings produced.
    pub finding_count: usize,
    /// Total reclaimable bytes.
    pub total_reclaimable: u64,
    /// Set when itemisation was trimmed.
    pub truncated: Option<String>,
    /// Unreadable paths encountered.
    pub denied_paths: usize,
    /// Entries skipped without a known path.
    pub errors_skipped: u64,
}

/// Payload for `scan://cancelled`.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CancelledPayload {
    /// The scan that stopped.
    pub scan_id: String,
}

/// Write report files.
///
/// `output_dir` is chosen by the user through the OS folder picker, so this only
/// ever writes where they pointed it.
#[tauri::command]
pub fn export_report(request: ExportRequest, output_dir: String) -> CommandResult<Vec<PathBuf>> {
    let dir = PathBuf::from(&output_dir);
    if !dir.is_dir() {
        return Err(CommandError::new(format!("{output_dir} is not a folder.")));
    }
    if request.formats.is_empty() {
        return Err(CommandError::new("Choose at least one report format."));
    }

    let written = diskus_core::report::write_reports(&request, &dir);
    if written.is_empty() {
        return Err(CommandError::new(
            "Nothing was written. Check that the folder is writable.",
        ));
    }

    Ok(written.into_iter().map(|w| w.path).collect())
}
