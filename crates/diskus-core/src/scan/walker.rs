//! The filesystem walker.
//!
//! Design notes, because these constraints are not obvious:
//!
//! * **Parallel, but deterministically ordered.** `ignore`'s parallel walker
//!   hands entries to whichever thread is free, so results arrive shuffled.
//!   Every detector groups by parent path, so the walk sorts by path before
//!   returning. Without that, detector output changes run to run.
//! * **Aggregates are filled in a separate pass.** Computing a directory's size
//!   while its children are still arriving across threads is a data race. So
//!   the walk only records raw per-file sizes; [`aggregate_bottom_up`] then
//!   rolls children up into parents once everything is known.
//! * **Nothing is fatal.** A permission error is recorded and the walk
//!   continues. A scan always finishes, and always reports what it could not
//!   see.

use crate::config::{DETAIL_FILE_FLOOR, ScanConfig};
use crate::model::{Bytes, FileKind, ScanNode, ScanResult};
use crate::scan::cancel::CancelToken;
use crate::scan::platform;
use crate::util;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

/// Cap on entries held in the hardlink-dedupe map before it gives up.
///
/// Only files with a link count above one are ever inserted, so this is rarely
/// approached; it exists so a pathological filesystem cannot grow the map
/// without bound. Past the cap, hardlinked files are counted individually, which
/// over-reports slightly rather than truncating the scan.
const MAX_INODE_ENTRIES: usize = 2_000_000;

/// How often the cancellation flag is checked, in entries.
const CANCEL_CHECK_INTERVAL: u32 = 512;

/// Minimum gap between `on_progress` callbacks, in milliseconds.
const PROGRESS_INTERVAL_MS: u64 = 16;

/// Minimum gap between `on_directory` callbacks, in milliseconds.
const DIRECTORY_INTERVAL_MS: u64 = 33;

/// How the caller hears about scan progress.
///
/// Callbacks are invoked from arbitrary worker threads, so anything they touch
/// must be synchronised. Throttling happens inside the walker: firing per entry
/// would make the event channel, not the filesystem, the bottleneck.
pub trait ScanObserver: Send + Sync {
    /// Called periodically with cumulative counters.
    fn on_progress(&self, progress: &Progress);

    /// Called for directories as they complete, so the UI can grow its treemap
    /// live instead of waiting for the whole scan.
    fn on_directory(&self, node: &ScanNode);
}

/// An observer that drops everything. For tests and headless runs.
pub struct SilentObserver;

impl ScanObserver for SilentObserver {
    fn on_progress(&self, _: &Progress) {}
    fn on_directory(&self, _: &ScanNode) {}
}

/// An observer built from closures, for the Tauri layer.
pub struct FnObserver {
    progress: Box<dyn Fn(&Progress) + Send + Sync>,
    directory: Box<dyn Fn(&ScanNode) + Send + Sync>,
}

impl FnObserver {
    /// Build an observer from a progress closure and a directory closure.
    pub fn new(
        progress: impl Fn(&Progress) + Send + Sync + 'static,
        directory: impl Fn(&ScanNode) + Send + Sync + 'static,
    ) -> Self {
        Self {
            progress: Box::new(progress),
            directory: Box::new(directory),
        }
    }
}

impl ScanObserver for FnObserver {
    fn on_progress(&self, p: &Progress) {
        (self.progress)(p);
    }
    fn on_directory(&self, d: &ScanNode) {
        (self.directory)(d);
    }
}

/// A snapshot of how far the walk has got.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    /// Files counted so far.
    pub files: u64,
    /// Directories counted so far.
    pub dirs: u64,
    /// Bytes seen so far.
    pub bytes: Bytes,
    /// Most recently visited path, for the UI's "currently reading" line.
    pub current_path: String,
    /// Milliseconds elapsed.
    pub elapsed_ms: u64,
}

/// State shared across all worker threads.
struct Shared {
    nodes: Mutex<Vec<ScanNode>>,
    denied: Mutex<Vec<PathBuf>>,
    counters: Mutex<Counters>,
    /// Inode identities of multi-linked files already counted.
    seen_inodes: Mutex<HashMap<InodeKey, ()>>,
    truncated: Mutex<Option<String>>,
    cancelled: Mutex<bool>,
    /// Walker errors that could not be attributed to a specific path, because
    /// `ignore::Error` does not carry one.
    unattributed_errors: std::sync::atomic::AtomicU64,
}

#[derive(Default)]
struct Counters {
    files: u64,
    dirs: u64,
    bytes: Bytes,
    last_progress_ms: u64,
    last_dir_ms: u64,
    entries_since_cancel_check: u32,
    last_reported_path: Mutex<String>,
}

impl Counters {
    fn snapshot(&self, current_path: String, elapsed_ms: u64) -> Progress {
        Progress {
            files: self.files,
            dirs: self.dirs,
            bytes: self.bytes,
            current_path,
            elapsed_ms,
        }
    }
}

/// Walk `config.roots` and build a complete [`ScanResult`].
///
/// # Errors
///
/// Returns an error only when nothing at all could be read. Partial failures are
/// recorded in [`ScanResult::denied_paths`] and never abort the scan.
pub fn walk(
    config: &ScanConfig,
    cancel: &CancelToken,
    observer: &dyn ScanObserver,
) -> Result<ScanResult, WalkError> {
    let started_at = util::now();
    let clock = Instant::now();

    let roots = resolve_roots(config);
    if roots.is_empty() {
        return Err(WalkError::NoRoots);
    }

    let shared = Shared {
        nodes: Mutex::new(Vec::new()),
        denied: Mutex::new(Vec::new()),
        counters: Mutex::new(Counters {
            last_reported_path: Mutex::new(String::new()),
            ..Counters::default()
        }),
        seen_inodes: Mutex::new(HashMap::new()),
        truncated: Mutex::new(None),
        cancelled: Mutex::new(false),
        unattributed_errors: std::sync::atomic::AtomicU64::new(0),
    };

    let builder = make_builder(config, &roots);
    let root_components = roots
        .iter()
        .map(|r| r.components().count())
        .min()
        .unwrap_or(0);

    // Bound as shared references *outside* the `move` closure. `&T` is `Copy`, so
    // each factory call copies the reference rather than moving the state, and
    // `walk` keeps ownership of `shared` for the unwinding below.
    let shared_ref = &shared;
    let config_ref = config;
    let cancel_ref = cancel;
    let observer_ref = observer;

    // `WalkParallel` spawns one thread per worker thread and calls this factory
    // for each. Each thread gets its own `Processor`, but they all point at the
    // same `Shared` mutexes and the same `Observer`.
    builder.build_parallel().run(|| {
        Box::new(move |entry: Result<ignore::DirEntry, ignore::Error>| {
            Processor {
                config: config_ref,
                shared: shared_ref,
                cancel: cancel_ref,
                observer: observer_ref,
                clock,
                root_components,
            }
            .process(entry)
        })
            as Box<dyn FnMut(Result<ignore::DirEntry, ignore::Error>) -> ignore::WalkState + Send>
    });

    let cancelled = *shared.cancelled.lock().expect("cancelled lock");
    let skipped = shared
        .unattributed_errors
        .load(std::sync::atomic::Ordering::Relaxed);

    // Totals come from the live counters, not from the node list. In summary
    // mode the node list is deliberately trimmed, so deriving totals from it
    // would silently report a near-empty scan as if the disk were empty.
    let (total_files, total_dirs, total_bytes) = {
        let c = shared.counters.lock().expect("counters lock");
        (c.files, c.dirs, c.bytes)
    };

    let denied = shared.denied.into_inner().expect("denied lock");
    let truncated = shared.truncated.into_inner().expect("truncated lock");
    let nodes = shared.nodes.into_inner().expect("nodes lock");

    if nodes.is_empty() && denied.len() >= roots.len() {
        return Err(WalkError::AllRootsDenied { denied });
    }

    // Deterministic order: a prerequisite for every detector, not cosmetics.
    let mut nodes = nodes;
    nodes.sort_by(|a, b| a.path.cmp(&b.path));
    aggregate_bottom_up(&mut nodes);

    Ok(ScanResult {
        id: String::new(),
        started_at,
        finished_at: Some(util::now()),
        roots,
        nodes,
        total_bytes,
        total_files,
        total_dirs,
        denied_paths: denied,
        errors_skipped: skipped,
        elapsed_ms: u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX),
        cancelled,
        truncated,
    })
}

/// Why a scan could not run at all.
#[derive(Debug, thiserror::Error)]
pub enum WalkError {
    /// No usable root could be determined.
    #[error("No scannable locations were found.")]
    NoRoots,
    /// Every root was unreadable.
    #[error("Every scan location was unreadable: {denied:?}. Check folder permissions.")]
    AllRootsDenied {
        /// The roots that failed.
        denied: Vec<PathBuf>,
    },
}

/// Pick the roots to walk: the configured ones, or sensible defaults.
///
/// Unreadable roots are dropped rather than fatal; the caller only errors if
/// nothing at all survives.
fn resolve_roots(config: &ScanConfig) -> Vec<PathBuf> {
    let candidates = if config.roots.is_empty() {
        platform::default_roots()
    } else {
        config.roots.clone()
    };

    let mut roots: Vec<PathBuf> = Vec::new();
    for candidate in candidates {
        if config.is_excluded(&candidate) {
            continue;
        }
        if let Ok(p) = std::fs::canonicalize(&candidate) {
            if p.is_dir() && !roots.contains(&p) {
                roots.push(p);
            }
        }
    }
    roots
}

fn make_builder(config: &ScanConfig, roots: &[PathBuf]) -> ignore::WalkBuilder {
    let mut builder = ignore::WalkBuilder::new(&roots[0]);
    for root in roots.iter().skip(1) {
        builder.add(root);
    }

    // We want *everything*. `ignore`'s defaults — respect `.gitignore`, skip
    // hidden, honour global excludes — are right for a linter and exactly wrong
    // here: a 4 GB `.venv` and a 40 GB `node_modules` are among the most
    // important things on the machine to find.
    builder
        .hidden(!config.include_hidden)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .ignore(false)
        .parents(false)
        .follow_links(config.follow_symlinks)
        .max_depth(config.max_depth.map(usize::from))
        .threads(config.thread_count())
        .same_file_system(false);

    builder
}

/// Shared handler for the parallel walker.
///
/// `WalkParallel` calls this once per entry from several worker threads at once,
/// so every field here must be `Sync`. That is why all mutable state lives
/// behind the mutexes in [`Shared`] rather than in the struct itself.
struct Processor<'a> {
    config: &'a ScanConfig,
    shared: &'a Shared,
    cancel: &'a CancelToken,
    observer: &'a dyn ScanObserver,
    clock: Instant,
    /// Component count of the shallowest root, used to compute relative depth.
    root_components: usize,
}

impl Processor<'_> {
    /// Handle one entry, returning whether the walk should keep going.
    fn process(&self, entry: Result<ignore::DirEntry, ignore::Error>) -> ignore::WalkState {
        match entry {
            Ok(entry) => {
                if self.cancel.is_cancelled() {
                    *self.shared.cancelled.lock().expect("cancelled lock") = true;
                    return ignore::WalkState::Quit;
                }
                self.tick_cancellation();

                let path = entry.path();
                if self.config.is_excluded(path) {
                    return ignore::WalkState::Continue;
                }
                match self.visit(&entry) {
                    VisitOutcome::Handled => ignore::WalkState::Continue,
                    VisitOutcome::Cancelled => ignore::WalkState::Quit,
                }
            }
            Err(err) => {
                self.note_walk_error(&err);
                ignore::WalkState::Continue
            }
        }
    }

    /// Throttled cancellation check. An uncontended relaxed atomic load every
    /// 512 entries costs nothing measurable but caps abort latency.
    fn tick_cancellation(&self) {
        let mut c = self.shared.counters.lock().expect("counters lock");
        c.entries_since_cancel_check += 1;
        if c.entries_since_cancel_check >= CANCEL_CHECK_INTERVAL {
            c.entries_since_cancel_check = 0;
            if self.cancel.is_cancelled() {
                drop(c);
                *self.shared.cancelled.lock().expect("cancelled lock") = true;
            }
        }
    }

    /// Record a walker error.
    ///
    /// `ignore::Error` does not expose the offending path, so only errors raised at
    /// a known entry (where [`Worker::visit`] holds the path) contribute to
    /// `denied_paths`. Everything else is counted, not misattributed to a guess.
    fn note_walk_error(&self, err: &ignore::Error) {
        if let Some(io) = err.io_error() {
            let denied = matches!(
                io.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
            );
            self.shared
                .unattributed_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::debug!("walker error (denied={denied}): {err}");
            return;
        }
        self.shared
            .unattributed_errors
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        log::warn!("walker error: {err}");
    }

    fn record_failure(&self, path: PathBuf) {
        log::debug!("skipping {path:?}: unreadable");
        self.shared.denied.lock().expect("denied lock").push(path);
    }

    fn visit(&self, entry: &ignore::DirEntry) -> VisitOutcome {
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            self.record_failure(path.to_path_buf());
            return VisitOutcome::Handled;
        };

        let name = path.file_name().map_or_else(
            || path.to_string_lossy().to_string(),
            |n| n.to_string_lossy().to_string(),
        );

        let is_symlink = entry.file_type().is_some_and(|ft| ft.is_symlink());
        let kind = if is_symlink {
            FileKind::Symlink
        } else if metadata.is_dir() {
            FileKind::Dir
        } else if metadata.is_file() {
            FileKind::File
        } else {
            FileKind::Other
        };

        let apparent = metadata.len();
        let allocated = platform::allocated_size(&metadata).unwrap_or(apparent);

        // Hardlinks share one inode and one copy of the bytes. Counting each
        // link would inflate the total and make every downstream number wrong.
        let deduped = kind == FileKind::File && self.is_duplicate_inode(path, &metadata);
        let (size, on_disk) = match kind {
            FileKind::File => {
                if deduped {
                    (0, 0)
                } else {
                    (apparent, allocated)
                }
            }
            // Filled in by `aggregate_bottom_up` once every child is known.
            FileKind::Dir => (0, 0),
            // A symlink occupies only the link itself. Following it is opt-in and
            // handled by the walker's `follow_links` setting.
            FileKind::Symlink | FileKind::Other => (0, allocated),
        };

        let node = ScanNode {
            path: path.to_path_buf(),
            name,
            parent: path.parent().map(Path::to_path_buf),
            depth: self.relative_depth(path),
            kind,
            size,
            on_disk,
            modified: platform::modified(&metadata).map(util::to_offset),
            accessed: platform::accessed(&metadata).map(util::to_offset),
            created: platform::created(&metadata).map(util::to_offset),
            extension: util::extension_of(path),
            hidden: platform::is_hidden(path, &metadata),
            symlink_target: if is_symlink {
                std::fs::read_link(path).ok()
            } else {
                None
            },
            content_hash: None,
            child_count: 0,
            file_count: 0,
            dir_count: 0,
            error: None,
        };

        if kind == FileKind::File {
            let mut c = self.shared.counters.lock().expect("counters lock");
            c.files += 1;
            c.bytes += size;
            drop(c);
        } else if kind == FileKind::Dir {
            let mut c = self.shared.counters.lock().expect("counters lock");
            c.dirs += 1;
            drop(c);
        }

        let is_dir = node.is_dir();
        if is_dir {
            self.report_directory(&node);
        } else {
            self.maybe_report_progress(&node.path);
        }
        self.push(node);

        if self.cancel.is_cancelled() {
            *self.shared.cancelled.lock().expect("cancelled lock") = true;
            VisitOutcome::Cancelled
        } else {
            VisitOutcome::Handled
        }
    }

    /// Depth below the shallowest scan root.
    fn relative_depth(&self, path: &Path) -> u16 {
        let components = path.components().count();
        u16::try_from(components.saturating_sub(self.root_components)).unwrap_or(u16::MAX)
    }

    /// Whether this inode's bytes have already been counted.
    ///
    /// Unix can cheaply skip single-link files. Windows records file identities
    /// through the safe `same-file` API because stable std metadata has no link
    /// count accessor. The map is capped in either case.
    fn is_duplicate_inode(&self, path: &Path, metadata: &std::fs::Metadata) -> bool {
        let Some(key) = inode_key(path, metadata) else {
            return false;
        };
        let mut seen = self.shared.seen_inodes.lock().expect("inodes lock");
        if seen.len() >= MAX_INODE_ENTRIES {
            return false;
        }
        seen.insert(key, ()).is_some()
    }

    fn push(&self, node: ScanNode) {
        let mut nodes = self.shared.nodes.lock().expect("nodes lock");

        if self
            .shared
            .truncated
            .lock()
            .expect("truncated lock")
            .is_some()
        {
            // Summary mode: keep only what a report can still say something
            // useful about, so the interesting files survive.
            if node.is_dir() || node.on_disk >= DETAIL_FILE_FLOOR {
                nodes.push(node);
            }
            return;
        }

        if nodes.len() >= self.config.max_nodes {
            drop(nodes);
            self.enter_summary_mode();
            return;
        }
        nodes.push(node);
    }

    /// Switch to summary mode, reclaiming memory by discarding small files.
    fn enter_summary_mode(&self) {
        {
            let mut truncated = self.shared.truncated.lock().expect("truncated lock");
            if truncated.is_some() {
                return;
            }
            *truncated = Some(format!(
                "More than {} entries were found. Only directories and files above {} are \
                 itemised individually; totals and all findings remain accurate.",
                util::human_count(self.config.max_nodes as u64),
                util::human_bytes(DETAIL_FILE_FLOOR)
            ));
        }

        let mut nodes = self.shared.nodes.lock().expect("nodes lock");
        nodes.retain(|n| n.is_dir() || n.on_disk >= DETAIL_FILE_FLOOR);
        if nodes.len() > self.config.max_nodes {
            nodes.truncate(self.config.max_nodes);
        }
        log::warn!(
            "summary mode: retained {} of the entries found",
            nodes.len()
        );
    }

    fn report_directory(&self, node: &ScanNode) {
        let snapshot = {
            let mut c = self.shared.counters.lock().expect("counters lock");
            let elapsed = self.elapsed_ms();
            if elapsed.saturating_sub(c.last_dir_ms) < DIRECTORY_INTERVAL_MS {
                return;
            }
            c.last_dir_ms = elapsed;
            let path_string = node.path.to_string_lossy().to_string();
            *c.last_reported_path.lock().expect("path lock") = path_string.clone();
            c.snapshot(path_string, elapsed)
        };
        self.observer.on_directory(node);
        self.observer.on_progress(&snapshot);
    }

    fn maybe_report_progress(&self, path: &Path) {
        let snapshot = {
            let mut c = self.shared.counters.lock().expect("counters lock");
            let elapsed = self.elapsed_ms();
            if elapsed.saturating_sub(c.last_progress_ms) < PROGRESS_INTERVAL_MS {
                return;
            }
            c.last_progress_ms = elapsed;
            let path_string = path.to_string_lossy().to_string();
            *c.last_reported_path.lock().expect("path lock") = path_string.clone();
            c.snapshot(path_string, elapsed)
        };
        self.observer.on_progress(&snapshot);
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// What happened when a single entry was visited.
enum VisitOutcome {
    /// Recorded or skipped; keep going.
    Handled,
    /// Cancellation was noticed mid-entry; stop this worker.
    Cancelled,
}

/// Identity of a filesystem object, for hardlink deduplication.
#[derive(Debug, Eq, Hash, PartialEq)]
enum InodeKey {
    #[cfg(unix)]
    Unix(u64, u64),
    #[cfg(windows)]
    Windows(u64, u64),
}

#[cfg(unix)]
fn inode_key(_: &Path, metadata: &std::fs::Metadata) -> Option<InodeKey> {
    use std::os::unix::fs::MetadataExt;
    (metadata.nlink() > 1).then_some(InodeKey::Unix(metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn inode_key(path: &Path, _: &std::fs::Metadata) -> Option<InodeKey> {
    use std::hash::{DefaultHasher, Hash, Hasher};

    // The safe `same-file` API obtains the stable Windows file identity without
    // relying on unstable std::fs::MetadataExt methods. Hash it twice with
    // separate domains so the scan stores a compact key, not an open file handle.
    let handle = same_file::Handle::from_path(path).ok()?;
    let mut first = DefaultHasher::new();
    0_u8.hash(&mut first);
    handle.hash(&mut first);
    let mut second = DefaultHasher::new();
    1_u8.hash(&mut second);
    handle.hash(&mut second);
    Some(InodeKey::Windows(first.finish(), second.finish()))
}

#[cfg(not(any(unix, windows)))]
fn inode_key(_: &Path, _: &std::fs::Metadata) -> Option<InodeKey> {
    None
}

/// Roll every directory's subtree totals up from its children.
///
/// Runs after the parallel walk, single-threaded, deepest-first. Sorting by path
/// component count (rather than the `depth` field, which is only advisory across
/// mixed-depth roots) guarantees a child is always processed before its parent,
/// because a path always has more components than its parent.
pub(crate) fn aggregate_bottom_up(nodes: &mut [ScanNode]) {
    // Resolve every parent link and the processing order up front. The index
    // borrows `nodes` immutably, so it must go out of scope before the mutation
    // loop below borrows mutably.
    let (parent_of, order) = {
        let mut index: HashMap<&Path, usize> = HashMap::with_capacity(nodes.len());
        let mut depths: Vec<usize> = Vec::with_capacity(nodes.len());
        for (i, node) in nodes.iter().enumerate() {
            index.insert(node.path.as_path(), i);
            depths.push(node.path.components().count());
        }
        let parents: Vec<Option<usize>> = nodes
            .iter()
            .map(|node| node.parent.as_deref().and_then(|p| index.get(p).copied()))
            .collect();
        let mut order: Vec<usize> = (0..nodes.len()).collect();
        // A child always has more path components than its parent, so descending
        // by component count guarantees children are processed first. Sorting on
        // the advisory `depth` field would not: roots can sit at different
        // nesting depths, e.g. `/home` alongside `/Users/jdoe`.
        order.sort_unstable_by_key(|&i| std::cmp::Reverse(depths[i]));
        (parents, order)
    };

    // Leaf-level counts. Everything else accumulates below.
    for node in nodes.iter_mut() {
        node.child_count = 0;
        node.file_count = u64::from(node.kind == FileKind::File);
        node.dir_count = 0;
    }

    for i in order {
        let Some(pi) = parent_of[i] else { continue };
        let (size, on_disk, files, dirs, is_dir) = {
            let n = &nodes[i];
            (n.size, n.on_disk, n.file_count, n.dir_count, n.is_dir())
        };
        let p = &mut nodes[pi];
        p.size = p.size.saturating_add(size);
        p.on_disk = p.on_disk.saturating_add(on_disk);
        p.file_count = p.file_count.saturating_add(files);
        p.dir_count = p
            .dir_count
            .saturating_add(dirs)
            .saturating_add(u64::from(is_dir));
        p.child_count = p.child_count.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a synthetic tree of files with explicit byte sizes.
    fn build_tree(files: &[(&str, usize)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (rel, size) in files {
            let path = dir.path().join(rel);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(&path, vec![0_u8; *size]).expect("write");
        }
        dir
    }

    /// The canonical path of a temp directory.
    ///
    /// On macOS `tempfile` hands back `/var/folders/...`, which is a symlink to
    /// `/private/var/folders/...`. The walker canonicalises its roots, so node
    /// paths come back under the resolved prefix — comparing against the raw
    /// temp path would silently match nothing.
    fn root_of(dir: &tempfile::TempDir) -> std::path::PathBuf {
        dir.path().canonicalize().expect("canonical root")
    }

    fn scan(_dir: &tempfile::TempDir, config: &ScanConfig) -> ScanResult {
        let cancel = CancelToken::new();
        walk(config, &cancel, &SilentObserver).expect("walk should succeed")
    }

    fn config_for(dir: &tempfile::TempDir) -> ScanConfig {
        ScanConfig {
            roots: vec![root_of(dir)],
            ..ScanConfig::default()
        }
    }

    #[test]
    fn aggregates_sizes_up_the_tree() {
        let dir = build_tree(&[
            ("a.bin", 1000),
            ("sub/b.bin", 2000),
            ("sub/deeper/c.bin", 3000),
            ("sub/deeper/d.bin", 4000),
        ]);

        let result = scan(&dir, &config_for(&dir));

        let root = result
            .nodes
            .iter()
            .find(|n| n.path == root_of(&dir))
            .expect("root node");
        assert_eq!(root.size, 10_000, "root sums the whole subtree");
        assert_eq!(root.file_count, 4);
        assert_eq!(root.child_count, 2, "two direct children: a.bin and sub");

        let sub = result
            .nodes
            .iter()
            .find(|n| n.path.ends_with("sub"))
            .expect("sub node");
        assert_eq!(sub.size, 9000, "sub sums its own subtree");
        assert_eq!(sub.file_count, 3);
        assert_eq!(sub.dir_count, 1, "counts deeper/");
    }

    #[test]
    fn totals_match_the_sum_of_file_sizes() {
        let dir = build_tree(&[("a.bin", 111), ("x/b.bin", 222), ("x/y/c.bin", 333)]);
        let result = scan(&dir, &config_for(&dir));
        assert_eq!(result.total_bytes, 666);
        assert_eq!(result.total_files, 3);
        let real_dirs = result.nodes.iter().filter(|n| n.is_dir()).count() as u64;
        assert_eq!(result.total_dirs, real_dirs);
    }

    #[test]
    fn results_are_deterministic_across_runs() {
        let dir = build_tree(&[
            ("a.bin", 100),
            ("m/n/o.bin", 200),
            ("m/p.bin", 300),
            ("z.bin", 400),
        ]);
        let first = scan(&dir, &config_for(&dir));
        let second = scan(&dir, &config_for(&dir));

        let paths_a: Vec<_> = first.nodes.iter().map(|n| &n.path).collect();
        let paths_b: Vec<_> = second.nodes.iter().map(|n| &n.path).collect();
        assert_eq!(paths_a, paths_b, "same paths in the same order every run");

        let sizes_a: Vec<_> = first.nodes.iter().map(|n| n.size).collect();
        let sizes_b: Vec<_> = second.nodes.iter().map(|n| n.size).collect();
        assert_eq!(sizes_a, sizes_b, "and the same sizes, not just order");
    }

    #[test]
    fn empty_directories_are_still_recorded() {
        let dir = build_tree(&[("a.bin", 10)]);
        fs::create_dir_all(dir.path().join("empty")).expect("mkdir");
        let result = scan(&dir, &config_for(&dir));
        let empty = result
            .nodes
            .iter()
            .find(|n| n.path.ends_with("empty"))
            .expect("empty dir must appear");
        assert_eq!(empty.size, 0);
        assert_eq!(empty.child_count, 0);
    }

    #[test]
    fn excluded_paths_are_skipped() {
        let dir = build_tree(&[("keep.bin", 100), ("skip/drop.bin", 900)]);
        let mut config = config_for(&dir);
        config.exclude_paths = vec![root_of(&dir).join("skip")];
        let result = scan(&dir, &config);
        assert!(result.nodes.iter().all(|n| !n.path.ends_with("drop.bin")));
        assert_eq!(result.total_bytes, 100);
    }

    #[test]
    fn hidden_files_are_included_by_default_and_can_be_skipped() {
        let dir = build_tree(&[(".hidden.bin", 50), ("visible.bin", 60)]);

        let with_hidden = scan(&dir, &config_for(&dir));
        assert!(
            with_hidden
                .nodes
                .iter()
                .any(|n| n.path.ends_with(".hidden.bin")),
            "hidden files are exactly the ones we most need to find"
        );

        let mut config = config_for(&dir);
        config.include_hidden = false;
        let without = scan(&dir, &config);
        assert!(
            !without
                .nodes
                .iter()
                .any(|n| n.path.ends_with(".hidden.bin"))
        );
        assert!(
            without
                .nodes
                .iter()
                .any(|n| n.path.ends_with("visible.bin"))
        );
    }

    #[test]
    fn max_depth_limits_descent() {
        let dir = build_tree(&[("a.bin", 10), ("one/b.bin", 20), ("one/two/c.bin", 30)]);
        let mut config = config_for(&dir);
        config.max_depth = Some(1);

        let result = scan(&dir, &config);
        let names: Vec<&str> = result.nodes.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"one"), "depth 1 is included, got {names:?}");
        assert!(!names.contains(&"c.bin"), "depth 2 is not, got {names:?}");
    }

    #[test]
    fn symlinks_are_recorded_but_not_followed_by_default() {
        let dir = build_tree(&[("real/inner.bin", 500)]);
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link"))
            .expect("symlink");

        let result = scan(&dir, &config_for(&dir));
        let link = result
            .nodes
            .iter()
            .find(|n| n.path.ends_with("link"))
            .expect("symlink must appear as its own entry");
        assert_eq!(link.kind, FileKind::Symlink);
        assert!(
            !result
                .nodes
                .iter()
                .any(|n| n.path.ends_with("link/inner.bin")),
            "must not descend through the link"
        );
    }

    #[test]
    fn hardlinks_are_counted_once() {
        let dir = build_tree(&[("original.bin", 4096)]);
        #[cfg(unix)]
        std::fs::hard_link(
            dir.path().join("original.bin"),
            dir.path().join("link1.bin"),
        )
        .expect("link 1");
        #[cfg(unix)]
        std::fs::hard_link(
            dir.path().join("original.bin"),
            dir.path().join("link2.bin"),
        )
        .expect("link 2");

        let result = scan(&dir, &config_for(&dir));
        assert_eq!(
            result.total_bytes, 4096,
            "three names for one copy of the bytes must report 4 KB, not 12 KB"
        );
    }

    #[test]
    fn cancellation_stops_the_walk() {
        let dir = build_tree(&[("a.bin", 10), ("b.bin", 10), ("c.bin", 10)]);
        let cancel = CancelToken::new();
        cancel.cancel();

        let result = walk(&config_for(&dir), &cancel, &SilentObserver).expect("walk returns");
        assert!(
            result.cancelled,
            "a pre-cancelled token short-circuits the scan"
        );
    }

    #[test]
    fn progress_callback_receives_monotonic_counts() {
        let dir = build_tree(&[("a.bin", 100), ("sub/b.bin", 200)]);
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();

        let observer = FnObserver::new(
            move |p: &Progress| {
                sink.lock().expect("lock").push((p.files, p.bytes));
            },
            |_: &ScanNode| {},
        );

        let cancel = CancelToken::new();
        let result = walk(&config_for(&dir), &cancel, &observer).expect("walk");
        assert!(result.total_files > 0);

        let samples = seen.lock().expect("lock").clone();
        for pair in samples.windows(2) {
            assert!(pair[0].0 <= pair[1].0, "file count must never go backwards");
            assert!(pair[0].1 <= pair[1].1, "byte count must never go backwards");
        }
    }

    #[test]
    fn no_roots_resolves_to_an_error_not_a_panic() {
        let config = ScanConfig {
            roots: vec![PathBuf::from("/definitely/not/here")],
            exclude_system: false,
            ..ScanConfig::default()
        };
        let cancel = CancelToken::new();
        // `ignore` walks a non-existent path by yielding an error entry, so this
        // may legitimately succeed with zero nodes; what must never happen is a
        // panic or a bogus success claiming files.
        match walk(&config, &cancel, &SilentObserver) {
            Ok(r) => assert_eq!(r.total_files, 0),
            Err(e) => assert!(matches!(
                e,
                WalkError::NoRoots | WalkError::AllRootsDenied { .. }
            )),
        }
    }

    #[test]
    fn summary_mode_trims_small_files_but_keeps_totals() {
        let dir = build_tree(&[("big.bin", 2_000_000), ("tiny.bin", 10)]);
        let mut config = config_for(&dir);
        config.max_nodes = 2; // force the ceiling

        let result = scan(&dir, &config);
        assert!(
            result.truncated.is_some(),
            "the user must be told the itemisation was trimmed"
        );
        assert_eq!(result.total_bytes, 2_000_010, "totals stay exact");
        let kept = result.nodes.iter().any(|n| n.name == "tiny.bin");
        assert!(!kept, "the small file is dropped from the itemised list");
    }
}
