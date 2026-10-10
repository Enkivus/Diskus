//! In-memory [`ScanResult`] builder for detector tests.
//!
//! Detector tests build a synthetic tree directly rather than writing files to
//! disk, for two reasons: it is fast, and — more importantly — it lets a test set
//! an arbitrary modification time. Whether a log is "actively growing" or a VM
//! is "abandoned" depends entirely on mtime, so tests must be able to control it
//! without touching the filesystem clock.
//!
//! Directory aggregates are filled in by the same
//! [`aggregate_bottom_up`](crate::scan::walker::aggregate_bottom_up) the real
//! walker uses, so tests exercise production aggregation logic.

use crate::model::{FileKind, ScanNode, ScanResult};
use crate::util;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

/// Builds a [`ScanResult`] from a list of paths.
#[derive(Debug, Default)]
pub(crate) struct ScanBuilder {
    roots: Vec<PathBuf>,
    nodes: Vec<ScanNode>,
    known: std::collections::HashSet<PathBuf>,
}

/// A logical modification time, relative to now, for test scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Age {
    /// Modified the given number of days ago.
    Days(i64),
    /// Modified the given number of hours ago.
    Hours(i64),
    /// No modification time at all.
    Never,
}

impl Age {
    fn resolve(self) -> Option<OffsetDateTime> {
        let base = util::now();
        match self {
            Self::Never => None,
            Self::Days(d) => Some(base - Duration::days(d)),
            Self::Hours(h) => Some(base - Duration::hours(h)),
        }
    }
}

impl ScanBuilder {
    /// A new, empty builder.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Declare a scan root. Parents of declared files are created implicitly, so
    /// this only needs setting when a test cares about the root's own totals.
    pub(crate) fn root(&mut self, path: &str) -> &mut Self {
        let p = PathBuf::from(path);
        self.roots.push(p.clone());
        self.ensure_dir(p);
        self
    }

    /// Declare every root this tree should report as scanned.
    pub(crate) fn roots(&mut self, paths: &[&str]) -> &mut Self {
        for p in paths {
            self.root(p);
        }
        self
    }

    /// Declare a file of `size` bytes, `age` old, creating parent directories.
    pub(crate) fn file(&mut self, path: &str, size: u64, age: Age) -> &mut Self {
        let p = PathBuf::from(path);
        if let Some(parent) = p.parent() {
            self.ensure_dir(parent.to_path_buf());
        }
        let modified = age.resolve();
        let name = p.file_name().map_or_else(
            || p.to_string_lossy().to_string(),
            |n| n.to_string_lossy().to_string(),
        );
        self.nodes.push(ScanNode {
            path: p.clone(),
            name,
            parent: p.parent().map(Path::to_path_buf),
            depth: 0,
            kind: FileKind::File,
            size,
            on_disk: size,
            modified,
            accessed: modified,
            created: modified,
            extension: util::extension_of(&p),
            hidden: false,
            symlink_target: None,
            content_hash: None,
            child_count: 0,
            file_count: 1,
            dir_count: 0,
            error: None,
        });
        self
    }

    fn ensure_dir(&mut self, path: PathBuf) {
        if path.as_os_str().is_empty() || self.known.contains(&path) {
            return;
        }
        if let Some(parent) = path.parent() {
            if parent != path && !parent.as_os_str().is_empty() {
                self.ensure_dir(parent.to_path_buf());
            }
        }
        self.known.insert(path.clone());
        self.nodes.push(ScanNode {
            name: path.file_name().map_or_else(
                || path.to_string_lossy().to_string(),
                |n| n.to_string_lossy().to_string(),
            ),
            parent: path.parent().map(Path::to_path_buf),
            path,
            depth: 0,
            kind: FileKind::Dir,
            size: 0,
            on_disk: 0,
            modified: None,
            accessed: None,
            created: None,
            extension: None,
            hidden: false,
            symlink_target: None,
            content_hash: None,
            child_count: 0,
            file_count: 0,
            dir_count: 0,
            error: None,
        });
    }

    /// Sort, aggregate, and produce the final [`ScanResult`].
    pub(crate) fn build(&mut self) -> ScanResult {
        self.nodes.sort_by(|a, b| a.path.cmp(&b.path));
        crate::scan::walker::aggregate_bottom_up(&mut self.nodes);

        let total_files = self
            .nodes
            .iter()
            .filter(|n| n.kind == FileKind::File)
            .count() as u64;
        let total_dirs = self.nodes.iter().filter(|n| n.is_dir()).count() as u64;
        let total_bytes = self
            .nodes
            .iter()
            .filter(|n| n.kind == FileKind::File)
            .map(|n| n.size)
            .sum();

        ScanResult {
            id: "test".into(),
            started_at: util::now(),
            finished_at: Some(util::now()),
            roots: self.roots.clone(),
            nodes: std::mem::take(&mut self.nodes),
            total_bytes,
            total_files,
            total_dirs,
            denied_paths: Vec::new(),
            errors_skipped: 0,
            elapsed_ms: 1,
            cancelled: false,
            truncated: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_aggregates_like_the_real_walker() {
        let result = ScanBuilder::new()
            .roots(&["/data"])
            .file("/data/a.bin", 100, Age::Days(1))
            .file("/data/sub/b.bin", 250, Age::Days(1))
            .build();

        let root = result
            .nodes
            .iter()
            .find(|n| n.path == std::path::Path::new("/data"))
            .expect("root");
        assert_eq!(root.size, 350);
        assert_eq!(root.file_count, 2);

        let sub = result
            .nodes
            .iter()
            .find(|n| n.path == std::path::Path::new("/data/sub"))
            .expect("sub");
        assert_eq!(sub.size, 250);
        assert_eq!(sub.dir_count, 0);
    }

    #[test]
    fn ages_resolve_relative_to_now() {
        let old = Age::Days(400).resolve().expect("resolves");
        let recent = Age::Hours(1).resolve().expect("resolves");
        assert!(old < recent, "400 days ago must be before 1 hour ago");
        assert!(Age::Never.resolve().is_none());
    }
}
