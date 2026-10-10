//! Data model shared by the scanner, detectors, reporters and the UI.
//!
//! Everything in this module that crosses the Tauri IPC boundary is serialised
//! with `camelCase` so the TypeScript side can use it verbatim, and every
//! optional field is skipped when empty. The latter matters: a scan of a large
//! machine can produce millions of [`ScanNode`]s, and paying for `null` fields
//! on every one of them is a measurable cost.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use time::OffsetDateTime;

/// A quantity of bytes.
pub type Bytes = u64;

/// Default number of bytes hashed before a duplicate candidate is rejected.
pub const KIB: u64 = 1024;
/// One kibibyte.
pub const MIB: u64 = 1024 * KIB;
/// One mebibyte.
pub const GIB: u64 = 1024 * MIB;
/// One gibibyte.
pub const TIB: u64 = 1024 * GIB;

/// What kind of filesystem entry a [`ScanNode`] represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link. Never followed unless explicitly enabled.
    Symlink,
    /// A socket, FIFO, device node, or anything else unclassifiable.
    Other,
}

impl FileKind {
    /// Whether this kind of entry can contain children.
    #[must_use]
    pub fn is_container(self) -> bool {
        matches!(self, Self::Dir)
    }
}

/// A single filesystem entry, as observed by the scanner.
///
/// For directories, the size fields are populated bottom-up after the walk
/// completes so that a directory's `size` is the recursive sum of its subtree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanNode {
    /// Absolute path to the entry.
    pub path: PathBuf,
    /// Final path component. Cheap, avoids recomputing during layout.
    pub name: String,
    /// Parent directory, absent only for the scan roots themselves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<PathBuf>,
    /// Depth below the nearest scan root. Roots are `0`.
    pub depth: u16,
    /// What kind of entry this is.
    pub kind: FileKind,
    /// Bytes: the entry's own length for files, the recursive sum for directories.
    pub size: Bytes,
    /// Bytes actually allocated on the volume.
    ///
    /// Differs from [`ScanNode::size`] for sparse files, and — importantly for
    /// thin-provisioned VMs — can be a fraction of the apparent size. Reporting
    /// only `size` is the single most common way disk tools overstate reclaimable
    /// space, so both are always surfaced.
    pub on_disk: Bytes,
    /// Last content modification time, when the platform exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<OffsetDateTime>,
    /// Last access time, when the platform exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed: Option<OffsetDateTime>,
    /// Creation / inode-change time, when the platform exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<OffsetDateTime>,
    /// Lowercase extension including the leading dot, e.g. `.log`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    /// Whether the entry is hidden by platform convention.
    pub hidden: bool,
    /// If this is a symlink, where it points.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<PathBuf>,
    /// blake3 digest, present **only** for files duplicate detection decided to
    /// hash. The digest proves two files are identical; it never reveals content,
    /// and it is never transmitted anywhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// Number of direct children (files + subdirectories).
    pub child_count: u64,
    /// Number of descendant files.
    pub file_count: u64,
    /// Number of descendant directories, excluding this one.
    pub dir_count: u64,
    /// Populated when the entry could not be fully read. The scan continues past
    /// the failure and this string explains what was lost.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ScanNode {
    /// Whether this node represents a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.kind.is_container()
    }

    /// Whether the node is hidden by platform convention.
    #[must_use]
    pub fn is_hidden(&self) -> bool {
        self.hidden
    }

    /// Bytes that would actually be returned if the entry were removed.
    ///
    /// For a directory this is the allocated size, which correctly accounts for
    /// sparse files and thin-provisioned disk images inside it.
    #[must_use]
    pub fn reclaimable(&self) -> Bytes {
        if self.is_dir() {
            self.on_disk
        } else {
            self.on_disk.max(self.size)
        }
    }
}

/// The complete outcome of one filesystem walk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    /// Identifier for this scan; used to correlate commands and events.
    pub id: String,
    /// When the walk began.
    pub started_at: OffsetDateTime,
    /// When the walk finished, or `None` while still running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<OffsetDateTime>,
    /// The roots that were scanned.
    pub roots: Vec<PathBuf>,
    /// Every entry observed, sorted by path. Mutated after the walk completes:
    /// directory aggregates are filled in bottom-up, then results are re-sorted
    /// for the UI.
    pub nodes: Vec<ScanNode>,
    /// Sum of all file sizes below the roots.
    pub total_bytes: Bytes,
    /// Total files observed.
    pub total_files: u64,
    /// Total directories observed.
    pub total_dirs: u64,
    /// Paths the OS refused to read. Non-fatal by design — a scan always runs to
    /// completion and simply reports what it could not see.
    pub denied_paths: Vec<PathBuf>,
    /// Count of entries the walker skipped without being able to name the path.
    /// The `ignore` walker does not surface a path on its errors, so these are
    /// counted rather than guessed at. Reported so totals can never silently
    /// overstate what was actually inspected.
    #[serde(default)]
    pub errors_skipped: u64,
    /// Wall-clock duration of the walk.
    pub elapsed_ms: u64,
    /// Whether the user aborted the scan.
    pub cancelled: bool,
    /// Set when the walk hit the node-retention ceiling and switched to summary
    /// mode. The UI surfaces this as a banner so numbers are never silently
    /// truncated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<String>,
}

impl ScanResult {
    /// Total bytes that could plausibly be reclaimed, accounting for hardlinks.
    #[must_use]
    pub fn total_on_disk(&self) -> Bytes {
        self.nodes
            .iter()
            .filter(|n| !n.is_dir())
            .map(|n| n.reclaimable())
            .sum()
    }

    /// Build an index from path to node position for fast parent lookups.
    #[must_use]
    pub fn path_index(&self) -> BTreeMap<PathBuf, usize> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.path.clone(), i))
            .collect()
    }
}

/// Which specialised detector produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    /// Logs that are actively eating disk and will keep eating it.
    GrowingLogs,
    /// VM bundles nobody has opened in months.
    AbandonedVms,
    /// User home directories that are far too large.
    OversizedProfiles,
    /// Stale installers and package-manager download caches.
    OldInstallers,
    /// Byte-identical files stored more than once.
    Duplicates,
}

impl Detector {
    /// Every detector, in the order shown in the UI.
    pub const ALL: [Self; 5] = [
        Self::GrowingLogs,
        Self::AbandonedVms,
        Self::OversizedProfiles,
        Self::OldInstallers,
        Self::Duplicates,
    ];

    /// Stable identifier used in reports and CSV columns.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::GrowingLogs => "growing_logs",
            Self::AbandonedVms => "abandoned_vms",
            Self::OversizedProfiles => "oversized_profiles",
            Self::OldInstallers => "old_installers",
            Self::Duplicates => "duplicates",
        }
    }

    /// Human-readable name for the UI and reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::GrowingLogs => "Growing logs",
            Self::AbandonedVms => "Abandoned VMs",
            Self::OversizedProfiles => "Oversized profiles",
            Self::OldInstallers => "Old installers",
            Self::Duplicates => "Duplicates",
        }
    }

    /// Index into the categorical colour ramp, so a detector always gets the
    /// same colour everywhere in the product.
    #[must_use]
    pub fn color_index(self) -> usize {
        match self {
            Self::GrowingLogs => 2,
            Self::AbandonedVms => 4,
            Self::OversizedProfiles => 0,
            Self::OldInstallers => 6,
            Self::Duplicates => 5,
        }
    }
}

/// How much a finding matters, derived from its reclaimable size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Over 20 GiB wasted, or enough to exhaust the volume.
    Critical,
    /// 5–20 GiB wasted.
    High,
    /// 1–5 GiB wasted.
    Medium,
    /// 100 MiB – 1 GiB wasted.
    Low,
    /// Under 100 MiB, or purely advisory.
    Info,
}

impl Severity {
    /// All severities, most severe first.
    pub const ALL: [Self; 5] = [
        Self::Critical,
        Self::High,
        Self::Medium,
        Self::Low,
        Self::Info,
    ];

    /// Band a reclaimable byte count into a severity.
    #[must_use]
    pub fn from_bytes(bytes: Bytes) -> Self {
        match bytes {
            b if b > 20 * GIB => Self::Critical,
            b if b > 5 * GIB => Self::High,
            b if b > GIB => Self::Medium,
            b if b > 100 * MIB => Self::Low,
            _ => Self::Info,
        }
    }

    /// Lowercase identifier for reports and CSS class names.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }

    /// Ordering rank, with the most severe highest.
    ///
    /// The derived `Ord` is *backwards* for this enum: `Critical` is declared
    /// first, so derived ordering makes it the smallest value and a descending
    /// sort puts `Info` at the top. Anything ordering findings must use this
    /// instead.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Info => "Info",
        }
    }

    /// CSS custom property backing this severity's colour.
    #[must_use]
    pub fn css_var(self) -> &'static str {
        match self {
            Self::Critical => "--sev-critical",
            Self::High => "--sev-high",
            Self::Medium => "--sev-medium",
            Self::Low => "--sev-low",
            Self::Info => "--sev-info",
        }
    }
}

/// Whether deleting the thing a finding points at is destructive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Safety {
    /// Regenerable cache. Deleting it costs nothing but a re-download.
    SafeToDelete,
    /// Probably fine, but a human should glance at it first.
    ReviewFirst,
    /// Deleting loses data. Requires explicit human confirmation.
    DataLoss,
}

impl Safety {
    /// Lowercase identifier for reports and CSS class names.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::SafeToDelete => "safe_to_delete",
            Self::ReviewFirst => "review_first",
            Self::DataLoss => "data_loss",
        }
    }

    /// Human-readable name.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::SafeToDelete => "Safe to delete",
            Self::ReviewFirst => "Review first",
            Self::DataLoss => "Data loss",
        }
    }
}

/// A single actionable piece of wasted storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable identifier, unique within a run.
    pub id: String,
    /// Which detector produced this.
    pub detector: Detector,
    /// How much it matters.
    pub severity: Severity,
    /// Whether deleting it destroys data.
    pub safety: Safety,
    /// One human sentence naming the problem, e.g.
    /// `"Rotated IIS logs: 3 archives, 14.2 GB"`.
    pub title: String,
    /// Primary path. For duplicates this is the copy recommended for keeping.
    pub path: PathBuf,
    /// Every other path involved — the other duplicates, or the other files in a
    /// VM bundle or rotation set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_paths: Vec<PathBuf>,
    /// Total size of everything involved.
    pub size: Bytes,
    /// Bytes recoverable. May be less than `size` — e.g. a rotation set where the
    /// active log must be kept.
    pub reclaimable: Bytes,
    /// Detector confidence from `0.0` to `1.0`.
    pub confidence: f32,
    /// One actionable sentence telling the user what to do.
    pub recommendation: String,
    /// Detector-specific structured detail, rendered as a key/value list in the UI
    /// and as a nested object in the JSON report.
    pub detail: serde_json::Value,
    /// When the finding was produced.
    pub detected_at: OffsetDateTime,
}

/// Counts of findings at each severity.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeverityCounts {
    /// Number of critical findings.
    pub critical: u64,
    /// Number of high findings.
    pub high: u64,
    /// Number of medium findings.
    pub medium: u64,
    /// Number of low findings.
    pub low: u64,
    /// Number of info findings.
    pub info: u64,
}

impl SeverityCounts {
    /// Increment the counter for one severity.
    pub fn add(&mut self, severity: Severity) {
        let slot = match severity {
            Severity::Critical => &mut self.critical,
            Severity::High => &mut self.high,
            Severity::Medium => &mut self.medium,
            Severity::Low => &mut self.low,
            Severity::Info => &mut self.info,
        };
        *slot += 1;
    }

    /// The count for a single severity.
    #[must_use]
    pub fn get(&self, severity: Severity) -> u64 {
        match severity {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Info => self.info,
        }
    }

    /// Total findings across all severities.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// Per-detector rollup shown on the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectorRollup {
    /// The detector.
    pub detector: Detector,
    /// How many findings it produced.
    pub finding_count: u64,
    /// Total bytes those findings claim.
    pub bytes: Bytes,
}

/// Aggregate numbers for one completed detection run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    /// Bytes examined.
    pub total_scanned: Bytes,
    /// Sum of every finding's `reclaimable`. May double-count bytes claimed by
    /// two detectors; this caveat is stated in every report footer.
    pub total_reclaimable: Bytes,
    /// Counts by severity.
    pub counts_by_severity: SeverityCounts,
    /// Rollups in detector order.
    pub counts_by_detector: Vec<DetectorRollup>,
    /// Milliseconds the whole run took.
    pub elapsed_ms: u64,
}

/// A mounted volume Diskus can scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    /// Platform volume name, e.g. ` Macintosh HD`.
    pub name: String,
    /// Where it is mounted, e.g. `/`.
    pub mount_point: PathBuf,
    /// Total capacity, absent when the platform will not report it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<Bytes>,
    /// Free space, absent when the platform will not report it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_bytes: Option<Bytes>,
    /// False for pseudo-filesystems, app bundles and other things that are not
    /// worth scanning.
    pub is_scannable: bool,
}

impl Volume {
    /// Fraction of the volume in use, or `None` when capacity is unknown.
    #[must_use]
    pub fn used_fraction(&self) -> Option<f64> {
        let total = self.total_bytes?;
        if total == 0 {
            return None;
        }
        let used = total.saturating_sub(self.available_bytes.unwrap_or(0));
        Some(used as f64 / total as f64)
    }
}

/// A user home directory discovered on the machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    /// The profile directory's name, used as the display username.
    pub username: String,
    /// Absolute path to the home directory.
    pub path: PathBuf,
    /// Its size, if a scan already covered it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<Bytes>,
    /// Capacity of the volume holding it, when the percentage matters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<Bytes>,
    /// Whether this is the user running Diskus.
    pub is_current: bool,
}

/// Progress of the hashing pass inside duplicate detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashProgress {
    /// Files hashed so far.
    pub done: u64,
    /// Files that need hashing in total, after the cheap size filter.
    pub total: u64,
    /// Bytes hashed so far.
    pub bytes_done: Bytes,
}
