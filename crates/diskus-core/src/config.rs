//! Scan and export configuration.
//!
//! Everything the user can tune lives here. Defaults are deliberately
//! conservative: a first scan should never silently delete nothing and take an
//! hour. Field names are `camelCase` because they cross the IPC boundary straight
//! into TypeScript.

use crate::model::{Bytes, Detector, GIB, MIB};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Node-retention ceiling. Past this many entries the scanner switches to summary
/// mode so a pathological directory cannot exhaust memory.
pub const DEFAULT_MAX_NODES: usize = 3_000_000;

/// Files below this size are ignored when they sit inside a retained-entries
/// overflow, to keep the interesting large files.
pub const DETAIL_FILE_FLOOR: Bytes = 100 * MIB;

/// Everything needed to run one scan plus its detection pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanConfig {
    /// Directories to walk. Empty means "ask the app for sensible defaults".
    pub roots: Vec<PathBuf>,
    /// Follow symbolic links. Off by default: links are how filesystem cycles
    /// happen, and following them can produce an infinite walk.
    pub follow_symlinks: bool,
    /// Include dotfiles and hidden attributes.
    pub include_hidden: bool,
    /// Skip OS pseudo-filesystems and system volume folders that are either
    /// enormous and unreclaimable (`/private/var/vm`) or that break when touched.
    pub exclude_system: bool,
    /// User-supplied additional exclusions.
    pub exclude_paths: Vec<PathBuf>,
    /// Stop descending past this depth. `None` means unlimited.
    pub max_depth: Option<u16>,
    /// Parallel walker threads. `None` means one per available core.
    pub threads: Option<usize>,
    /// Files smaller than this are never hashed for duplicate detection.
    /// Filtering by size first discards the overwhelming majority of files with
    /// zero disk reads.
    pub min_file_size_for_dupes: Bytes,
    /// A profile this large is flagged regardless of volume size.
    pub profile_size_threshold: Bytes,
    /// A profile using more than this fraction of its volume is also flagged.
    pub profile_volume_fraction: f64,
    /// Logs untouched for longer than this are de-prioritised, not ignored.
    pub log_stale_days: u16,
    /// A log touched within this many days is treated as actively growing.
    pub log_active_days: u16,
    /// Installers untouched for longer than this are flagged.
    pub installer_stale_days: u16,
    /// Smallest installer/archive considered worth reporting.
    pub min_installer_size: Bytes,
    /// VM bundles unopened for longer than this are flagged as abandoned.
    pub vm_stale_days: u16,
    /// Filesystem paths whose duplicates are never reported. Comparing the
    /// operating system's own files produces nothing but noise, and acting on it
    /// breaks the machine.
    pub duplicate_skip_prefixes: Vec<PathBuf>,
    /// Ceiling on retained entries before summary mode kicks in.
    pub max_nodes: usize,
    /// Detectors to run, in report order.
    pub detect: Vec<Detector>,
    /// Human label for this scan, shown in reports.
    pub label: Option<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            follow_symlinks: false,
            include_hidden: true,
            exclude_system: true,
            exclude_paths: Vec::new(),
            max_depth: None,
            threads: None,
            min_file_size_for_dupes: MIB,
            profile_size_threshold: 40 * GIB,
            profile_volume_fraction: 0.15,
            log_stale_days: 90,
            log_active_days: 7,
            installer_stale_days: 180,
            min_installer_size: 50 * MIB,
            vm_stale_days: 180,
            duplicate_skip_prefixes: default_duplicate_skip_prefixes(),
            max_nodes: DEFAULT_MAX_NODES,
            detect: Detector::ALL.to_vec(),
            label: None,
        }
    }
}

impl ScanConfig {
    /// A ready-to-run config: all detectors, current user's home, plus the
    /// platform's data roots.
    #[must_use]
    pub fn quick_sweep() -> Self {
        Self {
            roots: crate::scan::default_roots(),
            ..Self::default()
        }
    }

    /// Everything, including hidden files, package caches and no path
    /// exclusions beyond the unsafe ones.
    #[must_use]
    pub fn deep_audit() -> Self {
        Self {
            roots: crate::scan::default_roots(),
            include_hidden: true,
            exclude_system: true,
            log_stale_days: 365,
            installer_stale_days: 365,
            vm_stale_days: 365,
            ..Self::default()
        }
    }

    /// Effective walker thread count.
    #[must_use]
    pub fn thread_count(&self) -> usize {
        self.threads.unwrap_or_else(|| {
            std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get)
        })
    }

    /// Whether `path` should be skipped entirely.
    #[must_use]
    pub fn is_excluded(&self, path: &Path) -> bool {
        if self.exclude_paths.iter().any(|ex| path.starts_with(ex)) {
            return true;
        }
        self.exclude_system && crate::scan::is_system_path(path)
    }

    /// Whether a detector is enabled.
    #[must_use]
    pub fn runs(&self, detector: Detector) -> bool {
        self.detect.contains(&detector)
    }
}

/// Paths whose contents are never reported as duplicates.
///
/// Two consequences: the report stays readable, and — far more importantly —
/// following a duplicate recommendation can never suggest deleting part of the
/// operating system.
fn default_duplicate_skip_prefixes() -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from("/System"),
        PathBuf::from("/usr"),
        PathBuf::from("/bin"),
        PathBuf::from("/sbin"),
        PathBuf::from("/lib"),
        PathBuf::from("/Applications"),
        PathBuf::from("/Library/Frameworks"),
        PathBuf::from("/nix"),
    ];
    if cfg!(windows) {
        v.push(PathBuf::from(r"C:\Windows"));
        v.push(PathBuf::from(r"C:\Program Files"));
        v.push(PathBuf::from(r"C:\Program Files (x86)"));
    }
    v
}

/// A format Diskus can write a report in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    /// One self-contained, offline, interactive HTML file.
    Html,
    /// Full structured data for scripting and automation.
    Json,
    /// Spreadsheet-friendly triage tables, one file per category.
    Csv,
    /// Human-readable summary document.
    Markdown,
}

impl ExportFormat {
    /// All formats, in the order the export screen lists them.
    pub const ALL: [Self; 4] = [Self::Html, Self::Json, Self::Csv, Self::Markdown];

    /// File extension, without the dot.
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Markdown => "md",
        }
    }

    /// Lowercase identifier used in the UI and manifest.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Markdown => "markdown",
        }
    }

    /// Display name.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Html => "HTML",
            Self::Json => "JSON",
            Self::Csv => "CSV",
            Self::Markdown => "Markdown",
        }
    }

    /// One-line description shown on the export card.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Html => "Self-contained interactive page with charts. Opens anywhere.",
            Self::Json => "Complete structured data for scripting and automation.",
            Self::Csv => "Spreadsheet-friendly tables for IT triage. One file per category.",
            Self::Markdown => "Readable summary document with top findings and actions.",
        }
    }

    /// How many files this format produces when exported.
    #[must_use]
    pub fn file_count(self) -> usize {
        match self {
            Self::Csv => 3,
            _ => 1,
        }
    }
}

/// A request to write one or more report files.
///
/// `formats` is deliberately a `Vec`: the export screen offers checkboxes and a
/// user commonly wants the HTML to share and the CSV to actually work in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportRequest {
    /// Scan these findings came from.
    pub scan_id: String,
    /// Every finding to report on.
    pub findings: Vec<crate::model::Finding>,
    /// Aggregate numbers for the report header.
    pub summary: crate::model::ScanSummary,
    /// Volumes involved, for the header.
    pub volumes: Vec<crate::model::Volume>,
    /// Which formats to write. One or more.
    pub formats: Vec<ExportFormat>,
    /// Write absolute paths. Off renders paths relative to the scan root, which
    /// keeps a shared report from leaking the operator's home directory.
    pub include_absolute_paths: bool,
    /// The roots that were scanned. Used to relativise paths when
    /// `include_absolute_paths` is off.
    #[serde(default)]
    pub roots: Vec<PathBuf>,
    /// Include duplicate content hashes in reports. Off by default: a digest
    /// proves two files match, which is more than a shared report needs.
    pub include_hashes: bool,
    /// Label shown in the header instead of the detected hostname.
    pub machine_label: Option<String>,
}

impl ExportRequest {
    /// Shared stem every generated file is named from:
    /// `diskus-report-{host}-{YYYYMMDD-HHMM}`.
    ///
    /// The label is truncated so the stem stays comfortably inside `NAME_MAX`
    /// (255 bytes on every supported platform) even with a long timestamp and a
    /// long file extension. Without the cap, a verbose machine label produces
    /// `ENAMETOOLONG` and *every* export silently fails.
    #[must_use]
    pub fn file_stem(&self) -> String {
        let raw_label = self
            .machine_label
            .clone()
            .unwrap_or_else(crate::util::hostname);
        let host = crate::util::sanitise_filename_part(&raw_label);
        // 64 leaves room for "diskus-report-", "-", a 13-char stamp, "-manifest"
        // and any format extension, with a wide margin to spare.
        let host: String = host.chars().take(64).collect();
        let host = if host.is_empty() { "machine" } else { &host };
        format!(
            "diskus-report-{host}-{}",
            crate::util::compact_stamp(crate::util::now())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_enable_every_detector() {
        let cfg = ScanConfig::default();
        assert_eq!(cfg.detect.len(), 5);
        for d in Detector::ALL {
            assert!(cfg.runs(d), "{d:?} should be on by default");
        }
    }

    #[test]
    fn default_config_serialises_as_camel_case() {
        let json = serde_json::to_string(&ScanConfig::default()).expect("serialise");
        assert!(json.contains("\"minFileSizeForDupes\""), "{json}");
        assert!(json.contains("\"excludeSystem\""), "{json}");
        assert!(
            !json.contains("min_file_size"),
            "must be camelCase, got: {json}"
        );
    }

    #[test]
    fn config_round_trips_through_json() {
        let cfg = ScanConfig {
            max_depth: Some(4),
            roots: vec![PathBuf::from("/tmp")],
            ..ScanConfig::default()
        };
        let json = serde_json::to_string(&cfg).expect("serialise");
        let back: ScanConfig = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back.max_depth, Some(4));
        assert_eq!(back.roots, vec![PathBuf::from("/tmp")]);
    }

    #[test]
    fn user_exclusions_win() {
        let cfg = ScanConfig {
            exclude_paths: vec![PathBuf::from("/Users/jdoe/Documents")],
            ..ScanConfig::default()
        };
        assert!(cfg.is_excluded(Path::new("/Users/jdoe/Documents/secret.txt")));
        assert!(!cfg.is_excluded(Path::new("/Users/jdoe/Pictures")));
    }

    #[test]
    fn file_stem_is_filename_safe() {
        let req = ExportRequest {
            scan_id: "x".into(),
            findings: vec![],
            summary: Default::default(),
            volumes: vec![],
            formats: vec![ExportFormat::Html],
            include_absolute_paths: false,
            roots: Vec::new(),
            include_hashes: false,
            machine_label: Some("Alice's Laptop (2024)".into()),
        };
        let stem = req.file_stem();
        assert!(
            stem.starts_with("diskus-report-Alice-s-Laptop-2024"),
            "{stem}"
        );
        assert!(!stem.contains(' '), "no spaces: {stem}");
        assert!(
            !stem.contains('(') && !stem.contains(')'),
            "no parens: {stem}"
        );
    }

    #[test]
    fn export_formats_are_complete() {
        assert_eq!(ExportFormat::ALL.len(), 4);
        assert_eq!(ExportFormat::Csv.file_count(), 3);
        assert_eq!(ExportFormat::Html.file_count(), 1);
    }
}
