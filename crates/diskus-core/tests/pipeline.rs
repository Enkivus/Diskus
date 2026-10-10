//! End-to-end pipeline test.
//!
//! Walks a real filesystem, runs every detector, and writes every report format
//! — the whole path a user takes, exercised headlessly.
//!
//! This exists because the unit tests deliberately isolate each detector from
//! the walker and from each other. That is the right way to test them
//! individually and the wrong way to find out whether the pieces fit together.
//! Several genuine bugs surfaced only here: totals that went to zero in summary
//! mode, a severity ordering that was inverted, and a duplicate cluster key that
//! silently merged different file types.

use diskus_core::config::{ExportFormat, ExportRequest, ScanConfig};
use diskus_core::detect;
use diskus_core::model::FileKind;
use diskus_core::report;
use diskus_core::scan::CancelToken;
use diskus_core::scan::walker::{SilentObserver, walk};
use diskus_core::viz;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Write a file of `mb` megabytes, sparse where the platform allows it.
fn write_sparse(path: &Path, mb: u64) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    let file = fs::File::create(path).expect("create");
    file.set_len(mb * 1024 * 1024).expect("set_len");
}

/// Set a file's modification time by walking back `days` from now.
fn backdate(path: &Path, days: u64) {
    let when = SystemTime::now() - Duration::from_secs(days * 86_400);
    set_mtime(path, when);
}

/// Set a file's modification time.
///
/// Backdating fixtures is not cosmetic: "stale", "abandoned" and "actively
/// growing" are all mtime decisions, so a test with real timestamps would be
/// testing nothing.
fn set_mtime(path: &Path, when: SystemTime) {
    let file = fs::File::options()
        .write(true)
        .open(path)
        .expect("open for mtime");
    let stamp = filetime::FileTime::from(when);
    filetime::set_file_handle_times(&file, Some(stamp), Some(stamp)).expect("set mtime");
}

/// Build a fixture that triggers all five detectors.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // Laid out as `<tmp>/Users/testuser` because the profile detector only
        // treats a directory directly under `Users` or `home` as a user profile.
        // A fixture at an arbitrary path would silently never trigger it.
        let root = dir.path().join("Users/testuser");

        // 1. Growing logs: a rotation set, recently written.
        write_sparse(&root.join("Library/Logs/nginx/access.log"), 120);
        write_sparse(&root.join("Library/Logs/nginx/access.log.1"), 80);
        write_sparse(&root.join("Library/Logs/nginx/access.log.2"), 40);
        backdate(&root.join("Library/Logs/nginx/access.log"), 1);
        backdate(&root.join("Library/Logs/nginx/access.log.1"), 30);
        backdate(&root.join("Library/Logs/nginx/access.log.2"), 60);

        // 2. Abandoned VM: an image with no config file.
        write_sparse(&root.join("VMs/legacy/legacy.qcow2"), 2500);
        backdate(&root.join("VMs/legacy/legacy.qcow2"), 400);

        // 3. Oversized profile: a regenerable cache and a personal file, both
        //    above the 1 GiB per-subfolder reporting floor, so the detector has
        //    to tell them apart by category rather than by size.
        write_sparse(&root.join("Library/Caches/com.example/blob.bin"), 1500);
        write_sparse(&root.join("Documents/holiday.mov"), 1200);

        // 4. Old installers and package caches.
        write_sparse(&root.join("Downloads/ToolSetup-1.2.3-x64.msi"), 70);
        backdate(&root.join("Downloads/ToolSetup-1.2.3-x64.msi"), 300);
        write_sparse(&root.join(".npm/_cacache/index.bin"), 55);

        // 5. Duplicates: identical bytes in three places.
        let payload = vec![0x5a; 3 * 1024 * 1024];
        for target in [
            "Documents/clip.mov",
            "Downloads/clip.mov",
            "Downloads/old/clip.mov",
        ] {
            let path = root.join(target);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(&path, &payload).expect("write");
            backdate(&path, 200);
        }

        Self { dir }
    }

    /// The canonical root.
    ///
    /// On macOS `tempfile` returns `/var/folders/...`, which is a symlink to
    /// `/private/var/folders/...`. The walker canonicalises its roots, so node
    /// paths come back under the resolved prefix — comparing against the raw
    /// path would silently match nothing.
    fn root(&self) -> PathBuf {
        self.dir
            .path()
            .join("Users/testuser")
            .canonicalize()
            .expect("canonical fixture root")
    }

    fn config(&self) -> ScanConfig {
        ScanConfig {
            roots: vec![self.root()],
            // Low enough that the fixture profile actually crosses it. The
            // shipped default is 40 GiB, which a few gigabytes of test data will
            // never reach.
            profile_size_threshold: 1024 * 1024 * 1024,
            min_file_size_for_dupes: 1024,
            ..ScanConfig::default()
        }
    }
}

#[test]
fn the_whole_pipeline_produces_coherent_results() {
    let fixture = Fixture::new();
    let config = fixture.config();

    // ---- Walk ------------------------------------------------------------
    let result = walk(&config, &CancelToken::new(), &SilentObserver).expect("walk");

    assert!(!result.cancelled, "scan should not have been cancelled");
    assert!(
        result.total_files > 0 && result.total_bytes > 0,
        "totals must be non-zero: {} files, {} bytes",
        result.total_files,
        result.total_bytes
    );
    assert_eq!(
        result.total_files,
        result
            .nodes
            .iter()
            .filter(|n| n.kind == FileKind::File)
            .count() as u64,
        "file total must match the node list"
    );

    // The scan root must carry the recursive sum of everything under it.
    let root_node = result
        .nodes
        .iter()
        .find(|n| n.path == fixture.root())
        .expect("root node");
    assert_eq!(root_node.size, result.total_bytes);
    assert_eq!(root_node.file_count, result.total_files);

    // ---- Detect ----------------------------------------------------------
    let findings = detect::run_all(&result, &config);
    assert!(!findings.is_empty(), "the fixture should produce findings");

    let summary = detect::summarise(&findings, result.total_bytes, result.elapsed_ms);
    assert_eq!(summary.counts_by_severity.total(), findings.len() as u64);

    // Reclaimable can never exceed what was scanned. A detector over-reporting
    // here is the single worst failure this pipeline can have: it would tell a
    // user to expect more free space than physically exists.
    assert!(
        summary.total_reclaimable <= result.total_bytes,
        "reclaimed {} exceeds scanned {}",
        summary.total_reclaimable,
        result.total_bytes
    );

    // ---- Ordering --------------------------------------------------------
    for window in findings.windows(2) {
        let (a, b) = (&window[0], &window[1]);
        assert!(
            a.severity.rank() >= b.severity.rank(),
            "findings must be ordered most-severe-first: {:?} before {:?}",
            a.severity,
            b.severity
        );
        if a.severity == b.severity {
            assert!(
                a.reclaimable >= b.reclaimable,
                "within a severity, largest reclaimable first"
            );
        }
    }

    // ---- Every detector contributed --------------------------------------
    let detectors: std::collections::HashSet<_> = findings.iter().map(|f| f.detector).collect();
    for expected in [
        diskus_core::model::Detector::GrowingLogs,
        diskus_core::model::Detector::AbandonedVms,
        diskus_core::model::Detector::OversizedProfiles,
        diskus_core::model::Detector::OldInstallers,
        diskus_core::model::Detector::Duplicates,
    ] {
        assert!(
            detectors.contains(&expected),
            "{expected:?} produced nothing from a fixture built to trigger it"
        );
    }

    // ---- Treemap tree ----------------------------------------------------
    let tree = viz::build_tree(&result, &viz::VizOptions::default());
    assert_eq!(tree.size, result.total_bytes);
    assert!(!tree.children.is_empty(), "the treemap should have content");

    let top_files = viz::top_files(&result, 10);
    assert!(!top_files.is_empty());
    assert!(
        top_files.windows(2).all(|w| w[0].size >= w[1].size),
        "top files must be sorted largest first"
    );

    // ---- Reports ---------------------------------------------------------
    let volumes = diskus_core::scan::volumes();
    let request = ExportRequest {
        scan_id: result.id.clone(),
        findings: findings.clone(),
        summary: summary.clone(),
        volumes,
        formats: ExportFormat::ALL.to_vec(),
        include_absolute_paths: true,
        roots: Vec::new(),
        include_hashes: true,
        machine_label: Some("pipeline-test".into()),
    };

    let out_dir = tempfile::tempdir().expect("out dir");
    let written = report::write_reports(&request, out_dir.path());

    assert!(
        written.len() >= 4,
        "all four formats requested, got {} files",
        written.len()
    );

    // Distinct files, distinct paths. Two formats colliding on one filename
    // would silently overwrite each other.
    let unique: std::collections::HashSet<&PathBuf> = written.iter().map(|w| &w.path).collect();
    assert_eq!(
        unique.len(),
        written.len(),
        "two reports were written to the same path: {:?}",
        written.iter().map(|w| &w.path).collect::<Vec<_>>()
    );

    for file in &written {
        assert!(
            file.path.exists(),
            "declared file was not written: {}",
            file.path.display()
        );
        let size = fs::metadata(&file.path).expect("stat").len();
        assert!(size > 0, "empty report: {}", file.path.display());
        assert_eq!(
            size,
            file.bytes,
            "reported size {} != on-disk {} for {}",
            file.bytes,
            size,
            file.path.display()
        );

        let contents = fs::read_to_string(&file.path).expect("read report");
        // The privacy statement must survive into every written artefact.
        assert!(
            contents.contains("uploaded nothing")
                || contents.contains("never read or transmitted")
                || contents.contains("metadata only"),
            "privacy note missing from {}",
            file.path.display()
        );
        assert!(
            !contents.contains("://"),
            "report must be fully offline, found a URL in {}",
            file.path.display()
        );
    }

    // The HTML report must be a complete, self-contained document.
    let html = written
        .iter()
        .find(|w| w.format == ExportFormat::Html)
        .expect("html report");
    let html = fs::read_to_string(&html.path).expect("read html");
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("</html>"));
    assert!(html.contains("<style>"), "CSS must be inline");
    assert!(
        html.contains("<svg"),
        "the treemap must be pre-rendered inline"
    );
    assert!(
        html.contains("clip.mov"),
        "findings should appear in the HTML"
    );

    // JSON must round-trip.
    let json = written
        .iter()
        .find(|w| w.format == ExportFormat::Json)
        .expect("json report");
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&json.path).expect("read json"))
            .expect("valid json");
    assert_eq!(
        parsed["findings"].as_array().expect("array").len(),
        findings.len()
    );
    assert!(parsed["meta"]["privacy"].is_string());
}

#[test]
fn re_running_detection_is_deterministic() {
    let fixture = Fixture::new();
    let config = fixture.config();

    let first = walk(&config, &CancelToken::new(), &SilentObserver).expect("walk");
    let second = walk(&config, &CancelToken::new(), &SilentObserver).expect("walk");

    let a = detect::run_all(&first, &config);
    let b = detect::run_all(&second, &config);

    let ids_a: Vec<&str> = a.iter().map(|f| f.id.as_str()).collect();
    let ids_b: Vec<&str> = b.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ids_a, ids_b,
        "identical input must produce identical findings"
    );

    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.reclaimable, y.reclaimable, "{} disagrees", x.id);
        assert_eq!(
            (x.confidence * 1000.0).round(),
            (y.confidence * 1000.0).round(),
            "{} confidence disagrees",
            x.id
        );
    }
}

#[test]
fn a_cancelled_scan_yields_partial_results_not_a_failure() {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.exclude_paths = Vec::new();

    let cancel = CancelToken::new();
    cancel.cancel();

    let result = walk(&config, &cancel, &SilentObserver).expect("walk still returns");
    assert!(result.cancelled);
    // The UI relies on this flag to say "these totals are lower than a full scan
    // would show", so it must be false only when the walk genuinely finished.
    let findings = detect::run_all(&result, &config);
    let summary = detect::summarise(&findings, result.total_bytes, result.elapsed_ms);
    assert!(summary.total_reclaimable <= result.total_bytes);
}

/// A profile that is mostly cache must not report its reclaimable bytes twice.
///
/// The summary finding rolls up its children, and each child finding re-reports
/// the same bytes. Summing those double-counts, which on a cache-heavy profile
/// can claim more reclaimable space than the whole disk holds — the single worst
/// failure a storage analyser can have.
#[test]
fn a_cache_heavy_profile_does_not_double_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("Users/alex");

    // 90% of the profile is one regenerable cache.
    fs::create_dir_all(root.join("Library/Caches/com.example")).expect("mkdir");
    fs::File::create(root.join("Library/Caches/com.example/blob.bin"))
        .expect("create")
        .set_len(9 * 1024 * 1024 * 1024)
        .expect("set_len");
    fs::create_dir_all(root.join("Documents")).expect("mkdir");
    fs::File::create(root.join("Documents/notes.mov"))
        .expect("create")
        .set_len(1024 * 1024 * 1024)
        .expect("set_len");

    let config = ScanConfig {
        roots: vec![root.clone()],
        profile_size_threshold: 1024 * 1024 * 1024,
        profile_volume_fraction: 2.0, // disable the volume-share rule
        ..ScanConfig::default()
    };

    let result = walk(&config, &CancelToken::new(), &SilentObserver).expect("walk");
    let findings = detect::run_all(&result, &config);
    let summary = detect::summarise(&findings, result.total_bytes, result.elapsed_ms);

    assert!(
        summary.total_reclaimable <= result.total_bytes,
        "claimed {} reclaimable out of {} scanned — a disk cannot give back more than it holds",
        summary.total_reclaimable,
        result.total_bytes
    );

    // The cache should still be found, once.
    let cache_findings = findings
        .iter()
        .filter(|f| f.path.to_string_lossy().contains("Caches"))
        .count();
    assert_eq!(
        cache_findings, 1,
        "the cache is reported once, as a subfolder"
    );
}

/// Turning off absolute paths must actually strip them, everywhere.
///
/// The export screen tells the user in plain language that switching this off
/// keeps their home directory out of a shared report. A no-op toggle would be a
/// privacy promise the app does not keep — and it did exactly that: both the
/// top-level path field and the paths nested inside each detector's `detail`
/// were emitted verbatim.
#[test]
fn relative_path_mode_leaks_no_absolute_paths() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let result = walk(&config, &CancelToken::new(), &SilentObserver).expect("walk");
    let findings = detect::run_all(&result, &config);
    let summary = detect::summarise(&findings, result.total_bytes, result.elapsed_ms);
    let root = fixture.root();

    let out_dir = tempfile::tempdir().expect("out dir");
    let request = diskus_core::config::ExportRequest {
        scan_id: result.id.clone(),
        findings,
        summary,
        volumes: vec![],
        formats: vec![diskus_core::config::ExportFormat::Json],
        include_absolute_paths: false,
        roots: vec![root.clone()],
        include_hashes: true,
        machine_label: Some("leak-check".into()),
    };

    let written = diskus_core::report::write_reports(&request, out_dir.path());
    let json = written
        .iter()
        .find(|w| w.format == diskus_core::config::ExportFormat::Json)
        .expect("json report");
    let body = fs::read_to_string(&json.path).expect("read");

    // Report exactly which field leaked, so a failure names the culprit rather
    // than dumping the whole document.
    let root_text = root.to_string_lossy().to_string();
    let leaks: Vec<String> = body
        .lines()
        .filter(|line| line.contains(&root_text))
        .map(|line| line.trim().to_string())
        .collect();
    assert!(
        leaks.is_empty(),
        "the scanned root leaked into {} field(s):\n{}",
        leaks.len(),
        leaks.join("\n")
    );

    // And the whole thing must still be valid JSON with its findings intact.
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let count = parsed["findings"].as_array().expect("array").len();
    assert!(count > 0, "sanity: findings survived");
    assert!(
        body.contains("~/"),
        "paths should render relative to the scan root"
    );

    // The same export with absolute paths on must contain them again.
    let absolute_dir = tempfile::tempdir().expect("out dir");
    let mut absolute = request.clone();
    absolute.include_absolute_paths = true;
    let written = diskus_core::report::write_reports(&absolute, absolute_dir.path());
    let json = written
        .iter()
        .find(|w| w.format == diskus_core::config::ExportFormat::Json)
        .expect("json report");
    let body = fs::read_to_string(&json.path).expect("read");
    assert!(
        body.contains(&root.to_string_lossy().to_string()),
        "absolute mode should keep full paths"
    );
}
