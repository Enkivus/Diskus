//! What is wasting storage on this machine.
//!
//! Five detectors, each a pure function over a [`ScanResult`]:
//!
//! | Module | Question it answers |
//! |---|---|
//! | [`logs`] | What is actively filling the disk, and will keep filling it? |
//! | [`vms`] | Which virtual machines does nobody use any more? |
//! | [`profiles`] | Whose home directory is too big, and what inside it is responsible? |
//! | [`installers`] | What can go that is only an installer or a download cache? |
//! | [`duplicates`] | Where is the same data stored twice? |
//!
//! Every detector is independently testable because it takes data and returns
//! data — no I/O, no globals, no side effects.

pub mod duplicates;
pub mod installers;
pub mod logs;
pub mod profiles;
pub mod rules;
#[cfg(test)]
pub(crate) mod testing;
pub mod vms;

use crate::config::ScanConfig;
use crate::model::{Detector, DetectorRollup, Finding, ScanResult, ScanSummary, SeverityCounts};
use crate::scan::CancelToken;
use crate::util;

/// Run every detector enabled in `config`.
///
/// Detectors are independent, so they run concurrently and their findings are
/// merged afterwards. Each is wrapped in `catch_unwind`: a detector that panics
/// must degrade to "no findings from that detector", never take down the app.
#[must_use]
pub fn run_all(result: &ScanResult, config: &ScanConfig) -> Vec<Finding> {
    run_all_cancellable(result, config, &CancelToken::new())
}

/// Run every enabled detector, aborting early if the scan is cancelled.
///
/// Cancellation matters most for [`Detector::Duplicates`], the only detector
/// that reads file contents and can run for minutes. Without a token the Stop
/// button does nothing once the walk is over, and the UI sits on "Stopping…"
/// forever.
#[must_use]
pub fn run_all_cancellable(
    result: &ScanResult,
    config: &ScanConfig,
    cancel: &CancelToken,
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    for detector in Detector::ALL {
        if !config.runs(detector) {
            continue;
        }
        if cancel.is_cancelled() {
            log::info!("detection cancelled before {detector:?}");
            break;
        }
        // Panic isolation is per detector: one bad detector must not take down
        // the app or discard the other four.
        let produced = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_one(detector, result, config, cancel)
        }));
        match produced {
            Ok(mut f) => findings.append(&mut f),
            Err(_) => log::error!("detector {detector:?} panicked; continuing without it"),
        }
    }

    dedupe_by_path(&mut findings);
    sort_by_impact(&mut findings);
    findings
}

/// Run a single detector.
#[must_use]
pub fn run_one(
    detector: Detector,
    result: &ScanResult,
    config: &ScanConfig,
    cancel: &CancelToken,
) -> Vec<Finding> {
    match detector {
        Detector::GrowingLogs => logs::detect(result, config),
        Detector::AbandonedVms => vms::detect(result, config),
        Detector::OversizedProfiles => profiles::detect(result, config),
        Detector::OldInstallers => installers::detect(result, config),
        Detector::Duplicates => duplicates::detect(result, config, cancel),
    }
}

/// Drop duplicate `(detector, canonical path)` pairs.
///
/// Two detectors can legitimately claim the same path — a file can be both a log
/// and a duplicate — but the same detector must never report one path twice.
fn dedupe_by_path(findings: &mut Vec<Finding>) {
    use std::collections::HashSet;
    let mut seen: HashSet<(Detector, std::path::PathBuf)> = HashSet::with_capacity(findings.len());
    findings.retain(|f| seen.insert((f.detector, f.path.clone())));
}

/// Sort most-urgent first: severity, then reclaimable bytes.
fn sort_by_impact(findings: &mut [Finding]) {
    // Ordered by `rank`, not the derived `Ord` — see `Severity::rank`.
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| b.reclaimable.cmp(&a.reclaimable))
            .then_with(|| a.title.cmp(&b.title))
    });
}

/// Aggregate findings into the numbers shown on the dashboard and in reports.
#[must_use]
pub fn summarise(findings: &[Finding], total_scanned: u64, elapsed_ms: u64) -> ScanSummary {
    let mut counts_by_severity = SeverityCounts::default();
    let mut per_detector: std::collections::BTreeMap<Detector, (u64, u64)> =
        std::collections::BTreeMap::new();
    let mut total_reclaimable = 0_u64;

    for f in findings {
        counts_by_severity.add(f.severity);
        total_reclaimable = total_reclaimable.saturating_add(f.reclaimable);
        let entry = per_detector.entry(f.detector).or_insert((0, 0));
        entry.0 += 1;
        entry.1 = entry.1.saturating_add(f.reclaimable);
    }

    let counts_by_detector = per_detector
        .into_iter()
        .map(|(detector, (finding_count, bytes))| DetectorRollup {
            detector,
            finding_count,
            bytes,
        })
        .collect();

    ScanSummary {
        total_scanned,
        total_reclaimable,
        counts_by_severity,
        counts_by_detector,
        elapsed_ms,
    }
}

/// Stable finding identifier: detector plus a path slug.
///
/// Deterministic across runs, so two reports of the same machine can be diffed.
pub(crate) fn finding_id(detector: Detector, path: &std::path::Path) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    detector.id().hash(&mut hasher);
    path.hash(&mut hasher);
    format!("{}-{:012x}", detector.id(), hasher.finish())
}

/// Build a [`Finding`], filling in the fields every detector shares.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_finding(
    detector: Detector,
    path: &std::path::Path,
    size: u64,
    reclaimable: u64,
    confidence: f32,
    safety: crate::model::Safety,
    title: String,
    recommendation: String,
    detail: serde_json::Value,
) -> Finding {
    Finding {
        id: finding_id(detector, path),
        detector,
        severity: crate::model::Severity::from_bytes(reclaimable),
        safety,
        title,
        path: path.to_path_buf(),
        related_paths: Vec::new(),
        size,
        reclaimable,
        confidence: util::clamp_confidence(confidence),
        recommendation,
        detail,
        detected_at: util::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Safety, Severity};

    fn finding(detector: Detector, path: &str, reclaimable: u64) -> Finding {
        make_finding(
            detector,
            std::path::Path::new(path),
            reclaimable,
            reclaimable,
            0.9,
            Safety::SafeToDelete,
            path.to_string(),
            "delete it".into(),
            serde_json::json!({}),
        )
    }

    #[test]
    fn summarise_totals_reclaimable_bytes() {
        let findings = vec![
            finding(Detector::GrowingLogs, "/a", 10 * crate::model::GIB),
            finding(Detector::Duplicates, "/b", 5 * crate::model::GIB),
            finding(Detector::Duplicates, "/c", crate::model::GIB),
        ];
        let s = summarise(&findings, 100 * crate::model::GIB, 1234);

        assert_eq!(s.total_reclaimable, 16 * crate::model::GIB);
        assert_eq!(s.total_scanned, 100 * crate::model::GIB);
        assert_eq!(s.counts_by_severity.total(), 3);
        assert_eq!(s.elapsed_ms, 1234);
        assert_eq!(s.counts_by_detector.len(), 2);
    }

    #[test]
    fn summarise_counts_severities_independently() {
        let findings = vec![
            finding(Detector::GrowingLogs, "/a", 30 * crate::model::GIB),
            finding(Detector::GrowingLogs, "/b", 7 * crate::model::GIB),
            finding(Detector::GrowingLogs, "/c", 2 * crate::model::GIB),
            finding(Detector::GrowingLogs, "/d", 500 * crate::model::MIB),
            finding(Detector::GrowingLogs, "/e", 1024),
        ];
        let s = summarise(&findings, 0, 0);

        assert_eq!(s.counts_by_severity.get(Severity::Critical), 1);
        assert_eq!(s.counts_by_severity.get(Severity::High), 1);
        assert_eq!(s.counts_by_severity.get(Severity::Medium), 1);
        assert_eq!(s.counts_by_severity.get(Severity::Low), 1);
        assert_eq!(s.counts_by_severity.get(Severity::Info), 1);
    }

    #[test]
    fn findings_sort_most_urgent_first() {
        let mut findings = vec![
            finding(Detector::Duplicates, "/small", 1024),
            finding(Detector::GrowingLogs, "/huge", 50 * crate::model::GIB),
            finding(Detector::OldInstallers, "/medium", 2 * crate::model::GIB),
        ];
        sort_by_impact(&mut findings);
        assert_eq!(findings[0].path.to_string_lossy(), "/huge");
        assert_eq!(findings[1].path.to_string_lossy(), "/medium");
        assert_eq!(findings[2].path.to_string_lossy(), "/small");
    }

    #[test]
    fn finding_ids_are_deterministic_and_detector_scoped() {
        let a = finding_id(Detector::GrowingLogs, std::path::Path::new("/x/y.log"));
        let b = finding_id(Detector::GrowingLogs, std::path::Path::new("/x/y.log"));
        let c = finding_id(Detector::Duplicates, std::path::Path::new("/x/y.log"));
        assert_eq!(
            a, b,
            "same input must give the same id, so reports can be diffed"
        );
        assert_ne!(a, c, "different detectors must not collide");
        assert!(a.starts_with("growing_logs-"), "{a}");
    }

    #[test]
    fn duplicate_paths_from_one_detector_are_dropped() {
        let mut findings = vec![
            finding(Detector::GrowingLogs, "/same", 100),
            finding(Detector::GrowingLogs, "/same", 200),
            finding(Detector::Duplicates, "/same", 300),
        ];
        dedupe_by_path(&mut findings);
        assert_eq!(findings.len(), 2, "one per detector, not one overall");
    }

    #[test]
    fn confidence_is_clamped_at_construction() {
        let f = make_finding(
            Detector::GrowingLogs,
            std::path::Path::new("/a"),
            10,
            10,
            f32::NAN,
            Safety::ReviewFirst,
            "t".into(),
            "r".into(),
            serde_json::json!({}),
        );
        assert_eq!(f.confidence, 0.0, "NaN must never reach the UI");
        assert!(f.confidence.is_finite());
    }
}
