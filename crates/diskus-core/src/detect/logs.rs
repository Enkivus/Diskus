//! **Detector 1 — Growing log files.**
//!
//! Answers: *what is actively filling this disk, and what will fill it again
//! tomorrow?*
//!
//! The insight that makes this detector worth having: a log file is rarely one
//! file. `server.log`, `server.log.1`, `server.log.2.gz` and `server.log.3.gz`
//! are one problem wearing four costumes. Grouping by the un-rotated base name
//! turns four findings into one, and the number that matters — "this application
//! is holding 14 GB of logs and will keep growing" — only becomes visible after
//! grouping.
//!
//! The second insight: never recommend deleting the *active* log of a live
//! application. The reclaimable figure subtracts it.

use crate::config::ScanConfig;
use crate::detect::make_finding;
use crate::detect::rules;
use crate::model::{Detector, Finding, Safety, ScanNode, ScanResult};
use crate::util;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Below this, a rotation set is not worth reporting.
const MIN_SET_BYTES: u64 = 64 * 1024 * 1024;

/// A single log below this is not worth reporting on its own.
const MIN_LONE_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// How many rotations before a set is interesting regardless of size.
const INTERESTING_ROTATIONS: usize = 3;

/// Extensions that mean "this is a log", by compound form.
const LOG_EXTENSIONS: [&str; 10] = [
    ".log",
    ".err",
    ".out",
    ".trace",
    ".errlog",
    ".evtx",
    ".etl",
    ".glog",
    ".log.gz",
    ".log.1.gz",
];

/// One rotation set: a base log and everything rotated away from it.
#[derive(Debug)]
struct RotationSet {
    /// Directory the set lives in.
    dir: PathBuf,
    /// Base name with rotation suffixes removed.
    base_name: String,
    /// Full path of the active (un-rotated) log, if present.
    active: Option<ScanNode>,
    /// Rotated siblings.
    rotations: Vec<ScanNode>,
    /// Whether the set sits under a directory we recognise as a log location.
    known_log_dir: bool,
}

impl RotationSet {
    /// Every member of the set, active log first.
    fn members(&self) -> impl Iterator<Item = &ScanNode> {
        self.active.iter().chain(self.rotations.iter())
    }

    /// Total bytes across the set.
    fn total(&self) -> u64 {
        self.members().map(|n| n.size).sum()
    }

    /// Newest modification time in the set.
    fn newest_modified(&self) -> Option<time::OffsetDateTime> {
        self.members().filter_map(|n| n.modified).max()
    }

    /// Bytes we can honestly expect back.
    ///
    /// If the set is still being written to, the active log has to stay: deleting
    /// it loses the current run's output. Only archived rotations are offered.
    fn reclaimable(&self, actively_growing: bool) -> u64 {
        if actively_growing {
            self.rotations.iter().map(|n| n.size).sum()
        } else {
            self.total()
        }
    }
}

/// Find log files and rotation sets that are consuming space they should not.
#[must_use]
pub fn detect(result: &ScanResult, config: &ScanConfig) -> Vec<Finding> {
    let now = util::now();
    let sets = group_into_sets(result);
    let mut findings = Vec::new();

    for set in sets {
        let total = set.total();
        let newest = set.newest_modified();
        let days_since_newest = util::days_since(newest, now);
        let actively_growing =
            days_since_newest.is_some_and(|d| d <= i64::from(config.log_active_days));
        let stale = days_since_newest.is_some_and(|d| d >= i64::from(config.log_stale_days));

        let rotations = set.rotations.len();
        let interesting = (total >= MIN_SET_BYTES && rotations >= 2)
            || (actively_growing && total >= MIN_SET_BYTES)
            || rotations >= INTERESTING_ROTATIONS
            || (set.known_log_dir && total >= MIN_LONE_FILE_BYTES);

        if !interesting {
            continue;
        }

        let reclaimable = set.reclaimable(actively_growing);
        if reclaimable == 0 {
            continue;
        }

        // Confidence blends how well we know this is a log location, whether it
        // is demonstrably still being written, and how stale it is.
        let mut confidence = if set.known_log_dir { 0.85 } else { 0.55 };
        if actively_growing {
            confidence += 0.1;
        }
        if rotations >= 3 {
            confidence += 0.05;
        }
        if stale {
            confidence += 0.05;
        }

        // A live application's logs are only ever safe to clear once nothing has
        // been written for a long time. Otherwise the recommendation is to
        // archive, not delete.
        let safety = if set.known_log_dir && stale {
            Safety::SafeToDelete
        } else {
            Safety::ReviewFirst
        };

        let base_path = set
            .active
            .as_ref()
            .map_or_else(|| set.dir.join(&set.base_name), |n| n.path.clone());

        let has_compressed = set.rotations.iter().any(|n| {
            n.name.ends_with(".gz") || n.name.ends_with(".xz") || n.name.ends_with(".bz2")
        });
        let uncompressed_rotations = set
            .rotations
            .iter()
            .filter(|n| {
                !(n.name.ends_with(".gz") || n.name.ends_with(".xz") || n.name.ends_with(".bz2"))
            })
            .count();

        let title = if rotations == 0 {
            format!("Large log file: {}", set.base_name)
        } else if actively_growing {
            format!(
                "{} rotated logs are holding {} for {}",
                set.base_name,
                util::human_bytes(total),
                set.dir.file_name().map_or_else(
                    || set.dir.display().to_string(),
                    |n| n.to_string_lossy().to_string()
                )
            )
        } else {
            format!(
                "{} stale log rotations, {}",
                rotations,
                util::human_bytes(total)
            )
        };

        let recommendation = if stale {
            format!(
                "Nothing has been written to this log set since {}. Delete all {} file(s) and free {}.",
                util::fmt_rfc3339(newest),
                set.members().count(),
                util::human_bytes(reclaimable)
            )
        } else if uncompressed_rotations > 0 {
            format!(
                "Archive and compress the {} uncompressed rotation(s), keeping the active log. \
                 Compressing them typically reclaims 70–90% of the {} available.",
                uncompressed_rotations,
                util::human_bytes(reclaimable)
            )
        } else if rotations > 0 {
            format!(
                "This application is still writing. Delete the {} archived rotation(s) to free \
                 {} — the active log must stay.",
                rotations,
                util::human_bytes(reclaimable)
            )
        } else {
            format!(
                "Configure log rotation for this application so old output is compressed and \
                 pruned. It currently holds {}.",
                util::human_bytes(total)
            )
        };

        let mut finding = make_finding(
            Detector::GrowingLogs,
            &base_path,
            total,
            reclaimable,
            confidence,
            safety,
            title,
            recommendation,
            serde_json::json!({
                "basePath": base_path.to_string_lossy(),
                "directory": set.dir.to_string_lossy(),
                "rotations": set.rotations.iter().map(|n| n.name.clone()).collect::<Vec<_>>(),
                "totalBytes": total,
                "reclaimableBytes": reclaimable,
                "newestModified": util::fmt_rfc3339(newest),
                "daysSinceLastWrite": days_since_newest,
                "activelyGrowing": actively_growing,
                "stale": stale,
                "knownLogDir": set.known_log_dir,
                "alreadyCompressed": has_compressed,
                "files": set.members().map(|n| n.name.clone()).collect::<Vec<_>>(),
            }),
        );
        // The primary path is the active log; everything else in the set is
        // listed alongside it.
        finding.related_paths = set
            .members()
            .map(|n| n.path.clone())
            .filter(|p| *p != finding.path)
            .collect();

        findings.push(finding);
    }

    findings
}

/// Group every log-like file into its rotation set.
fn group_into_sets(result: &ScanResult) -> Vec<RotationSet> {
    let mut grouped: BTreeMap<(PathBuf, String), RotationSet> = BTreeMap::new();

    for node in result
        .nodes
        .iter()
        .filter(|n| n.kind == crate::model::FileKind::File)
    {
        if !is_log_like(node) {
            continue;
        }
        let dir = node.path.parent().unwrap_or(Path::new("/")).to_path_buf();
        let (base_name, was_rotated) = util::strip_rotation_suffix(&node.name);
        if base_name.is_empty() {
            continue;
        }

        let entry = grouped
            .entry((dir.clone(), base_name.clone()))
            .or_insert_with(|| RotationSet {
                dir: dir.clone(),
                base_name: base_name.clone(),
                active: None,
                rotations: Vec::new(),
                known_log_dir: rules::is_known_log_dir(&dir),
            });

        if was_rotated || node.name != base_name {
            entry.rotations.push(node.clone());
        } else {
            entry.active = Some(node.clone());
        }
    }

    grouped.into_values().collect()
}

/// Whether a file is plausibly a log.
///
/// Two independent signals, either of which is enough: it looks like a log by
/// name, or it sits somewhere logs live. The second matters because plenty of
/// applications log to files with unhelpful names.
fn is_log_like(node: &ScanNode) -> bool {
    let in_log_dir = rules::is_known_log_dir(node.path.parent().unwrap_or(Path::new("/")));
    if in_log_dir && has_logish_extension(node) {
        return true;
    }
    let compound = util::compound_extension(&node.name).unwrap_or_default();
    compound.starts_with(".log.")
        || LOG_EXTENSIONS.iter().any(|e| compound.ends_with(e))
        || compound == ".log"
}

/// Whether a filename carries any extension commonly used by log output.
fn has_logish_extension(node: &ScanNode) -> bool {
    let compound = util::compound_extension(&node.name).unwrap_or_default();
    compound.starts_with(".log")
        || LOG_EXTENSIONS.iter().any(|e| compound.ends_with(e))
        || matches!(
            node.extension.as_deref(),
            Some(".log") | Some(".err") | Some(".out") | Some(".txt")
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::detect::testing::{Age, ScanBuilder};
    use crate::model::{GIB, MIB};

    fn config() -> ScanConfig {
        ScanConfig::default()
    }

    #[test]
    fn rotation_sets_are_grouped_into_one_finding() {
        let result = ScanBuilder::new()
            .roots(&["/var/log"])
            .file("/var/log/app/server.log", 500 * MIB, Age::Hours(2))
            .file("/var/log/app/server.log.1", 800 * MIB, Age::Days(10))
            .file("/var/log/app/server.log.2", 800 * MIB, Age::Days(20))
            .file("/var/log/app/server.log.3.gz", 100 * MIB, Age::Days(30))
            .build();

        let findings = detect(&result, &config());
        assert_eq!(findings.len(), 1, "four files, one problem, one finding");

        let f = &findings[0];
        assert_eq!(f.size, 2200 * MIB);
        assert_eq!(f.reclaimable, 1700 * MIB);
        assert_eq!(f.related_paths.len(), 3, "the other three files are listed");
        assert!(f.detail["activelyGrowing"].as_bool().unwrap());
        assert_eq!(f.detail["rotations"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn the_active_log_is_never_offered_for_deletion() {
        let result = ScanBuilder::new()
            .roots(&["/var/log"])
            .file("/var/log/app/server.log", 5 * GIB, Age::Hours(1))
            .file("/var/log/app/server.log.1", 2 * GIB, Age::Days(15))
            .build();

        let f = &detect(&result, &config())[0];
        assert_eq!(f.reclaimable, 2 * GIB, "only the rotation is reclaimable");
        assert_eq!(f.size, 7 * GIB);
        assert_eq!(f.safety, Safety::ReviewFirst, "the app is still writing");
        assert!(
            f.recommendation.contains("active log"),
            "the advice must be explicit about the active log: {}",
            f.recommendation
        );
    }

    #[test]
    fn stale_sets_become_safe_to_delete_including_the_active_file() {
        let result = ScanBuilder::new()
            .roots(&["/var/log"])
            .file("/var/log/app/old.log", 3 * GIB, Age::Days(400))
            .file("/var/log/app/old.log.1", 3 * GIB, Age::Days(430))
            .build();

        let f = &detect(&result, &config())[0];
        assert_eq!(
            f.reclaimable,
            6 * GIB,
            "nothing is being written; all of it can go"
        );
        assert_eq!(f.safety, Safety::SafeToDelete);
        assert!(!f.detail["activelyGrowing"].as_bool().unwrap());
    }

    #[test]
    fn uncompressed_rotations_get_a_compression_recommendation() {
        // Recent enough to still be in rotation, so compressing beats deleting.
        let result = ScanBuilder::new()
            .roots(&["/var/log"])
            .file("/var/log/app/x.log", 10 * MIB, Age::Hours(3))
            .file("/var/log/app/x.log.1", 700 * MIB, Age::Days(9))
            .file("/var/log/app/x.log.2", 700 * MIB, Age::Days(11))
            .build();

        let f = &detect(&result, &config())[0];
        assert!(
            f.recommendation.contains("compress"),
            "should suggest compression, got: {}",
            f.recommendation
        );
    }

    #[test]
    fn small_rotation_sets_are_ignored() {
        let result = ScanBuilder::new()
            .roots(&["/var/log"])
            .file("/var/log/tiny/a.log", 1024, Age::Hours(1))
            .file("/var/log/tiny/a.log.1", 2048, Age::Days(5))
            .build();

        assert!(
            detect(&result, &config()).is_empty(),
            "8 KB of logs is noise, not a finding"
        );
    }

    #[test]
    fn unrelated_files_are_never_treated_as_logs() {
        let result = ScanBuilder::new()
            .roots(&["/data"])
            .file("/data/photo.jpg", 900 * MIB, Age::Days(1))
            .file("/data/photo2.jpg", 900 * MIB, Age::Days(1))
            .build();

        assert!(detect(&result, &config()).is_empty());
    }

    #[test]
    fn logs_outside_known_directories_still_get_reported() {
        // Applications routinely log into their own install tree. Sitting outside
        // /var/log must not make a 40 GB log invisible.
        let result = ScanBuilder::new()
            .roots(&["/opt"])
            .file("/opt/myapp/logs/service.log", 30 * GIB, Age::Hours(3))
            .file("/opt/myapp/logs/service.log.1", 20 * GIB, Age::Days(12))
            .build();

        let findings = detect(&result, &config());
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].detail["knownLogDir"].as_bool().unwrap());
        assert!(
            findings[0].confidence < 0.9,
            "lower confidence outside a known log dir: {}",
            findings[0].confidence
        );
    }

    #[test]
    fn severity_tracks_reclaimable_bytes() {
        let result = ScanBuilder::new()
            .roots(&["/var/log"])
            .file("/var/log/app/huge.log", 40 * GIB, Age::Hours(1))
            .file("/var/log/app/huge.log.1", 40 * GIB, Age::Days(30))
            .build();

        let f = &detect(&result, &config())[0];
        assert_eq!(f.severity, crate::model::Severity::Critical);
    }

    #[test]
    fn separate_applications_produce_separate_findings() {
        let result = ScanBuilder::new()
            .roots(&["/var/log"])
            .file("/var/log/nginx/access.log", 900 * MIB, Age::Hours(5))
            .file("/var/log/nginx/access.log.1", 900 * MIB, Age::Days(12))
            .file("/var/log/mysql/slow.log", 900 * MIB, Age::Hours(6))
            .file("/var/log/mysql/slow.log.1", 900 * MIB, Age::Days(12))
            .build();

        let findings = detect(&result, &config());
        assert_eq!(findings.len(), 2, "one per application");
        assert_ne!(findings[0].path, findings[1].path);
    }
}
