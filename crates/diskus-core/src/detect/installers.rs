//! **Detector 4 — Old installers.**
//!
//! Answers: *what can I delete that is only an installer or a download cache
//! nobody will ever need again?*
//!
//! Two sources, deliberately kept apart because they carry very different risk:
//!
//! * **Package-manager caches** are reported wholesale with very high confidence.
//!   Clearing `~/.npm` is a well-understood, lossless operation — the packages
//!   re-download on demand. Saying so plainly is more useful than hedging.
//!
//! * **Loose installer files** in Downloads and Desktop are reported with
//!   `ReviewFirst`. A `.msi` might be the only copy of a tool somebody needs to
//!   reinstall offline, and Diskus has no way to know that.

use crate::config::ScanConfig;
use crate::detect::make_finding;
use crate::detect::rules;
use crate::model::{Detector, Finding, Safety, ScanResult};
use crate::util;
use std::path::PathBuf;

/// How much of a package cache is assumed reclaimable.
///
/// Not 100%: lock files and in-flight downloads are genuinely in use. 90% is a
/// deliberate, conservative round number, and it is stated in every finding.
const CACHE_RECLAIM_FRACTION: f64 = 0.9;

/// Upper bound on loose installer findings, so one machine with 10,000 archives
/// in Downloads does not produce an unusable report.
const MAX_INSTALLER_FINDINGS: usize = 500;

/// Find stale installers and reclaimable package-manager caches.
#[must_use]
pub fn detect(result: &ScanResult, config: &ScanConfig) -> Vec<Finding> {
    let now = util::now();
    let mut cache_findings = Vec::new();
    let mut installer_findings = Vec::new();

    // A directory that is itself a package-manager cache, reported once.
    let mut reported_caches: Vec<PathBuf> = Vec::new();

    for node in result.nodes.iter().filter(|n| n.is_dir()) {
        let Some(package) = rules::is_package_manager_cache(&node.path) else {
            continue;
        };
        // Report the outermost cache directory only. Without this, a cache with
        // nested subdirectories yields several findings for the same bytes, and
        // the report double-counts them.
        if reported_caches
            .iter()
            .any(|seen| node.path.starts_with(seen.as_path()))
        {
            continue;
        }
        if node.size == 0 {
            continue;
        }
        reported_caches.push(node.path.clone());

        let reclaimable = (node.on_disk.max(node.size) as f64 * CACHE_RECLAIM_FRACTION) as u64;
        cache_findings.push(make_finding(
            Detector::OldInstallers,
            &node.path,
            node.on_disk.max(node.size),
            reclaimable,
            0.95,
            Safety::SafeToDelete,
            format!("{package} cache: {}", util::human_bytes(node.size)),
            format!(
                "Clear the {package} cache. Diskus estimates {} is reclaimable; the remainder is \
                 in-flight downloads and lock files. Packages re-download automatically when \
                 needed.",
                util::human_bytes(reclaimable)
            ),
            serde_json::json!({
                "kind": "package_cache",
                "packageManager": package,
                "path": node.path.to_string_lossy(),
                "bytes": node.size,
                "allocatedBytes": node.on_disk,
                "reclaimableBytes": reclaimable,
                "reclaimFraction": CACHE_RECLAIM_FRACTION,
                "assumption": "Assumes 90% of the cache is not currently in use.",
            }),
        ));
    }

    for node in &result.nodes {
        if node.kind != crate::model::FileKind::File {
            continue;
        }
        if node.size < config.min_installer_size {
            continue;
        }
        let Some(parent) = node.path.parent() else {
            continue;
        };
        if !rules::is_staging_location(parent) {
            continue;
        }

        let installer_like = rules::is_installer_extension(node.extension.as_deref());
        let name_like = rules::looks_like_installer(&node.name);
        if !installer_like && !name_like {
            continue;
        }

        let age_days = util::days_since(node.modified, now);
        let Some(days_old) = age_days else {
            continue;
        };
        if days_old < i64::from(config.installer_stale_days) {
            continue;
        }

        // Anything already inside a package cache is handled by the cache finding
        // above; reporting it twice would double-count the same bytes.
        if rules::is_package_manager_cache(parent).is_some() {
            continue;
        }

        // An archive among someone's documents is more likely to be their data
        // than a setup file that merely happens to be zipped. Downloads and
        // Desktop are staging areas, so a file there only warrants a look.
        let safety = if rules::is_document_location(parent) {
            Safety::DataLoss
        } else {
            Safety::ReviewFirst
        };

        // Confidence rises when *both* signals agree: the extension is an
        // installer type *and* the filename looks like one.
        let confidence = match (installer_like, name_like) {
            (true, true) => 0.95,
            (true, false) => 0.7,
            (false, true) => 0.55,
            (false, false) => 0.3,
        };

        let title = format!(
            "Stale {} from {} days ago",
            installer_label(node.extension.as_deref(), &node.name),
            days_old
        );

        let recommendation = if safety == Safety::DataLoss {
            format!(
                "`{}` is in a folder Diskus treats as personal files. If you already have \
                 another copy, or can re-download it, deleting frees {}.",
                node.path.display(),
                util::human_bytes(node.size)
            )
        } else {
            format!(
                "Confirm you can re-download or reinstall this, then delete \
                 `{}` to free {}.",
                node.path.display(),
                util::human_bytes(node.size)
            )
        };

        installer_findings.push(make_finding(
            Detector::OldInstallers,
            &node.path,
            node.size,
            node.on_disk.max(node.size),
            confidence,
            safety,
            title,
            recommendation,
            serde_json::json!({
                "kind": "installer_file",
                "extension": node.extension,
                "filename": node.name,
                "path": node.path.to_string_lossy(),
                "directory": parent.to_string_lossy(),
                "bytes": node.size,
                "allocatedBytes": node.on_disk,
                "modified": util::fmt_rfc3339(node.modified),
                "daysOld": days_old,
                "inStagingLocation": true,
                "extensionIsInstaller": installer_like,
                "nameLooksLikeInstaller": name_like,
            }),
        ));
    }

    // Caches are the high-confidence, high-value results, so they lead.
    installer_findings.sort_by_key(|f| std::cmp::Reverse(f.reclaimable));
    installer_findings.truncate(MAX_INSTALLER_FINDINGS);

    cache_findings.extend(installer_findings);
    cache_findings
}

/// A human label for the kind of installer.
fn installer_label(extension: Option<&str>, name: &str) -> String {
    match extension.map(str::to_ascii_lowercase).as_deref() {
        Some(".msi") | Some(".msix") | Some(".msixbundle") | Some(".msu") => {
            "Windows installer".to_string()
        }
        Some(".dmg") => "macOS disk image".to_string(),
        Some(".pkg") => "macOS package".to_string(),
        Some(".deb") => "Debian package".to_string(),
        Some(".rpm") => "RPM package".to_string(),
        Some(".appimage") => "AppImage".to_string(),
        Some(".iso") => "disc image".to_string(),
        Some(".exe") => "Windows executable".to_string(),
        Some(ext) if ext.starts_with('.') => format!("archive ({ext})"),
        _ if name.to_ascii_lowercase().contains("setup") => "installer".to_string(),
        _ => "installer or archive".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testing::{Age, ScanBuilder};
    use crate::model::{GIB, MIB};

    fn config() -> ScanConfig {
        ScanConfig::default()
    }

    #[test]
    fn package_caches_are_reported_wholesale() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/.npm/_cacache/a.bin", 12 * GIB, Age::Days(30))
            .build();

        let findings = detect(&result, &config());
        let npm = findings
            .iter()
            .find(|f| f.detail["kind"] == "package_cache")
            .expect("npm cache finding");

        assert_eq!(npm.detail["packageManager"].as_str().unwrap(), "npm");
        assert_eq!(npm.size, 12 * GIB);
        assert_eq!(
            npm.reclaimable,
            (12.0 * 1024.0 * 1024.0 * 1024.0 * CACHE_RECLAIM_FRACTION) as u64,
            "90% of the cache, not all of it"
        );
        assert_eq!(npm.safety, Safety::SafeToDelete);
        assert!(npm.confidence >= 0.95);
    }

    #[test]
    fn a_cache_is_one_finding_not_one_per_file() {
        let mut builder = ScanBuilder::new();
        builder
            .roots(&["/Users"])
            .file("/Users/jdoe/.npm/x", 100 * MIB, Age::Days(5));
        for i in 0..50 {
            builder.file(
                &format!("/Users/jdoe/.npm/_cacache/pack{i}.bin"),
                10 * MIB,
                Age::Days(5),
            );
        }
        let result = builder.build();

        let findings = detect(&result, &config());
        let cache_findings = findings
            .iter()
            .filter(|f| f.detail["kind"] == "package_cache")
            .count();
        assert_eq!(cache_findings, 1, "51 files, one cache, one finding");
    }

    #[test]
    fn stale_installers_in_downloads_are_flagged() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file(
                "/Users/jdoe/Downloads/VSCodeSetup.exe",
                120 * MIB,
                Age::Days(400),
            )
            .build();

        let findings = detect(&result, &config());
        let f = findings
            .iter()
            .find(|f| f.detail["kind"] == "installer_file")
            .expect("installer finding");

        assert_eq!(f.detail["filename"].as_str().unwrap(), "VSCodeSetup.exe");
        assert_eq!(f.safety, Safety::ReviewFirst);
        assert!(f.title.contains("400 days"), "{}", f.title);
    }

    #[test]
    fn recent_downloads_are_left_alone() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file(
                "/Users/jdoe/Downloads/installer.exe",
                120 * MIB,
                Age::Days(2),
            )
            .build();

        assert!(
            detect(&result, &config()).is_empty(),
            "downloaded this week is not stale"
        );
    }

    #[test]
    fn small_files_are_ignored() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file(
                "/Users/jdoe/Downloads/old-tool.zip",
                2 * MIB,
                Age::Days(500),
            )
            .build();

        assert!(detect(&result, &config()).is_empty());
    }

    #[test]
    fn files_outside_staging_locations_are_ignored() {
        let result = ScanBuilder::new()
            .roots(&["/opt"])
            .file("/opt/app/bundles/data.zip", 500 * MIB, Age::Days(500))
            .build();

        assert!(
            detect(&result, &config()).is_empty(),
            "a zip in an install tree is not a stale download"
        );
    }

    #[test]
    fn archives_in_documents_are_treated_as_data_loss() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file(
                "/Users/jdoe/Documents/archive.zip",
                400 * MIB,
                Age::Days(400),
            )
            .build();

        let f = detect(&result, &config())
            .into_iter()
            .find(|f| f.detail["kind"] == "installer_file")
            .expect("finding");
        assert_eq!(f.safety, Safety::DataLoss);
    }

    #[test]
    fn files_inside_a_package_cache_are_not_double_counted() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/.npm/old-setup.msi", 300 * MIB, Age::Days(400))
            .build();

        let findings = detect(&result, &config());
        assert_eq!(
            findings.len(),
            1,
            "only the cache finding, not also the file"
        );
        assert_eq!(findings[0].detail["kind"], "package_cache");
    }

    #[test]
    fn confidence_rises_when_both_signals_agree() {
        let strong = ScanBuilder::new()
            .roots(&["/Users"])
            .file(
                "/Users/jdoe/Downloads/Setup_x64.msi",
                200 * MIB,
                Age::Days(400),
            )
            .build();
        let weak = ScanBuilder::new()
            .roots(&["/Users"])
            .file(
                "/Users/jdoe/Downloads/installer-data.bin",
                200 * MIB,
                Age::Days(400),
            )
            .build();

        let find = |r: ScanResult| {
            detect(&r, &config())
                .into_iter()
                .find(|f| f.detail["kind"] == "installer_file")
                .expect("installer finding")
                .confidence
        };

        assert!(find(strong) > find(weak));
    }
}
