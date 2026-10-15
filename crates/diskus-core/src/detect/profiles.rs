//! **Detector 3 — Oversized user profiles.**
//!
//! Answers: *whose home directory is too big, and what inside it is responsible?*
//!
//! "jdoe's profile is 180 GB" is not actionable. "`jdoe/Library/Caches` is 90 GB
//! and safe to delete" is. So this detector emits one finding per significant
//! top-level subfolder, each classified by how much of it is genuinely
//! recoverable — which is also the part that separates a useful report from a
//! scary one.
//!
//! Every estimate this detector makes is written into the finding's `detail`,
//! including the assumption behind it, so a user who disagrees can see exactly
//! which number was guessed.

use crate::config::ScanConfig;
use crate::detect::make_finding;
use crate::detect::rules::{self, Reclaimability};
use crate::model::{Detector, Finding, Safety, ScanNode, ScanResult};
use crate::util;
use std::path::{Path, PathBuf};

/// A top-level subfolder of a user profile worth reporting on its own.
const MIN_SUBFOLDER_BYTES: u64 = 1024 * 1024 * 1024;

/// How many subfolder findings to emit per profile before summarising the rest.
const MAX_SUBFOLDERS_PER_PROFILE: usize = 8;

/// A user profile that exceeded the threshold.
struct FlaggedProfile {
    root: PathBuf,
    username: String,
    size: u64,
    volume_total: u64,
    /// Why it was flagged: above the absolute threshold, or a share of its volume.
    reason: &'static str,
    children: Vec<ScanNode>,
}

/// Find user profiles that are too large, and break down why.
#[must_use]
pub fn detect(result: &ScanResult, config: &ScanConfig) -> Vec<Finding> {
    let mut findings = Vec::new();

    for profile in flag_profiles(result, config) {
        findings.push(profile_summary_finding(&profile));

        for child in profile.children.iter().take(MAX_SUBFOLDERS_PER_PROFILE) {
            if let Some(f) = subfolder_finding(&profile, child) {
                findings.push(f);
            }
        }

        // If there were more big subfolders than we listed, say so rather than
        // letting the total quietly not add up.
        let hidden = profile
            .children
            .len()
            .saturating_sub(MAX_SUBFOLDERS_PER_PROFILE);
        if hidden > 0 {
            let rest: u64 = profile
                .children
                .iter()
                .skip(MAX_SUBFOLDERS_PER_PROFILE)
                .map(|c| c.size)
                .sum();
            findings.push(overflow_finding(&profile, hidden, rest));
        }
    }

    findings
}

/// Locate profiles that exceed either the absolute or the relative threshold.
fn flag_profiles(result: &ScanResult, config: &ScanConfig) -> Vec<FlaggedProfile> {
    let mut flagged: Vec<FlaggedProfile> = Vec::new();

    // Only directories that are genuinely a user's home: a direct child of a
    // `Users` or `home` directory. Anything looser picks up system directories.
    for node in result.nodes.iter().filter(|n| n.is_dir()) {
        let Some(root) = home_root_of(&node.path) else {
            continue;
        };
        // Only consider the profile root itself, not nested folders.
        if node.path != root {
            continue;
        }

        let over_absolute = node.size > config.profile_size_threshold;
        let volume_total = crate::scan::platform::volume_total_bytes(&root).unwrap_or(0);
        let fraction = if volume_total > 0 {
            node.size as f64 / volume_total as f64
        } else {
            0.0
        };
        let over_relative = volume_total > 0 && fraction > config.profile_volume_fraction;

        if !over_absolute && !over_relative {
            continue;
        }

        let username = root.file_name().map_or_else(
            || root.display().to_string(),
            |n| n.to_string_lossy().to_string(),
        );

        let children = significant_children(result, &root);
        flagged.push(FlaggedProfile {
            root,
            username,
            size: node.size,
            volume_total,
            reason: if over_absolute {
                "size"
            } else {
                "volume_fraction"
            },
            children,
        });
    }

    // Two roots could resolve to the same profile (e.g. `/Users/jdoe` and a
    // symlink). Keep the first, which the sorted scan order makes deterministic.
    let mut seen = std::collections::HashSet::new();
    flagged.retain(|p| seen.insert(p.root.clone()));
    flagged.sort_by_key(|p| std::cmp::Reverse(p.size));
    flagged
}

/// The subtrees inside a profile worth breaking down.
///
/// Deliberately not "direct children", and deliberately ranked by **reclaimable
/// bytes rather than raw size**.
///
/// Both choices exist for the same reason: a profile's biggest problem is almost
/// always nested. `Library/Caches` might be 90 GB, but its direct parent
/// `Library` is 91 GB and classifies as personal application data. Ranking by raw
/// size selects `Library`, classifies the 90 GB of cache as untouchable, and
/// tells the user nothing. Ranking by what can actually be freed selects
/// `Library/Caches` instead.
///
/// Overlapping selections are dropped rather than merged, so the reported
/// subfolders never double-count the same bytes.
fn significant_children(result: &ScanResult, root: &Path) -> Vec<ScanNode> {
    let candidates: Vec<ScanNode> = result
        .nodes
        .iter()
        .filter(|n| n.is_dir() && n.path != root && n.path.starts_with(root))
        .filter(|n| n.size >= MIN_SUBFOLDER_BYTES)
        .cloned()
        .collect();

    if candidates.is_empty() {
        return Vec::new();
    }

    // Descending: `sort_by` puts *smaller* first, so the comparison is inverted.
    let by_reclaimable = |a: &ScanNode, b: &ScanNode| {
        subfolder_reclaimable(&relative_to(root, &b.path), b)
            .cmp(&subfolder_reclaimable(&relative_to(root, &a.path), a))
            .then_with(|| a.size.cmp(&b.size))
            .then_with(|| a.path.cmp(&b.path))
    };

    let mut ordered = candidates.clone();
    ordered.sort_by(by_reclaimable);

    // If nothing in the profile is reclaimable — a profile that is simply full of
    // the user's own files — rank by size instead, so the breakdown still
    // explains where the space went.
    let any_reclaimable = ordered
        .iter()
        .any(|n| subfolder_reclaimable(&relative_to(root, &n.path), n) > 0);
    if !any_reclaimable {
        ordered.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
    }

    let mut selected: Vec<ScanNode> = Vec::new();
    for candidate in ordered {
        // Already covered by a larger folder we are reporting on.
        if selected.iter().any(|s| candidate.path.starts_with(&s.path)) {
            continue;
        }
        selected.push(candidate);
    }

    selected
}

/// The home directory a path is directly inside, if it is one.
fn home_root_of(path: &Path) -> Option<PathBuf> {
    let components: Vec<_> = path.components().collect();
    // Scans can include mounted volumes or backups from another OS, so accept
    // both common Unix home roots regardless of the host running the scan.
    let markers: &[&str] = if cfg!(windows) {
        &["users"]
    } else {
        &["users", "home"]
    };

    for (i, c) in components.iter().enumerate() {
        let s = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        if markers.contains(&s.as_str()) {
            // Must be `marker` / `username` — exactly two levels, or a Windows
            // drive root like `C:\Users` itself.
            if i + 1 >= components.len() || i + 2 < components.len() {
                continue;
            }
            let name = components[i + 1].as_os_str().to_string_lossy().to_string();
            if name.is_empty() {
                continue;
            }
            // Reject `Users`, `Public`, `Default` and other non-profiles.
            if is_reserved(&name) {
                continue;
            }
            return Some(components[..=i + 1].iter().collect());
        }
    }
    None
}

fn is_reserved(name: &str) -> bool {
    const RESERVED: [&str; 10] = [
        "public",
        "default",
        "default user",
        "all users",
        "shared",
        "library",
        "system",
        "lost+found",
        "bin",
        "sbin",
    ];
    RESERVED.contains(&name.to_ascii_lowercase().as_str())
}

/// The bytes a single profile subfolder contributes to a reclaimable total.
///
/// Shared by the per-subfolder findings and by the profile summary, so the two
/// can never disagree. They used to compute it separately and the summary
/// double-counted: on a profile that was mostly cache, the rollup claimed the
/// same bytes the child findings already carried, and the app reported more
/// reclaimable space than the disk physically held.
fn child_reclaimable(root: &Path, child: &ScanNode) -> u64 {
    let rel = relative_to(root, &child.path);
    match rules::classify_home_subpath(&rel) {
        Reclaimability::Safe => subfolder_reclaimable(&rel, child),
        Reclaimability::Rebuildable => {
            let apparent = child.on_disk.max(child.size);
            (apparent as f64 * Reclaimability::Rebuildable.reclaim_fraction()) as u64
        }
        Reclaimability::UserData => 0,
    }
}

/// One finding summarising the whole profile.
fn profile_summary_finding(profile: &FlaggedProfile) -> Finding {
    // What every child contributes in total…
    let total: u64 = profile
        .children
        .iter()
        .map(|c| child_reclaimable(&profile.root, c))
        .sum();

    // …minus what the individual subfolder findings are already reporting, so
    // the same bytes are never counted twice.
    let already_reported: u64 = profile
        .children
        .iter()
        .take(MAX_SUBFOLDERS_PER_PROFILE)
        .map(|c| child_reclaimable(&profile.root, c))
        .sum();
    let reclaimable = total.saturating_sub(already_reported);

    let percent = if profile.volume_total > 0 {
        profile.size as f64 / profile.volume_total as f64 * 100.0
    } else {
        0.0
    };

    let title = format!(
        "{}'s profile uses {}",
        profile.username,
        util::human_bytes(profile.size)
    );

    let recommendation = if reclaimable > 0 {
        format!(
            "{} of this profile is cache or build output that can be regenerated. \
             The breakdown below ranks each folder by what is actually recoverable.",
            util::human_bytes(reclaimable)
        )
    } else {
        "Nothing in this profile is automatically reclaimable — it is mostly personal files. \
         Review the largest folders below."
            .to_string()
    };

    make_finding(
        Detector::OversizedProfiles,
        &profile.root,
        profile.size,
        reclaimable,
        0.9,
        if reclaimable == profile.size {
            Safety::ReviewFirst
        } else {
            Safety::DataLoss
        },
        title,
        recommendation,
        serde_json::json!({
            "username": profile.username,
            "profilePath": profile.root.to_string_lossy(),
            "profileBytes": profile.size,
            "volumeTotal": profile.volume_total,
            "percentOfVolume": (percent * 100.0).round() / 100.0,
            "thresholdReason": profile.reason,
            "isCurrentUser": rules::is_current_user_home(&profile.root),
            "largestChildren": profile.children.iter().take(5)
                .map(|c| serde_json::json!({ "name": c.name, "bytes": c.size }))
                .collect::<Vec<_>>(),
            "childrenTruncated": profile.children.len().saturating_sub(5),
        }),
    )
}

/// A child's path relative to its profile root, or the full path if stripping
/// somehow fails.
fn relative_to(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

/// One finding per large top-level subfolder, classified by recoverability.
fn subfolder_finding(profile: &FlaggedProfile, child: &ScanNode) -> Option<Finding> {
    if child.size < MIN_SUBFOLDER_BYTES {
        return None;
    }

    let rel = relative_to(&profile.root, &child.path);

    let class = rules::classify_home_subpath(&rel);
    let fraction = class.reclaim_fraction();
    // Shares its implementation with the profile summary so the two can never
    // disagree about what a given folder is worth.
    let reclaimable = child_reclaimable(&profile.root, child);

    // A folder with nothing recoverable is still worth reporting if it is huge —
    // it is the reason the profile is oversized — but it must not inflate the
    // reclaimable total.
    let title = format!(
        "{} · {} ({})",
        child.name,
        util::human_bytes(child.size),
        category_label(class)
    );

    let recommendation = match class {
        Reclaimability::Safe => format!(
            "`{}` is a cache. Delete it — it will be rebuilt automatically if the application \
             needs it again. Frees {}.",
            child.path.display(),
            util::human_bytes(reclaimable)
        ),
        Reclaimability::Rebuildable => format!(
            "`{}` is mostly build output or application support data. Removing it is usually \
             safe but the next build or app launch will be slower. Estimated recoverable: {}.",
            child.path.display(),
            util::human_bytes(reclaimable)
        ),
        Reclaimability::UserData => format!(
            "`{}` holds personal files. Diskus will not estimate this as reclaimable — review \
             it yourself, or move it to shared storage.",
            child.path.display()
        ),
    };

    Some(make_finding(
        Detector::OversizedProfiles,
        &child.path,
        child.size,
        reclaimable,
        match class {
            Reclaimability::Safe => 0.9,
            Reclaimability::Rebuildable => 0.7,
            Reclaimability::UserData => 0.5,
        },
        class.safety(),
        title,
        recommendation,
        serde_json::json!({
            "username": profile.username,
            "subfolder": child.name,
            "subfolderPath": child.path.to_string_lossy(),
            "category": format!("{class:?}").to_lowercase(),
            "categoryLabel": category_label(class),
            "bytes": child.size,
            "reclaimableBytes": reclaimable,
            "reclaimFraction": fraction,
            "profileTotalReclaimable": profile
                .children
                .iter()
                .map(|c| child_reclaimable(&profile.root, c))
                .sum::<u64>(),
            "assumption": assumption_for(class),
            "fileCount": child.file_count,
            "childFolders": child.child_count,
        }),
    ))
}

/// The "+N more folders" finding.
fn overflow_finding(profile: &FlaggedProfile, count: usize, bytes: u64) -> Finding {
    make_finding(
        Detector::OversizedProfiles,
        &profile.root,
        bytes,
        0,
        0.6,
        Safety::ReviewFirst,
        format!(
            "{}'s profile has {} more folders over {}",
            profile.username,
            count,
            util::human_bytes(MIN_SUBFOLDER_BYTES)
        ),
        format!(
            "{} across these folders is not itemised in this report. Open the folder to \
             investigate it manually.",
            util::human_bytes(bytes)
        ),
        serde_json::json!({
            "username": profile.username,
            "profilePath": profile.root.to_string_lossy(),
            "hiddenFolderCount": count,
            "hiddenBytes": bytes,
            "isOverflowNotice": true,
        }),
    )
}

/// What can actually be reclaimed from a profile subfolder.
///
/// Only a genuine cache folder counts in full. Everything else is zero, because
/// quietly claiming a user's documents are recoverable is exactly the kind of
/// claim this product must never make.
///
/// `rel` is the subfolder path *relative to the profile root*, which is what the
/// classifier's rules are written against.
fn subfolder_reclaimable(rel: &Path, child: &ScanNode) -> u64 {
    if rules::classify_home_subpath(rel) == Reclaimability::Safe {
        child.on_disk.max(child.size)
    } else {
        0
    }
}

fn category_label(class: Reclaimability) -> &'static str {
    match class {
        Reclaimability::Safe => "Cache — safe to delete",
        Reclaimability::Rebuildable => "Build output — rebuildable",
        Reclaimability::UserData => "Personal files",
    }
}

fn assumption_for(class: Reclaimability) -> &'static str {
    match class {
        Reclaimability::Safe => "Entirely regenerable cache; counted as 100% recoverable.",
        Reclaimability::Rebuildable => {
            "Assumes ~80% is rebuildable output and ~20% is data worth keeping."
        }
        Reclaimability::UserData => {
            "Personal files are never counted as recoverable. Diskus will not guess here."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testing::{Age, ScanBuilder};
    use crate::model::GIB;

    fn config() -> ScanConfig {
        ScanConfig::default()
    }

    #[test]
    fn oversized_profiles_are_flagged_and_broken_down() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/Library/Caches/x.bin", 90 * GIB, Age::Days(3))
            .file("/Users/jdoe/Documents/a.bin", 60 * GIB, Age::Days(3))
            .build();

        let findings = detect(&result, &config());
        let summary = findings
            .iter()
            .find(|f| f.path == std::path::Path::new("/Users/jdoe"))
            .expect("profile summary finding");

        assert_eq!(summary.size, 150 * GIB);
        assert!(summary.detail["largestChildren"].as_array().unwrap().len() >= 2);

        // The summary is a rollup, so it must not re-claim the bytes its own
        // subfolder findings already carry. Together, this profile's findings
        // should account for the 90 GB cache exactly once.
        let total: u64 = findings
            .iter()
            .filter(|f| f.path.starts_with(std::path::Path::new("/Users/jdoe")))
            .map(|f| f.reclaimable)
            .sum();
        assert_eq!(
            total,
            90 * GIB,
            "the cache is claimed once across the profile's findings"
        );
        assert_eq!(
            summary.reclaimable, 0,
            "the summary defers the bytes to its children"
        );
    }

    #[test]
    fn small_profiles_are_not_flagged() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/Documents/a.bin", 5 * GIB, Age::Days(3))
            .build();

        assert!(detect(&result, &config()).is_empty());
    }

    #[test]
    fn personal_files_are_never_claimed_as_recoverable() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/Documents/holiday.mov", 200 * GIB, Age::Days(3))
            .build();

        let findings = detect(&result, &config());
        let docs = findings
            .iter()
            .find(|f| f.path == std::path::Path::new("/Users/jdoe/Documents"))
            .expect("documents finding");

        assert_eq!(docs.reclaimable, 0, "never promise a user's own files back");
        assert_eq!(docs.safety, Safety::DataLoss);
        assert!(
            docs.detail["assumption"]
                .as_str()
                .unwrap()
                .contains("never counted"),
            "the reasoning must be visible: {}",
            docs.detail["assumption"]
        );
    }

    #[test]
    fn caches_are_high_confidence_and_safe() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file(
                "/Users/jdoe/Library/Caches/com.docker/x.bin",
                80 * GIB,
                Age::Days(1),
            )
            .build();

        let findings = detect(&result, &config());
        let cache = findings
            .iter()
            .find(|f| f.path.to_string_lossy().contains("Library/Caches"))
            .expect("cache finding");

        assert_eq!(cache.reclaimable, 80 * GIB);
        assert_eq!(cache.safety, Safety::SafeToDelete);
        assert!(cache.confidence > 0.85, "{}", cache.confidence);
    }

    #[test]
    fn system_directories_under_users_are_not_profiles() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/Shared/scratch.bin", 60 * GIB, Age::Days(1))
            .build();

        assert!(
            detect(&result, &config()).is_empty(),
            "Shared is not a user profile"
        );
    }

    #[test]
    fn nested_directories_are_not_treated_as_separate_profiles() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file(
                "/Users/jdoe/Documents/sub/deep/leaf.bin",
                100 * GIB,
                Age::Days(1),
            )
            .build();

        let findings = detect(&result, &config());
        let profiles = findings
            .iter()
            .filter(|f| {
                f.path == std::path::Path::new("/Users/jdoe/Documents/sub/deep")
                    || f.path == std::path::Path::new("/Users/jdoe/Documents/sub")
            })
            .count();
        assert_eq!(profiles, 0, "only the direct profile root counts");
    }

    #[test]
    fn volume_fraction_can_trigger_a_flag() {
        // Below the absolute 40 GB threshold, but flagged on volume share.
        let mut config = self::config();
        config.profile_size_threshold = 500 * GIB;
        config.profile_volume_fraction = 0.0; // any volume share triggers

        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/Documents/a.bin", 10 * GIB, Age::Days(1))
            .build();

        let findings = detect(&result, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.path == std::path::Path::new("/Users/jdoe")),
            "the volume-share rule should have flagged it"
        );
    }

    #[test]
    fn summary_totals_never_exceed_the_profile_size() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/Library/Caches/a.bin", 50 * GIB, Age::Days(1))
            .file("/Users/jdoe/Documents/b.bin", 50 * GIB, Age::Days(1))
            .build();

        let summary = detect(&result, &config())
            .into_iter()
            .find(|f| f.path == std::path::Path::new("/Users/jdoe"))
            .expect("summary");

        assert!(summary.reclaimable <= summary.size);
    }
}
