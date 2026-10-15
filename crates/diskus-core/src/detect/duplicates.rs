//! **Detector 5 — Duplicate data.**
//!
//! Answers: *where is the same data stored twice, and how much would I get back?*
//!
//! The whole detector exists to avoid one terrible outcome: reading every file on
//! the machine. A modern workstation has tens of gigabytes of small files, and
//! hashing all of them takes minutes and thrashes the disk cache. So this is a
//! two-pass algorithm:
//!
//! 1. **Bucket by size.** Two identical files must be the same size, so anything
//!    whose size is unique cannot possibly have a duplicate. This discards the
//!    large majority of files after pure arithmetic and zero disk reads.
//! 2. **Hash only what survives**, streaming through blake3 in 64 KiB chunks so a
//!    40 GB virtual disk image never has to fit in memory.
//!
//! Two further safety rules, both non-negotiable:
//!
//! * **Never report duplicates inside system paths.** Comparing the operating
//!   system's own files produces thousands of meaningless matches, and acting on
//!   the advice breaks the machine.
//! * **Never read contents into memory, and never store them.** Only the digest
//!   is retained. A digest proves two files are identical without revealing
//!   anything about what is in them.

use crate::config::ScanConfig;
use crate::detect::make_finding;
use crate::model::{Bytes, Detector, Finding, Safety, ScanResult};
use crate::scan::CancelToken;
use crate::util;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Cap on paths stored per finding. Beyond this the cluster is summarised with a
/// count rather than materialising thousands of strings into a report.
const MAX_PATHS_PER_FINDING: usize = 200;

/// Below this a cluster is not worth a row in the report.
///
/// One megabyte of provably duplicated bytes is worth reporting even once, so
/// the floor is set low; the UI offers further filtering on top of this.
const MIN_CLUSTER_RECLAIMABLE: Bytes = 1024 * 1024;

/// How a duplicate cluster is narrowed down for hashing.
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct BucketKey {
    size: Bytes,
    /// Extension is part of the key: a 4 GB `.mov` and a 4 GB `.bak` are
    /// different problems, and grouping them together makes the report harder to
    /// act on.
    extension: String,
}

/// One set of byte-identical files.
#[derive(Debug)]
struct Cluster {
    key: BucketKey,
    hash: String,
    paths: Vec<PathBuf>,
}

impl Cluster {
    /// Bytes recoverable by keeping exactly one copy.
    fn reclaimable(&self) -> Bytes {
        self.key
            .size
            .saturating_mul((self.paths.len() as u64).saturating_sub(1))
    }

    /// The copy to keep.
    ///
    /// Prefers the path in the user's primary documents folder, because that is
    /// the one they are most likely to open next. Falls back to the shortest
    /// path, which is easiest for a human to reason about.
    fn canonical(&self) -> &Path {
        self.paths
            .iter()
            .min_by_key(|p| {
                let in_documents = is_preferred_keep_location(p);
                let depth = p.components().count();
                (u8::from(!in_documents), depth, p.as_os_str().len())
            })
            .map_or(&self.paths[0], std::convert::AsRef::as_ref)
    }
}

/// Find groups of byte-identical files.
#[must_use]
pub fn detect(result: &ScanResult, config: &ScanConfig, cancel: &CancelToken) -> Vec<Finding> {
    // ---- Pass 1: bucket by size + extension. No disk reads at all. ----------
    let mut buckets: HashMap<BucketKey, Vec<usize>> = HashMap::new();
    let min_size = config.min_file_size_for_dupes;

    for (i, node) in result.nodes.iter().enumerate() {
        if node.kind != crate::model::FileKind::File || node.size < min_size {
            continue;
        }
        if is_excluded_from_duplicates(&node.path, config) {
            continue;
        }
        buckets
            .entry(BucketKey {
                size: node.size,
                extension: node.extension.clone().unwrap_or_default(),
            })
            .or_default()
            .push(i);
    }

    // Buckets with fewer than two members cannot contain a duplicate. This is
    // where the overwhelming majority of files are discarded.
    let candidates: Vec<Vec<usize>> = buckets.into_values().filter(|v| v.len() >= 2).collect();

    if candidates.is_empty() {
        return Vec::new();
    }

    // ---- Pass 2: hash only the survivors. ------------------------------------
    // Keyed by `(size, hash, extension)`, not `(size, hash)`. The extension is
    // not part of the identity of a file's *contents*, but it is part of the
    // identity of the *problem*: one 2 GB `.mov` and one 2 GB `.bak` of the same
    // bytes are two separate duplicates with two separate keep-decisions, and
    // merging them produces a cluster whose advice is meaningless.
    let mut by_hash: HashMap<(Bytes, String, String), Vec<usize>> = HashMap::new();
    let files_to_hash: usize = candidates.iter().map(Vec::len).sum();

    for bucket in candidates {
        // Checked per file, because this is the only loop in the product that can
        // run for minutes. This is what makes the Stop button actually work.
        if cancel.is_cancelled() {
            log::info!("duplicate hashing cancelled");
            return Vec::new();
        }
        for &i in &bucket {
            let node = &result.nodes[i];
            let Some(hash) = util::blake3_file(&node.path) else {
                // Unreadable: not a hashable candidate. One bad file must never
                // abort the pass.
                log::debug!("skipping unhashable {}", node.path.display());
                continue;
            };
            by_hash
                .entry((node.size, hash, bucket_key_extension(node)))
                .or_default()
                .push(i);
        }
    }
    log::debug!("hashed {files_to_hash} candidate files");

    // ---- Cluster and report. -------------------------------------------------
    let mut clusters: Vec<Cluster> = by_hash
        .into_iter()
        .filter(|(_, members)| members.len() >= 2)
        .map(|((size, hash, extension), members)| {
            let mut paths: Vec<PathBuf> = members
                .iter()
                .map(|&i| result.nodes[i].path.clone())
                .collect();
            paths.sort();
            Cluster {
                key: BucketKey { size, extension },
                hash,
                paths,
            }
        })
        .filter(|c| c.reclaimable() >= MIN_CLUSTER_RECLAIMABLE)
        .collect();

    clusters.sort_by_key(|c| std::cmp::Reverse(c.reclaimable()));
    clusters
        .into_iter()
        .map(|cluster| cluster_finding(&cluster))
        .collect()
}

/// The extension a node belongs to, as a grouping key.
fn bucket_key_extension(node: &crate::model::ScanNode) -> String {
    node.extension.clone().unwrap_or_default()
}

/// Turn one cluster into a finding.
fn cluster_finding(cluster: &Cluster) -> Finding {
    let keep = cluster.canonical().to_path_buf();
    let size = cluster.key.size;
    let copies = cluster.paths.len();
    let reclaimable = cluster.reclaimable();

    // Deleting is only free when *every* copy is regenerable cache. A duplicate
    // where one copy is the user's source document is a data-loss decision.
    let all_cache = cluster.paths.iter().all(|p| is_cache_path(p));
    let safety = if all_cache {
        Safety::SafeToDelete
    } else {
        Safety::DataLoss
    };

    // Stored as structured directories rather than pre-formatted prose.
    //
    // A string like "in /Users/alex/Videos" does not start with a separator, so
    // the report's relative-path rendering — which matches on the leading path —
    // cannot rewrite it, and the operator's directory layout leaks into a shared
    // report anyway. Keeping the paths raw lets the report redact them.
    let directories: Vec<String> = cluster
        .paths
        .iter()
        .filter_map(|p| p.parent().map(|d| d.to_string_lossy().to_string()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    let ext_label = if cluster.key.extension.is_empty() {
        "file".to_string()
    } else {
        cluster.key.extension.clone()
    };

    let title = format!(
        "{} × {} identical {ext_label}{}",
        copies,
        util::human_bytes(size),
        if copies > 1 { "s" } else { "" }
    );

    let recommendation = if safety == Safety::SafeToDelete {
        format!(
            "All {} copies are in cache directories. Clear the cache to free {}.",
            copies,
            util::human_bytes(reclaimable)
        )
    } else {
        format!(
            "Keep `{}` and delete the other {} copy/copies to free {}. Verify the copies really \
             are identical before removing any — Diskus compared them by cryptographic hash, \
             but it has not opened them.",
            // The full path, not a truncated one. Truncating here elides the
            // scan root, which the report's relative-path rendering then cannot
            // match — so a report the user asked to make shareable would still
            // leak the volume name. Redaction shortens it to `~/...` anyway.
            keep.display(),
            copies - 1,
            util::human_bytes(reclaimable)
        )
    };

    let truncated = cluster.paths.len() > MAX_PATHS_PER_FINDING;
    let shown: Vec<&PathBuf> = cluster.paths.iter().take(MAX_PATHS_PER_FINDING).collect();

    let mut finding = make_finding(
        Detector::Duplicates,
        &keep,
        size.saturating_mul(copies as u64),
        reclaimable,
        // Identical sizes *and* identical digests is certain, not probable.
        1.0,
        safety,
        title,
        recommendation,
        serde_json::json!({
            "hash": cluster.hash,
            "fileSize": size,
            "copies": copies,
            "reclaimableBytes": reclaimable,
            "keepSuggestion": keep.to_string_lossy(),
            "pathsTruncated": truncated,
            "hiddenPathCount": cluster.paths.len().saturating_sub(MAX_PATHS_PER_FINDING),
            "allInCache": all_cache,
            "locations": directories,
            "extension": cluster.key.extension,
        }),
    );
    finding.related_paths = shown
        .iter()
        .filter(|p| **p != &keep)
        .map(|p| (*p).clone())
        .collect();
    finding
}

/// Whether a path is excluded from duplicate reporting.
///
/// System paths are excluded unconditionally. This is the single most important
/// safety rule in the detector: the operating system is full of legitimately
/// duplicated shared libraries, and telling someone to delete them breaks the
/// machine.
fn is_excluded_from_duplicates(path: &Path, config: &ScanConfig) -> bool {
    if config
        .duplicate_skip_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return true;
    }
    let s = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    const ALWAYS_SKIP: [&str; 8] = [
        "/system/",
        "/windows/",
        "/program files/",
        "/usr/",
        "/library/frameworks/",
        "/node_modules/.cache/",
        "/.git/",
        "/.cargo/registry/",
    ];
    ALWAYS_SKIP.iter().any(|needle| s.contains(needle))
}

/// Whether a path is inside a regenerable cache.
fn is_cache_path(path: &Path) -> bool {
    let s = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    const CACHE: [&str; 5] = [
        "/library/caches",
        "/.cache/",
        "/appdata/local/temp",
        "/.npm/",
        "/appdata/local/microsoft/windows/inetcache",
    ];
    CACHE.iter().any(|needle| s.contains(needle))
}

/// Whether this is the kind of location a person would expect to keep.
fn is_preferred_keep_location(path: &Path) -> bool {
    let s = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    const PREFERRED: [&str; 6] = [
        "/documents/",
        "/pictures/",
        "/videos/",
        "/music/",
        "/desktop/",
        "/work/",
    ];
    PREFERRED.iter().any(|needle| s.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testing::{Age, ScanBuilder};
    use crate::model::{GIB, MIB};
    use std::fs;

    fn config() -> ScanConfig {
        ScanConfig::default()
    }

    /// Write `contents` to `dir/name` and declare it in the scan tree.
    fn real_file(builder: &mut ScanBuilder, dir: &Path, name: &str, contents: &[u8]) {
        fs::create_dir_all(dir).expect("mkdir");
        fs::write(dir.join(name), contents).expect("write");
        builder.file(
            &dir.join(name).to_string_lossy(),
            contents.len() as u64,
            Age::Days(30),
        );
    }

    #[test]
    fn identical_files_are_grouped_and_hashed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = vec![7_u8; 2 * MIB as usize];

        let mut builder = ScanBuilder::new();
        for sub in ["a", "b", "c"] {
            real_file(&mut builder, &dir.path().join(sub), "same.bin", &payload);
        }
        let result = builder.build();

        let findings = detect(&result, &config(), &CancelToken::new());
        assert_eq!(findings.len(), 1, "three identical files are one cluster");

        let f = &findings[0];
        assert_eq!(f.detail["copies"].as_u64().unwrap(), 3);
        assert_eq!(f.detail["fileSize"].as_u64().unwrap(), payload.len() as u64);
        assert_eq!(
            f.reclaimable,
            payload.len() as u64 * 2,
            "two of three copies can go"
        );
        assert_eq!(f.safety, Safety::DataLoss, "one copy must survive");
        assert!(
            (f.confidence - 1.0).abs() < f32::EPSILON,
            "hash match is certain"
        );
    }

    #[test]
    fn files_of_equal_size_but_different_content_are_not_duplicates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut builder = ScanBuilder::new();
        real_file(
            &mut builder,
            &dir.path().join("a"),
            "x.bin",
            &[1_u8; MIB as usize],
        );
        real_file(
            &mut builder,
            &dir.path().join("b"),
            "x.bin",
            &[2_u8; MIB as usize],
        );
        let result = builder.build();

        assert!(
            detect(&result, &config(), &CancelToken::new()).is_empty(),
            "same size is not the same file"
        );
    }

    #[test]
    fn unique_sizes_are_discarded_without_any_disk_read() {
        // Sizes are all distinct, so pass one must eliminate everything. The
        // files do not even exist on disk — if the detector tried to hash them,
        // `blake3_file` would return None and it would find nothing either way.
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/a.bin", 100 * MIB, Age::Days(1))
            .file("/Users/jdoe/b.bin", 101 * MIB, Age::Days(1))
            .file("/Users/jdoe/c.bin", 102 * MIB, Age::Days(1))
            .build();

        assert!(detect(&result, &config(), &CancelToken::new()).is_empty());
    }

    #[test]
    fn files_below_the_size_floor_are_never_hashed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut builder = ScanBuilder::new();
        real_file(
            &mut builder,
            &dir.path().join("a"),
            "tiny.bin",
            &[9_u8; 1024],
        );
        real_file(
            &mut builder,
            &dir.path().join("b"),
            "tiny.bin",
            &[9_u8; 1024],
        );
        let result = builder.build();

        assert!(
            detect(&result, &config(), &CancelToken::new()).is_empty(),
            "1 KB duplicates are not worth a report row"
        );
    }

    #[test]
    fn system_paths_are_never_reported_as_duplicates() {
        // The real files are never written: the exclusion must be decidable from
        // the path alone, before any file is opened. If it depended on reading
        // them, a permission error would be the only thing stopping a report
        // that invites the user to delete their operating system.
        let config = config();
        for path in [
            "/usr/lib/libfoo.dylib",
            "/usr/local/lib/libfoo.dylib",
            "/System/Library/libbar.dylib",
            "/Library/Frameworks/libbaz.dylib",
            "C:\\Windows\\System32\\dup.dll",
            "C:\\Program Files\\App\\dup.dll",
            "/home/jdoe/project/node_modules/.cache/blob",
            "/home/jdoe/.cargo/registry/cache/x",
        ] {
            assert!(
                is_excluded_from_duplicates(Path::new(path), &config),
                "{path} must never be reported as a user duplicate"
            );
        }

        for path in [
            "/Users/jdoe/Documents/report.pdf",
            "/home/jdoe/Videos/holiday.mov",
            "D:\\Projects\\diskus\\src\\main.rs",
        ] {
            assert!(
                !is_excluded_from_duplicates(Path::new(path), &config),
                "{path} is user data and must be eligible"
            );
        }
    }

    #[test]
    fn different_extensions_are_separate_clusters() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = vec![4_u8; MIB as usize];
        let mut builder = ScanBuilder::new();
        real_file(&mut builder, &dir.path().join("a"), "clip.mov", &payload);
        real_file(&mut builder, &dir.path().join("b"), "clip.mov", &payload);
        real_file(&mut builder, &dir.path().join("c"), "clip.bak", &payload);
        real_file(&mut builder, &dir.path().join("d"), "clip.bak", &payload);
        let result = builder.build();

        let findings = detect(&result, &config(), &CancelToken::new());
        assert_eq!(findings.len(), 2, "same bytes, different file types");
        assert!(
            findings
                .iter()
                .all(|f| f.detail["copies"].as_u64().unwrap() == 2)
        );
    }

    #[test]
    fn cache_duplicates_are_safe_to_delete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = vec![5_u8; MIB as usize];
        let mut builder = ScanBuilder::new();
        real_file(
            &mut builder,
            Path::new(&dir.path().join("Library/Caches/a"))
                .to_path_buf()
                .as_path(),
            "d.bin",
            &payload,
        );
        real_file(
            &mut builder,
            Path::new(&dir.path().join("Library/Caches/b"))
                .to_path_buf()
                .as_path(),
            "d.bin",
            &payload,
        );
        let result = builder.build();

        let findings = detect(&result, &config(), &CancelToken::new());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].safety, Safety::SafeToDelete);
        assert!(findings[0].detail["allInCache"].as_bool().unwrap());
    }

    #[test]
    fn clusters_are_ranked_by_reclaimable_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let big = vec![6_u8; 4 * MIB as usize];
        let small = vec![7_u8; MIB as usize];

        let mut builder = ScanBuilder::new();
        real_file(&mut builder, &dir.path().join("a"), "big.bin", &big);
        real_file(&mut builder, &dir.path().join("b"), "big.bin", &big);
        real_file(&mut builder, &dir.path().join("c"), "small.bin", &small);
        real_file(&mut builder, &dir.path().join("d"), "small.bin", &small);
        let result = builder.build();

        let findings = detect(&result, &config(), &CancelToken::new());
        assert_eq!(findings.len(), 2);
        assert!(
            findings[0].reclaimable > findings[1].reclaimable,
            "biggest win first"
        );
    }

    #[test]
    fn the_copy_to_keep_is_preferred_in_documents() {
        let cluster = Cluster {
            key: BucketKey {
                size: 1024,
                extension: ".mov".into(),
            },
            hash: "abc".into(),
            paths: vec![
                PathBuf::from("/Users/jdoe/.cache/deep/nested/a.mov"),
                PathBuf::from("/Users/jdoe/Documents/a.mov"),
            ],
        };
        assert_eq!(
            cluster.canonical(),
            Path::new("/Users/jdoe/Documents/a.mov")
        );
    }

    #[test]
    fn reclaimable_is_size_times_extras() {
        let cluster = Cluster {
            key: BucketKey {
                size: 1000,
                extension: ".bin".into(),
            },
            hash: "abc".into(),
            paths: vec![
                PathBuf::from("/a"),
                PathBuf::from("/b"),
                PathBuf::from("/c"),
            ],
        };
        assert_eq!(cluster.reclaimable(), 2000, "keep one of three");
    }

    #[test]
    fn cache_detection_drives_the_safety_verdict() {
        assert!(is_cache_path(Path::new("/Users/x/Library/Caches/a")));
        assert!(is_cache_path(Path::new("/Users/x/.cache/b")));
        assert!(!is_cache_path(Path::new("/Users/x/Documents/a")));
        assert!(!is_cache_path(Path::new("/opt/app/bin/a")));
    }

    #[test]
    fn large_clusters_cap_their_stored_paths() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Hardlinks rather than 225 real copies. Identical content hashes
        // identically, so the cluster is identical either way, but this keeps
        // the test's disk cost at a single payload instead of 225 of them —
        // which matters, because the machines most likely to run these tests are
        // the ones that are short of space.
        let payload = vec![8_u8; MIB as usize];
        let source = dir.path().join("source.bin");
        fs::write(&source, &payload).expect("write");

        let mut builder = ScanBuilder::new();
        for i in 0..MAX_PATHS_PER_FINDING + 25 {
            let target = dir.path().join(format!("dir{i:04}/same.bin"));
            fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
            #[cfg(unix)]
            fs::hard_link(&source, &target).expect("hard link");
            #[cfg(windows)]
            fs::copy(&source, &target).expect("copy");

            builder.file(
                &target.to_string_lossy(),
                payload.len() as u64,
                Age::Days(30),
            );
        }
        let result = builder.build();

        let findings = detect(&result, &config(), &CancelToken::new());
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].related_paths.len(),
            MAX_PATHS_PER_FINDING - 1,
            "capped, plus the primary path"
        );
        assert!(findings[0].detail["pathsTruncated"].as_bool().unwrap());
        assert_eq!(
            findings[0].detail["hiddenPathCount"].as_u64().unwrap(),
            25,
            "but the true count is still reported"
        );
    }

    #[test]
    fn reclaimable_totals_add_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = vec![11_u8; 3 * MIB as usize];
        let mut builder = ScanBuilder::new();
        for sub in ["x", "y", "z"] {
            real_file(&mut builder, &dir.path().join(sub), "v.mov", &payload);
        }
        let result = builder.build();

        let findings = detect(&result, &config(), &CancelToken::new());
        let total: Bytes = findings.iter().map(|f| f.reclaimable).sum();
        assert_eq!(total, payload.len() as u64 * 2);
        assert!(
            total < result.total_bytes,
            "reclaimable can never exceed what was scanned"
        );
    }

    #[test]
    fn a_gib_scale_duplicate_cluster_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut builder = ScanBuilder::new();
        // 8 MiB of zeros: big enough to clear MIN_CLUSTER_RECLAIMABLE without
        // making the test slow.
        let payload = vec![0_u8; 8 * MIB as usize];
        real_file(
            &mut builder,
            &dir.path().join("media/a"),
            "master.mov",
            &payload,
        );
        real_file(
            &mut builder,
            &dir.path().join("backup/b"),
            "master.mov",
            &payload,
        );
        let result = builder.build();

        let findings = detect(&result, &config(), &CancelToken::new());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].reclaimable, payload.len() as u64);
        assert!(findings[0].size >= 16 * MIB);
        let _ = GIB;
    }
}
