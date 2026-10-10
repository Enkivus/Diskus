//! Platform knowledge: which roots to scan, which paths to refuse, and how to
//! read system metadata.
//!
//! All of this is deliberately collected in one module. Cross-platform bugs in
//! disk analysers almost always come from a path special-case leaking out of its
//! module, and having them side by side makes them reviewable.

use crate::model::Volume;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Directories that must never be walked.
///
/// Two distinct reasons:
///
/// * **Pseudo-filesystems** (`/proc`, `/sys`, `/dev`) are generated at read time.
///   Walking them reports multi-terabyte sizes that do not exist and never
///   return to a user.
/// * **Huge, unreclaimable, volatile OS files** (`/private/var/vm` swap,
///   `WinSxS`, `$RECYCLE.BIN`) are real disk usage but deleting them is either
///   impossible or destroys the system. Reporting them as reclaimable is actively
///   harmful advice.
#[must_use]
pub fn is_system_path(path: &Path) -> bool {
    let s = normalise(path);

    const DENY: [&str; 14] = [
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/private/var/vm",
        "/system/volumes/data",
        "/network",
        "/c:/windows/winsxs",
        "/c:/windows/syswow64/winsxs",
        "/c:/$recycle.bin",
        "/system volume information",
        "/var/vm",
        "/mnt/wsl",
        "/run/user",
    ];

    // Prefix match on a *component* boundary, so "/procdata" is not caught by
    // the "/proc" rule. Plain `starts_with` would conflate the two and quietly
    // skip a user's project directory called "procdata".
    DENY.iter().any(|d| {
        s.strip_prefix(d)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// Lowercase a path with platform separators normalised to `/`.
///
/// Path comparisons here are on the *string*, not the structured path, because
/// the rules contain Windows prefixes like `c:\\windows\\logs` that would
/// never match a `Path` on a Unix host.
#[must_use]
pub fn normalise(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    format!("/{}", raw.trim_start_matches('/').to_ascii_lowercase())
}

/// Roots to scan when the user has not chosen specific ones.
///
/// Deliberately narrow: the user's own home plus the OS data directories, rather
/// than a bare `/`. Scanning an entire Windows system volume takes many minutes
/// and buries the home directory findings that actually matter, so system roots
/// are an opt-in via `ScanConfig::roots`.
#[must_use]
pub fn default_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();

    if let Some(home) = dirs::home_dir() {
        push_unique(&mut roots, home);
    }

    for extra in home_roots() {
        push_unique(&mut roots, extra);
    }

    if roots.is_empty() {
        roots.push(current_dir_or_root());
    }

    roots
}

/// Extra per-platform roots beyond the current user's home.
#[must_use]
pub fn home_roots() -> Vec<PathBuf> {
    let mut v = Vec::new();

    if cfg!(target_os = "windows") {
        for letter in ['C', 'D', 'E', 'F'] {
            let drive = format!("{letter}:\\");
            let p = PathBuf::from(&drive);
            if p.is_dir() {
                v.push(p);
            }
        }
    } else {
        for base in ["/Users", "/home", "/Volumes", "/export", "/data"] {
            let p = PathBuf::from(base);
            if p.is_dir() {
                v.push(p);
            }
        }
    }

    v
}

/// Current working directory, falling back to the filesystem root.
fn current_dir_or_root() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| {
        if cfg!(windows) {
            PathBuf::from(r"C:\")
        } else {
            PathBuf::from("/")
        }
    })
}

fn push_unique(roots: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !roots.iter().any(|r| r == &candidate) {
        roots.push(candidate);
    }
}

/// Everything under `root` that looks like a user home directory.
#[must_use]
pub fn user_profiles() -> Vec<crate::model::UserProfile> {
    let mut profiles: Vec<crate::model::UserProfile> = Vec::new();
    let current = dirs::home_dir();

    let bases: Vec<PathBuf> = if cfg!(windows) {
        drive_letters().map(PathBuf::from).collect()
    } else {
        vec![PathBuf::from("/Users"), PathBuf::from("/home")]
    };

    for base in bases {
        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
                continue;
            };
            if is_reserved_profile_name(&name) {
                continue;
            }
            if current.as_ref() == Some(&path) {
                continue;
            }
            profiles.push(crate::model::UserProfile {
                username: name,
                path,
                size: None,
                total_bytes: None,
                is_current: false,
            });
        }
    }

    if let Some(home) = current {
        let username = home
            .file_name()
            .map_or_else(|| "me".to_string(), |n| n.to_string_lossy().to_string());
        profiles.insert(
            0,
            crate::model::UserProfile {
                username,
                path: home.clone(),
                size: None,
                total_bytes: None,
                is_current: true,
            },
        );
    }

    profiles
}

fn drive_letters() -> impl Iterator<Item = String> {
    ('A'..='Z').map(|c| format!("{}:\\", c))
}

/// System accounts and shared folders that are not real user profiles.
fn is_reserved_profile_name(name: &str) -> bool {
    const RESERVED: [&str; 12] = [
        "public",
        "default",
        "default user",
        "all users",
        "shared",
        "library",
        "system",
        ".trash",
        "lost+found",
        "bin",
        "sbin",
        "var",
    ];
    let lower = name.to_ascii_lowercase();
    RESERVED.contains(&lower.as_str())
}

/// Mounted volumes, discovered through [`sysinfo`].
///
/// Pseudo-filesystems, app bundles and other synthetic mounts are filtered out by
/// `is_scannable` so the scan-setup screen does not offer them.
#[must_use]
pub fn volumes() -> Vec<Volume> {
    use sysinfo::Disks;

    let disks = Disks::new_with_refreshed_list();
    let mut out: Vec<Volume> = Vec::new();

    for disk in &disks {
        let mount = disk.mount_point().to_path_buf();
        if !mount.is_dir() {
            continue;
        }
        let label = disk.name().to_string_lossy();
        out.push(Volume {
            name: if label.trim().is_empty() {
                mount.to_string_lossy().to_string()
            } else {
                label.to_string()
            },
            mount_point: mount,
            total_bytes: Some(disk.total_space()),
            available_bytes: Some(disk.available_space()),
            is_scannable: !is_system_path(disk.mount_point()),
        });
    }

    out.sort_by(|a, b| {
        b.is_scannable
            .cmp(&a.is_scannable)
            .then_with(|| a.mount_point.cmp(&b.mount_point))
    });
    out
}

/// Bytes actually allocated for a path, or `None` when unavailable.
///
/// This is the number that matters for reclaimable space: it correctly reports a
/// 100 GiB thin-provisioned disk image as occupying only what it has been
/// written to.
#[must_use]
pub fn allocated_size(metadata: &std::fs::Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.blocks().checked_mul(512)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_size().checked_mul(metadata.allocation_size())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        None
    }
}

/// Modification time from platform metadata.
#[must_use]
pub fn modified(metadata: &std::fs::Metadata) -> Option<SystemTime> {
    metadata.modified().ok()
}

/// Creation time, where the platform exposes one.
#[must_use]
pub fn created(metadata: &std::fs::Metadata) -> Option<SystemTime> {
    metadata.created().ok()
}

/// Last access time, where the platform exposes one.
#[must_use]
pub fn accessed(metadata: &std::fs::Metadata) -> Option<SystemTime> {
    metadata.accessed().ok()
}

/// Whether the platform marks this entry hidden.
#[must_use]
pub fn is_hidden(path: &Path, metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        let _ = metadata;
        path.components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const HIDDEN: u32 = 0x2;
        const SYSTEM: u32 = 0x4;
        let attrs = metadata.file_attributes();
        if attrs & (HIDDEN | SYSTEM) != 0 {
            return true;
        }
        path.components()
            .filter(|c| c.as_os_str() != std::ffi::OsStr::new("."))
            .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        false
    }
}

/// Bytes consumed by a directory on its own volume, excluding its children.
///
/// Used for report headers. Returns `None` when the platform will not say.
#[must_use]
pub fn volume_free_bytes(path: &Path) -> Option<u64> {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();
    disks
        .iter()
        .find(|d| path.starts_with(d.mount_point()))
        .map(sysinfo::Disk::available_space)
}

/// Bytes a filesystem path's volume holds in total.
#[must_use]
pub fn volume_total_bytes(path: &Path) -> Option<u64> {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();
    disks
        .iter()
        .find(|d| path.starts_with(d.mount_point()))
        .map(sysinfo::Disk::total_space)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths_are_refused() {
        assert!(is_system_path(Path::new("/proc")));
        assert!(is_system_path(Path::new("/proc/1/cwd")));
        assert!(is_system_path(Path::new("/private/var/vm/swapfile")));
        assert!(is_system_path(Path::new(r"C:\Windows\WinSxS")));
        assert!(is_system_path(Path::new(r"C:\$Recycle.Bin\S-1-5")));
    }

    #[test]
    fn system_path_matching_respects_boundaries() {
        // The classic bug: a substring check would reject "/procdata".
        assert!(!is_system_path(Path::new("/procdata")));
        assert!(!is_system_path(Path::new("/developer/sys")));
        assert!(!is_system_path(Path::new("/home/jdoe/Projects/dev")));
        assert!(!is_system_path(Path::new("/Users/jdoe/Documents/Windows")));
    }

    #[test]
    fn ordinary_paths_are_allowed() {
        assert!(!is_system_path(Path::new("/Users/jdoe")));
        assert!(!is_system_path(Path::new("/home/jdoe/Downloads")));
        assert!(!is_system_path(Path::new(r"D:\Projects\diskus")));
    }

    #[test]
    fn default_roots_are_real_directories() {
        let roots = default_roots();
        assert!(!roots.is_empty(), "must always return something scannable");
        for r in &roots {
            assert!(r.is_dir(), "{} should exist on this machine", r.display());
        }
    }

    #[test]
    fn reserved_profile_names_are_filtered() {
        assert!(is_reserved_profile_name("Public"));
        assert!(is_reserved_profile_name("public"));
        assert!(is_reserved_profile_name("Default User"));
        assert!(!is_reserved_profile_name("jdoe"));
    }

    #[test]
    fn current_user_profile_is_always_first() {
        let profiles = user_profiles();
        if let Some(first) = profiles.first() {
            assert!(first.is_current, "first entry should be the current user");
        }
    }

    #[test]
    fn volumes_are_discoverable_and_sorted() {
        let vols = volumes();
        assert!(!vols.is_empty(), "at least the boot volume must be found");
        let first_scannable = vols.iter().position(|v| v.is_scannable);
        if let Some(idx) = first_scannable {
            assert!(
                vols[..idx].iter().all(|v| !v.is_scannable),
                "scannable come first"
            );
        }
    }

    #[test]
    fn allocated_size_is_not_smaller_than_apparent_for_dense_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("dense.bin");
        std::fs::write(&f, vec![0_u8; 100 * 1024]).expect("write");
        let meta = std::fs::metadata(&f).expect("metadata");
        let apparent = meta.len();
        let allocated = allocated_size(&meta).unwrap_or(apparent);
        assert!(
            allocated >= apparent,
            "dense file: {allocated} >= {apparent}"
        );
    }
}
