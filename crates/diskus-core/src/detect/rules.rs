//! Platform path knowledge and classification shared by the detectors.

use std::path::{Path, PathBuf};

/// Directories that hold rotating application logs.
#[must_use]
pub fn is_known_log_dir(path: &Path) -> bool {
    let s = crate::scan::platform::normalise(path);
    KNOWN_LOG_DIRS.iter().any(|d| {
        s.strip_prefix(d)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// Known log directories, per platform.
///
/// Matched as prefixes against the whole path, so a `/var/log` entry also covers
/// `/var/log/app/server.log`.
const KNOWN_LOG_DIRS: &[&str] = &[
    "/var/log",
    "/private/var/log",
    "/var/lib/docker/containers",
    "/var/lib/systemd/coredump",
    "/c:/windows/logs",
    "/c:/windows/system32/winevt/logs",
    "/c:/inetpub/logs",
    "/c:/programdata",
    "/c:/users",
];

/// A user home directory, if `path` sits inside one.
///
/// Distinguishing "this is a user's cache" from "this is the operating system's
/// cache" matters: one is safe to delete, the other breaks the machine.
#[must_use]
pub fn user_home_containing(path: &Path) -> Option<PathBuf> {
    let components: Vec<_> = path.components().collect();
    let markers: &[&str] = if cfg!(windows) {
        &["users"]
    } else if cfg!(target_os = "macos") {
        &["users", "home"]
    } else {
        &["home"]
    };

    for (i, c) in components.iter().enumerate() {
        let s = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        if markers.contains(&s.as_str()) {
            // The next component is the username.
            return components
                .get(i + 1)
                .map(|_| components[..=i + 1].iter().collect());
        }
    }
    None
}

/// Whether `path` is inside the current user's home directory.
#[must_use]
pub fn is_current_user_home(path: &Path) -> bool {
    dirs::home_dir().is_some_and(|home| path.starts_with(home))
}

/// How reclaimable a directory's contents are.
///
/// This is the single most useful piece of classification in the whole product:
/// it turns "12 GB in Documents" into "12 GB, but only 2 GB of it is cache you can
/// safely delete".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reclaimability {
    /// Regenerable cache. Deleting costs nothing but a re-download.
    Safe,
    /// Build output or package cache, which can be rebuilt.
    Rebuildable,
    /// The user's own content. Only they can decide.
    UserData,
}

impl Reclaimability {
    /// The safety verdict that matches this reclaimability.
    #[must_use]
    pub fn safety(self) -> crate::model::Safety {
        match self {
            Self::Safe => crate::model::Safety::SafeToDelete,
            Self::Rebuildable => crate::model::Safety::ReviewFirst,
            Self::UserData => crate::model::Safety::DataLoss,
        }
    }

    /// The fraction of this category's bytes a reasonable person can expect to
    /// get back without losing anything they care about.
    ///
    /// These are estimates, and each one is documented in the finding's `detail`
    /// so the user can disagree with it.
    #[must_use]
    pub fn reclaim_fraction(self) -> f64 {
        match self {
            Self::Safe => 1.0,
            Self::Rebuildable => 0.8,
            Self::UserData => 0.0,
        }
    }
}

/// Classify a path relative to a user home directory.
#[must_use]
pub fn classify_home_subpath(rel: &Path) -> Reclaimability {
    // Normalise to a leading slash so the rules below can be written with one,
    // and so a relative path like "Library/Caches" matches "/library/caches".
    let s = format!(
        "/{}",
        rel.to_string_lossy()
            .replace('\\', "/")
            .trim_start_matches('/')
            .to_ascii_lowercase()
    );

    // Package-manager and build caches. Fully regenerable.
    const SAFE: [&str; 14] = [
        "/library/caches",
        "/appdata/local/temp",
        "/.cache",
        "/.npm",
        "/.yarn",
        "/.pnpm-store",
        "/.npm/_cacache",
        "/.gradle/caches",
        "/.cargo/registry",
        "/.rustup",
        "/.m2/repository",
        "/go/pkg/mod",
        "/.nuget/packages",
        "/appdata/local/microsoft/windows/inetcache",
    ];
    if SAFE.iter().any(|p| s.contains(p)) {
        return Reclaimability::Safe;
    }

    // Caches of individual applications. Rebuildable, but the app will be slow
    // to start again.
    const REBUILDABLE: [&str; 10] = [
        "/appdata/roaming",
        "/appdata/local",
        "/library/application support",
        "/.config",
        "/.docker",
        "/containerd",
        "/node_modules",
        "/.venv",
        "/venv",
        "/target/debug",
    ];
    if REBUILDABLE.iter().any(|p| s.contains(p)) {
        return Reclaimability::Rebuildable;
    }

    // Definitively the user's own content.
    const USER_CONTENT: [&str; 8] = [
        "/documents",
        "/pictures",
        "/videos",
        "/music",
        "/desktop",
        "/downloads",
        "/documents and settings",
        "/.ssh",
    ];
    if USER_CONTENT.iter().any(|p| s.contains(p)) {
        return Reclaimability::UserData;
    }

    // Anything inside a version-controlled working tree: mostly source the user
    // wrote, plus build output that could be removed. Assume the source wins.
    if s.contains("/.git") || s.contains("/.svn") {
        return Reclaimability::Rebuildable;
    }

    Reclaimability::UserData
}

/// Whether a path sits among someone's actual documents.
///
/// Narrower than [`classify_home_subpath`]'s `UserData` verdict, which also
/// covers Downloads and Desktop. Those are staging areas; a stale archive there
/// only warrants a look, whereas one among documents may be irreplaceable.
#[must_use]
pub fn is_document_location(path: &Path) -> bool {
    let s = crate::scan::platform::normalise(path);
    const DOCUMENTS: [&str; 6] = [
        "/documents",
        "/pictures",
        "/videos",
        "/music",
        "/onedrive",
        "/library/mobile documents",
    ];
    // Matched anywhere in the path but only on a component boundary, so
    // "/documents" matches "/Users/jdoe/Documents" without matching a folder
    // called "/Users/jdoe/my-documents".
    DOCUMENTS
        .iter()
        .any(|needle| s.contains(&format!("{needle}/")) || s.ends_with(needle))
}

/// Classify a directory that is itself a package-manager cache.
///
/// These are reported wholesale with very high confidence, because clearing them
/// is a well-understood, lossless operation.
#[must_use]
pub fn is_package_manager_cache(path: &Path) -> Option<&'static str> {
    let s = crate::scan::platform::normalise(path);
    const CACHES: [(&str, &str); 16] = [
        ("/.npm", "npm"),
        ("/.cache/yarn", "Yarn"),
        ("/.yarn/cache", "Yarn"),
        ("/.pnpm-store", "pnpm"),
        ("/library/caches/homebrew", "Homebrew"),
        ("/homebrew/cache", "Homebrew"),
        ("/.cache/pip", "pip"),
        ("/pip/cache", "pip"),
        ("/.gradle/caches", "Gradle"),
        ("/.cargo/registry", "Cargo"),
        ("/c:/windows/installer", "Windows Installer"),
        (
            "/c:/windows/softwaredistribution/download",
            "Windows Update",
        ),
        ("/c:/programdata/chocolatey/cache", "Chocolatey"),
        (
            "/c:/programdata/packagemanager/cache",
            "Windows Package Manager",
        ),
        ("/appdata/local/temp", "Windows Temp"),
        ("/.cache/go-build", "Go build cache"),
    ];
    CACHES
        .iter()
        .find(|(needle, _)| s.ends_with(needle) || s.contains(&format!("{needle}/")))
        .map(|(_, name)| *name)
}

/// Installers and archives, by extension.
#[must_use]
pub fn is_installer_extension(ext: Option<&str>) -> bool {
    const INSTALLERS: [&str; 12] = [
        "msi",
        "msix",
        "msixbundle",
        "msu",
        "exe",
        "dmg",
        "pkg",
        "deb",
        "rpm",
        "appimage",
        "iso",
        "snap",
    ];
    const ARCHIVES: [&str; 6] = ["zip", "7z", "rar", "tar", "gz", "xz"];
    let Some(ext) = ext else { return false };
    let ext = ext.trim_start_matches('.');
    INSTALLERS.contains(&ext) || ARCHIVES.contains(&ext)
}

/// Whether a filename looks like an installer even without its extension.
///
/// Catches the common cases: `Setup_x64.exe`, `installer-v3.2.pkg`,
/// `python-3.11.4-amd64.msi`.
#[must_use]
pub fn looks_like_installer(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const PATTERNS: [&str; 10] = [
        "setup",
        "install",
        "installer",
        "-x64",
        "-x86",
        "-win32",
        "-win64",
        "_amd64",
        "-amd64",
        "update",
    ];
    PATTERNS.iter().any(|p| lower.contains(p))
}

/// Whether a file sits in a "staging" location where people dump downloads.
///
/// Only files in these locations are considered for the stale-installer rule;
/// an `.iso` in a mounted disk image or a build output directory is not garbage.
#[must_use]
pub fn is_staging_location(path: &Path) -> bool {
    let s = crate::scan::platform::normalise(path);
    const STAGING: [&str; 8] = [
        "/downloads",
        "/desktop",
        "/documents",
        "/temp",
        "/tmp/",
        "/public/downloads",
        "/.cache/downloads",
        "/onevar/tmp",
    ];
    STAGING.iter().any(|p| s.contains(p))
}

/// Candidate virtual machine formats, keyed by the extension that identifies one.
#[must_use]
pub fn vm_image_extension(ext: Option<&str>) -> Option<VmFlavour> {
    match ext
        .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
        .as_deref()
    {
        Some("vmdk") => Some(VmFlavour::VMware),
        Some("vmx") => Some(VmFlavour::VMwareConfig),
        Some("vbox") => Some(VmFlavour::VirtualBoxConfig),
        Some("vdi") => Some(VmFlavour::VirtualBox),
        Some("qcow2") => Some(VmFlavour::Qemu),
        Some("qemu") => Some(VmFlavour::QemuConfig),
        Some("vhdx") | Some("vhd") => Some(VmFlavour::HyperV),
        Some("ova") | Some("ovf") => Some(VmFlavour::Appliance),
        Some("pvm") => Some(VmFlavour::Parallels),
        Some("hdd") => Some(VmFlavour::ParallelsDisk),
        Some("utm") => Some(VmFlavour::Utm),
        _ => None,
    }
}

/// Which virtual machine product a file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmFlavour {
    /// `VMware` disk image.
    VMware,
    /// `VMware` machine configuration.
    VMwareConfig,
    /// `VirtualBox` machine configuration.
    VirtualBoxConfig,
    /// `VirtualBox` disk image.
    VirtualBox,
    /// QEMU/KVM disk image.
    Qemu,
    /// QEMU/KVM machine configuration.
    QemuConfig,
    /// Hyper-V virtual or fixed disk.
    HyperV,
    /// OVF appliance bundle.
    Appliance,
    /// Parallels bundle.
    Parallels,
    /// Parallels hard disk.
    ParallelsDisk,
    /// UTM bundle.
    Utm,
}

impl VmFlavour {
    /// The file that records when a machine was last used.
    ///
    /// Its modification time is the best proxy for "is anyone still using this",
    /// because opening a VM touches its configuration but not its images.
    #[must_use]
    pub fn is_config(self) -> bool {
        matches!(
            self,
            Self::VMwareConfig | Self::VirtualBoxConfig | Self::QemuConfig | Self::Appliance
        )
    }

    /// Human-readable product name for reports.
    #[must_use]
    pub fn product(self) -> &'static str {
        match self {
            Self::VMware | Self::VMwareConfig => "VMware",
            Self::VirtualBox | Self::VirtualBoxConfig => "VirtualBox",
            Self::Qemu | Self::QemuConfig => "QEMU / KVM",
            Self::HyperV => "Hyper-V",
            Self::Appliance => "OVF appliance",
            Self::Parallels | Self::ParallelsDisk => "Parallels",
            Self::Utm => "UTM",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_log_dirs_are_recognised() {
        assert!(is_known_log_dir(Path::new("/var/log")));
        assert!(is_known_log_dir(Path::new("/var/log/nginx/error.log")));
        assert!(is_known_log_dir(Path::new(r"C:\Windows\Logs")));
        assert!(is_known_log_dir(Path::new(r"C:\inetpub\logs\LogFiles")));
        assert!(!is_known_log_dir(Path::new("/opt/myapp/data")));
    }

    #[test]
    fn user_home_containing_finds_the_right_user() {
        assert_eq!(
            user_home_containing(Path::new("/Users/jdoe/Documents/a.txt")),
            Some(PathBuf::from("/Users/jdoe"))
        );
        assert_eq!(
            user_home_containing(Path::new("/home/ana/x/y")),
            Some(PathBuf::from("/home/ana"))
        );
        assert_eq!(user_home_containing(Path::new("/var/log/x")), None);
    }

    #[test]
    fn caches_classify_as_safe() {
        assert_eq!(
            classify_home_subpath(Path::new("Library/Caches")),
            Reclaimability::Safe
        );
        assert_eq!(
            classify_home_subpath(Path::new(".cache/pip")),
            Reclaimability::Safe
        );
        assert_eq!(
            classify_home_subpath(Path::new("AppData/Local/Temp")),
            Reclaimability::Safe
        );
        assert_eq!(
            classify_home_subpath(Path::new("Library/Caches")).safety(),
            crate::model::Safety::SafeToDelete
        );
    }

    #[test]
    fn user_documents_classify_as_user_data() {
        assert_eq!(
            classify_home_subpath(Path::new("Documents")),
            Reclaimability::UserData
        );
        assert_eq!(
            classify_home_subpath(Path::new("Downloads")),
            Reclaimability::UserData
        );
        assert_eq!(
            classify_home_subpath(Path::new("Documents")).safety(),
            crate::model::Safety::DataLoss
        );
        assert_eq!(
            Reclaimability::UserData.reclaim_fraction(),
            0.0,
            "we must never claim a user's own files are recoverable"
        );
    }

    #[test]
    fn build_output_classifies_as_rebuildable() {
        assert_eq!(
            classify_home_subpath(Path::new("project/node_modules")),
            Reclaimability::Rebuildable
        );
        assert_eq!(
            classify_home_subpath(Path::new("project/.git")),
            Reclaimability::Rebuildable
        );
    }

    #[test]
    fn package_manager_caches_are_identified() {
        assert_eq!(
            is_package_manager_cache(Path::new("/Users/x/.npm")),
            Some("npm")
        );
        assert_eq!(
            is_package_manager_cache(Path::new("/Users/x/.npm/_cacache")),
            Some("npm")
        );
        assert_eq!(
            is_package_manager_cache(Path::new("/Users/x/Documents")),
            None
        );
    }

    #[test]
    fn installer_extensions_and_names() {
        assert!(is_installer_extension(Some(".msi")));
        assert!(is_installer_extension(Some(".dmg")));
        assert!(is_installer_extension(Some(".zip")));
        assert!(!is_installer_extension(Some(".txt")));
        assert!(!is_installer_extension(None));

        assert!(looks_like_installer("python-3.11-amd64.msi"));
        assert!(looks_like_installer("Setup.exe"));
        assert!(!looks_like_installer("notes.txt"));
    }

    #[test]
    fn staging_locations_gate_installer_findings() {
        assert!(is_staging_location(Path::new("/Users/x/Downloads/a.zip")));
        assert!(is_staging_location(Path::new("/tmp/a.zip")));
        assert!(!is_staging_location(Path::new("/opt/app/bundles/a.zip")));
    }

    #[test]
    fn vm_extensions_map_to_flavours() {
        assert_eq!(vm_image_extension(Some(".vmdk")), Some(VmFlavour::VMware));
        assert_eq!(
            vm_image_extension(Some(".vmx")),
            Some(VmFlavour::VMwareConfig)
        );
        assert_eq!(
            vm_image_extension(Some(".vdi")),
            Some(VmFlavour::VirtualBox)
        );
        assert_eq!(vm_image_extension(Some(".txt")), None);
        assert!(VmFlavour::VMwareConfig.is_config());
        assert!(!VmFlavour::VMware.is_config());
    }
}
