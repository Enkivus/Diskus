//! **Detector 2 — Abandoned virtual machines.**
//!
//! Answers: *which virtual machines does nobody use any more?*
//!
//! Two ideas carry this detector:
//!
//! 1. **A VM is a bundle, not a file.** Deleting `debian.vmdk` but leaving
//!    `debian.vmx` behind produces a machine that will never boot again. So the
//!    unit of analysis and the unit of recommendation are both the whole bundle
//!    directory, never an individual image.
//!
//! 2. **Last-used is the config file's mtime, not the image's.** Opening a VM
//!    updates its configuration and metadata; it does not write to the disk
//!    image. An image with an old mtime is usually just an image that has not
//!    been touched since it was created, which makes image mtime useless as a
//!    usage signal.
//!
//! The reporting subtlety that matters most: thin-provisioned disks. A 200 GB
//! VMDK that has only ever had 30 GB written to it *occupies* 30 GB. Reporting
//! the apparent 200 GB would overstate reclaimable space by nearly 7×, which is
//! the single most common way disk tools lie to their users.

use crate::config::ScanConfig;
use crate::detect::make_finding;
use crate::detect::rules::{self, VmFlavour};
use crate::model::{Detector, Finding, Safety, ScanResult};
use crate::util;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Smallest *apparent* bundle size worth mentioning.
///
/// Deliberately apparent rather than allocated. A 200 GB virtual disk that is
/// 95% thin-provisioned occupies perhaps 10 GB, but the user still recognises it
/// as a large machine and wants to know nobody has used it for a year. Gating on
/// allocated size would hide precisely the VMs this detector exists to find.
///
/// Reclaimable space is still reported as *allocated*, so a fully sparse image
/// correctly comes back as worth very little.
const MIN_VM_BYTES: u64 = 1024 * 1024 * 1024;

/// A discovered virtual machine bundle.
#[derive(Debug)]
struct VmBundle {
    /// Directory holding the machine's files. This is the unit of analysis.
    dir: PathBuf,
    /// Which product this bundle belongs to.
    flavour: VmFlavour,
    /// Disk images and other bulk files.
    images: Vec<crate::model::ScanNode>,
    /// The configuration file, whose mtime is the last-used signal.
    config: Option<crate::model::ScanNode>,
}

impl VmBundle {
    /// Total apparent size of the bundle.
    fn apparent_bytes(&self) -> u64 {
        self.images.iter().map(|n| n.size).sum()
    }

    /// Bytes actually occupied. Always the number to quote as reclaimable.
    fn allocated_bytes(&self) -> u64 {
        self.images.iter().map(|n| n.on_disk).sum()
    }

    /// How many snapshots or additional disks the bundle carries.
    fn image_count(&self) -> usize {
        self.images.len()
    }

    /// Last-used proxy: the configuration file's modification time.
    ///
    /// Falls back to the newest image when there is no config file, which is the
    /// orphan-image case.
    fn last_used(&self) -> Option<time::OffsetDateTime> {
        self.config
            .as_ref()
            .and_then(|c| c.modified)
            .or_else(|| self.images.iter().filter_map(|i| i.modified).max())
    }
}

/// Find virtual machine bundles that nobody has touched in months.
#[must_use]
pub fn detect(result: &ScanResult, config: &ScanConfig) -> Vec<Finding> {
    let now = util::now();
    let mut findings = Vec::new();

    for bundle in discover_bundles(result) {
        let allocated = bundle.allocated_bytes();
        if bundle.apparent_bytes() < MIN_VM_BYTES {
            continue;
        }

        let last_used = bundle.last_used();
        let days_unused = util::days_since(last_used, now);
        let orphan = bundle.config.is_none();

        // No config file means no evidence the machine has ever been run. That is
        // a strong abandoned signal, but weaker than a known-old config, so it
        // caps severity a little and confidence accordingly.
        let abandoned = match days_unused {
            Some(d) => d >= i64::from(config.vm_stale_days),
            // No timestamps at all: cannot prove staleness, so do not accuse.
            None => false,
        };
        if !abandoned {
            continue;
        }

        let apparent = bundle.apparent_bytes();
        let days = days_unused.unwrap_or_default();

        let confidence = if orphan {
            0.7
        } else if days >= i64::from(config.vm_stale_days) * 2 {
            0.95
        } else {
            0.85
        };

        let title = if orphan {
            format!(
                "Orphaned {} disk image, {}",
                bundle.flavour.product(),
                util::human_bytes(allocated)
            )
        } else {
            format!(
                "Abandoned {} machine \"{}\", unused for {} days",
                bundle.flavour.product(),
                display_name(&bundle),
                days
            )
        };

        // Thin provisioning is worth calling out explicitly: a 200 GB image
        // holding 30 GB is a much better story than "delete 200 GB".
        let overprovisioned = apparent.saturating_sub(allocated);
        let provision_note = if overprovisioned > apparent / 2 && apparent > 0 {
            format!(
                " The disk is thin-provisioned: {} apparent, only {} actually allocated.",
                util::human_bytes(apparent),
                util::human_bytes(allocated)
            )
        } else {
            String::new()
        };

        let recommendation = if orphan {
            format!(
                "No configuration file was found, so this {} image cannot start a machine. \
                 Confirm it is not needed, then delete the whole \"{}\" directory to free \
                 {}.{}",
                bundle.flavour.product(),
                bundle.dir.display(),
                util::human_bytes(allocated),
                provision_note
            )
        } else {
            format!(
                "This machine has not been started since {}. If it is no longer needed, delete \
                 the entire \"{}\" directory — not just the disk image, which would leave an \
                 unbootable machine behind. Frees {}.{}",
                util::fmt_rfc3339(last_used),
                bundle.dir.display(),
                util::human_bytes(allocated),
                provision_note
            )
        };

        let safety = if orphan {
            Safety::ReviewFirst
        } else {
            Safety::DataLoss
        };

        let mut finding = make_finding(
            Detector::AbandonedVms,
            &bundle.dir,
            apparent,
            allocated,
            confidence,
            safety,
            title,
            recommendation,
            serde_json::json!({
                "vmType": bundle.flavour.product(),
                "flavour": format!("{:?}", bundle.flavour),
                "bundlePath": bundle.dir.to_string_lossy(),
                "configFile": bundle.config.as_ref().map(|c| c.name.clone()),
                "lastUsed": util::fmt_rfc3339(last_used),
                "daysUnused": days,
                "images": bundle.images.iter().map(|n| n.name.clone()).collect::<Vec<_>>(),
                "imageCount": bundle.image_count(),
                "allocatedBytes": allocated,
                "apparentBytes": apparent,
                "thinProvisioned": overprovisioned > apparent / 2,
                "orphanImage": orphan,
            }),
        );
        // List every file in the bundle, config included: deleting the bundle
        // means removing all of them, and a partial list invites a partial delete.
        finding.related_paths = bundle
            .images
            .iter()
            .chain(bundle.config.iter())
            .map(|n| n.path.clone())
            .filter(|p| p != &finding.path)
            .collect();
        findings.push(finding);
    }

    findings
}

/// Group VM-related files into bundle directories.
///
/// The bundle directory is the unit of analysis, because it is also the unit the
/// user must delete: removing one image out of a bundle leaves an unbootable
/// machine behind.
fn discover_bundles(result: &ScanResult) -> Vec<VmBundle> {
    let mut bundles: BTreeMap<PathBuf, VmBundle> = BTreeMap::new();

    for node in &result.nodes {
        let Some(flavour) = rules::vm_image_extension(node.extension.as_deref()) else {
            continue;
        };
        let dir = node.path.parent().unwrap_or(Path::new("/")).to_path_buf();

        let entry = bundles.entry(dir.clone()).or_insert_with(|| VmBundle {
            dir,
            flavour,
            images: Vec::new(),
            config: None,
        });

        // Keep the first flavour seen. A VMware bundle yields both `VMware` and
        // `VMwareConfig`, which report the same product name, so there is nothing
        // to disambiguate and picking either is correct.
        if flavour.is_config() {
            entry.config = Some(node.clone());
        } else {
            entry.images.push(node.clone());
        }
    }

    bundles.into_values().collect()
}

/// A human-friendly name for a VM: its config file's stem.
fn display_name(bundle: &VmBundle) -> String {
    if let Some(config) = &bundle.config {
        if let Some(stem) = config.path.file_stem() {
            return stem.to_string_lossy().to_string();
        }
    }
    bundle.dir.file_name().map_or_else(
        || bundle.dir.display().to_string(),
        |n| n.to_string_lossy().to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::detect::testing::{Age, ScanBuilder};
    use crate::model::{GIB, MIB};

    #[test]
    fn unused_vmware_bundles_are_flagged() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/VMs/debian/debian.vmx", 4 * MIB, Age::Days(600))
            .file(
                "/Users/jdoe/VMs/debian/debian.vmdk",
                40 * GIB,
                Age::Days(600),
            )
            .build();

        let findings = detect(&result, &ScanConfig::default());
        assert_eq!(findings.len(), 1);

        let f = &findings[0];
        assert_eq!(f.path, PathBuf::from("/Users/jdoe/VMs/debian"));
        assert_eq!(f.detector, Detector::AbandonedVms);
        assert_eq!(f.safety, Safety::DataLoss);
        assert_eq!(f.detail["daysUnused"].as_i64().unwrap(), 600);
        assert_eq!(f.detail["vmType"].as_str().unwrap(), "VMware");
        assert!(!f.detail["orphanImage"].as_bool().unwrap());
    }

    #[test]
    fn recently_used_vms_are_left_alone() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/VMs/current/current.vmx", 4 * MIB, Age::Days(3))
            .file(
                "/Users/jdoe/VMs/current/current.vmdk",
                60 * GIB,
                Age::Days(300),
            )
            .build();

        assert!(
            detect(&result, &ScanConfig::default()).is_empty(),
            "a VM started three days ago is not abandoned"
        );
    }

    #[test]
    fn the_whole_bundle_is_recommended_not_just_the_image() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/VMs/old/old.vmx", 4 * MIB, Age::Days(500))
            .file("/Users/jdoe/VMs/old/old.vmdk", 30 * GIB, Age::Days(500))
            .build();

        let f = &detect(&result, &ScanConfig::default())[0];
        assert!(f.recommendation.contains("entire"), "{}", f.recommendation);
        assert!(
            f.recommendation.contains("unbootable"),
            "{}",
            f.recommendation
        );
        assert_eq!(
            f.related_paths.len(),
            2,
            "both files are listed so nothing is missed"
        );
    }

    #[test]
    fn orphan_images_are_flagged_with_lower_confidence() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/orphan.qcow2", 30 * GIB, Age::Days(500))
            .build();

        let findings = detect(&result, &ScanConfig::default());
        assert_eq!(findings.len(), 1);

        let f = &findings[0];
        assert!(f.detail["orphanImage"].as_bool().unwrap());
        assert_eq!(
            f.safety,
            Safety::ReviewFirst,
            "weaker evidence, gentler advice"
        );
        assert!(
            (f.confidence - 0.7).abs() < f32::EPSILON,
            "{}",
            f.confidence
        );
        assert!(
            f.recommendation.contains("cannot start"),
            "{}",
            f.recommendation
        );
    }

    #[test]
    fn thin_provisioned_disks_report_allocated_not_apparent_size() {
        // The scanner records apparent 200 GiB but only 30 GiB allocated.
        let mut result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/VMs/win/win.vmx", 4 * MIB, Age::Days(400))
            .file("/Users/jdoe/VMs/win/win.vmdk", 200 * GIB, Age::Days(400))
            .build();
        for node in &mut result.nodes {
            if node.name == "win.vmdk" {
                node.on_disk = 30 * GIB;
            }
        }

        let f = &detect(&result, &ScanConfig::default())[0];
        assert_eq!(f.size, 200 * GIB, "apparent size is still reported");
        assert_eq!(
            f.reclaimable,
            30 * GIB,
            "but only what is actually allocated can be reclaimed"
        );
        assert!(f.detail["thinProvisioned"].as_bool().unwrap());
        assert!(
            f.recommendation.contains("thin-provisioned"),
            "the discrepancy must be explained: {}",
            f.recommendation
        );
    }

    #[test]
    fn small_vm_bundles_are_ignored() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/VMs/tiny/tiny.vmx", 1024, Age::Days(900))
            .file("/Users/jdoe/VMs/tiny/tiny.vmdk", 500 * MIB, Age::Days(900))
            .build();

        assert!(detect(&result, &ScanConfig::default()).is_empty());
    }

    #[test]
    fn a_fully_sparse_vm_is_still_reported_but_claims_little_space() {
        // Apparent 4 GiB, nothing actually allocated: a never-written disk image.
        // It is unmistakably a large abandoned VM, but deleting it frees almost
        // nothing, so the reclaimable figure must say so.
        let mut result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/VMs/sparse/sparse.vmx", 4096, Age::Days(500))
            .file(
                "/Users/jdoe/VMs/sparse/sparse.vmdk",
                4 * GIB,
                Age::Days(500),
            )
            .build();
        for node in &mut result.nodes {
            if node.name == "sparse.vmdk" {
                node.on_disk = 0;
            }
        }

        let findings = detect(&result, &ScanConfig::default());
        assert_eq!(findings.len(), 1, "thin provisioning must not hide it");
        assert_eq!(findings[0].size, 4 * GIB);
        assert_eq!(findings[0].reclaimable, 0, "but it frees nothing");
    }

    #[test]
    fn vms_without_any_timestamp_are_not_accused() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/VMs/unknown/unknown.vmx", 4 * MIB, Age::Never)
            .file("/Users/jdoe/VMs/unknown/unknown.vmdk", 40 * GIB, Age::Never)
            .build();

        assert!(
            detect(&result, &ScanConfig::default()).is_empty(),
            "no evidence of staleness means no finding"
        );
    }

    #[test]
    fn hyperv_and_qemu_images_are_recognised() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/VMs/hyperv/data.vhdx", 25 * GIB, Age::Days(300))
            .file("/Users/jdoe/VMs/qemu/linux.qcow2", 15 * GIB, Age::Days(300))
            .build();

        let findings = detect(&result, &ScanConfig::default());
        assert_eq!(findings.len(), 2);
        let types: Vec<&str> = findings
            .iter()
            .map(|f| f.detail["vmType"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"Hyper-V"), "{types:?}");
        assert!(types.contains(&"QEMU / KVM"), "{types:?}");
    }

    #[test]
    fn multiple_disks_in_one_bundle_are_counted_once() {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/VMs/multi/multi.vmx", 4 * MIB, Age::Days(700))
            .file("/Users/jdoe/VMs/multi/base.vmdk", 20 * GIB, Age::Days(700))
            .file(
                "/Users/jdoe/VMs/multi/snapshot1.vmdk",
                8 * GIB,
                Age::Days(700),
            )
            .file(
                "/Users/jdoe/VMs/multi/snapshot2.vmdk",
                6 * GIB,
                Age::Days(700),
            )
            .build();

        let findings = detect(&result, &ScanConfig::default());
        assert_eq!(findings.len(), 1, "four files in one bundle is one finding");
        assert_eq!(findings[0].reclaimable, 34 * GIB);
        assert_eq!(findings[0].detail["imageCount"].as_u64().unwrap(), 3);
    }
}
