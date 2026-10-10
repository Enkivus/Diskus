//! Export every report format for a synthetic machine.
//!
//! Useful for eyeballing report output without running the app:
//! `cargo run -p diskus-core --example export_demo -- /tmp/diskus-reports`

use diskus_core::config::{ExportFormat, ExportRequest, ScanConfig};
use diskus_core::detect;
use diskus_core::report;
use diskus_core::scan::CancelToken;
use diskus_core::scan::walker::{SilentObserver, walk};
use std::fs;
use std::path::{Path, PathBuf};

fn sparse(path: &Path, mb: u64) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::File::create(path)
        .expect("create")
        .set_len(mb * 1024 * 1024)
        .expect("set_len");
}

fn main() {
    // `export_demo <out-dir> [--absolute]`
    // Default is relative paths, which is the mode that matters for sharing.
    let mut args = std::env::args().skip(1);
    let out = args
        .next()
        .unwrap_or_else(|| "/tmp/diskus-reports".to_string());
    let absolute = args.any(|a| a == "--absolute");
    fs::create_dir_all(&out).expect("create out dir");

    let fixture = std::env::temp_dir().join("diskus-demo-profile");
    sparse(&fixture.join("Library/Logs/nginx/access.log"), 900);
    sparse(&fixture.join("Library/Logs/nginx/access.log.1"), 420);
    sparse(&fixture.join("Library/Logs/nginx/access.log.2"), 180);
    sparse(
        &fixture.join("Library/Caches/com.docker.docker/blob.bin"),
        1500,
    );
    sparse(&fixture.join("Documents/holiday.mov"), 2400);
    sparse(&fixture.join("Documents/report-final.mov"), 2400);
    sparse(&fixture.join("Downloads/VSCodeSetup-x64.msi"), 130);
    sparse(&fixture.join(".npm/_cacache/index.bin"), 640);
    sparse(&fixture.join("VMs/legacy/legacy.qcow2"), 8000);

    // Canonicalise, because the walker does. Node paths come back under the
    // resolved prefix, and relative rendering matches against these roots — so
    // a non-canonical root would silently never match. The app gets this for
    // free from `results.stats.roots`, which are the walker's own canonical paths.
    let root = fixture.canonicalize().expect("canonical fixture");

    let config = ScanConfig {
        roots: vec![root.clone()],
        profile_size_threshold: 1024 * 1024 * 1024,
        min_file_size_for_dupes: 1024 * 1024,
        ..ScanConfig::default()
    };

    let result = walk(&config, &CancelToken::new(), &SilentObserver).expect("walk");
    let findings = detect::run_all(&result, &config);
    let summary = detect::summarise(&findings, result.total_bytes, result.elapsed_ms);

    println!(
        "scanned {} files, {} — {} findings, {} reclaimable",
        result.total_files,
        diskus_core::util::human_bytes(result.total_bytes),
        findings.len(),
        diskus_core::util::human_bytes(summary.total_reclaimable)
    );

    let request = ExportRequest {
        scan_id: "demo".into(),
        findings,
        summary,
        volumes: diskus_core::scan::volumes(),
        formats: ExportFormat::ALL.to_vec(),
        include_absolute_paths: absolute,
        roots: vec![root.clone()],
        include_hashes: true,
        machine_label: Some("demo-workstation".into()),
    };

    for w in report::write_reports(&request, PathBuf::from(&out).as_path()) {
        println!("  wrote {}", w.path.display());
    }
}
