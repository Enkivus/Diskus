//! Report generation in four formats.
//!
//! **No file contents ever reach a report.** Reports carry metadata only: paths,
//! sizes, timestamps, severities, and — for duplicate clusters — cryptographic
//! digests, which prove two files match without revealing what is inside them.
//!
//! Every format shares the same header (machine, timestamp, totals, detector
//! counts) and the same footer note about double-counting, so a report in any
//! format says the same thing.

pub mod csv;
pub mod html;
pub mod json;
pub mod markdown;

use crate::config::{ExportFormat, ExportRequest};
use crate::model::{Finding, ScanSummary};
use crate::util;
use std::path::{Path, PathBuf};

/// One file produced by an export.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrittenReport {
    /// The format it was written in.
    pub format: ExportFormat,
    /// Absolute path of the file on disk.
    pub path: PathBuf,
    /// Size of the generated file in bytes.
    pub bytes: u64,
}

/// Write every requested format into `output_dir`.
///
/// Returns one entry per file written. CSV produces several files — one per
/// category — so the count is not necessarily the number of formats.
#[must_use]
pub fn write_reports(request: &ExportRequest, output_dir: &Path) -> Vec<WrittenReport> {
    let stem = request.file_stem();
    let mut written: Vec<WrittenReport> = Vec::new();

    // Everything is rendered before anything is written, so the manifest can
    // describe the export and a mid-sequence failure cannot leave a half-written
    // set with no record of it.
    let mut attempts: Vec<(ExportFormat, String, String)> = Vec::new();

    for &format in &request.formats {
        match format {
            ExportFormat::Html => attempts.push((format, stem.clone(), html::render(request))),
            ExportFormat::Json => attempts.push((format, stem.clone(), json::render(request))),
            ExportFormat::Markdown => {
                attempts.push((format, stem.clone(), markdown::render(request)));
            }
            ExportFormat::Csv => {
                for (suffix, body) in csv::render_all(request) {
                    attempts.push((format, format!("{stem}-{suffix}"), body));
                }
            }
        }
    }

    let mut failures = 0_usize;
    for (format, file_stem, body) in attempts {
        match write_one(format, output_dir, &file_stem, body) {
            Ok(report) => written.push(report),
            Err(err) => {
                failures += 1;
                log::error!("failed writing {file_stem}: {err}");
            }
        }
    }

    if failures > 0 {
        // Never swallowed: the caller reports a partial export as a partial
        // export rather than as a complete one.
        log::error!("{failures} of the requested files could not be written");
    }

    // A manifest makes a multi-file export self-describing: open the folder and
    // see what was produced.
    //
    // It gets its own `-manifest` suffix rather than reusing the base stem. With
    // the shared stem it would be written as `<stem>.json` and silently overwrite
    // the JSON report whenever JSON was one of the selected formats.
    //
    // Written last, because it has to describe what was actually produced — which
    // is only known once the rest of the export has landed.
    if written.len() > 1 {
        let manifest_stem = format!("{stem}-manifest");
        if let Some(body) = csv::render_manifest(request, &written) {
            match write_one(ExportFormat::Json, output_dir, &manifest_stem, body) {
                Ok(report) => written.push(report),
                Err(err) => log::error!("failed writing manifest: {err}"),
            }
        }
    }

    written
}

/// Render one file and record its size.
///
/// A write failure is returned, never swallowed. Reporting a file the app failed
/// to produce is worse than reporting nothing: the export screen lists every
/// returned path under a "Written" heading, so a full disk or a read-only
/// destination would show a row of confident success cards pointing at files
/// that do not exist.
fn write_one(
    format: ExportFormat,
    dir: &Path,
    stem: &str,
    body: String,
) -> Result<WrittenReport, std::io::Error> {
    let path = dir.join(format!("{stem}.{}", format.extension()));
    let bytes = body.len() as u64;
    std::fs::write(&path, body)?;

    Ok(WrittenReport {
        format,
        path,
        bytes,
    })
}

/// The machine label shown in report headers.
#[must_use]
pub fn machine_label(request: &ExportRequest) -> String {
    request.machine_label.clone().unwrap_or_else(util::hostname)
}

/// Paths rendered for a report, honouring the absolute-paths toggle.
///
/// When absolute paths are switched off, each path is rewritten relative to the
/// scan root that contains it and prefixed with `~/`. The point is that a report
/// shared with a colleague should not carry the operator's home directory and
/// username — and the export screen says exactly that when offering the toggle,
/// so it has to actually do something.
///
/// Falls back to the absolute path for anything outside the scanned roots, since
/// a relative rendering would be meaningless there.
#[must_use]
pub fn display_path(request: &ExportRequest, path: &Path) -> String {
    if request.include_absolute_paths {
        return path.to_string_lossy().to_string();
    }

    let relative = request
        .roots
        .iter()
        .filter(|root| path.starts_with(root))
        // The deepest matching root wins, so nested scan roots do not produce a
        // path relative to the wrong one.
        .max_by_key(|root| root.components().count())
        .and_then(|root| path.strip_prefix(root).ok());

    match relative {
        // `rel` is empty when `path` *is* a scan root, which renders as `~/`.
        Some(rel) => {
            let rel = rel.to_string_lossy().replace('\\', "/");
            let rel = rel.trim_matches('/');
            if rel.is_empty() {
                "~/".to_string()
            } else {
                format!("~/{rel}")
            }
        }
        None => path.to_string_lossy().to_string(),
    }
}

/// Rewrite absolute paths nested inside a detector's `detail` object.
///
/// The top-level `path` field goes through [`display_path`], but detectors also
/// embed paths in `detail` — `basePath`, `keepSuggestion`, `directory`. Those
/// render verbatim in the UI and land unfiltered in the JSON report, so without
/// this the relative-path toggle would be defeated by a nested field and a
/// shared report would still expose the operator's directory layout.
///
/// Only strings that actually sit under a scanned root are touched, so ordinary
/// text in `detail` (package names, VM types, warnings) passes through
/// unchanged.
#[must_use]
pub fn redact_detail_paths(
    request: &ExportRequest,
    detail: &serde_json::Value,
) -> serde_json::Value {
    if request.include_absolute_paths {
        return detail.clone();
    }
    rewrite_strings(detail, request)
}

fn rewrite_strings(value: &serde_json::Value, request: &ExportRequest) -> serde_json::Value {
    use serde_json::Value;
    match value {
        // Detail fields are a mix of bare paths and sentences containing paths,
        // so the prose-safe redactor covers both.
        Value::String(s) => Value::String(redact_text(request, s)),
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| rewrite_strings(v, request)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), rewrite_strings(v, request)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Rewrite absolute paths embedded anywhere inside a piece of text.
///
/// [`display_path`] handles fields that *are* a path. This handles the fields
/// that merely *contain* one — and those matter most, because the detectors
/// write their recommendations as prose that names the path:
///
/// ```text
/// "`/Users/alex/Library/Caches` is a cache. Delete it to free 12 GB."
/// ```
///
/// Redacting only whole-path fields left that sentence intact and shipped the
/// user's home directory in a report they had explicitly asked to be
/// shareable.
///
/// Only the exact scan-root prefix is replaced, so ordinary prose is untouched;
/// roots are absolute paths and cannot occur in text by coincidence.
#[must_use]
pub fn redact_text(request: &ExportRequest, text: &str) -> String {
    if request.include_absolute_paths || request.roots.is_empty() {
        return text.to_string();
    }

    let mut out = text.to_string();
    // Longest root first, so a nested root wins over its parent.
    let mut roots: Vec<String> = request
        .roots
        .iter()
        .map(|r| {
            r.to_string_lossy()
                .trim_end_matches(['/', '\\'])
                .to_string()
        })
        .filter(|r| !r.is_empty())
        .collect();
    roots.sort_by_key(|r| std::cmp::Reverse(r.len()));
    roots.dedup();

    for root in roots {
        // `root + separator` first, so `/Users/alex` does not leave a stray `/`
        // behind when it matches the start of `/Users/alexandra`.
        out = out.replace(&format!("{root}/"), "~/");
        out = out.replace(&root, "~/");
    }
    out
}

/// Findings sorted the way every report should present them.
#[must_use]
pub fn ordered_findings(request: &ExportRequest) -> Vec<&Finding> {
    let mut findings: Vec<&Finding> = request.findings.iter().collect();
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| b.reclaimable.cmp(&a.reclaimable))
            .then_with(|| a.title.cmp(&b.title))
    });
    findings
}

/// Aggregate numbers shared by every report header.
#[must_use]
pub fn header_lines(request: &ExportRequest) -> Vec<(String, String)> {
    let s: &ScanSummary = &request.summary;
    let mut lines = vec![
        ("Machine".to_string(), machine_label(request)),
        (
            "Generated".to_string(),
            util::fmt_rfc3339(Some(util::now())),
        ),
        (
            "Diskus version".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        ),
        (
            "Storage scanned".to_string(),
            util::human_bytes(s.total_scanned),
        ),
        (
            "Reclaimable".to_string(),
            util::human_bytes(s.total_reclaimable),
        ),
        (
            "Findings".to_string(),
            s.counts_by_severity.total().to_string(),
        ),
        (
            "Analysis time".to_string(),
            util::human_duration(s.elapsed_ms),
        ),
    ];

    if !request.volumes.is_empty() {
        let volumes = request
            .volumes
            .iter()
            .map(|v| {
                let used = v
                    .total_bytes
                    .unwrap_or(0)
                    .saturating_sub(v.available_bytes.unwrap_or(0));
                format!(
                    "{} ({} of {} used)",
                    v.mount_point.display(),
                    util::human_bytes(used),
                    util::human_bytes(v.total_bytes.unwrap_or(0))
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(("Volumes".to_string(), volumes));
    }

    lines
}

/// The privacy statement that appears in every human-readable report.
pub const PRIVACY_NOTE: &str = "This report contains file metadata only — paths, sizes, timestamps and severities. \
     Diskus performed all analysis locally on this machine and uploaded nothing. Where content \
     hashes appear, they are cryptographic digests used to prove two files are identical; they \
     reveal nothing about the contents and were not transmitted.";

/// The accounting caveat that appears in every report footer.
pub const COUNTING_NOTE: &str = "Reclaimable totals are the sum of individual findings. A single file can be claimed by more \
     than one detector (a log file may also be a duplicate), so the total is an upper bound, not a \
     guaranteed amount of free space.";

/// Escape text for safe inclusion in HTML.
#[must_use]
pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape text for safe inclusion in a Markdown table cell.
///
/// Pipes would split the row and newlines would end the row early.
#[must_use]
pub fn md_escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', " ")
        .replace('\r', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with(roots: Vec<PathBuf>, absolute: bool) -> ExportRequest {
        ExportRequest {
            scan_id: "s".into(),
            findings: vec![],
            summary: ScanSummary::default(),
            volumes: vec![],
            formats: vec![],
            include_absolute_paths: absolute,
            roots,
            include_hashes: false,
            machine_label: Some("box".into()),
        }
    }

    #[test]
    fn relative_paths_drop_the_home_directory() {
        let request = request_with(vec![PathBuf::from("/Users/alex")], false);
        let shown = display_path(&request, Path::new("/Users/alex/Documents/a.mov"));
        assert_eq!(shown, "~/Documents/a.mov");
        assert!(
            !shown.contains("alex"),
            "the operator's name must not survive: {shown}"
        );
    }

    #[test]
    fn relative_paths_do_not_hide_the_file_structure() {
        let request = request_with(vec![PathBuf::from("/Users/alex")], false);
        let shown = display_path(
            &request,
            Path::new("/Users/alex/Library/Caches/com.example/b"),
        );
        assert_eq!(shown, "~/Library/Caches/com.example/b");
    }

    #[test]
    fn absolute_paths_are_untouched_when_requested() {
        let request = request_with(vec![PathBuf::from("/Users/alex")], true);
        assert_eq!(
            display_path(&request, Path::new("/Users/alex/Documents/a.mov")),
            "/Users/alex/Documents/a.mov"
        );
    }

    #[test]
    fn the_deepest_matching_root_wins() {
        let request = request_with(
            vec![
                PathBuf::from("/Users/alex"),
                PathBuf::from("/Users/alex/Projects"),
            ],
            false,
        );
        assert_eq!(
            display_path(&request, Path::new("/Users/alex/Projects/app/main.rs")),
            "~/app/main.rs"
        );
    }

    #[test]
    fn paths_outside_the_scanned_roots_stay_absolute() {
        // Relativising a path against an unrelated root would be meaningless, so
        // it stays absolute rather than becoming nonsense.
        let request = request_with(vec![PathBuf::from("/Volumes/Data")], false);
        let shown = display_path(&request, Path::new("/elsewhere/file.txt"));
        assert_eq!(shown, "/elsewhere/file.txt");
    }

    #[test]
    fn the_scan_root_itself_renders_sensibly() {
        let request = request_with(vec![PathBuf::from("/Users/alex")], false);
        assert_eq!(display_path(&request, Path::new("/Users/alex")), "~/");
    }

    #[test]
    fn file_stems_stay_inside_the_platform_filename_limit() {
        // A long label would otherwise push the filename past NAME_MAX (255) and
        // every export would fail with ENAMETOOLONG.
        let mut request = request_with(vec![], true);
        request.machine_label = Some("x".repeat(400));
        let stem = request.file_stem();
        assert!(stem.len() <= 255, "stem is {} bytes", stem.len());
        for format in ExportFormat::ALL {
            let name = format!("{stem}.{}", format.extension());
            assert!(name.len() <= 255, "{name} is {} bytes", name.len());
        }
        let manifest = format!("{stem}-manifest.json");
        assert!(
            manifest.len() <= 255,
            "{manifest} is {} bytes",
            manifest.len()
        );
    }

    #[test]
    fn a_hostile_machine_label_cannot_escape_the_output_directory() {
        let mut request = request_with(vec![], true);
        for hostile in [
            "../../etc/passwd",
            "..\\..\\windows",
            "a/b/c",
            "/absolute/path",
        ] {
            request.machine_label = Some(hostile.to_string());
            let stem = request.file_stem();
            let joined = Path::new("/tmp/out").join(format!("{stem}.html"));
            assert!(
                joined.starts_with("/tmp/out"),
                "{hostile} escaped to {}",
                joined.display()
            );
            assert!(!stem.contains('/'), "{hostile} kept a separator: {stem}");
            assert!(!stem.contains('\\'), "{hostile} kept a backslash: {stem}");
        }
    }

    #[test]
    fn write_failures_are_not_reported_as_successes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path();
        let request = request_with(vec![], true);

        // A subdirectory that does not exist is a write failure, not a success.
        let missing = out.join("does-not-exist");
        let written = write_reports(&request, &missing);
        assert!(
            written.is_empty(),
            "no file should be reported when nothing was written, got {}",
            written.len()
        );

        // And the real directory does produce files.
        let mut with_format = request;
        with_format.formats = vec![ExportFormat::Html, ExportFormat::Json];
        let written = write_reports(&with_format, out);
        assert_eq!(written.len(), 3, "html + json + manifest");
        for report in &written {
            assert!(report.path.exists(), "{}", report.path.display());
        }
    }
}

#[cfg(test)]
mod escaping_tests {
    use super::*;

    #[test]
    fn html_escaping_covers_every_dangerous_character() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(
            html_escape(r#""quoted" 'single'"#),
            "&quot;quoted&quot; &#39;single&#39;"
        );
    }

    #[test]
    fn markdown_escaping_keeps_tables_intact() {
        assert_eq!(md_escape("a|b"), "a\\|b");
        assert_eq!(md_escape("line\nbreak"), "line break");
        assert_eq!(md_escape(r"back\slash"), r"back\\slash");
    }

    #[test]
    fn escaping_is_idempotent_safe_for_already_plain_text() {
        let plain = "/Users/jdoe/Documents/report 2024.pdf";
        assert_eq!(html_escape(plain), plain);
        assert_eq!(md_escape(plain), plain);
    }

    #[test]
    fn escapes_neutralise_an_injected_tag() {
        let hostile = r#"<img src=x onerror="alert(1)">"#;
        let escaped = html_escape(hostile);
        assert!(!escaped.contains('<'), "no raw angle brackets survive");
        assert!(!escaped.contains('>'), "no raw angle brackets survive");
    }
}
