//! CSV report: one file per category, for sorting in a spreadsheet.
//!
//! Two details that are easy to get wrong and painful to discover later:
//!
//! * **UTF-8 BOM.** Without it, Excel on Windows reads the file as the local
//!   codepage and mangles every non-ASCII character in a path.
//! * **CRLF line endings.** RFC 4180, and the only thing Excel reliably opens.
//!
//! The file is split by category rather than lumping everything together
//! because the three audiences are different: IT triages `findings.csv`, whoever
//! owns the data triages `duplicates.csv`, and everyone wants `largest-files`.

use crate::config::ExportRequest;
use crate::model::{Detector, Finding};
use crate::report::{PRIVACY_NOTE, display_path, machine_label, ordered_findings};
use crate::util;

/// A byte-order mark, prepended so Excel detects UTF-8.
const BOM: &str = "\u{feff}";

/// Column headers for the main findings table.
const FINDING_COLUMNS: [&str; 13] = [
    "severity",
    "detector",
    "title",
    "size_bytes",
    "size_human",
    "reclaimable_bytes",
    "reclaimable_human",
    "safety",
    "confidence",
    "path",
    "related_path_count",
    "modified",
    "recommendation",
];

/// Render every CSV file this export produces, as `(filename_suffix, contents)`.
#[must_use]
pub fn render_all(request: &ExportRequest) -> Vec<(String, String)> {
    let mut out = Vec::new();

    out.push(("findings".to_string(), findings_csv(request)));

    if request
        .findings
        .iter()
        .any(|f| f.detector == Detector::Duplicates)
    {
        out.push(("duplicates".to_string(), duplicates_csv(request)));
    }

    let largest = largest_files_csv(request);
    if !largest.is_empty() {
        out.push(("largest-files".to_string(), largest));
    }

    out
}

/// The main findings table: every finding, one row each.
#[must_use]
pub fn findings_csv(request: &ExportRequest) -> String {
    let mut w = CsvWriter::new(&FINDING_COLUMNS);
    w.comment(&format!(
        "Diskus findings — {} — generated {}",
        machine_label(request),
        util::fmt_rfc3339(Some(util::now()))
    ));
    w.line(PRIVACY_NOTE);
    w.line(crate::report::COUNTING_NOTE);

    for f in ordered_findings(request) {
        w.row(&[
            f.severity.id(),
            f.detector.id(),
            &f.title,
            &f.size.to_string(),
            &util::human_bytes(f.size),
            &f.reclaimable.to_string(),
            &util::human_bytes(f.reclaimable),
            f.safety.id(),
            &format!("{:.2}", f.confidence),
            &display_path(request, &f.path),
            &f.related_paths.len().to_string(),
            &timestamp_of(f),
            &crate::report::redact_text(request, &f.recommendation),
        ]);
    }

    w.finish()
}

/// Duplicate clusters only, with the keep-suggestion front and centre.
///
/// The useful column here is not the path — it is which copy to keep, because
/// that is the decision the reader has to make.
#[must_use]
pub fn duplicates_csv(request: &ExportRequest) -> String {
    let mut w = CsvWriter::new(&[
        "hash",
        "file_size_bytes",
        "file_size_human",
        "copies",
        "reclaimable_bytes",
        "reclaimable_human",
        "safety",
        "keep_this_copy",
        "all_paths",
    ]);
    w.comment(&format!(
        "Diskus duplicate clusters — {} — generated {}",
        machine_label(request),
        util::fmt_rfc3339(Some(util::now()))
    ));
    w.line(PRIVACY_NOTE);
    w.line(
        "Hashes prove the copies are byte-identical. Diskus never read or transmitted their \
         contents.",
    );

    for f in ordered_findings(request)
        .into_iter()
        .filter(|f| f.detector == Detector::Duplicates)
    {
        // Redacted rather than raw: CSV is the format most likely to be shared
        // around, and `keepSuggestion` is exactly the kind of field that betrays
        // the operator's directory layout.
        let redacted_paths = std::iter::once(&f.path)
            .chain(f.related_paths.iter())
            .map(|p| display_path(request, p))
            .collect::<Vec<_>>()
            .join(" | ");
        w.row(&[
            f.detail.get("hash").and_then(|h| h.as_str()).unwrap_or(""),
            &f.detail
                .get("fileSize")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                .to_string(),
            &util::human_bytes(
                f.detail
                    .get("fileSize")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
            ),
            &f.detail
                .get("copies")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(f.related_paths.len() as u64 + 1)
                .to_string(),
            &f.reclaimable.to_string(),
            &util::human_bytes(f.reclaimable),
            f.safety.id(),
            &display_path(request, &f.path),
            &redacted_paths,
        ]);
    }

    w.finish()
}

/// The largest individual files on the machine, whether or not they are
/// duplicates. Sometimes the answer to "what is using my disk" is one file.
#[must_use]
pub fn largest_files_csv(request: &ExportRequest) -> String {
    let mut w = CsvWriter::new(&[
        "rank",
        "size_bytes",
        "size_human",
        "name",
        "path",
        "modified",
    ]);
    w.comment(&format!(
        "Diskus — largest files — {} — generated {}",
        machine_label(request),
        util::fmt_rfc3339(Some(util::now()))
    ));
    w.line(PRIVACY_NOTE);

    // The largest files are the ones findings point at. Names are owned
    // `String`s because they borrow from paths that do not outlive the loop.
    let mut entries: Vec<(u64, String, &Finding)> = Vec::new();
    for f in ordered_findings(request) {
        let size = f
            .detail
            .get("fileSize")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(f.size);
        if size > 0 {
            if let Some(name) = f.path.file_name() {
                entries.push((size, name.to_string_lossy().into_owned(), f));
            }
        }
        for p in &f.related_paths {
            if let Some(name) = p.file_name() {
                entries.push((f.size, name.to_string_lossy().into_owned(), f));
            }
        }
    }

    entries.sort_by_key(|e| std::cmp::Reverse(e.0));
    entries.dedup_by(|a, b| a.1 == b.1 && a.0 == b.0);

    for (i, (size, name, f)) in entries.iter().take(200).enumerate() {
        w.row(&[
            &(i + 1).to_string(),
            &size.to_string(),
            &util::human_bytes(*size),
            name,
            &display_path(request, &f.path),
            &timestamp_of(f),
        ]);
    }

    w.finish()
}

/// A manifest describing what a multi-file export produced.
#[must_use]
pub fn render_manifest(
    request: &ExportRequest,
    written: &[crate::report::WrittenReport],
) -> Option<String> {
    if written.is_empty() {
        return None;
    }
    let manifest = serde_json::json!({
        "tool": "Diskus",
        "version": env!("CARGO_PKG_VERSION"),
        "machine": machine_label(request),
        "scanId": request.scan_id,
        "generatedAt": util::fmt_rfc3339(Some(util::now())),
        "files": written
            .iter()
            .map(|w| serde_json::json!({
                "format": w.format.id(),
                "file": w.path.file_name().map(|n| n.to_string_lossy().to_string()),
                "bytes": w.bytes,
            }))
            .collect::<Vec<_>>(),
        "privacy": PRIVACY_NOTE,
    });
    Some(serde_json::to_string_pretty(&manifest).unwrap_or_default())
}

/// Pull the best available timestamp out of a finding's detail object.
///
/// Each detector names its timestamp differently, so this normalises them for
/// the CSV columns.
fn timestamp_of(f: &Finding) -> String {
    for key in ["modified", "lastUsed", "newestModified"] {
        if let Some(v) = f.detail.get(key).and_then(serde_json::Value::as_str) {
            if v != "-" {
                return v.to_string();
            }
        }
    }
    "-".to_string()
}

/// Minimal RFC 4180 CSV writer: BOM, CRLF, correct quoting.
struct CsvWriter {
    buffer: String,
    columns: usize,
}

impl CsvWriter {
    fn new(columns: &[&str]) -> Self {
        let mut buffer = String::from(BOM);
        buffer.push_str(&columns.join(","));
        buffer.push_str("\r\n");
        Self {
            buffer,
            columns: columns.len(),
        }
    }

    /// Write a `#`-prefixed comment line.
    ///
    /// CSV has no comment syntax, so these become ordinary single-cell rows. A
    /// `#` prefix makes them obviously metadata to anyone who opens the file.
    fn comment(&mut self, text: &str) {
        self.line(&format!("# {text}"));
    }

    fn line(&mut self, text: &str) {
        self.buffer.push_str(&quote(text));
        self.buffer.push_str("\r\n");
    }

    fn row(&mut self, cells: &[&str]) {
        debug_assert_eq!(cells.len(), self.columns, "column count mismatch");
        let joined = cells.iter().map(|c| quote(c)).collect::<Vec<_>>().join(",");
        self.buffer.push_str(&joined);
        self.buffer.push_str("\r\n");
    }

    fn finish(self) -> String {
        self.buffer
    }
}

/// Quote a single field per RFC 4180.
fn quote(field: &str) -> String {
    let needs_quoting = field.contains([',', '"', '\n', '\r']);
    if !needs_quoting {
        return field.to_string();
    }
    let mut out = String::with_capacity(field.len() + 2);
    out.push('"');
    for c in field.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExportRequest;
    use crate::detect::testing::Age;
    use crate::detect::testing::ScanBuilder;
    use crate::model::{GIB, MIB, Volume};

    fn sample() -> ExportRequest {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/Library/Caches/x.bin", 90 * MIB, Age::Days(3))
            .file(
                "/Users/jdoe/Downloads/old-setup.exe",
                300 * MIB,
                Age::Days(400),
            )
            .build();
        let findings = crate::detect::run_all(&result, &crate::config::ScanConfig::default());
        let summary = crate::detect::summarise(&findings, result.total_bytes, 1234);
        ExportRequest {
            scan_id: "s1".into(),
            findings,
            summary,
            volumes: vec![Volume {
                name: "HD".into(),
                mount_point: std::path::PathBuf::from("/"),
                total_bytes: Some(GIB),
                available_bytes: Some(GIB / 2),
                is_scannable: true,
            }],
            formats: vec![],
            include_absolute_paths: true,
            roots: Vec::new(),
            include_hashes: true,
            machine_label: Some("box".into()),
        }
    }

    #[test]
    fn csv_starts_with_a_bom_for_excel() {
        let csv = findings_csv(&sample());
        assert!(
            csv.starts_with('\u{feff}'),
            "Excel needs the BOM to read UTF-8"
        );
    }

    #[test]
    fn csv_uses_crlf_line_endings() {
        let csv = findings_csv(&sample());
        assert!(csv.contains("\r\n"), "RFC 4180 line endings");
        let bare_lf = csv.replace("\r\n", "").matches('\n').count();
        assert_eq!(bare_lf, 0, "every newline must be part of a CRLF");
    }

    #[test]
    fn header_row_lists_every_column() {
        let csv = findings_csv(&sample());
        let header = csv
            .trim_start_matches('\u{feff}')
            .lines()
            .next()
            .expect("header row");
        for column in FINDING_COLUMNS {
            assert!(header.contains(column), "missing column {column}");
        }
    }

    #[test]
    fn commas_and_quotes_in_values_are_escaped() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote("has, comma"), "\"has, comma\"");
        assert_eq!(quote("has \"quotes\""), "\"has \"\"quotes\"\"\"");
        assert_eq!(quote("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn a_recommendation_with_a_comma_does_not_break_the_row() {
        let mut request = sample();
        request.findings[0].recommendation = "Delete this, it is huge.".into();
        let csv = findings_csv(&request);
        let data_line = csv
            .lines()
            .find(|l| l.contains("Delete this"))
            .expect("recommendation row");
        assert!(data_line.contains("\"Delete this, it is huge.\""));
    }

    #[test]
    fn multi_format_export_produces_the_expected_files() {
        let files = render_all(&sample());
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"findings"), "{names:?}");
        assert!(names.contains(&"largest-files"), "{names:?}");
    }

    #[test]
    fn duplicate_csv_is_only_emitted_when_there_are_duplicates() {
        let mut request = sample();
        let without = render_all(&request);
        assert!(
            !without.iter().any(|(n, _)| n == "duplicates"),
            "no duplicate findings, no duplicate file"
        );

        request.findings.push(crate::model::Finding {
            id: "d1".into(),
            detector: crate::model::Detector::Duplicates,
            severity: crate::model::Severity::High,
            safety: crate::model::Safety::DataLoss,
            title: "2 × 1 GB identical".into(),
            path: std::path::PathBuf::from("/Users/jdoe/Documents/a.mov"),
            related_paths: vec![std::path::PathBuf::from("/Users/jdoe/b.mov")],
            size: 2 * GIB,
            reclaimable: GIB,
            confidence: 1.0,
            recommendation: "Keep one".into(),
            detail: serde_json::json!({ "hash": "abc123", "fileSize": GIB, "copies": 2 }),
            detected_at: util::now(),
        });

        let with = render_all(&request);
        let dupes = with
            .iter()
            .find(|(n, _)| n == "duplicates")
            .expect("duplicates file");
        assert!(
            dupes.1.contains("abc123"),
            "the hash column must be populated"
        );
        assert!(
            dupes.1.contains("Documents/a.mov"),
            "keep-suggestion column"
        );
    }

    #[test]
    fn every_report_states_the_privacy_position() {
        for (_, body) in render_all(&sample()) {
            assert!(
                body.contains("metadata only") || body.contains("never read or transmitted"),
                "privacy statement missing from a CSV file"
            );
        }
    }

    #[test]
    fn manifest_lists_every_written_file() {
        let written = vec![
            crate::report::WrittenReport {
                format: crate::config::ExportFormat::Html,
                path: "/tmp/a.html".into(),
                bytes: 10,
            },
            crate::report::WrittenReport {
                format: crate::config::ExportFormat::Csv,
                path: "/tmp/a-findings.csv".into(),
                bytes: 20,
            },
        ];
        let manifest = render_manifest(&sample(), &written).expect("manifest");
        let parsed: serde_json::Value = serde_json::from_str(&manifest).expect("valid JSON");
        assert_eq!(parsed["files"].as_array().unwrap().len(), 2);
        assert!(manifest.contains("a.html"));
    }
}
