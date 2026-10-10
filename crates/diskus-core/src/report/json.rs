//! JSON report: the full, structured, machine-readable output.
//!
//! This is the format to build automation on. It is deliberately the most
//! complete representation Diskus produces — every field, every detector's
//! structured `detail`, and the raw per-severity counts — so a script never has
//! to parse prose or HTML.

use crate::config::ExportRequest;
use crate::model::{Finding, ScanSummary};
use crate::report::{
    PRIVACY_NOTE, display_path, machine_label, ordered_findings, redact_detail_paths, redact_text,
};
use crate::util;
use serde::Serialize;
use serde_json::{Value, json};

/// Top-level shape of the JSON report.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    meta: Meta,
    summary: SummaryView,
    volumes: Vec<VolumeView>,
    detectors: Vec<DetectorView>,
    findings: Vec<FindingView>,
    notes: Vec<String>,
}

/// Provenance and environment.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    tool: &'static str,
    version: &'static str,
    machine: String,
    scan_id: String,
    generated_at: String,
    analysis_time: String,
    privacy: &'static str,
    includes_absolute_paths: bool,
    includes_content_hashes: bool,
}

/// Aggregate numbers.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SummaryView {
    total_scanned: u64,
    total_scanned_human: String,
    total_reclaimable: u64,
    total_reclaimable_human: String,
    finding_count: u64,
    counts_by_severity: SeverityView,
    top_categories: Vec<CategoryView>,
}

/// Severity tally.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SeverityView {
    critical: u64,
    high: u64,
    medium: u64,
    low: u64,
    info: u64,
}

/// Reclaimable bytes per detector.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CategoryView {
    detector: &'static str,
    label: &'static str,
    finding_count: u64,
    bytes: u64,
    bytes_human: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VolumeView {
    name: String,
    mount_point: String,
    total_bytes: Option<u64>,
    available_bytes: Option<u64>,
    used_fraction: Option<f64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DetectorView {
    id: &'static str,
    label: &'static str,
    finding_count: u64,
    bytes: u64,
    bytes_human: String,
}

/// One finding, flattened for spreadsheet-style consumption.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingView {
    id: String,
    detector: &'static str,
    detector_label: &'static str,
    severity: &'static str,
    severity_label: &'static str,
    safety: &'static str,
    safety_label: &'static str,
    title: String,
    path: String,
    path_is_absolute: bool,
    related_paths: Vec<String>,
    related_path_count: usize,
    size: u64,
    size_human: String,
    reclaimable: u64,
    reclaimable_human: String,
    confidence: f32,
    recommendation: String,
    modified: Option<String>,
    /// Only populated when the export requested hashes.
    #[serde(skip_serializing_if = "Option::is_none")]
    content_hash: Option<String>,
    detail: Value,
}

/// Render the JSON report.
///
/// # Panics
///
/// Never. Serialisation of the in-memory model cannot fail, and a failure would
/// be a bug in the model rather than bad input.
#[must_use]
pub fn render(request: &ExportRequest) -> String {
    let s: &ScanSummary = &request.summary;

    let report = Report {
        meta: Meta {
            tool: "Diskus",
            version: env!("CARGO_PKG_VERSION"),
            machine: machine_label(request),
            scan_id: request.scan_id.clone(),
            generated_at: util::fmt_rfc3339(Some(util::now())),
            analysis_time: util::human_duration(s.elapsed_ms),
            privacy: PRIVACY_NOTE,
            includes_absolute_paths: request.include_absolute_paths,
            includes_content_hashes: request.include_hashes,
        },
        summary: SummaryView {
            total_scanned: s.total_scanned,
            total_scanned_human: util::human_bytes(s.total_scanned),
            total_reclaimable: s.total_reclaimable,
            total_reclaimable_human: util::human_bytes(s.total_reclaimable),
            finding_count: s.counts_by_severity.total(),
            counts_by_severity: SeverityView {
                critical: s.counts_by_severity.critical,
                high: s.counts_by_severity.high,
                medium: s.counts_by_severity.medium,
                low: s.counts_by_severity.low,
                info: s.counts_by_severity.info,
            },
            top_categories: request
                .summary
                .counts_by_detector
                .iter()
                .map(|d| CategoryView {
                    detector: d.detector.id(),
                    label: d.detector.label(),
                    finding_count: d.finding_count,
                    bytes: d.bytes,
                    bytes_human: util::human_bytes(d.bytes),
                })
                .collect(),
        },
        volumes: request
            .volumes
            .iter()
            .map(|v| VolumeView {
                name: v.name.clone(),
                mount_point: v.mount_point.to_string_lossy().to_string(),
                total_bytes: v.total_bytes,
                available_bytes: v.available_bytes,
                used_fraction: v.used_fraction().map(|f| (f * 1000.0).round() / 1000.0),
            })
            .collect(),
        detectors: crate::model::Detector::ALL
            .iter()
            .filter_map(|d| {
                request
                    .summary
                    .counts_by_detector
                    .iter()
                    .find(|r| r.detector == *d)
                    .map(|r| DetectorView {
                        id: d.id(),
                        label: d.label(),
                        finding_count: r.finding_count,
                        bytes: r.bytes,
                        bytes_human: util::human_bytes(r.bytes),
                    })
            })
            .collect(),
        findings: ordered_findings(request)
            .into_iter()
            .map(|f| view(request, f))
            .collect(),
        notes: vec![
            PRIVACY_NOTE.to_string(),
            crate::report::COUNTING_NOTE.to_string(),
        ],
    };

    // `to_string_pretty` on plain owned data cannot fail; fall back to an
    // explicit error object rather than panicking if it somehow did.
    serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
        json!({ "error": format!("report serialisation failed: {e}") }).to_string()
    })
}

fn view(request: &ExportRequest, f: &Finding) -> FindingView {
    let path = display_path(request, &f.path);

    // Hashes are opt-in. A shared report does not need them, and leaving them out
    // by default keeps the report smaller and the privacy story simpler.
    let content_hash = if request.include_hashes {
        f.detail
            .get("hash")
            .and_then(Value::as_str)
            .map(ToString::to_string)
    } else {
        None
    };

    let modified = f
        .detail
        .get("modified")
        .or_else(|| f.detail.get("lastUsed"))
        .or_else(|| f.detail.get("newestModified"))
        .and_then(Value::as_str)
        .map(ToString::to_string);

    FindingView {
        id: f.id.clone(),
        detector: f.detector.id(),
        detector_label: f.detector.label(),
        severity: f.severity.id(),
        severity_label: f.severity.label(),
        safety: f.safety.id(),
        safety_label: f.safety.label(),
        title: redact_text(request, &f.title),
        path_is_absolute: path.starts_with('/') || path.contains(':'),
        path,
        related_paths: f
            .related_paths
            .iter()
            .map(|p| display_path(request, p))
            .collect(),
        related_path_count: f.related_paths.len(),
        size: f.size,
        size_human: util::human_bytes(f.size),
        reclaimable: f.reclaimable,
        reclaimable_human: util::human_bytes(f.reclaimable),
        confidence: (f.confidence * 100.0).round() / 100.0,
        recommendation: redact_text(request, &f.recommendation),
        modified,
        content_hash,
        // Paths nested inside `detail` are redacted too, otherwise a shared
        // report still leaks the operator's directory layout through fields like
        // `basePath` and `keepSuggestion`.
        detail: redact_detail_paths(request, &redact_hashes(&f.detail, request.include_hashes)),
    }
}

/// Strip content hashes from `detail` when the export did not request them.
///
/// Without this, the `detail` object would smuggle the hash past the
/// `includes_hashes` toggle entirely — a real leak of an opt-out control.
fn redact_hashes(detail: &Value, include_hashes: bool) -> Value {
    if include_hashes {
        return detail.clone();
    }
    match detail {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(k, _)| k.as_str() != "hash")
                .map(|(k, v)| (k.clone(), redact_hashes(v, include_hashes)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| redact_hashes(v, include_hashes))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExportRequest;
    use crate::detect::testing::ScanBuilder;
    use crate::model::{Detector, Finding, GIB, MIB, Safety, Severity, Volume};
    use std::path::PathBuf;

    fn sample() -> ExportRequest {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/Library/Caches/x.bin", 90 * MIB, Age::Days(3))
            .build();
        let findings = crate::detect::run_all(&result, &crate::config::ScanConfig::default());
        let summary = crate::detect::summarise(&findings, result.total_bytes, result.elapsed_ms);

        ExportRequest {
            scan_id: "scan-1".into(),
            findings,
            summary,
            volumes: vec![Volume {
                name: "Macintosh HD".into(),
                mount_point: PathBuf::from("/"),
                total_bytes: Some(500 * GIB),
                available_bytes: Some(120 * GIB),
                is_scannable: true,
            }],
            formats: vec![],
            include_absolute_paths: true,
            roots: Vec::new(),
            include_hashes: false,
            machine_label: Some("testbox".into()),
        }
    }

    fn duplicate_finding() -> Finding {
        Finding {
            id: "duplicates-abc".into(),
            detector: Detector::Duplicates,
            severity: Severity::High,
            safety: Safety::DataLoss,
            title: "3 × 1 GB identical .mov".into(),
            path: PathBuf::from("/Users/jdoe/Documents/a.mov"),
            related_paths: vec![PathBuf::from("/Users/jdoe/b.mov")],
            size: 3 * GIB,
            reclaimable: 2 * GIB,
            confidence: 1.0,
            recommendation: "Keep one copy.".into(),
            detail: json!({ "hash": "deadbeef", "copies": 3 }),
            detected_at: util::now(),
        }
    }

    #[test]
    fn report_is_valid_json_with_the_expected_shape() {
        let json = render(&sample());
        let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["meta"]["tool"], "Diskus");
        assert_eq!(parsed["meta"]["machine"], "testbox");
        assert!(parsed["summary"]["totalScanned"].is_number());
        assert!(parsed["summary"]["countsBySeverity"].is_object());
        assert!(parsed["findings"].is_array());
    }

    #[test]
    fn human_sizes_travel_alongside_raw_bytes() {
        let parsed: Value = serde_json::from_str(&render(&sample())).expect("valid JSON");
        let scanned = parsed["summary"]["totalScanned"].as_u64().expect("bytes");
        let human = parsed["summary"]["totalScannedHuman"]
            .as_str()
            .expect("human");
        assert_eq!(human, util::human_bytes(scanned));
    }

    #[test]
    fn hashes_are_stripped_unless_explicitly_requested() {
        let mut request = sample();
        request.findings = vec![duplicate_finding()];
        request.include_hashes = false;

        let json = render(&request);
        assert!(
            !json.contains("deadbeef"),
            "the hash must not survive in the top-level field"
        );
        assert!(
            !json.contains("deadbeef"),
            "and must not survive inside detail either: {json}"
        );

        request.include_hashes = true;
        let json = render(&request);
        assert!(json.contains("deadbeef"), "opt-in must be honoured");
    }

    #[test]
    fn volumes_report_usage_fraction() {
        let parsed: Value = serde_json::from_str(&render(&sample())).expect("valid JSON");
        let used = parsed["volumes"][0]["usedFraction"]
            .as_f64()
            .expect("fraction");
        assert!(
            (used - 0.76).abs() < 0.01,
            "380 GB of 500 GB used, got {used}"
        );
    }

    #[test]
    fn privacy_note_is_present_in_every_report() {
        let parsed: Value = serde_json::from_str(&render(&sample())).expect("valid JSON");
        let privacy = parsed["meta"]["privacy"].as_str().expect("privacy note");
        assert!(privacy.contains("metadata only"), "{privacy}");
        assert!(
            parsed["notes"].as_array().unwrap().len() >= 2,
            "both the privacy note and the counting caveat"
        );
    }

    #[test]
    fn empty_scan_still_produces_a_valid_report() {
        let mut request = sample();
        request.findings = vec![];
        let parsed: Value = serde_json::from_str(&render(&request)).expect("valid JSON");
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["summary"]["totalReclaimable"].as_u64().unwrap(), 0);
    }

    use crate::detect::testing::Age;

    #[test]
    fn hash_redaction_recurses_into_nested_objects() {
        let nested = json!({ "a": { "hash": "secret", "b": 1 }, "c": [{ "hash": "s2" }] });
        let redacted = redact_hashes(&nested, false);
        let text = redacted.to_string();
        assert!(!text.contains("secret"), "{text}");
        assert!(!text.contains("s2"), "{text}");
        assert_eq!(redacted["a"]["b"], json!(1), "unrelated fields survive");
    }
}
