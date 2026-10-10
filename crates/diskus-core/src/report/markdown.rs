//! Markdown report: the version a human actually reads.
//!
//! Organised the way someone triaging a machine wants to read it — worst first,
//! grouped by the action to take, with the caveats stated up front rather than
//! buried at the bottom.

use crate::config::ExportRequest;
use crate::model::{Detector, Safety};
use crate::report::{
    COUNTING_NOTE, PRIVACY_NOTE, display_path, header_lines, machine_label, md_escape,
    ordered_findings,
};
use crate::util;
use std::fmt::Write as _;

/// How many findings to list in full before collapsing into a summary.
const TOP_FINDINGS: usize = 50;

/// Render the Markdown report.
#[must_use]
pub fn render(request: &ExportRequest) -> String {
    let mut out = String::with_capacity(8192);
    let s = &request.summary;

    let _ = writeln!(out, "# Diskus storage report\n");
    let _ = writeln!(out, "**{}**\n", md_escape(&machine_label(request)));

    // ---- Header ------------------------------------------------------------
    let _ = writeln!(out, "| | |");
    let _ = writeln!(out, "|---|---|");
    for (k, v) in header_lines(request) {
        let _ = writeln!(out, "| {} | {} |", md_escape(&k), md_escape(&v));
    }
    let _ = writeln!(out);

    // ---- Headline ----------------------------------------------------------
    let _ = writeln!(out, "## At a glance\n");
    let _ = writeln!(
        out,
        "- **Storage scanned:** {}",
        util::human_bytes(s.total_scanned)
    );
    let _ = writeln!(
        out,
        "- **Potentially reclaimable:** {}",
        util::human_bytes(s.total_reclaimable)
    );
    let _ = writeln!(out, "- **Findings:** {}", s.counts_by_severity.total());
    let _ = writeln!(out);
    let _ = writeln!(out, "> {}\n", COUNTING_NOTE.replace('\n', " "));

    // ---- Severity ----------------------------------------------------------
    let c = &s.counts_by_severity;
    let _ = writeln!(out, "### Findings by severity\n");
    let _ = writeln!(out, "| Severity | Count |");
    let _ = writeln!(out, "|---|---|");
    for severity in crate::model::Severity::ALL {
        let _ = writeln!(out, "| {} | {} |", severity.label(), c.get(severity));
    }
    let _ = writeln!(out);

    // ---- Reclaimable by category ------------------------------------------
    if !s.counts_by_detector.is_empty() {
        let _ = writeln!(out, "### Reclaimable by category\n");
        let _ = writeln!(out, "| Category | Findings | Reclaimable |");
        let _ = writeln!(out, "|---|---:|---:|");
        for d in &s.counts_by_detector {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                md_escape(d.detector.label()),
                d.finding_count,
                util::human_bytes(d.bytes)
            );
        }
        let _ = writeln!(out);
    }

    // ---- Top findings ------------------------------------------------------
    let findings = ordered_findings(request);
    if !findings.is_empty() {
        let _ = writeln!(out, "## Top findings\n");
        let _ = writeln!(
            out,
            "| Severity | Category | Reclaimable | Finding | Location |"
        );
        let _ = writeln!(out, "|---|---|---:|---|---|");
        for f in findings.iter().take(TOP_FINDINGS) {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | `{}` |",
                f.severity.label(),
                f.detector.label(),
                util::human_bytes(f.reclaimable),
                md_escape(&f.title),
                md_escape(&display_path(request, &f.path))
            );
        }
        if findings.len() > TOP_FINDINGS {
            let _ = writeln!(
                out,
                "\n_…and {} more. See the CSV or JSON report for the full set._",
                findings.len() - TOP_FINDINGS
            );
        }
        let _ = writeln!(out);
    }

    // ---- Recommendations, grouped by action --------------------------------
    for section in [
        (Safety::SafeToDelete, "Safe to delete now"),
        (Safety::ReviewFirst, "Review first"),
        (Safety::DataLoss, "Deleting these loses data"),
    ] {
        let matching: Vec<_> = findings.iter().filter(|f| f.safety == section.0).collect();
        if matching.is_empty() {
            continue;
        }
        let _ = writeln!(out, "## {}\n", section.1);
        let total: u64 = matching.iter().map(|f| f.reclaimable).sum();
        let _ = writeln!(
            out,
            "{} finding(s), {} at stake.\n",
            matching.len(),
            util::human_bytes(total)
        );
        for f in matching.iter().take(10) {
            let _ = writeln!(
                out,
                "- **{}** — {}",
                md_escape(&f.title),
                md_escape(&crate::report::redact_text(request, &f.recommendation))
            );
        }
        if matching.len() > 10 {
            let _ = writeln!(
                out,
                "- _…and {} more in this category._",
                matching.len() - 10
            );
        }
        let _ = writeln!(out);
    }

    // ---- Duplicate clusters ------------------------------------------------
    let dupes: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == Detector::Duplicates)
        .collect();
    if !dupes.is_empty() {
        let _ = writeln!(out, "## Largest duplicate clusters\n");
        let _ = writeln!(out, "| Copies | Each | Reclaimable | Keep this one |");
        let _ = writeln!(out, "|---:|---:|---:|---|");
        for f in dupes.iter().take(20) {
            let copies = f
                .detail
                .get("copies")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(f.related_paths.len() as u64 + 1);
            let each = f
                .detail
                .get("fileSize")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let _ = writeln!(
                out,
                "| {} | {} | {} | `{}` |",
                copies,
                util::human_bytes(each),
                util::human_bytes(f.reclaimable),
                md_escape(&display_path(request, &f.path))
            );
        }
        let _ = writeln!(out);
    }

    // ---- Footer ------------------------------------------------------------
    let _ = writeln!(out, "---\n");
    let _ = writeln!(out, "*Generated by Diskus {}.*", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "\n> {}", PRIVACY_NOTE.replace('\n', " "));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExportRequest;
    use crate::detect::testing::{Age, ScanBuilder};
    use crate::model::{GIB, MIB, Volume};

    fn sample() -> ExportRequest {
        let result = ScanBuilder::new()
            .roots(&["/Users"])
            .file("/Users/jdoe/Library/Caches/x.bin", 90 * GIB, Age::Days(3))
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
                total_bytes: Some(500 * GIB),
                available_bytes: Some(120 * GIB),
                is_scannable: true,
            }],
            formats: vec![],
            include_absolute_paths: true,
            roots: Vec::new(),
            include_hashes: false,
            machine_label: Some("workstation-01".into()),
        }
    }

    #[test]
    fn report_has_the_expected_sections() {
        let md = render(&sample());
        for heading in [
            "# Diskus storage report",
            "## At a glance",
            "### Findings by severity",
            "### Reclaimable by category",
            "## Top findings",
        ] {
            assert!(md.contains(heading), "missing section: {heading}");
        }
    }

    #[test]
    fn report_is_valid_enough_markdown_that_tables_have_matching_columns() {
        let md = render(&sample());
        for line in md.lines().filter(|l| l.starts_with('|')) {
            let cells = line.matches('|').count();
            assert!(cells >= 3, "suspicious table row: {line}");
            // Escaped pipes must not be counted as delimiters.
            assert!(
                !line.contains("||"),
                "empty cell may indicate a broken escape: {line}"
            );
        }
    }

    #[test]
    fn pipes_in_paths_do_not_break_the_table() {
        let mut request = sample();
        request.findings[0].path = std::path::PathBuf::from("/Users/jdoe/weird|name");
        let md = render(&request);
        assert!(md.contains("weird\\|name"), "the pipe must be escaped");
    }

    #[test]
    fn findings_are_grouped_by_safety() {
        let md = render(&sample());
        assert!(md.contains("## Safe to delete now"), "{md}");
        assert!(
            md.contains("## Deleting these loses data") || md.contains("## Review first"),
            "at least one action group"
        );
    }

    #[test]
    fn totals_appear_in_human_form() {
        let md = render(&sample());
        assert!(
            md.contains(&util::human_bytes(request_summary_bytes())),
            "the scanned total must be human-readable"
        );
    }

    fn request_summary_bytes() -> u64 {
        90 * GIB + 300 * MIB
    }

    #[test]
    fn privacy_note_closes_the_report() {
        let md = render(&sample());
        let tail = &md[md.len().saturating_sub(800)..];
        assert!(
            tail.contains("metadata only"),
            "privacy note must be at the end"
        );
        assert!(tail.contains("uploaded nothing"));
    }

    #[test]
    fn empty_results_still_produce_a_readable_report() {
        let mut request = sample();
        request.findings = vec![];
        let md = render(&request);
        assert!(md.contains("# Diskus storage report"));
        assert!(
            !md.contains("## Top findings"),
            "no findings section when empty"
        );
    }

    #[test]
    fn long_lists_are_truncated_with_an_ellipsis_note() {
        let mut request = sample();
        request.findings = (0..80)
            .map(|i| {
                crate::detect::make_finding(
                    Detector::Duplicates,
                    std::path::Path::new(&format!("/data/file{i}.bin")),
                    200 * MIB,
                    100 * MIB,
                    0.9,
                    Safety::DataLoss,
                    format!("Duplicate set {i}"),
                    "Remove extras".into(),
                    serde_json::json!({ "fileSize": 200 * MIB, "copies": 2 }),
                )
            })
            .collect();
        let md = render(&request);
        assert!(md.contains("and 30 more"), "truncation must be disclosed");
    }
}
