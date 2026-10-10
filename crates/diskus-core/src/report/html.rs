//! Self-contained HTML report.
//!
//! The requirement that shapes this whole module: **one file, zero external
//! assets, zero network requests.** A storage report gets emailed to IT, opened
//! from a network share, and archived for years. Anything that loads a font,
//! stylesheet or script from a CDN turns into a broken page the moment it is
//! opened offline or on a locked-down network. So:
//!
//! * No CDN links. No web fonts. System font stacks only.
//! * All CSS and JS inline.
//! * The treemap is rendered as inline SVG, precomputed on this side, so the
//!   browser does no layout work to draw it.
//!
//! It still has to feel like part of the product, so it reuses the same colour
//! ramp, spacing scale and easing curves as the app itself.

use crate::config::ExportRequest;
use crate::model::{Detector, Finding, Severity};
use crate::report::{
    COUNTING_NOTE, PRIVACY_NOTE, display_path, header_lines, html_escape, machine_label,
    ordered_findings,
};
use crate::util;
use std::fmt::Write as _;

/// Treemap width in SVG user units.
const MAP_W: u32 = 1000;
/// Treemap height in SVG user units.
const MAP_H: u32 = 560;
/// Maximum rectangles drawn. Beyond this the map is unreadable noise.
const MAX_RECTS: usize = 160;

/// Categorical colour ramp, matching the app's `--cat-*` tokens.
const RAMP: [&str; 12] = [
    "#6E8BFF", "#34D399", "#FBBF24", "#F87171", "#C084FC", "#22D3EE", "#FB923C", "#A3E635",
    "#F472B6", "#818CF8", "#2DD4BF", "#EAB308",
];

/// Severity colours, matching the app's `--sev-*` tokens.
const SEVERITY_COLOR: [(&str, &str); 5] = [
    ("critical", "#FF4D6D"),
    ("high", "#FF8A3D"),
    ("medium", "#FBBF24"),
    ("low", "#4ADE80"),
    ("info", "#60A5FA"),
];

/// Render the complete HTML report.
#[must_use]
pub fn render(request: &ExportRequest) -> String {
    let s = &request.summary;
    let findings = ordered_findings(request);

    let mut out = String::with_capacity(48 * 1024);
    let _ = writeln!(out, "<!DOCTYPE html>");
    let _ = writeln!(out, r#"<html lang="en"><head>"#);
    let _ = writeln!(
        out,
        r#"<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">"#
    );
    let _ = writeln!(
        out,
        "<title>Diskus report — {}</title>",
        html_escape(&machine_label(request))
    );
    let _ = writeln!(out, "<style>{}</style>", css());
    let _ = writeln!(out, "</head><body>");

    // ---- Header ------------------------------------------------------------
    let _ = writeln!(
        out,
        r#"<header class="hero"><div class="hero-inner"><p class="eyebrow">Diskus storage report</p><h1>{}</h1><p class="sub">{}</p></div></header>"#,
        html_escape(&machine_label(request)),
        html_escape(&util::fmt_rfc3339(Some(util::now())))
    );

    out.push_str("<main>");

    // ---- KPI row -----------------------------------------------------------
    out.push_str("<section class=\"kpis\">");
    for (label, value, accent) in [
        (
            "Storage scanned",
            util::human_bytes(s.total_scanned),
            "var(--accent)",
        ),
        (
            "Reclaimable",
            util::human_bytes(s.total_reclaimable),
            "var(--sev-high)",
        ),
        (
            "Findings",
            s.counts_by_severity.total().to_string(),
            "var(--cat-6)",
        ),
        (
            "Analysis time",
            util::human_duration(s.elapsed_ms),
            "var(--cat-4)",
        ),
    ] {
        let _ = write!(
            out,
            r#"<div class="kpi" style="--accent:{accent}"><p class="kpi-label">{label}</p><p class="kpi-value">{value}</p></div>"#
        );
    }
    out.push_str("</section>");

    // ---- Treemap + severity ------------------------------------------------
    out.push_str("<section class=\"split\">");
    out.push_str("<div class=\"panel\"><h2>Largest reclaimable items</h2>");
    out.push_str(&treemap(&findings));
    out.push_str("</div>");
    out.push_str("<div class=\"panel\"><h2>By severity</h2>");
    out.push_str(&severity_chart(&s.counts_by_severity));
    out.push_str("</div>");
    out.push_str("</section>");

    // ---- Reclaimable by category -------------------------------------------
    if !s.counts_by_detector.is_empty() {
        out.push_str("<section class=\"panel\"><h2>Reclaimable by category</h2>");
        out.push_str(&category_chart(&s.counts_by_detector));
        out.push_str("</section>");
    }

    // ---- Volumes ------------------------------------------------------------
    if !request.volumes.is_empty() {
        out.push_str("<section class=\"panel\"><h2>Volumes</h2><table><thead><tr><th>Volume</th><th>Mounted at</th><th class=\"num\">Used</th><th class=\"num\">Free</th></tr></thead><tbody>");
        for v in &request.volumes {
            let used = v
                .total_bytes
                .unwrap_or(0)
                .saturating_sub(v.available_bytes.unwrap_or(0));
            let _ = write!(
                out,
                "<tr><td>{}</td><td><code>{}</code></td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                html_escape(&v.name),
                html_escape(&v.mount_point.to_string_lossy()),
                util::human_bytes(used),
                util::human_bytes(v.available_bytes.unwrap_or(0))
            );
        }
        out.push_str("</tbody></table></section>");
    }

    // ---- Findings table -----------------------------------------------------
    if !findings.is_empty() {
        out.push_str("<section class=\"panel\"><h2>Findings</h2><div class=\"filters\">");
        for (id, label) in Severity::ALL
            .iter()
            .map(|x| (x.id(), x.label()))
            .chain(std::iter::once(("all", "All")))
        {
            out.push_str(&format!(
                r#"<button class="chip" data-sev="{id}" onclick="filterSev('{id}')">{label}</button>"#
            ));
        }
        out.push_str("</div><table id=\"findings\"><thead><tr>");
        for h in [
            "Severity",
            "Category",
            "Reclaimable",
            "Size",
            "Finding",
            "Location",
            "Action",
        ] {
            out.push_str(&format!("<th>{h}</th>"));
        }
        out.push_str("</tr></thead><tbody>");
        for f in findings.iter().take(500) {
            out.push_str(&finding_row(request, f));
        }
        out.push_str("</tbody></table>");
        if findings.len() > 500 {
            let _ = write!(
                out,
                r#"<p class="note">Showing the first 500 of {} findings. Export the CSV or JSON report for the complete set.</p>"#,
                findings.len()
            );
        }
        out.push_str("</section>");
    }

    // ---- Footer -------------------------------------------------------------
    out.push_str("<footer>");
    for (k, v) in header_lines(request) {
        let _ = write!(
            out,
            r#"<div><span>{}</span><strong>{}</strong></div>"#,
            html_escape(&k),
            html_escape(&v)
        );
    }
    let _ = write!(out, r#"<p class="note">{}</p>"#, html_escape(PRIVACY_NOTE));
    let _ = write!(out, r#"<p class="note">{}</p>"#, html_escape(COUNTING_NOTE));
    out.push_str("</footer>");

    out.push_str("</main>");
    out.push_str(&script());
    out.push_str("</body></html>");
    out
}

/// One table row for a finding.
fn finding_row(request: &ExportRequest, f: &Finding) -> String {
    let color = SEVERITY_COLOR
        .iter()
        .find(|(id, _)| *id == f.severity.id())
        .map_or("#60A5FA", |(_, c)| *c);

    let mut row = String::with_capacity(512);
    let _ = write!(row, r#"<tr data-sev="{}">"#, f.severity.id());
    let _ = write!(
        row,
        r#"<td><span class="dot" style="background:{color}"></span>{}</td>"#,
        html_escape(f.severity.label())
    );
    let _ = write!(row, "<td>{}</td>", html_escape(f.detector.label()));
    let _ = write!(
        row,
        r#"<td class="num strong">{}</td>"#,
        html_escape(&util::human_bytes(f.reclaimable))
    );
    let _ = write!(
        row,
        r#"<td class="num muted">{}</td>"#,
        html_escape(&util::human_bytes(f.size))
    );
    let _ = write!(row, "<td>{}</td>", html_escape(&f.title));

    // Title attribute carries the full path, so the truncated cell still gives
    // the reader the whole thing on hover.
    let full = display_path(request, &f.path);
    let _ = write!(
        row,
        r#"<td><code class="path" title="{}">{}</code></td>"#,
        html_escape(&full),
        html_escape(&util::mid_truncate(&f.path, 4))
    );
    let _ = write!(
        row,
        "<td>{}</td>",
        html_escape(&crate::report::redact_text(request, &f.recommendation))
    );
    row.push_str("</tr>");
    row
}

/// A squarified treemap of the largest reclaimable findings.
fn treemap(findings: &[&Finding]) -> String {
    let items: Vec<(&Finding, f64)> = findings
        .iter()
        .take(MAX_RECTS)
        .filter(|f| f.reclaimable > 0)
        .map(|f| (*f, f.reclaimable as f64))
        .collect();

    if items.is_empty() {
        return r#"<p class="empty">Nothing reclaimable was found.</p>"#.to_string();
    }

    let total: f64 = items.iter().map(|(_, v)| *v).sum();
    // Squarified layout, computed here so the browser only paints rectangles.
    let mut rects = squarify(
        &items
            .iter()
            .map(|(f, v)| ((*v / total * MAP_W as f64 * MAP_H as f64) as u32, *f))
            .collect::<Vec<_>>(),
        0.0,
        0.0,
        MAP_W as f64,
        MAP_H as f64,
    );
    rects.truncate(MAX_RECTS);

    let mut svg = String::with_capacity(rects.len() * 220);
    let _ = write!(
        svg,
        r#"<svg class="treemap" viewBox="0 0 {MAP_W} {MAP_H}" role="img" aria-label="Treemap of reclaimable space">"#
    );

    for (i, (x, y, w, h, f)) in rects.iter().enumerate() {
        let color = RAMP[f.detector.color_index() % RAMP.len()];
        // Skip slivers: a 1px rectangle is noise, not information.
        if *w < 3.0 || *h < 3.0 {
            continue;
        }
        let label = if *w > 90.0 && *h > 30.0 {
            format!(
                r#"<text x="{:.1}" y="{:.1}" class="tm-label">{}</text><text x="{:.1}" y="{:.1}" class="tm-size">{}</text>"#,
                x + 10.0,
                y + 22.0,
                html_escape(&util::mid_truncate(&f.path, 3)),
                x + 10.0,
                y + 42.0,
                html_escape(&util::human_bytes(f.reclaimable))
            )
        } else {
            String::new()
        };

        let _ = write!(
            svg,
            r#"<g class="rect" style="animation-delay:{}ms"><title>{} — {} ({} from {})</title><rect x="{:.1}" y="{:.1}" width="{:.1}" height="{:.1}" fill="{}" rx="3"/>{}</g>"#,
            i * 6,
            html_escape(&f.title),
            html_escape(&util::human_bytes(f.reclaimable)),
            html_escape(f.severity.label()),
            html_escape(f.detector.label()),
            x,
            y,
            w.max(0.5),
            h.max(0.5),
            color,
            label
        );
    }

    svg.push_str("</svg>");
    svg.push_str(r#"<p class="legend-note">Colour shows which detector found the item. Hover for details.</p>"#);
    svg
}

/// Squarified treemap layout.
///
/// Places items in rows along the shorter side, growing each row until adding
/// the next item would make the aspect ratio worse. Produces rectangles close to
/// square, which is what makes a treemap readable.
fn squarify<'a>(
    entries: &[(u32, &'a Finding)],
    x: f64,
    y: f64,
    w: f64,
    h: f64,
) -> Vec<(f64, f64, f64, f64, &'a Finding)> {
    let mut out = Vec::with_capacity(entries.len());
    if entries.is_empty() || w <= 0.0 || h <= 0.0 {
        return out;
    }

    // Scale area units into the available rectangle.
    let area_total: f64 = entries.iter().map(|(a, _)| *a as f64).sum();
    if area_total <= 0.0 {
        return out;
    }
    let scale = (w * h) / area_total;

    let mut cursor_x = x;
    let mut cursor_y = y;
    let mut remaining_w = w;
    let mut remaining_h = h;
    let mut index = 0;

    while index < entries.len() {
        let shorter_is_width = remaining_w <= remaining_h;
        let short_side = remaining_w.min(remaining_h);

        // Accumulate items into a row until the next one would worsen the worst
        // aspect ratio.
        let mut row: Vec<(f64, f64, &Finding)> = Vec::new(); // (area, thickness, finding)
        let mut row_area = 0.0;
        let mut best_ratio = f64::INFINITY;

        while index < entries.len() {
            let area = f64::from(entries[index].0) * scale;
            let candidate_area = row_area + area;
            // Clamp so a single dominant item can never produce a row thicker
            // than the short side, which would overflow the box.
            let thickness = (candidate_area / short_side).min(short_side);

            let ratio = row
                .iter()
                .map(|(a, _, _)| worst_ratio(*a / thickness, thickness, short_side))
                .chain(std::iter::once(worst_ratio(
                    area / thickness,
                    thickness,
                    short_side,
                )))
                .fold(f64::INFINITY, f64::min);

            if !row.is_empty() && ratio > best_ratio {
                break;
            }
            row.push((area, thickness, entries[index].1));
            row_area = candidate_area;
            best_ratio = ratio;
            index += 1;
        }

        if row.is_empty() {
            break;
        }

        // Lay the row out along the short side, advancing a local offset.
        //
        // The cursor must not be mutated inside this loop. Doing so leaves it
        // pointing at the *end* of the row, and the next row would then be
        // positioned past the bottom (or right) of the box, silently discarding
        // every remaining item and leaving most of the treemap empty.
        let thickness = row[0].1;
        let mut offset = 0.0;
        for (area, _, finding) in &row {
            let length = if *area > 0.0 { area / thickness } else { 0.0 };
            let (rx, ry, rw, rh) = if shorter_is_width {
                (cursor_x, cursor_y + offset, thickness, length)
            } else {
                (cursor_x + offset, cursor_y, length, thickness)
            };
            out.push((rx, ry, rw, rh, finding));
            offset += length;
        }

        // Commit the row: it consumed `thickness` of the short side, and the
        // full length of the long side.
        if shorter_is_width {
            cursor_x += thickness;
            remaining_w -= thickness;
        } else {
            cursor_y += thickness;
            remaining_h -= thickness;
        }

        if remaining_w <= 0.5 || remaining_h <= 0.5 {
            break;
        }
    }

    out
}

/// Worst aspect ratio in a row — lower is squarer, better.
fn worst_ratio(a: f64, b: f64, c: f64) -> f64 {
    let max = a.max(b);
    let min = a.min(b);
    if min <= 0.0 || c <= 0.0 {
        return f64::INFINITY;
    }
    (max * c * c) / (min.powi(2))
}

/// Severity breakdown as a horizontal bar chart.
fn severity_chart(counts: &crate::model::SeverityCounts) -> String {
    let max = Severity::ALL
        .iter()
        .map(|s| counts.get(*s))
        .max()
        .unwrap_or(0);
    if max == 0 {
        return r#"<p class="empty">No findings.</p>"#.to_string();
    }

    let mut out = String::with_capacity(1024);
    out.push_str("<div class=\"bars\">");
    for severity in Severity::ALL {
        let count = counts.get(severity);
        let pct = count as f64 / max as f64 * 100.0;
        let color = SEVERITY_COLOR
            .iter()
            .find(|(id, _)| *id == severity.id())
            .map_or("#60A5FA", |(_, c)| *c);
        let _ = write!(
            out,
            r#"<div class="bar-row"><span class="bar-label">{label}</span><div class="bar-track"><div class="bar-fill" style="width:{pct:.1}%;background:{color}"></div></div><span class="bar-value">{count}</span></div>"#,
            label = severity.label(),
            pct = pct,
            color = color,
            count = count
        );
    }
    out.push_str("</div>");
    out
}

/// Reclaimable bytes per detector as horizontal bars.
fn category_chart(rollups: &[crate::model::DetectorRollup]) -> String {
    let max = rollups.iter().map(|r| r.bytes).max().unwrap_or(1).max(1);

    let mut out = String::with_capacity(2048);
    out.push_str("<div class=\"bars\">");
    for r in rollups {
        let pct = r.bytes as f64 / max as f64 * 100.0;
        let color = RAMP[r.detector.color_index() % RAMP.len()];
        let _ = write!(
            out,
            r#"<div class="bar-row"><span class="bar-label">{label}<small>{count} finding(s)</small></span><div class="bar-track"><div class="bar-fill" style="width:{pct:.1}%;background:{color}"></div></div><span class="bar-value">{human}</span></div>"#,
            label = html_escape(r.detector.label()),
            count = r.finding_count,
            pct = pct,
            color = color,
            human = html_escape(&util::human_bytes(r.bytes))
        );
    }
    out.push_str("</div></div>");
    out
}

/// The inline stylesheet. Everything the report needs, nothing it does not.
fn css() -> &'static str {
    r#"
:root{
  --bg-base:#07090F; --bg-sunken:#04060A; --bg-surface:#0E121C; --bg-raised:#151A27;
  --bg-overlay:#1C2233; --border:rgba(255,255,255,.08); --border-strong:rgba(255,255,255,.16);
  --text:#EEF2FA; --text-2:#98A2B8; --text-3:#626C82;
  --accent:#6E8BFF; --radius:14px; --radius-sm:8px;
  --ease:cubic-bezier(.16,1,.3,1);
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  --mono:ui-monospace,"SF Mono","Cascadia Code",Menlo,monospace;
}
@media (prefers-color-scheme:light){
  :root{ --bg-base:#F7F8FB; --bg-sunken:#EEF0F5; --bg-surface:#FFFFFF; --bg-raised:#F2F4F9;
         --border:rgba(16,20,30,.10); --border-strong:rgba(16,20,30,.18);
         --text:#101420; --text-2:#4A5468; --text-3:#767F92; }
}
*{box-sizing:border-box}
html{ -webkit-text-size-adjust:100% }
body{margin:0;background:var(--bg-base);color:var(--text);font-family:var(--font);font-size:15px;line-height:1.55;
     font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
main{max-width:1240px;margin:0 auto;padding:0 28px 80px}

.hero{border-bottom:1px solid var(--border);background:linear-gradient(180deg,var(--bg-surface),var(--bg-base))}
.hero-inner{max-width:1240px;margin:0 auto;padding:44px 28px 34px}
.eyebrow{margin:0 0 6px;font-size:11px;letter-spacing:.13em;text-transform:uppercase;color:var(--accent);font-weight:600}
h1{margin:0;font-size:34px;letter-spacing:-.02em;font-weight:650}
.sub{margin:8px 0 0;color:var(--text-2);font-family:var(--mono);font-size:12.5px}

h2{margin:0 0 16px;font-size:13px;letter-spacing:.09em;text-transform:uppercase;color:var(--text-3);font-weight:650}
.panel{background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);
       padding:24px;margin-top:20px;animation:rise .42s var(--ease) both}
.panel:nth-of-type(2){animation-delay:.05s}.panel:nth-of-type(3){animation-delay:.1s}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}

.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:16px;margin-top:20px}
.kpi{position:relative;background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);
     padding:20px 22px;overflow:hidden}
.kpi::before{content:"";position:absolute;inset:0 auto 0 0;width:3px;background:var(--accent)}
.kpi-label{margin:0 0 6px;font-size:11.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--text-3);font-weight:600}
.kpi-value{margin:0;font-size:30px;font-weight:640;letter-spacing:-.02em}

.split{display:grid;grid-template-columns:minmax(0,2.1fr) minmax(0,1fr);gap:20px;margin-top:20px;align-items:start}
@media (max-width:900px){.split{grid-template-columns:1fr}}

.treemap{width:100%;height:auto;display:block;border-radius:var(--radius-sm)}
.rect{opacity:0;animation:fadein .45s var(--ease) forwards}
@keyframes fadein{to{opacity:1}}
.rect rect{transition:filter .16s var(--ease),transform .16s var(--ease);transform-origin:center}
.rect:hover rect{filter:brightness(1.22)}
.tm-label{fill:rgba(255,255,255,.95);font:600 12px var(--font);pointer-events:none}
.tm-size{fill:rgba(255,255,255,.72);font:500 11px var(--mono);pointer-events:none}
.legend-note{margin:12px 0 0;font-size:12px;color:var(--text-3)}

.bars{display:flex;flex-direction:column;gap:14px}
.bar-row{display:grid;grid-template-columns:150px 1fr auto;align-items:center;gap:14px}
.bar-label{font-size:13px;font-weight:550;display:flex;flex-direction:column}
.bar-label small{font-size:11px;color:var(--text-3);font-weight:400}
.bar-track{height:9px;background:var(--bg-raised);border-radius:99px;overflow:hidden}
.bar-fill{height:100%;border-radius:99px;width:0;transition:width .55s var(--ease)}
.bar-value{font-family:var(--mono);font-size:12.5px;color:var(--text-2);min-width:62px;text-align:right}
@media (max-width:560px){.bar-row{grid-template-columns:110px 1fr auto}}

.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.chip{font:inherit;font-size:12.5px;padding:6px 13px;border-radius:99px;cursor:pointer;
      border:1px solid var(--border);background:var(--bg-raised);color:var(--text-2);
      transition:background .14s var(--ease),color .14s var(--ease),border-color .14s var(--ease)}
.chip:hover{background:var(--bg-overlay);color:var(--text)}
.chip[aria-pressed="true"]{background:var(--accent);border-color:var(--accent);color:#fff}

table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;padding:10px 12px;font-size:11px;letter-spacing:.08em;text-transform:uppercase;
   color:var(--text-3);border-bottom:1px solid var(--border-strong);font-weight:650;white-space:nowrap}
td{padding:11px 12px;border-bottom:1px solid var(--border);vertical-align:top}
tbody tr{transition:background .12s var(--ease)}
tbody tr:hover{background:var(--bg-raised)}
.num{text-align:right;font-family:var(--mono);white-space:nowrap}
.strong{font-weight:600}
.muted{color:var(--text-3)}
code{font-family:var(--mono);font-size:12.5px}
.path{display:inline-block;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:9px;vertical-align:middle}
.empty{color:var(--text-3);font-style:italic;margin:0}
tr[hidden]{display:none}

footer{margin-top:36px;padding-top:24px;border-top:1px solid var(--border);display:grid;
       grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px 24px}
footer div{display:flex;flex-direction:column;gap:2px}
footer span{font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--text-3)}
footer strong{font-size:13px;font-weight:550}
.note{margin:18px 0 0;grid-column:1/-1;font-size:12.5px;color:var(--text-3);line-height:1.6}

@media print{
  :root{--bg-base:#fff;--bg-surface:#fff;--bg-raised:#f4f5f8;--text:#000;--text-2:#333;--text-3:#666;--border:#ddd}
  body{background:#fff;color:#000}
  .panel,.kpi{break-inside:avoid;border-color:#ddd}
  .filters{display:none}
  .rect{opacity:1!important}
}
"#
}

/// Inline script: severity filtering and sortable columns. No dependencies.
fn script() -> String {
    r#"<script>
(function(){
  var current='all';
  function filterSev(sev){
    current = (current===sev) ? 'all' : sev;
    document.querySelectorAll('#findings tbody tr').forEach(function(row){
      row.hidden = current!=='all' && row.dataset.sev!==current;
    });
    document.querySelectorAll('.chip').forEach(function(chip){
      chip.setAttribute('aria-pressed', String(chip.dataset.sev===current));
    });
  }
  window.filterSev = filterSev;

  document.querySelectorAll('#findings thead th').forEach(function(th, index){
    th.style.cursor='pointer';
    th.addEventListener('click', function(){
      var body = th.closest('table').tBodies[0];
      var rows = Array.prototype.slice.call(body.rows);
      var dir = th.dataset.dir === 'asc' ? -1 : 1;
      th.dataset.dir = dir === 1 ? 'asc' : 'desc';
      rows.sort(function(a,b){
        var x = a.cells[index], y = b.cells[index];
        var xv = parseFloat(x.dataset.num || x.textContent.replace(/[^0-9.]/g,''));
        var yv = parseFloat(y.dataset.num || y.textContent.replace(/[^0-9.]/g,''));
        if (!isNaN(xv) && !isNaN(yv) && xv !== yv) return (xv-yv)*dir;
        return x.textContent.localeCompare(y.textContent)*dir;
      });
      rows.forEach(function(r){ body.appendChild(r); });
    });
  });
})();
</script>"#
        .to_string()
}

/// The detector colour index, re-exported so the report and the app agree.
#[must_use]
pub fn detector_color(detector: Detector) -> &'static str {
    RAMP[detector.color_index() % RAMP.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExportRequest;
    use crate::detect::testing::{Age, ScanBuilder};
    use crate::model::{GIB, MIB, Safety, Severity, SeverityCounts, Volume};

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
            machine_label: Some("box".into()),
        }
    }

    #[test]
    fn report_is_a_complete_html_document() {
        let html = render(&sample());
        assert!(html.starts_with("<!DOCTYPE html>"), "needs a doctype");
        assert!(html.contains("</html>"), "must be closed");
        assert!(html.contains("<title>Diskus report"));
    }

    #[test]
    fn report_makes_no_network_requests() {
        let html = render(&sample());
        for pattern in ["http://", "https://", "//cdn", "@import"] {
            assert!(
                !html.contains(pattern),
                "report must be fully offline, found: {pattern}"
            );
        }
    }

    #[test]
    fn all_assets_are_inline() {
        let html = render(&sample());
        assert!(html.contains("<style>"), "CSS must be inline");
        assert!(html.contains("<script>"), "JS must be inline");
        assert!(!html.contains("<link "), "no external stylesheets");
        assert!(!html.contains(" src="), "no external scripts");
    }

    #[test]
    fn hostile_paths_are_escaped() {
        let mut request = sample();
        request.findings[0].path = std::path::PathBuf::from("/x/<script>alert(1)</script>");
        request.findings[0].title = "<img src=x onerror=alert(1)>".into();
        let html = render(&request);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn squarified_layout_covers_the_available_area_without_overflow() {
        let entries: Vec<(u32, &Finding)> = Vec::new();
        let rects = squarify(&entries, 0.0, 0.0, 100.0, 100.0);
        assert!(rects.is_empty(), "nothing in, nothing out");

        let request = sample();
        let items: Vec<&Finding> = ordered_findings(&request);
        let total: f64 = items.iter().map(|f| f.reclaimable as f64).sum();
        if total > 0.0 {
            let entries: Vec<(u32, &Finding)> = items
                .iter()
                .map(|f| ((f.reclaimable as f64 / total * 100.0 * 100.0) as u32, *f))
                .collect();
            let rects = squarify(&entries, 0.0, 0.0, 100.0, 100.0);
            let area: f64 = rects.iter().map(|(_, _, w, h, _)| w * h).sum();
            assert!(area <= 10_100.0, "layout overflows the box: {area}");
            for (_, _, w, h, _) in &rects {
                assert!(w.is_finite() && h.is_finite(), "no NaN dimensions");
                assert!(*w >= 0.0 && *h >= 0.0, "no negative dimensions");
            }
        }
    }

    #[test]
    fn empty_findings_still_render_a_readable_page() {
        let mut request = sample();
        request.findings = vec![];
        let html = render(&request);
        assert!(html.contains("</html>"));
        assert!(!html.contains("<section class=\"panel\"><h2>Findings</h2>"));
    }

    #[test]
    fn severity_chart_handles_zero_without_dividing_by_zero() {
        let counts = SeverityCounts::default();
        let svg = severity_chart(&counts);
        assert!(svg.contains("No findings"), "{svg}");
    }

    #[test]
    fn severity_colours_match_the_app_tokens() {
        assert_eq!(SEVERITY_COLOR[0].0, Severity::Critical.id());
        assert_eq!(SEVERITY_COLOR[4].0, Severity::Info.id());
    }

    #[test]
    fn filter_script_is_embedded_and_self_contained() {
        let html = render(&sample());
        assert!(html.contains("function filterSev"));
        assert!(html.contains("data-sev"));
    }

    #[test]
    fn print_stylesheet_is_included() {
        assert!(css().contains("@media print"), "reports get printed");
    }

    #[test]
    fn reduced_motion_is_respected() {
        assert!(css().contains("prefers-reduced-motion"));
    }

    #[test]
    fn every_detector_gets_a_distinct_stable_colour() {
        let colours: Vec<&str> = Detector::ALL.iter().map(|d| detector_color(*d)).collect();
        let unique: std::collections::HashSet<&&str> = colours.iter().collect();
        assert_eq!(
            unique.len(),
            colours.len(),
            "colours must differ: {colours:?}"
        );
    }

    #[test]
    fn safety_and_severity_survive_into_the_row_markup() {
        let mut request = sample();
        request.findings = vec![crate::detect::make_finding(
            Detector::Duplicates,
            std::path::Path::new("/data/a.bin"),
            4 * GIB,
            3 * GIB,
            1.0,
            Safety::DataLoss,
            "3 identical copies".into(),
            "Delete two.".into(),
            serde_json::json!({}),
        )];
        let html = render(&request);
        assert!(html.contains("data-sev=\"critical\""), "3 GiB is critical");
        assert!(html.contains("Delete two."));
        assert!(html.contains("3.00 GB"));
    }
}

#[cfg(test)]
mod squarify_tests {
    use super::*;
    use crate::model::{Detector, Safety, Severity};

    fn f(size: u64) -> Finding {
        Finding {
            id: "x".into(),
            detector: Detector::Duplicates,
            severity: Severity::from_bytes(size),
            safety: Safety::DataLoss,
            title: "t".into(),
            path: "/x".into(),
            related_paths: vec![],
            size,
            reclaimable: size,
            confidence: 1.0,
            recommendation: "r".into(),
            detail: serde_json::json!({}),
            detected_at: crate::util::now(),
        }
    }

    /// Fraction of the box the layout actually covers.
    fn coverage(sizes: &[u64]) -> f64 {
        let items: Vec<Finding> = sizes.iter().map(|&n| f(n)).collect();
        let total: f64 = sizes.iter().map(|&n| n as f64).sum();
        let entries: Vec<(u32, &Finding)> = sizes
            .iter()
            .zip(items.iter())
            .map(|(n, item)| {
                (
                    (*n as f64 / total * MAP_W as f64 * MAP_H as f64) as u32,
                    item,
                )
            })
            .collect();

        let rects = squarify(&entries, 0.0, 0.0, MAP_W as f64, MAP_H as f64);
        let area: f64 = rects.iter().map(|(_, _, w, h, _)| (w * h).max(0.0)).sum();
        area / (MAP_W as f64 * MAP_H as f64)
    }

    #[test]
    fn three_items_fill_the_box() {
        let c = coverage(&[2400, 900, 576]);
        assert!(
            c > 0.99,
            "layout must fill the treemap; it only covered {:.1}%",
            c * 100.0
        );
    }

    #[test]
    fn many_items_fill_the_box() {
        let sizes: Vec<u64> = (1..=40).map(|i| 100 + i * 37).collect();
        let c = coverage(&sizes);
        assert!(
            c > 0.99,
            "40 items left {:.1}% of the box empty",
            (1.0 - c) * 100.0
        );
    }

    #[test]
    fn one_dominant_item_still_leaves_room_for_the_rest() {
        let c = coverage(&[100_000, 100, 50, 20]);
        assert!(
            c > 0.99,
            "a dominant item must not swallow the layout; covered {:.1}%",
            c * 100.0
        );
    }
}
