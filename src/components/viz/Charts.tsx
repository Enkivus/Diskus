/** Chart components: donut, horizontal bars and the size-bar table row.
 *
 * All SVG, all animated, no chart library. Every value is driven by an explicit
 * `AnimatedNumber` or a CSS width transition rather than a layout animation, so
 * nothing reflows while data is still arriving.
 */

import clsx from "clsx";
import { useEffect, useState, type ReactNode } from "react";

import { formatBytes } from "../../lib/format";
import {
  CATEGORICAL,
  SEVERITIES,
  SEVERITY_COLORS,
  SEVERITY_LABELS,
  type Severity,
} from "../../lib/types";
import { AnimatedNumber } from "../primitives";

// ─── Donut ────────────────────────────────────────────────────────────────

export interface DonutSegment {
  /** Segment label. */
  label: string;
  /** Numeric value. */
  value: number;
  /** Fill colour. */
  color: string;
}

/**
 * A donut chart with animated sweep-in.
 *
 * Segments animate by animating `stroke-dashoffset` rather than rotating the
 * whole chart — it is a compositor-friendly property and avoids the sub-pixel
 * jitter you get animating SVG transforms.
 */
export function Donut({
  segments,
  size = 168,
  thickness = 22,
  centerLabel,
  centerValue,
}: {
  segments: DonutSegment[];
  size?: number;
  thickness?: number;
  centerLabel?: string;
  centerValue?: number;
}) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  const [swept, setSwept] = useState(0);

  // Sweep in on mount, and again whenever the total changes, so a rescanning
  // dashboard re-animates rather than sitting static.
  useEffect(() => {
    setSwept(0);
    const id = window.setTimeout(() => setSwept(1), 60);
    return () => window.clearTimeout(id);
  }, [total]);

  if (total === 0) {
    return (
      <div
        style={{
          height: size,
          display: "grid",
          placeItems: "center",
          color: "var(--text-tertiary)",
          fontSize: "var(--fs-sm)",
        }}
      >
        Nothing found
      </div>
    );
  }

  let offset = 0;

  return (
    <div className="row" style={{ gap: 24, flexWrap: "wrap" }}>
      <div style={{ position: "relative", width: size, height: size, flex: "none" }}>
        <svg width={size} height={size} role="img" aria-label="Findings by severity">
          <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
            {segments.map((segment, i) => {
              const fraction = segment.value / total;
              const length = fraction * circumference;
              const dash = `${length * swept} ${circumference}`;
              const dashOffset = -offset;
              offset += length;
              return (
                <circle
                  key={segment.label}
                  cx={size / 2}
                  cy={size / 2}
                  r={radius}
                  fill="none"
                  stroke={segment.color}
                  strokeWidth={thickness}
                  strokeDasharray={dash}
                  strokeDashoffset={dashOffset}
                  style={{
                    transition: `stroke-dasharray 520ms var(--ease-out) ${i * 40}ms`,
                  }}
                />
              );
            })}
          </g>
        </svg>
        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "grid",
            placeItems: "center",
            textAlign: "center",
            pointerEvents: "none",
          }}
        >
          <div>
            <div
              className="num"
              style={{ fontSize: "var(--fs-xl)", fontWeight: 640 }}
            >
              <AnimatedNumber value={centerValue ?? total} />
            </div>
            {centerLabel && (
              <div className="muted" style={{ fontSize: "var(--fs-xs)" }}>
                {centerLabel}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="col" style={{ gap: 8, flex: 1, minWidth: 160 }}>
        {segments
          .filter((s) => s.value > 0)
          .map((segment) => (
            <div key={segment.label} className="row" style={{ gap: 9 }}>
              <span
                className="badge-dot"
                style={{ background: segment.color, flex: "none" }}
              />
              <span
                style={{
                  fontSize: "var(--fs-sm)",
                  color: "var(--text-secondary)",
                  flex: 1,
                }}
              >
                {segment.label}
              </span>
              <span className="num" style={{ fontSize: "var(--fs-sm)" }}>
                <AnimatedNumber value={segment.value} />
              </span>
            </div>
          ))}
      </div>
    </div>
  );
}

/** A donut of findings by severity. */
export function SeverityDonut({
  counts,
  total,
}: {
  counts: Record<Severity, number>;
  total: number;
}) {
  return (
    <Donut
      centerValue={total}
      centerLabel="findings"
      segments={SEVERITIES.map((severity) => ({
        label: SEVERITY_LABELS[severity],
        value: counts[severity] ?? 0,
        color: SEVERITY_COLORS[severity],
      }))}
    />
  );
}

// ─── Horizontal bars ──────────────────────────────────────────────────────

export interface BarRow {
  /** Row label. */
  label: string;
  /** Optional secondary line. */
  sublabel?: string;
  /** Numeric value driving the bar width. */
  value: number;
  /** Optional explicit colour; falls back to the ramp. */
  color?: string;
  /** Right-hand text. */
  display: string;
}

/**
 * Horizontal bars that grow from zero on mount.
 *
 * Width is animated via CSS transition on an inline style rather than a keyframe,
 * so a value update re-animates smoothly from wherever the bar currently is.
 */
export function BarList({ rows, emptyText }: { rows: BarRow[]; emptyText?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.value));

  if (rows.length === 0) {
    return (
      <div className="muted" style={{ padding: "20px 0", fontSize: "var(--fs-sm)" }}>
        {emptyText ?? "Nothing to show."}
      </div>
    );
  }

  return (
    <div className="col" style={{ gap: 14 }}>
      {rows.map((row, i) => (
        <div
          key={row.label}
          className="row"
          style={{ gap: 14, alignItems: "center" }}
        >
          <div
            className="col"
            style={{ width: 132, flex: "none", gap: 1 }}
            title={row.label}
          >
            <span
              className="truncate"
              style={{ fontSize: "var(--fs-sm)", fontWeight: 550 }}
            >
              {row.label}
            </span>
            {row.sublabel && (
              <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
                {row.sublabel}
              </span>
            )}
          </div>
          <div
            style={{
              flex: 1,
              height: 9,
              borderRadius: "var(--radius-pill)",
              background: "var(--bg-raised)",
              overflow: "hidden",
              minWidth: 60,
            }}
          >
            <div
              style={{
                height: "100%",
                borderRadius: "var(--radius-pill)",
                background:
                  row.color ?? CATEGORICAL[i % CATEGORICAL.length],
                width: `${(row.value / max) * 100}%`,
                transition: `width 560ms var(--ease-out) ${i * 50}ms`,
              }}
            />
          </div>
          <span
            className="num"
            style={{
              fontSize: "var(--fs-sm)",
              color: "var(--text-secondary)",
              minWidth: 76,
              textAlign: "right",
              flex: "none",
            }}
          >
            {row.display}
          </span>
        </div>
      ))}
    </div>
  );
}

/** Reclaimable bytes per detector. */
export function CategoryBars({
  rollups,
  colors,
}: {
  rollups: { detector: string; label: string; findingCount: number; bytes: number }[];
  colors: Record<string, string>;
}) {
  return (
    <BarList
      rows={rollups.map((r) => ({
        label: r.label,
        sublabel: `${r.findingCount} finding${r.findingCount === 1 ? "" : "s"}`,
        value: r.bytes,
        color: colors[r.detector],
        display: formatBytes(r.bytes),
      }))}
      emptyText="Run a scan to see where your storage goes."
    />
  );
}

// ─── KPI card ─────────────────────────────────────────────────────────────

/** A headline figure with an accent edge. */
export function KpiCard({
  label,
  value,
  sublabel,
  accent = "var(--accent)",
  icon,
  animate = true,
  format = formatBytes,
}: {
  label: string;
  value: number;
  sublabel?: ReactNode;
  accent?: string;
  icon?: ReactNode;
  animate?: boolean;
  /** How to render `value`. Bytes by default; durations pass `formatDuration`. */
  format?: (value: number) => string;
}) {
  return (
    <div
      className="card"
      style={{ overflow: "hidden", padding: "20px 22px" }}
    >
      <span
        style={{
          position: "absolute",
          inset: "0 auto 0 0",
          width: 3,
          background: accent,
        }}
      />
      <div className="row-between" style={{ alignItems: "flex-start" }}>
        <span
          className="card-title"
          style={{ marginBottom: 6, display: "block" }}
        >
          {label}
        </span>
        {icon && <span style={{ color: accent, opacity: 0.85 }}>{icon}</span>}
      </div>
      <div
        className="num"
        style={{ fontSize: "var(--fs-2xl)", fontWeight: 650, letterSpacing: "-0.02em" }}
      >
        {animate ? (
          <AnimatedNumber value={value} format={format} />
        ) : (
          format(value)
        )}
      </div>
      {sublabel && (
        <div className="muted" style={{ fontSize: "var(--fs-sm)", marginTop: 3 }}>
          {sublabel}
        </div>
      )}
    </div>
  );
}

// ─── Size-bar table ───────────────────────────────────────────────────────

/**
 * A table row with a proportional bar behind the name.
 *
 * The bar is the point: scanning a column of "1.2 GB, 940 MB, 12 KB" takes real
 * effort, while a bar makes the outlier obvious instantly.
 */
export function SizeBar({
  value,
  max,
  color = "var(--cat-1)",
  height = 4,
}: {
  value: number;
  max: number;
  color?: string;
  height?: number;
}) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <span
      style={{
        display: "block",
        height,
        borderRadius: "var(--radius-pill)",
        background: "var(--bg-overlay)",
        overflow: "hidden",
        minWidth: 60,
      }}
    >
      <span
        className={clsx("block")}
        style={{
          height: "100%",
          width: `${pct}%`,
          background: color,
          borderRadius: "var(--radius-pill)",
          transition: "width var(--dur-slow) var(--ease-out)",
        }}
      />
    </span>
  );
}

/** A donut showing volume usage across every scanned volume. */
export function VolumeDonut({ volumes }: { volumes: { name: string; used: number; free: number }[] }) {
  const segments: DonutSegment[] = volumes.map((v, i) => ({
    label: v.name,
    value: v.used,
    color: CATEGORICAL[i % CATEGORICAL.length],
  }));

  return (
    <Donut
      segments={segments}
      centerValue={volumes.length}
      centerLabel="volumes"
    />
  );
}