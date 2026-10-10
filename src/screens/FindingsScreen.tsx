/** The findings list, with filters and a detail drawer. */

import { useMemo, useState } from "react";

import {
  formatBytes,
  formatConfidence,
  formatCount,
  formatDate,
  truncatePath,
} from "../lib/format";
import {
  DETECTOR_BLURBS,
  DETECTOR_LABELS,
  SAFETY_LABELS,
  SEVERITIES,
  SEVERITY_COLORS,
  SEVERITY_LABELS,
  detectorColor,
  type Finding,
  type Safety,
} from "../lib/types";
import {
  selectFilteredFindings,
  useStore,
} from "../store/useAppStore";
import {
  Badge,
  Button,
  Card,
  Chip,
  ConfidenceMeter,
  EmptyState,
  Icon,
  Tooltip,
} from "../components/primitives";
import { SizeBar } from "../components/viz/Charts";

/** The findings screen. */
export function FindingsScreen() {
  const results = useStore((s) => s.results);
  const filters = useStore((s) => s.filters);
  const setFilters = useStore((s) => s.setFilters);
  const toggleSeverityFilter = useStore((s) => s.toggleSeverityFilter);
  const toggleDetectorFilter = useStore((s) => s.toggleDetectorFilter);
  const resetFilters = useStore((s) => s.resetFilters);
  const selectedId = useStore((s) => s.selectedFindingId);
  const selectFinding = useStore((s) => s.selectFinding);
  const startScan = useStore((s) => s.startScan);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const findings = results?.findings ?? [];
  const filtered = useMemo(
    () => selectFilteredFindings(findings, filters),
    [findings, filters],
  );

  const maxReclaimable = useMemo(
    () => Math.max(1, ...filtered.map((f) => f.reclaimable)),
    [filtered],
  );

  const filteredTotal = filtered.reduce((sum, f) => sum + f.reclaimable, 0);

  if (!results) {
    return (
      <Card>
        <EmptyState
          icon={<Icon.list size={22} />}
          title="No findings yet"
          text="Run a scan and Diskus will look for growing logs, abandoned VMs, oversized profiles, old installers and duplicate data."
          action={
            <Button variant="primary" onClick={startScan}>
              Start a scan
            </Button>
          }
        />
      </Card>
    );
  }

  if (findings.length === 0) {
    return (
      <Card>
        <EmptyState
          icon={<Icon.check size={24} />}
          title="This machine is clean"
          text="No growing logs, abandoned VMs, oversized profiles, stale installers or duplicate data were found. Nothing to reclaim."
          action={
            <Button variant="secondary" onClick={startScan}>
              Scan again
            </Button>
          }
        />
      </Card>
    );
  }

  const toggleExpanded = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const hasActiveFilters =
    filters.severities.length > 0 ||
    filters.detectors.length > 0 ||
    filters.query.length > 0 ||
    filters.safeOnly;

  return (
    <div className="screen-inner">
      <div className="page-header">
        <div>
          <h2 className="page-title">Findings</h2>
          <p className="page-subtitle">
            {formatCount(filtered.length)} of {formatCount(findings.length)} showing,{" "}
            <strong style={{ color: "var(--text-primary)" }}>
              {formatBytes(filteredTotal)}
            </strong>{" "}
            reclaimable. Nothing is deleted — these are suggestions with the reasoning
            attached.
          </p>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <div className="col" style={{ gap: 14 }}>
          <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
            <input
              className="input"
              style={{ flex: 1, minWidth: 220 }}
              placeholder="Search titles, paths and recommendations…"
              value={filters.query}
              onChange={(e) => setFilters({ query: e.target.value })}
              aria-label="Search findings"
            />
            <select
              className="select"
              value={filters.sort}
              onChange={(e) => setFilters({ sort: e.target.value as typeof filters.sort })}
              aria-label="Sort findings"
            >
              <option value="reclaimable">Largest reclaimable first</option>
              <option value="severity">Most severe first</option>
              <option value="confidence">Most confident first</option>
              <option value="name">Name</option>
            </select>
          </div>

          <div className="col" style={{ gap: 8 }}>
            <span className="card-title" style={{ marginBottom: 0 }}>
              Severity
            </span>
            <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
              {SEVERITIES.map((severity) => (
                <Chip
                  key={severity}
                  color={SEVERITY_COLORS[severity]}
                  pressed={filters.severities.includes(severity)}
                  onClick={() => toggleSeverityFilter(severity)}
                  count={
                    results.summary.countsBySeverity[
                      severity === "critical"
                        ? "critical"
                        : severity === "high"
                          ? "high"
                          : severity === "medium"
                            ? "medium"
                            : severity === "low"
                              ? "low"
                              : "info"
                    ]
                  }
                >
                  {SEVERITY_LABELS[severity]}
                </Chip>
              ))}
              <Chip
                pressed={filters.safeOnly}
                onClick={() => setFilters({ safeOnly: !filters.safeOnly })}
                color="var(--success)"
              >
                Safe to delete only
              </Chip>
            </div>
          </div>

          <div className="col" style={{ gap: 8 }}>
            <span className="card-title" style={{ marginBottom: 0 }}>
              Category
            </span>
            <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
              {(
                Object.keys(DETECTOR_LABELS) as (keyof typeof DETECTOR_LABELS)[]
              ).map((detector) => (
                <Chip
                  key={detector}
                  color={detectorColor(detector)}
                  pressed={filters.detectors.includes(detector)}
                  onClick={() => toggleDetectorFilter(detector)}
                  title={DETECTOR_BLURBS[detector]}
                >
                  {DETECTOR_LABELS[detector]}
                </Chip>
              ))}
            </div>
          </div>

          {hasActiveFilters && (
            <div className="row">
              <Button variant="ghost" size="sm" onClick={resetFilters} icon={<Icon.close size={13} />}>
                Clear filters
              </Button>
            </div>
          )}
        </div>
      </Card>

      {/* List */}
      {filtered.length === 0 ? (
        <Card>
          <EmptyState
            icon={<Icon.list size={22} />}
            title="Nothing matches those filters"
            text="Try clearing a filter or widening your search."
            action={<Button variant="secondary" onClick={resetFilters}>Clear filters</Button>}
          />
        </Card>
      ) : (
        <div className="col" style={{ gap: 10 }}>
          {filtered.map((finding, i) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              maxReclaimable={maxReclaimable}
              expanded={expanded.has(finding.id)}
              selected={selectedId === finding.id}
              index={Math.min(i, 14)}
              onToggle={() => toggleExpanded(finding.id)}
              onSelect={() =>
                selectFinding(selectedId === finding.id ? null : finding.id)
              }
            />
          ))}
        </div>
      )}

      {selectedId && (
        <DetailDrawer
          finding={filtered.find((f) => f.id === selectedId)}
          onClose={() => selectFinding(null)}
        />
      )}
    </div>
  );
}

/** One finding, collapsed or expanded inline. */
function FindingRow({
  finding,
  maxReclaimable,
  expanded,
  selected,
  index,
  onToggle,
  onSelect,
}: {
  finding: Finding;
  maxReclaimable: number;
  expanded: boolean;
  selected: boolean;
  index: number;
  onToggle: () => void;
  onSelect: () => void;
}) {
  return (
    <div
      className="card enter"
      style={{
        ["--i" as string]: index,
        padding: 0,
        overflow: "hidden",
        borderColor: selected ? "var(--accent)" : undefined,
        transition: "border-color var(--dur-fast) var(--ease-out)",
      }}
    >
      <div
        style={{ display: "flex", alignItems: "stretch", cursor: "pointer" }}
        onClick={onSelect}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onSelect();
          }
        }}
        aria-expanded={selected}
      >
        {/* Severity stripe. */}
        <span
          style={{
            width: 3,
            flex: "none",
            background: SEVERITY_COLORS[finding.severity],
          }}
        />

        <div className="col" style={{ flex: 1, padding: "15px 18px", gap: 9, minWidth: 0 }}>
          <div className="row-between" style={{ gap: 16 }}>
            <div className="col" style={{ gap: 5, minWidth: 0, flex: 1 }}>
              <div className="row" style={{ gap: 9, flexWrap: "wrap" }}>
                <span style={{ fontWeight: 600, fontSize: "var(--fs-md)" }}>
                  {finding.title}
                </span>
                <Badge color={detectorColor(finding.detector)}>
                  {DETECTOR_LABELS[finding.detector]}
                </Badge>
                <span className={safetyClass(finding.safety)}>
                  {SAFETY_LABELS[finding.safety]}
                </span>
              </div>
              <Tooltip content={<code>{finding.path}</code>}>
                <span
                  className="muted truncate"
                  style={{ fontSize: "var(--fs-sm)", maxWidth: 640 }}
                >
                  {truncatePath(finding.path, 5)}
                </span>
              </Tooltip>
            </div>

            <div
              className="col"
              style={{ alignItems: "flex-end", gap: 5, flex: "none", minWidth: 168 }}
            >
              <span
                className="num"
                style={{ fontSize: "var(--fs-lg)", fontWeight: 640 }}
              >
                {formatBytes(finding.reclaimable)}
              </span>
              {finding.size > finding.reclaimable && (
                <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
                  of {formatBytes(finding.size)}
                </span>
              )}
              <div style={{ width: 120 }}>
                <SizeBar
                  value={finding.reclaimable}
                  max={maxReclaimable}
                  color={SEVERITY_COLORS[finding.severity]}
                />
              </div>
              <div className="row" style={{ gap: 7, marginTop: 2 }}>
                <ConfidenceMeter value={finding.confidence} />
                <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
                  {formatConfidence(finding.confidence)}
                </span>
              </div>
            </div>
          </div>
        </div>

        <button
          className="btn btn-ghost btn-icon"
          style={{ margin: "auto 12px auto 0", flex: "none" }}
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
          aria-label={expanded ? "Collapse" : "Expand"}
          aria-expanded={expanded}
        >
          <Icon.chevron dir={expanded ? "down" : "right"} />
        </button>
      </div>

      {expanded && <FindingDetail finding={finding} />}
    </div>
  );
}

/** The inline expanded detail. */
function FindingDetail({ finding }: { finding: Finding }) {
  const addExclusion = useStore((s) => s.addExclusion);

  return (
    <div
      style={{
        padding: "4px 18px 18px 21px",
        borderTop: "1px solid var(--border-subtle)",
        animation: "rise var(--dur-base) var(--ease-out) both",
      }}
    >
      <div className="col" style={{ gap: 16, paddingTop: 14 }}>
        <div className="col" style={{ gap: 6 }}>
          <span className="card-title" style={{ marginBottom: 0 }}>
            What to do
          </span>
          <p style={{ fontSize: "var(--fs-md)", lineHeight: 1.6, maxWidth: "76ch" }}>
            {finding.recommendation}
          </p>
        </div>

        <DetailTable finding={finding} />

        {finding.relatedPaths && finding.relatedPaths.length > 0 && (
          <div className="col" style={{ gap: 7 }}>
            <span className="card-title" style={{ marginBottom: 0 }}>
              Related paths ({finding.relatedPaths.length})
            </span>
            <div
              className="well col"
              style={{ gap: 3, maxHeight: 190, overflowY: "auto" }}
            >
              {finding.relatedPaths.slice(0, 60).map((path) => (
                <code
                  key={path}
                  style={{ fontSize: "var(--fs-sm)", color: "var(--text-secondary)" }}
                >
                  {path}
                </code>
              ))}
              {finding.relatedPaths.length > 60 && (
                <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
                  …and {finding.relatedPaths.length - 60} more
                </span>
              )}
            </div>
          </div>
        )}

        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <Button
            size="sm"
            variant="secondary"
            icon={<Icon.copy size={13} />}
            onClick={() => void navigator.clipboard?.writeText(finding.path)}
          >
            Copy path
          </Button>
          {finding.relatedPaths && finding.relatedPaths.length > 0 && (
            <Button
              size="sm"
              variant="secondary"
              icon={<Icon.copy size={13} />}
              onClick={() =>
                void navigator.clipboard?.writeText(
                  [finding.path, ...(finding.relatedPaths ?? [])].join("\n"),
                )
              }
            >
              Copy all {finding.relatedPaths.length + 1} paths
            </Button>
          )}
          <Button
            size="sm"
            variant="ghost"
            onClick={() => addExclusion(finding.path)}
            title="Exclude this location from future scans"
          >
            Add to exclusions
          </Button>
        </div>
      </div>
    </div>
  );
}

/** Renders `detail` as a readable key/value list. */
function DetailTable({ finding }: { finding: Finding }) {
  const entries = Object.entries(finding.detail).filter(
    ([, value]) => value !== null && value !== undefined && value !== "",
  );

  if (entries.length === 0) return null;

  const isLong = (value: unknown) =>
    typeof value === "string" && value.length > 60;
  const isArrayish = (value: unknown) =>
    Array.isArray(value) || (typeof value === "object" && value !== null);

  return (
    <div className="col" style={{ gap: 7 }}>
      <span className="card-title" style={{ marginBottom: 0 }}>
        Detail
      </span>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))",
          gap: 1,
          background: "var(--border-subtle)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "var(--radius-md)",
          overflow: "hidden",
        }}
      >
        {entries.map(([key, value]) => (
          <div
            key={key}
            style={{
              background: "var(--bg-sunken)",
              padding: "10px 13px",
              display: "flex",
              flexDirection: "column",
              gap: 3,
              minWidth: 0,
            }}
          >
            <span
              className="muted"
              style={{ fontSize: "var(--fs-xs)", textTransform: "capitalize" }}
            >
              {humaniseKey(key)}
            </span>
            {isArrayish(value) ? (
              <span
                className="truncate"
                style={{ fontSize: "var(--fs-sm)", color: "var(--text-secondary)" }}
                title={JSON.stringify(value, null, 2)}
              >
                {summariseValue(value)}
              </span>
            ) : (
              <span
                className={isLong(value) ? "truncate" : undefined}
                style={{
                  fontSize: "var(--fs-sm)",
                  fontFamily: isLong(value) ? undefined : "var(--font-mono)",
                  color: "var(--text-primary)",
                }}
                title={isLong(value) ? String(value) : undefined}
              >
                {formatDetailValue(value)}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function formatDetailValue(value: unknown): string {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") {
    return Number.isInteger(value)
      ? value.toLocaleString()
      : value.toFixed(2);
  }
  if (typeof value === "string") {
    if (/^-?\d{4}-\d{2}-\d{2}T/.test(value)) return formatDate(value);
    if (/^\d+(\.\d+)?$/.test(value)) return Number(value).toLocaleString();
    return value;
  }
  return String(value);
}

function summariseValue(value: unknown): string {
  if (Array.isArray(value)) {
    if (value.length === 0) return "none";
    return `${value.length} item${value.length === 1 ? "" : "s"}: ${value
      .slice(0, 3)
      .map((v) => String(v))
      .join(", ")}${value.length > 3 ? "…" : ""}`;
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) return "none";
  return entries
    .slice(0, 4)
    .map(([k, v]) => `${k}: ${formatDetailValue(v)}`)
    .join(" · ");
}

function humaniseKey(key: string): string {
  return key
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (c) => c.toUpperCase())
    .toLowerCase()
    .replace(/^./, (c) => c.toUpperCase());
}

function safetyClass(safety: Safety): string {
  switch (safety) {
    case "safe_to_delete":
      return "tag tag-safe";
    case "review_first":
      return "tag tag-review";
    default:
      return "tag tag-loss";
  }
}

/** A slide-in detail drawer. */
function DetailDrawer({
  finding,
  onClose,
}: {
  finding?: Finding;
  onClose: () => void;
}) {
  if (!finding) return null;

  return (
    <>
      <div
        onClick={onClose}
        style={{
          position: "fixed",
          inset: 0,
          background: "rgba(0,0,0,0.5)",
          backdropFilter: "blur(2px)",
          zIndex: 90,
          animation: "fade-in var(--dur-base) var(--ease-out) both",
        }}
      />
      <aside
        role="dialog"
        aria-label="Finding detail"
        style={{
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          width: "min(520px, 92vw)",
          background: "var(--bg-surface)",
          borderLeft: "1px solid var(--border-default)",
          boxShadow: "var(--shadow-lg)",
          zIndex: 91,
          display: "flex",
          flexDirection: "column",
          animation: "slide-in-right var(--dur-base) var(--ease-out) both",
        }}
      >
        <header
          className="row-between"
          style={{
            padding: "18px 22px",
            borderBottom: "1px solid var(--border-subtle)",
            flex: "none",
          }}
        >
          <div className="row" style={{ gap: 10 }}>
            <span
              className="badge-dot"
              style={{ background: SEVERITY_COLORS[finding.severity] }}
            />
            <span className="strong">{SEVERITY_LABELS[finding.severity]}</span>
            <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
              {DETECTOR_LABELS[finding.detector]}
            </span>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} ariaLabel="Close">
            <Icon.close size={15} />
          </Button>
        </header>

        <div className="col" style={{ padding: 22, gap: 20, overflowY: "auto" }}>
          <div>
            <h3 style={{ fontSize: "var(--fs-lg)", marginBottom: 8 }}>
              {finding.title}
            </h3>
            <div className="num" style={{ fontSize: "var(--fs-2xl)", fontWeight: 650 }}>
              {formatBytes(finding.reclaimable)}
            </div>
            {finding.size > finding.reclaimable && (
              <div className="muted" style={{ fontSize: "var(--fs-sm)" }}>
                of {formatBytes(finding.size)} total
              </div>
            )}
          </div>

          <div className="col" style={{ gap: 6 }}>
            <span className="card-title" style={{ marginBottom: 0 }}>
              Recommendation
            </span>
            <p style={{ lineHeight: 1.65 }}>{finding.recommendation}</p>
          </div>

          <div className="row" style={{ gap: 8 }}>
            <span className={safetyClass(finding.safety)}>
              {SAFETY_LABELS[finding.safety]}
            </span>
            <span className="tag">
              {formatConfidence(finding.confidence)} confidence
            </span>
            <span className="tag">Found {formatDate(finding.detectedAt)}</span>
          </div>

          <DetailTable finding={finding} />
        </div>
      </aside>
    </>
  );
}