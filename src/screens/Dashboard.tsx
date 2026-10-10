/** The dashboard: the answer to "what is using my disk, and what can I reclaim?" */

import { useMemo, useState } from "react";

import { formatBytes, formatCount, formatDate, formatDuration, truncatePath } from "../lib/format";
import {
  DETECTOR_LABELS,
  detectorColor,
  severityTotal,
} from "../lib/types";
import { isScanning, useStore } from "../store/useAppStore";
import {
  Banner,
  Button,
  Card,
  EmptyState,
  Icon,
  Skeleton,
  Tooltip,
} from "../components/primitives";
import { CategoryBars, KpiCard, SeverityDonut, SizeBar } from "../components/viz/Charts";
import { Treemap, TreemapBreadcrumb, TreemapLegend } from "../components/viz/Treemap";

/** The main results screen. */
export function Dashboard() {
  const results = useStore((s) => s.results);
  const loading = useStore((s) => s.loadingResults);
  const phase = useStore((s) => s.phase);
  const startScan = useStore((s) => s.startScan);
  const setScreen = useStore((s) => s.setScreen);
  const [focus, setFocus] = useState<string | null>(null);

  const stats = results?.stats;

  const largestFile = useMemo(
    () => (results?.topFiles.length ? results.topFiles[0].size : 0),
    [results],
  );

  if (!results && loading) return <DashboardSkeleton />;

  if (!results) {
    return isScanning(phase) ? (
      <LiveScanPanel />
    ) : (
      <Card>
        <EmptyState
          icon={<Icon.disk size={22} />}
          title="No scan yet"
          text="Run a scan to find out exactly what is consuming storage on this machine — and what is genuinely wasted."
          action={
            <div className="row" style={{ gap: 10, marginTop: 6 }}>
              <Button variant="primary" onClick={startScan} icon={<Icon.scan size={16} />}>
                Start a scan
              </Button>
              <Button variant="ghost" onClick={() => setScreen("scan")}>
                Choose locations
              </Button>
            </div>
          }
        />
      </Card>
    );
  }

  const summary = results.summary;

  return (
    <div className="screen-inner">
      <div className="page-header">
        <div>
          <h2 className="page-title">Storage overview</h2>
          <p className="page-subtitle">
            {formatBytes(summary.totalScanned)} across {formatCount(stats!.totalFiles)} files
            {stats!.totalDirs > 0 && ` and ${formatCount(stats!.totalDirs)} folders`}.{" "}
            {severityTotal(summary.countsBySeverity) > 0 ? (
              <>
                <strong style={{ color: "var(--text-primary)" }}>
                  {formatBytes(summary.totalReclaimable)}
                </strong>{" "}
                could potentially be reclaimed.
              </>
            ) : (
              "Nothing reclaimable was found."
            )}
          </p>
        </div>
        <div className="row" style={{ gap: 10 }}>
          <Button variant="ghost" onClick={() => void useStore.getState().rerunDetect()}>
            Re-run detection
          </Button>
          <Button variant="secondary" onClick={() => setScreen("findings")}>
            View findings
          </Button>
        </div>
      </div>

      {stats!.cancelled && (
        <Banner tone="warn" icon={<Icon.alert size={16} />}>
          This scan was stopped early. The figures below cover only what was read before it
          stopped, so totals are lower than a complete scan would show.
        </Banner>
      )}

      {stats!.truncated && (
        <Banner tone="warn" icon={<Icon.alert size={16} />}>
          {stats!.truncated}
        </Banner>
      )}

      {stats!.deniedPaths > 0 && (
        <Banner tone="info" icon={<Icon.alert size={16} />}>
          {formatCount(stats!.deniedPaths)} location
          {stats!.deniedPaths === 1 ? "" : "s"} could not be read — usually another user's
          private folders, or system directories. The scan continued past them, so the totals
          below are slightly lower than the true disk usage.
        </Banner>
      )}

      {/* KPI row */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))",
          gap: "var(--gap)",
        }}
      >
        <KpiCard
          label="Storage scanned"
          value={stats!.totalOnDisk || stats!.totalBytes}
          sublabel={formatCount(stats!.totalFiles) + " files"}
          accent="var(--cat-1)"
        />
        <KpiCard
          label="Potentially reclaimable"
          value={summary.totalReclaimable}
          sublabel={
            summary.totalScanned > 0
              ? `${Math.round((summary.totalReclaimable / summary.totalScanned) * 100)}% of what was scanned`
              : undefined
          }
          accent="var(--sev-high)"
          icon={<Icon.alert size={17} />}
        />
        <KpiCard
          label="Findings"
          value={severityTotal(summary.countsBySeverity)}
          sublabel={`${formatCount(summary.countsBySeverity.critical + summary.countsBySeverity.high)} high or critical`}
          accent="var(--cat-6)"
        />
        <KpiCard
          label="Scan time"
          value={stats!.elapsedMs}
          sublabel={`${formatCount(stats!.totalDirs)} folders visited`}
          accent="var(--cat-4)"
          animate={false}
          format={formatDuration}
        />
      </div>

      {/* Treemap + severity */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 2.15fr) minmax(0, 1fr)",
          gap: "var(--gap)",
          alignItems: "start",
        }}
      >
        <Card
          title="Largest locations"
          actions={
            <TreemapBreadcrumb data={results.tree} focusPath={focus} onFocusChange={setFocus} />
          }
        >
          <Treemap
            data={results.tree}
            focusPath={focus}
            onFocusChange={setFocus}
            instant={false}
          />
          <TreemapLegend data={results.tree} />
          {results.tree.truncated && (
            <p
              className="muted"
              style={{ fontSize: "var(--fs-xs)", marginTop: 10 }}
            >
              {formatCount(results.tree.omittedChildren)} smaller folders are not drawn.
              Click a folder to zoom in.
            </p>
          )}
        </Card>

        <Card title="By severity">
          <SeverityDonut
            counts={summary.countsBySeverity}
            total={severityTotal(summary.countsBySeverity)}
          />
        </Card>
      </div>

      {/* Reclaimable by category */}
      <Card title="Reclaimable by category">
        <CategoryBars
          rollups={summary.countsByDetector.map((r) => ({
            detector: r.detector,
            label: DETECTOR_LABELS[r.detector],
            findingCount: r.findingCount,
            bytes: r.bytes,
          }))}
          colors={Object.fromEntries(
            (Object.keys(DETECTOR_LABELS) as (keyof typeof DETECTOR_LABELS)[]).map((d) => [
              d,
              detectorColor(d),
            ]),
          )}
        />
      </Card>

      {/* Largest files */}
      <Card
        title="Largest files"
        actions={
          <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
            Top {Math.min(results.topFiles.length, 200)}
          </span>
        }
        padded={false}
      >
        {results.topFiles.length === 0 ? (
          <EmptyState
            icon={<Icon.check size={22} />}
            title="No large files found"
            text="Nothing in this scan exceeded the reporting threshold."
          />
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 90 }}>Size</th>
                  <th>File</th>
                  <th style={{ width: 90 }} />
                  <th style={{ width: 150 }}>Modified</th>
                </tr>
              </thead>
              <tbody>
                {results.topFiles.slice(0, 25).map((file, i) => (
                  <tr key={file.path} className="stagger" style={{ ["--i" as string]: Math.min(i, 12) }}>
                    <td className="num strong">{formatBytes(file.size)}</td>
                    <td>
                      <Tooltip content={<code>{file.path}</code>}>
                        <span className="truncate" style={{ display: "block", maxWidth: 520 }}>
                          {file.name}
                        </span>
                      </Tooltip>
                      <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
                        {truncatePath(file.path, 3)}
                      </span>
                    </td>
                    <td>
                      <SizeBar value={file.size} max={largestFile} color="var(--cat-1)" />
                    </td>
                    <td className="muted nowrap" style={{ fontSize: "var(--fs-sm)" }}>
                      {formatDate(file.modified)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Volumes */}
      {results.volumes.length > 0 && (
        <Card title="Volumes">
          <div className="col" style={{ gap: 12 }}>
            {results.volumes
              .filter((v) => v.totalBytes)
              .map((volume) => {
                const total = volume.totalBytes ?? 0;
                const available = volume.availableBytes ?? 0;
                const used = Math.max(0, total - available);
                const fraction = total > 0 ? used / total : 0;
                const critical = fraction > 0.9;

                return (
                  <div key={volume.mountPoint} className="col" style={{ gap: 6 }}>
                    <div className="row-between">
                      <span style={{ fontSize: "var(--fs-base)", fontWeight: 550 }}>
                        {volume.name}
                        <span className="muted" style={{ marginLeft: 8, fontWeight: 400 }}>
                          {volume.mountPoint}
                        </span>
                      </span>
                      <span
                        className="num"
                        style={{
                          fontSize: "var(--fs-sm)",
                          color: critical ? "var(--danger)" : "var(--text-secondary)",
                          fontWeight: critical ? 620 : 400,
                        }}
                      >
                        {formatBytes(used)} of {formatBytes(total)} used
                      </span>
                    </div>
                    <div
                      style={{
                        height: 7,
                        borderRadius: "var(--radius-pill)",
                        background: "var(--bg-overlay)",
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          height: "100%",
                          width: `${fraction * 100}%`,
                          background: critical
                            ? "var(--sev-critical)"
                            : "var(--cat-1)",
                          borderRadius: "var(--radius-pill)",
                          transition: "width var(--dur-slow) var(--ease-out)",
                        }}
                      />
                    </div>
                  </div>
                );
              })}
          </div>
        </Card>
      )}
    </div>
  );
}

/** Shown while a scan is running and there are no results yet. */
function LiveScanPanel() {
  const progress = useStore((s) => s.progress);
  const phase = useStore((s) => s.phase);

  return (
    <div className="screen-inner">
      <div className="page-header">
        <div>
          <h2 className="page-title">Scanning…</h2>
          <p className="page-subtitle">
            Reading folder metadata. Nothing is uploaded and no file contents are read —
            duplicate comparison runs afterwards.
          </p>
        </div>
      </div>

      <Card>
        <div className="col" style={{ gap: 16 }}>
          <ProgressHeader phase={phase} />
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
              gap: 18,
            }}
          >
            <Stat label="Files" value={formatCount(progress.files)} />
            <Stat label="Folders" value={formatCount(progress.dirs)} />
            <Stat label="Bytes seen" value={formatBytes(progress.bytes)} />
            <Stat label="Elapsed" value={formatDuration(progress.elapsedMs)} />
          </div>
          <div
            className="well truncate"
            style={{ fontSize: "var(--fs-sm)", color: "var(--text-secondary)" }}
            title={progress.currentPath}
          >
            {progress.currentPath || "Starting…"}
          </div>
        </div>
      </Card>
    </div>
  );
}

function ProgressHeader({ phase }: { phase: string }) {
  const steps = [
    { key: "walking", label: "Reading folders" },
    { key: "hashing", label: "Comparing duplicates" },
    { key: "detecting", label: "Detecting waste" },
    { key: "done", label: "Done" },
  ];
  const activeIndex = Math.max(
    0,
    steps.findIndex((s) => s.key === phase),
  );

  return (
    <div className="row" style={{ gap: 8 }}>
      {steps.map((step, i) => (
        <div key={step.key} className="row" style={{ gap: 8, flex: 1 }}>
          <div className="col" style={{ gap: 6, flex: 1 }}>
            <div
              style={{
                height: 3,
                borderRadius: "var(--radius-pill)",
                background:
                  i <= activeIndex ? "var(--accent)" : "var(--bg-overlay)",
                transition: "background var(--dur-base) var(--ease-out)",
              }}
            />
            <span
              style={{
                fontSize: "var(--fs-xs)",
                color: i <= activeIndex ? "var(--text-secondary)" : "var(--text-tertiary)",
                whiteSpace: "nowrap",
              }}
            >
              {step.label}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="col" style={{ gap: 2 }}>
      <span className="card-title" style={{ marginBottom: 0 }}>
        {label}
      </span>
      <span className="num" style={{ fontSize: "var(--fs-lg)", fontWeight: 600 }}>
        {value}
      </span>
    </div>
  );
}

/** Placeholder shown during the first results fetch. */
function DashboardSkeleton() {
  return (
    <div className="screen-inner">
      <div className="page-header">
        <div className="col" style={{ gap: 8, flex: 1, maxWidth: 460 }}>
          <Skeleton width={280} height={30} />
          <Skeleton width={420} height={15} />
        </div>
      </div>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))",
          gap: "var(--gap)",
        }}
      >
        {[0, 1, 2, 3].map((i) => (
          <Card key={i}>
            <Skeleton width={110} height={11} />
            <div style={{ height: 10 }} />
            <Skeleton width={150} height={30} />
          </Card>
        ))}
      </div>
      <Card>
        <Skeleton height={420} />
      </Card>
    </div>
  );
}