/** Report export: pick formats, then write files locally. */

import { useMemo, useState } from "react";

import { open } from "@tauri-apps/plugin-dialog";

import { buildExportRequest, exportReport } from "../lib/ipc";
import { formatBytes } from "../lib/format";
import {
  EXPORT_DESCRIPTIONS,
  EXPORT_FILE_COUNTS,
  EXPORT_FORMATS,
  EXPORT_LABELS,
  type ExportFormat,
} from "../lib/types";
import { useStore } from "../store/useAppStore";
import {
  Banner,
  Button,
  Card,
  EmptyState,
  Icon,
  ToggleRow,
} from "../components/primitives";

/** The export screen. */
export function ExportScreen() {
  const results = useStore((s) => s.results);
  const exportState = useStore((s) => s.exportState);
  const setExportState = useStore((s) => s.setExportState);
  const toggleExportFormat = useStore((s) => s.toggleExportFormat);
  const startScan = useStore((s) => s.startScan);
  const [revealed, setRevealed] = useState(false);

  const totalFiles = useMemo(
    () =>
      exportState.formats.reduce(
        (sum, f) => sum + EXPORT_FILE_COUNTS[f],
        0,
      ),
    [exportState.formats],
  );

  if (!results) {
    return (
      <Card>
        <EmptyState
          icon={<Icon.export size={22} />}
          title="Nothing to export yet"
          text="Run a scan first — the report is built from what the scan found."
          action={
            <Button variant="primary" onClick={startScan}>
              Start a scan
            </Button>
          }
        />
      </Card>
    );
  }

  const handleExport = async () => {
    if (exportState.formats.length === 0) return;

    let directory: string | null = null;
    try {
      directory = await open({
        directory: true,
        multiple: false,
        title: "Choose where to save the report",
        defaultPath: undefined,
      });
    } catch (err) {
      setExportState({ error: (err as Error).message });
      return;
    }
    if (!directory) return;

    setExportState({ busy: true, error: null, lastWritten: [] });
    setRevealed(false);

    try {
      const request = buildExportRequest(results, exportState.formats, {
        includeAbsolutePaths: exportState.includeAbsolutePaths,
        includeHashes: exportState.includeHashes,
        machineLabel: exportState.machineLabel.trim() || undefined,
      });

      const written = await exportReport(request, directory);
      setExportState({ busy: false, lastWritten: written });
    } catch (err) {
      setExportState({ busy: false, error: (err as Error).message });
    }
  };

  return (
    <div className="screen-inner">
      <div className="page-header">
        <div>
          <h2 className="page-title">Export report</h2>
          <p className="page-subtitle">
            {formatBytes(results.summary.totalReclaimable)} reclaimable from{" "}
            {results.findings.length} finding{results.findings.length === 1 ? "" : "s"}.
            Choose any combination of formats — each is written into the folder you pick.
          </p>
        </div>
      </div>

      {/* The privacy promise, stated where the user is about to act on it. */}
      <Banner tone="privacy" icon={<Icon.shield size={16} />}>
        <strong>Diskus runs entirely on this machine.</strong> Reports are written straight to
        the folder you choose. No file data, file names or statistics are uploaded anywhere,
        and there is no network code in the application at all.
      </Banner>

      {/* Formats */}
      <Card title="Formats">
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
            gap: 14,
          }}
        >
          {EXPORT_FORMATS.map((format) => (
            <FormatCard
              key={format}
              format={format}
              selected={exportState.formats.includes(format)}
              onToggle={() => toggleExportFormat(format)}
            />
          ))}
        </div>
      </Card>

      {/* Options */}
      <Card title="Options">
        <div className="col">
          <ToggleRow
            label="Include full paths"
            help="Off renders paths relative to the scanned root, so a report shared with a colleague does not expose your home directory layout."
            checked={exportState.includeAbsolutePaths}
            onChange={(v) => setExportState({ includeAbsolutePaths: v })}
          />
          <ToggleRow
            label="Include content hashes"
            help="A cryptographic digest that proves two files are identical. It reveals nothing about the contents and is not transmitted — but it is off by default because a shared report rarely needs it."
            checked={exportState.includeHashes}
            onChange={(v) => setExportState({ includeHashes: v })}
          />
        </div>
        <div className="col" style={{ gap: 7, marginTop: 16 }}>
          <label className="field-label" htmlFor="machine-label">
            Label for this report
          </label>
          <input
            id="machine-label"
            className="input"
            style={{ maxWidth: 380 }}
            placeholder="Defaults to this computer's name"
            value={exportState.machineLabel}
            onChange={(e) => setExportState({ machineLabel: e.target.value })}
          />
          <span className="field-help">
            Shown in the report header so a shared file is traceable to its source.
          </span>
        </div>
      </Card>

      {/* Summary + action */}
      <Card>
        <div className="row-between" style={{ gap: 20, flexWrap: "wrap" }}>
          <div className="col" style={{ gap: 4 }}>
            <span style={{ fontWeight: 600 }}>
              {exportState.formats.length === 0
                ? "No format selected"
                : `${totalFiles} file${totalFiles === 1 ? "" : "s"} will be written`}
            </span>
            <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
              {exportState.formats.length > 0
                ? exportState.formats
                    .map((f) => EXPORT_LABELS[f])
                    .join(" · ")
                : "Pick at least one format below."}
            </span>
          </div>
          <Button
            variant="primary"
            size="lg"
            disabled={exportState.formats.length === 0}
            loading={exportState.busy}
            onClick={() => void handleExport()}
            icon={<Icon.export size={17} />}
          >
            {exportState.busy ? "Writing…" : "Export reports"}
          </Button>
        </div>
      </Card>

      {exportState.error && (
        <Banner tone="danger" icon={<Icon.alert size={16} />}>
          {exportState.error}
        </Banner>
      )}

      {exportState.lastWritten.length > 0 && (
        <Card title="Written">
          <div className="col" style={{ gap: 8 }}>
            {exportState.lastWritten.map((path) => (
              <div
                key={path}
                className="row-between well"
                style={{ gap: 12, padding: "10px 14px" }}
              >
                <code
                  className="truncate"
                  style={{ fontSize: "var(--fs-sm)", color: "var(--text-secondary)" }}
                  title={path}
                >
                  {path}
                </code>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => void navigator.clipboard?.writeText(path)}
                  icon={<Icon.copy size={12} />}
                >
                  Copy path
                </Button>
              </div>
            ))}
            {!revealed && (
              <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
                Open the folder you chose to view them.
              </span>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}

/** One selectable format card. */
function FormatCard({
  format,
  selected,
  onToggle,
}: {
  format: ExportFormat;
  selected: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      onClick={onToggle}
      className="card card-interactive"
      style={{
        textAlign: "left",
        padding: 17,
        borderColor: selected ? "var(--accent)" : undefined,
        background: selected ? "var(--accent-muted)" : undefined,
      }}
      aria-pressed={selected}
    >
      <div className="row-between" style={{ marginBottom: 7 }}>
        <span style={{ fontWeight: 600, fontSize: "var(--fs-md)" }}>
          {EXPORT_LABELS[format]}
        </span>
        <span
          style={{
            width: 18,
            height: 18,
            borderRadius: 5,
            border: "1.5px solid",
            borderColor: selected ? "var(--accent)" : "var(--border-strong)",
            background: selected ? "var(--accent)" : "transparent",
            flex: "none",
            display: "grid",
            placeItems: "center",
            color: "#fff",
            transition: "all var(--dur-fast) var(--ease-out)",
          }}
        >
          {selected && <Icon.check size={12} />}
        </span>
      </div>
      <p className="muted" style={{ fontSize: "var(--fs-sm)", lineHeight: 1.55 }}>
        {EXPORT_DESCRIPTIONS[format]}
      </p>
      {EXPORT_FILE_COUNTS[format] > 1 && (
        <span className="tag" style={{ marginTop: 9 }}>
          {EXPORT_FILE_COUNTS[format]} files
        </span>
      )}
    </button>
  );
}