/** Scan setup: choose what to scan and how hard to look. */

import { useState } from "react";

import { formatBytes, formatPercent, truncatePath } from "../lib/format";
import { PRESETS, THRESHOLDS, applyPreset, type ScanPreset } from "../lib/defaults";
import { DETECTOR_BLURBS, DETECTOR_LABELS, type Detector } from "../lib/types";
import { canCancel, isScanning, useStore } from "../store/useAppStore";
import {
  Banner,
  Button,
  Card,
  Field,
  Icon,
  Toggle,
  ToggleRow,
} from "../components/primitives";

/** The scan-configuration screen. */
export function ScanSetup() {
  const config = useStore((s) => s.config);
  const patchConfig = useStore((s) => s.patchConfig);
  const volumes = useStore((s) => s.volumes);
  const profiles = useStore((s) => s.profiles);
  const toggleRoot = useStore((s) => s.toggleRoot);
  const addRoot = useStore((s) => s.addRoot);
  const removeRoot = useStore((s) => s.removeRoot);
  const addExclusion = useStore((s) => s.addExclusion);
  const removeExclusion = useStore((s) => s.removeExclusion);
  const toggleDetector = useStore((s) => s.toggleDetector);
  const startScan = useStore((s) => s.startScan);
  const cancelScan = useStore((s) => s.cancelScan);
  const phase = useStore((s) => s.phase);

  const [customPath, setCustomPath] = useState("");
  const [exclusion, setExclusion] = useState("");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [preset, setPreset] = useState<ScanPreset>("quick");

  const scanning = isScanning(phase);

  const applyPresetTo = (next: ScanPreset) => {
    setPreset(next);
    patchConfig(applyPreset(next, config));
  };

  const scannableVolumes = volumes.filter((v) => v.isScannable);

  return (
    <div className="screen-inner">
      <div className="page-header">
        <div>
          <h2 className="page-title">Scan setup</h2>
          <p className="page-subtitle">
            Diskus reads folder metadata only. It never opens files to read their contents,
            and nothing leaves this machine — except for the optional duplicate check, which
            compares files by cryptographic hash and keeps nothing.
          </p>
        </div>
        <div className="row" style={{ gap: 10 }}>
          {scanning ? (
            <Button variant="danger" onClick={() => void cancelScan()}>
              Stop scan
            </Button>
          ) : (
            <Button
              variant="primary"
              size="lg"
              onClick={startScan}
              icon={<Icon.scan size={17} />}
            >
              Start scan
            </Button>
          )}
        </div>
      </div>

      {/* Presets */}
      <Card title="Preset">
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
            gap: 14,
          }}
        >
          {(Object.keys(PRESETS) as ScanPreset[]).map((key) => (
            <button
              key={key}
              onClick={() => applyPresetTo(key)}
              className="card card-interactive"
              style={{
                textAlign: "left",
                borderColor: preset === key ? "var(--accent)" : undefined,
                padding: 17,
              }}
              aria-pressed={preset === key}
            >
              <div className="row" style={{ gap: 9, marginBottom: 6 }}>
                <span
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    background: preset === key ? "var(--accent)" : "var(--border-strong)",
                  }}
                />
                <span style={{ fontWeight: 600 }}>{PRESETS[key].label}</span>
              </div>
              <p className="muted" style={{ fontSize: "var(--fs-sm)", lineHeight: 1.55 }}>
                {PRESETS[key].description}
              </p>
            </button>
          ))}
        </div>
      </Card>

      {/* Locations */}
      <Card title="What to scan">
        <div className="col" style={{ gap: 18 }}>
          <div className="col" style={{ gap: 10 }}>
            <span className="field-label">Volumes</span>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
                gap: 12,
              }}
            >
              {scannableVolumes.map((volume) => {
                const selected = config.roots.includes(volume.mountPoint);
                const total = volume.totalBytes ?? 0;
                const available = volume.availableBytes ?? 0;
                const usedFraction = total > 0 ? (total - available) / total : 0;

                return (
                  <button
                    key={volume.mountPoint}
                    onClick={() => toggleRoot(volume.mountPoint)}
                    className="card card-interactive"
                    style={{
                      textAlign: "left",
                      padding: 15,
                      borderColor: selected ? "var(--accent)" : undefined,
                    }}
                    aria-pressed={selected}
                  >
                    <div className="row-between" style={{ marginBottom: 8 }}>
                      <div className="col" style={{ gap: 1, minWidth: 0 }}>
                        <span className="truncate" style={{ fontWeight: 570 }}>
                          {volume.name}
                        </span>
                        <code className="muted" style={{ fontSize: "var(--fs-xs)" }}>
                          {volume.mountPoint}
                        </code>
                      </div>
                      <span
                        style={{
                          width: 17,
                          height: 17,
                          borderRadius: 5,
                          border: "1.5px solid",
                          borderColor: selected ? "var(--accent)" : "var(--border-strong)",
                          background: selected ? "var(--accent)" : "transparent",
                          flex: "none",
                          display: "grid",
                          placeItems: "center",
                          color: "#fff",
                        }}
                      >
                        {selected && <Icon.check size={11} />}
                      </span>
                    </div>
                    {total > 0 && (
                      <>
                        <div
                          style={{
                            height: 4,
                            borderRadius: "var(--radius-pill)",
                            background: "var(--bg-overlay)",
                            overflow: "hidden",
                            marginBottom: 6,
                          }}
                        >
                          <div
                            style={{
                              height: "100%",
                              width: `${usedFraction * 100}%`,
                              background:
                                usedFraction > 0.9 ? "var(--sev-critical)" : "var(--cat-1)",
                            }}
                          />
                        </div>
                        <div
                          className="row-between muted"
                          style={{ fontSize: "var(--fs-xs)" }}
                        >
                          <span>{formatBytes(total - available)} used</span>
                          <span>{formatBytes(available)} free</span>
                        </div>
                      </>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="col" style={{ gap: 10 }}>
            <span className="field-label">User profiles</span>
            <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
              {profiles.map((profile) => {
                const selected = config.roots.includes(profile.path);
                return (
                  <button
                    key={profile.path}
                    className="chip"
                    aria-pressed={selected}
                    onClick={() => toggleRoot(profile.path)}
                    title={profile.path}
                  >
                    <span
                      style={{
                        width: 6,
                        height: 6,
                        borderRadius: "50%",
                        background: selected ? "#fff" : "var(--cat-5)",
                      }}
                    />
                    {profile.username}
                    {profile.isCurrent && (
                      <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
                        (you)
                      </span>
                    )}
                    {profile.size !== undefined && (
                      <span className="muted">{formatBytes(profile.size)}</span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Custom path */}
          <div className="col" style={{ gap: 10 }}>
            <span className="field-label">Add a folder</span>
            <div className="row" style={{ gap: 9 }}>
              <input
                className="input"
                style={{ flex: 1 }}
                placeholder="/Users/jdoe/Downloads"
                value={customPath}
                onChange={(e) => setCustomPath(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && customPath.trim()) {
                    addRoot(customPath.trim());
                    setCustomPath("");
                  }
                }}
                aria-label="Custom path to scan"
              />
              <Button
                variant="secondary"
                disabled={!customPath.trim()}
                icon={<Icon.plus size={14} />}
                onClick={() => {
                  addRoot(customPath.trim());
                  setCustomPath("");
                }}
              >
                Add
              </Button>
            </div>
            {config.roots.length > 0 && (
              <div className="row" style={{ gap: 7, flexWrap: "wrap", marginTop: 4 }}>
                {config.roots.map((root) => (
                  <span key={root} className="tag" title={root}>
                    <span
                      style={{
                        maxWidth: 300,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {truncatePath(root, 3)}
                    </span>
                    <button
                      onClick={() => removeRoot(root)}
                      aria-label={`Remove ${root}`}
                      style={{
                        display: "flex",
                        color: "var(--text-tertiary)",
                      }}
                    >
                      <Icon.close size={11} />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      </Card>

      {/* Detectors */}
      <Card
        title="What to look for"
        actions={
          <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
            {config.detect.length} of 5 enabled
          </span>
        }
      >
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            gap: 14,
          }}
        >
          {(Object.keys(DETECTOR_LABELS) as Detector[]).map((detector) => {
            const enabled = config.detect.includes(detector);
            return (
              <div
                key={detector}
                className="well row-between"
                style={{
                  alignItems: "flex-start",
                  gap: 14,
                  opacity: enabled ? 1 : 0.55,
                  transition: "opacity var(--dur-base) var(--ease-out)",
                }}
              >
                <div className="col" style={{ gap: 4, minWidth: 0 }}>
                  <span style={{ fontWeight: 580 }}>{DETECTOR_LABELS[detector]}</span>
                  <span
                    className="muted"
                    style={{ fontSize: "var(--fs-sm)", lineHeight: 1.5 }}
                  >
                    {DETECTOR_BLURBS[detector]}
                  </span>
                </div>
                <Toggle
                  checked={enabled}
                  onChange={() => toggleDetector(detector)}
                  ariaLabel={DETECTOR_LABELS[detector]}
                />
              </div>
            );
          })}
        </div>
      </Card>

      {/* Advanced */}
      <Card
        title="Advanced"
        actions={
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setAdvancedOpen((o) => !o)}
            icon={<Icon.chevron dir={advancedOpen ? "down" : "right"} size={13} />}
          >
            {advancedOpen ? "Hide" : "Show"}
          </Button>
        }
      >
        {advancedOpen && (
          <div className="col" style={{ gap: 20, animation: "rise var(--dur-base) var(--ease-out) both" }}>
            <div className="col" style={{ gap: 4 }}>
              <ToggleRow
                label="Include hidden files"
                help="Dotfiles and hidden system attributes. On by default — a hidden 20 GB folder is still 20 GB."
                checked={config.includeHidden}
                onChange={(v) => patchConfig({ includeHidden: v })}
              />
              <ToggleRow
                label="Skip system directories"
                help="Avoids pseudo-filesystems and unreclaimable OS data that would otherwise dominate the results."
                checked={config.excludeSystem}
                onChange={(v) => patchConfig({ excludeSystem: v })}
              />
              <ToggleRow
                label="Follow symbolic links"
                help="Off by default. Following links can turn a folder into a loop and multiply the reported size."
                checked={config.followSymlinks}
                onChange={(v) => patchConfig({ followSymlinks: v })}
              />
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                gap: 20,
              }}
            >
              {THRESHOLDS.map((field) => {
                const raw = config[field.key];
                const display =
                  field.kind === "bytes"
                    ? formatBytes(raw)
                    : field.kind === "percent"
                      ? formatPercent(raw)
                      : `${raw} days`;

                return (
                  <Field key={field.key} label={field.label} help={field.help}>
                    <div className="row" style={{ gap: 11 }}>
                      <input
                        className="range"
                        type="range"
                        min={field.min}
                        max={field.max}
                        step={field.step}
                        value={raw}
                        onChange={(e) =>
                          patchConfig({
                            [field.key]: Number(e.target.value),
                          } as never)
                        }
                        aria-label={field.label}
                      />
                      <span
                        className="num"
                        style={{
                          minWidth: 74,
                          textAlign: "right",
                          fontSize: "var(--fs-sm)",
                          fontWeight: 550,
                        }}
                      >
                        {display}
                      </span>
                    </div>
                  </Field>
                );
              })}
            </div>

            <div className="col" style={{ gap: 10 }}>
              <span className="field-label">Excluded folders</span>
              <div className="row" style={{ gap: 9 }}>
                <input
                  className="input"
                  style={{ flex: 1 }}
                  placeholder="/Users/jdoe/Documents"
                  value={exclusion}
                  onChange={(e) => setExclusion(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && exclusion.trim()) {
                      addExclusion(exclusion.trim());
                      setExclusion("");
                    }
                  }}
                  aria-label="Add exclusion"
                />
                <Button
                  variant="secondary"
                  disabled={!exclusion.trim()}
                  onClick={() => {
                    addExclusion(exclusion.trim());
                    setExclusion("");
                  }}
                >
                  Exclude
                </Button>
              </div>
              {config.excludePaths.length > 0 && (
                <div className="row" style={{ gap: 7, flexWrap: "wrap" }}>
                  {config.excludePaths.map((path) => (
                    <span key={path} className="tag">
                      <span
                        style={{
                          maxWidth: 300,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {truncatePath(path, 3)}
                      </span>
                      <button
                        onClick={() => removeExclusion(path)}
                        aria-label={`Remove exclusion ${path}`}
                        style={{ display: "flex", color: "var(--text-tertiary)" }}
                      >
                        <Icon.close size={11} />
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>

            <Banner tone="info" icon={<Icon.alert size={15} />}>
              Duplicate detection hashes files above{" "}
              <strong>{formatBytes(config.minFileSizeForDupes)}</strong>. Raising this
              threshold makes a scan much faster on machines with many small files, at the
              cost of missing small duplicates.
            </Banner>
          </div>
        )}
      </Card>

      {canCancel(phase) && (
        <Banner tone="warn" icon={<Icon.alert size={15} />}>
          A scan is currently running. Starting another is not possible — stop it first.
        </Banner>
      )}
    </div>
  );
}