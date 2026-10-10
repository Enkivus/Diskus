/** Settings and the privacy statement. */

import { formatBytes } from "../lib/format";
import { THRESHOLDS } from "../lib/defaults";
import { EXPORT_FORMATS, EXPORT_LABELS } from "../lib/types";
import { useStore } from "../store/useAppStore";
import { Badge, Banner, Card, Icon, ToggleRow } from "../components/primitives";

/** The settings screen. */
export function SettingsScreen() {
  const config = useStore((s) => s.config);
  const patchConfig = useStore((s) => s.patchConfig);
  const volumes = useStore((s) => s.volumes);
  const profiles = useStore((s) => s.profiles);

  return (
    <div className="screen-inner">
      <div className="page-header">
        <div>
          <h2 className="page-title">Settings</h2>
          <p className="page-subtitle">
            Detection thresholds, applied to the next scan. Detection can be re-run against
            the last scan without walking the filesystem again, which takes seconds rather
            than minutes.
          </p>
        </div>
      </div>

      {/* Privacy */}
      <Card title="Privacy">
        <Banner tone="privacy" icon={<Icon.shield size={16} />}>
          <strong>Diskus has no network code.</strong> There is no HTTP client anywhere in the
          application, which means there is no code path that could transmit anything —
          not file contents, not file names, not statistics. Every report is written directly
          to a folder you choose.
        </Banner>

        <div className="col" style={{ gap: 12, marginTop: 18 }}>
          <PrivacyPoint
            title="File contents are never read"
            body="Scanning uses filesystem metadata only: names, sizes, timestamps and allocation. File contents are never opened."
          />
          <PrivacyPoint
            title="Duplicate detection reads bytes, and keeps nothing"
            body="Files above the size threshold are streamed through blake3 in 64 KiB chunks to compute a digest. Only the digest is retained, which proves two files are identical without revealing anything about what is in them."
          />
          <PrivacyPoint
            title="Reports contain metadata only"
            body="Exports carry paths, sizes, timestamps and severities. Content hashes are off by default and can be enabled per export."
          />
          <PrivacyPoint
            title="Nothing is deleted"
            body="Diskus detects and reports. It never removes files. Every action it offers — reveal in folder, copy path — is read-only."
          />
        </div>
      </Card>

      {/* Thresholds */}
      <Card title="Detection thresholds">
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(290px, 1fr))",
            gap: 22,
          }}
        >
          {THRESHOLDS.map((field) => {
            const raw = config[field.key];
            const display =
              field.kind === "bytes"
                ? formatBytes(raw)
                : field.kind === "percent"
                  ? `${Math.round(raw * 100)}%`
                  : `${raw} days`;

            return (
              <div key={field.key} className="col" style={{ gap: 7 }}>
                <div className="row-between">
                  <span style={{ fontSize: "var(--fs-base)", fontWeight: 560 }}>
                    {field.label}
                  </span>
                  <span className="num" style={{ fontSize: "var(--fs-sm)", fontWeight: 600 }}>
                    {display}
                  </span>
                </div>
                <input
                  className="range"
                  type="range"
                  min={field.min}
                  max={field.max}
                  step={field.step}
                  value={raw}
                  onChange={(e) =>
                    patchConfig({ [field.key]: Number(e.target.value) } as never)
                  }
                  aria-label={field.label}
                />
                <span className="field-help">{field.help}</span>
              </div>
            );
          })}
        </div>
      </Card>

      {/* Scan behaviour */}
      <Card title="Scan behaviour">
        <div className="col">
          <ToggleRow
            label="Include hidden files"
            help="Dotfiles and hidden attributes are included by default. A hidden folder can still be tens of gigabytes."
            checked={config.includeHidden}
            onChange={(v) => patchConfig({ includeHidden: v })}
          />
          <ToggleRow
            label="Skip system directories"
            help="Excludes pseudo-filesystems and OS data that cannot be reclaimed. Turning this off produces numbers that do not reflect usable space."
            checked={config.excludeSystem}
            onChange={(v) => patchConfig({ excludeSystem: v })}
          />
          <ToggleRow
            label="Follow symbolic links"
            help="Off by default: following links can create cycles and multiply the reported size of a folder."
            checked={config.followSymlinks}
            onChange={(v) => patchConfig({ followSymlinks: v })}
          />
          <ToggleRow
            label="Limit scan depth"
            help="Stops descending past a set depth. Useful for a fast overview of a deep tree, but it will miss anything deeper."
            checked={config.maxDepth !== null}
            onChange={(v) => patchConfig({ maxDepth: v ? 4 : null })}
          />
          {config.maxDepth !== null && (
            <div className="col" style={{ gap: 7, paddingTop: 12, maxWidth: 300 }}>
              <input
                className="range"
                type="range"
                min={1}
                max={12}
                step={1}
                value={config.maxDepth}
                onChange={(e) => patchConfig({ maxDepth: Number(e.target.value) })}
                aria-label="Maximum scan depth"
              />
              <span className="field-help">
                Descending up to {config.maxDepth} levels below each root.
              </span>
            </div>
          )}
        </div>
      </Card>

      {/* Performance guardrails */}
      <Card title="Performance guardrails">
        <div className="col" style={{ gap: 4 }}>
          <SettingRow
            label="Entry limit"
            value={`${config.maxNodes.toLocaleString()} entries`}
            help="Past this, Diskus keeps directories and large files only, and tells you the itemised view was trimmed. Totals remain exact."
          />
          <SettingRow
            label="Hardlink deduplication"
            value="Enabled"
            help="Files with multiple links are counted once, so totals reflect reclaimable space rather than apparent size."
          />
          <SettingRow
            label="Sparse and thin-provisioned files"
            value="Allocated size reported"
            help="A 200 GB virtual disk holding 30 GB reports 30 GB as reclaimable, and shows both figures so the difference is visible."
          />
        </div>
      </Card>

      {/* Environment */}
      <Card title="This machine">
        <div className="col" style={{ gap: 4 }}>
          <SettingRow label="Mounted volumes" value={String(volumes.length)} />
          <SettingRow label="User profiles found" value={String(profiles.length)} />
          <SettingRow
            label="Scan locations"
            value={`${config.roots.length} configured`}
          />
          <SettingRow
            label="Report formats available"
            value={EXPORT_FORMATS.map((f) => EXPORT_LABELS[f]).join(", ")}
          />
          <SettingRow label="Duplicate comparison" value="blake3, metadata only" />
        </div>
      </Card>

      {/* About */}
      <Card title="About">
        <div className="row" style={{ gap: 14, alignItems: "center" }}>
          <div
            style={{
              width: 44,
              height: 44,
              borderRadius: 12,
              background: "linear-gradient(135deg, var(--cat-1), var(--cat-5))",
              display: "grid",
              placeItems: "center",
              color: "#fff",
            }}
          >
            <Icon.disk size={24} />
          </div>
          <div className="col" style={{ gap: 3 }}>
            <span style={{ fontWeight: 640, fontSize: "var(--fs-md)" }}>Diskus</span>
            <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
              Find exactly what is consuming storage — and what is wasted.
            </span>
          </div>
          <span className="spacer" />
          <Badge color="var(--success)">Local only</Badge>
        </div>
      </Card>
    </div>
  );
}

function PrivacyPoint({ title, body }: { title: string; body: string }) {
  return (
    <div className="row" style={{ gap: 12, alignItems: "flex-start" }}>
      <span
        style={{
          color: "var(--success)",
          flex: "none",
          marginTop: 2,
          display: "flex",
        }}
      >
        <Icon.check size={15} />
      </span>
      <div className="col" style={{ gap: 2 }}>
        <span style={{ fontWeight: 570, fontSize: "var(--fs-base)" }}>{title}</span>
        <span className="muted" style={{ fontSize: "var(--fs-sm)", lineHeight: 1.6 }}>
          {body}
        </span>
      </div>
    </div>
  );
}

function SettingRow({
  label,
  value,
  help,
}: {
  label: string;
  value: string;
  help?: string;
}) {
  return (
    <div
      className="row-between"
      style={{
        gap: 18,
        padding: "12px 0",
        borderBottom: "1px solid var(--border-subtle)",
        alignItems: "flex-start",
      }}
    >
      <div className="col" style={{ gap: 3 }}>
        <span style={{ fontWeight: 550, fontSize: "var(--fs-base)" }}>{label}</span>
        {help && (
          <span className="muted" style={{ fontSize: "var(--fs-sm)", lineHeight: 1.55 }}>
            {help}
          </span>
        )}
      </div>
      <span
        className="num"
        style={{
          fontSize: "var(--fs-sm)",
          color: "var(--text-secondary)",
          textAlign: "right",
          flex: "none",
        }}
      >
        {value}
      </span>
    </div>
  );
}