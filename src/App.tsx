/** The application shell: sidebar, topbar and screen routing. */

import { useEffect } from "react";

import * as ipc from "./lib/ipc";
import { formatBytes, formatCount, formatDuration, truncatePath } from "./lib/format";
import {
  canCancel,
  isScanning,
  phaseLabel,
  useStore,
  type Screen,
} from "./store/useAppStore";
import { Button, Icon, ProgressBar } from "./components/primitives";
import { Dashboard } from "./screens/Dashboard";
import { FindingsScreen } from "./screens/FindingsScreen";
import { ScanSetup } from "./screens/ScanSetup";
import { ExportScreen } from "./screens/ExportScreen";
import { SettingsScreen } from "./screens/SettingsScreen";

/** Navigation entries, in the order they appear. */
const NAV: { screen: Screen; label: string; icon: (p: { size?: number }) => React.ReactElement; shortcut: string }[] = [
  { screen: "dashboard", label: "Dashboard", icon: Icon.disk, shortcut: "1" },
  { screen: "findings", label: "Findings", icon: Icon.list, shortcut: "2" },
  { screen: "scan", label: "Scan setup", icon: Icon.scan, shortcut: "3" },
  { screen: "export", label: "Export", icon: Icon.export, shortcut: "4" },
  { screen: "settings", label: "Settings", icon: Icon.settings, shortcut: "5" },
];

/** The root component. */
export function App() {
  const screen = useStore((s) => s.screen);
  const setScreen = useStore((s) => s.setScreen);
  const loadConfig = useStore((s) => s.loadConfig);
  const configLoaded = useStore((s) => s.configLoaded);
  const results = useStore((s) => s.results);
  const startScan = useStore((s) => s.startScan);
  const phase = useStore((s) => s.phase);
  const error = useStore((s) => s.error);

  // Load configuration and subscribe to scan events once.
  useEffect(() => {
    void loadConfig();

    let dispose: (() => void) | undefined;
    let cancelled = false;

    void ipc
      .subscribeToScanEvents({
        onStarted: (e) => useStore.getState().handleScanStarted(e),
        onProgress: (e) => useStore.getState().handleProgress(e),
        onComplete: (e) => useStore.getState().handleComplete(e),
        onCancelled: () => useStore.getState().handleCancelled(),
        onError: (e) => useStore.getState().handleError(e),
      })
      .then((unlisten) => {
        // A slow subscription must not attach to a component that has gone away.
        if (cancelled) unlisten();
        else dispose = unlisten;
      });

    return () => {
      cancelled = true;
      dispose?.();
    };
  }, [loadConfig]);

  // Keyboard shortcuts. Ignored while typing in a field, so `1` in a search box
  // does not navigate away mid-query.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const typing =
        target?.tagName === "INPUT" ||
        target?.tagName === "TEXTAREA" ||
        target?.tagName === "SELECT";
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;

      const match = NAV.find((n) => n.shortcut === e.key);
      if (match) {
        e.preventDefault();
        setScreen(match.screen);
        return;
      }

      if (e.key === "Escape") useStore.getState().selectFinding(null);
      if (e.key === " " && isScanning(phase)) {
        e.preventDefault();
        void useStore.getState().cancelScan();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setScreen, phase]);

  const findingCount = results?.findings.length ?? 0;

  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
      <Sidebar findingCount={findingCount} />

      <div className="col" style={{ flex: 1, minWidth: 0 }}>
        <TopBar onStartScan={startScan} />
        {error && <ErrorStrip />}
        <div style={{ flex: 1, minHeight: 0, position: "relative" }}>
          {!configLoaded ? (
            <BootScreen />
          ) : (
            <div key={screen} className="screen enter">
              {screen === "dashboard" && <Dashboard />}
              {screen === "findings" && <FindingsScreen />}
              {screen === "scan" && <ScanSetup />}
              {screen === "export" && <ExportScreen />}
              {screen === "settings" && <SettingsScreen />}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** The left navigation rail. */
function Sidebar({ findingCount }: { findingCount: number }) {
  const screen = useStore((s) => s.screen);
  const setScreen = useStore((s) => s.setScreen);
  const phase = useStore((s) => s.phase);
  const progress = useStore((s) => s.progress);
  const results = useStore((s) => s.results);
  const cancelScan = useStore((s) => s.cancelScan);
  const config = useStore((s) => s.config);

  const scanning = isScanning(phase);

  return (
    <aside
      style={{
        width: "var(--sidebar-w)",
        flex: "none",
        background: "var(--bg-sunken)",
        borderRight: "1px solid var(--border-subtle)",
        display: "flex",
        flexDirection: "column",
        padding: "calc(var(--titlebar-h) + 18px) 12px 18px",
        gap: 4,
      }}
    >
      <div className="row" style={{ padding: "0 10px 18px", gap: 10 }}>
        <div
          style={{
            width: 30,
            height: 30,
            borderRadius: 9,
            background: "linear-gradient(135deg, var(--cat-1), var(--cat-5))",
            display: "grid",
            placeItems: "center",
            color: "#fff",
            flex: "none",
          }}
        >
          <Icon.disk size={17} />
        </div>
        <div className="col">
          <span style={{ fontWeight: 650, letterSpacing: "-0.01em" }}>Diskus</span>
          <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
            Storage analysis
          </span>
        </div>
      </div>

      <nav className="col" style={{ gap: 2 }}>
        {NAV.map((item) => {
          const active = screen === item.screen;
          return (
            <button
              key={item.screen}
              onClick={() => setScreen(item.screen)}
              className="row"
              style={{
                gap: 11,
                height: 38,
                padding: "0 11px",
                borderRadius: "var(--radius-md)",
                background: active ? "var(--bg-raised)" : "transparent",
                color: active ? "var(--text-primary)" : "var(--text-secondary)",
                fontSize: "var(--fs-base)",
                fontWeight: active ? 600 : 500,
                textAlign: "left",
                transition:
                  "background var(--dur-fast) var(--ease-out), color var(--dur-fast) var(--ease-out)",
              }}
              aria-current={active ? "page" : undefined}
              title={`${item.label} (${item.shortcut})`}
            >
              <span style={{ color: active ? "var(--accent)" : "inherit", display: "flex" }}>
                {item.icon({ size: 17 })}
              </span>
              <span style={{ flex: 1 }}>{item.label}</span>
              {item.screen === "findings" && findingCount > 0 && (
                <span
                  className="num"
                  style={{ fontSize: "var(--fs-xs)", color: "var(--text-tertiary)" }}
                >
                  {findingCount}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="spacer" />

      {/* Scan status. Always present so the layout never jumps when a scan
          starts; it simply fills in. */}
      <div
        className="col"
        style={{
          gap: 9,
          padding: 13,
          borderRadius: "var(--radius-md)",
          background: "var(--bg-surface)",
          border: "1px solid var(--border-subtle)",
        }}
      >
        <div className="row-between">
          <span
            className="badge"
            style={{
              background:
                phase === "error"
                  ? "rgba(248,113,113,0.16)"
                  : scanning
                    ? "var(--accent-muted)"
                    : phase === "complete"
                      ? "rgba(52,211,153,0.16)"
                      : "var(--bg-raised)",
              color:
                phase === "error"
                  ? "var(--danger)"
                  : scanning
                    ? "var(--accent-hover)"
                    : phase === "complete"
                      ? "var(--success)"
                      : "var(--text-tertiary)",
            }}
          >
            {scanning && <span className="spinner" style={{ width: 9, height: 9 }} />}
            {phaseLabel(phase)}
          </span>
          {canCancel(phase) && (
            <button
              className="btn btn-ghost btn-sm"
              style={{ height: 22, padding: "0 7px", fontSize: "var(--fs-xs)" }}
              onClick={() => void cancelScan()}
            >
              Stop
            </button>
          )}
        </div>

        {scanning ? (
          <>
            <ProgressBar
              value={0}
              indeterminate
              height={4}
            />
            <div className="col" style={{ gap: 1 }}>
              <span className="num" style={{ fontSize: "var(--fs-sm)" }}>
                {formatCount(progress.files)} files · {formatBytes(progress.bytes)}
              </span>
              <span
                className="muted truncate"
                style={{ fontSize: "var(--fs-xs)", maxWidth: 180 }}
                title={progress.currentPath}
              >
                {progress.currentPath
                  ? truncatePath(progress.currentPath, 3)
                  : "Starting…"}
              </span>
            </div>
          </>
        ) : results ? (
          <div className="col" style={{ gap: 1 }}>
            <span className="num" style={{ fontSize: "var(--fs-sm)" }}>
              {formatCount(results.stats.totalFiles)} files
            </span>
            <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
              {formatDuration(results.stats.elapsedMs)} ·{" "}
              {config.roots.length} location{config.roots.length === 1 ? "" : "s"}
            </span>
          </div>
        ) : (
          <span className="muted" style={{ fontSize: "var(--fs-xs)" }}>
            No scan yet
          </span>
        )}
      </div>

      <p
        className="muted"
        style={{
          fontSize: "var(--fs-xs)",
          padding: "10px 11px 0",
          lineHeight: 1.5,
          textAlign: "center",
        }}
      >
        Everything runs locally. Nothing is uploaded.
      </p>
    </aside>
  );
}

/** The top bar. */
function TopBar({ onStartScan }: { onStartScan: () => void }) {
  const screen = useStore((s) => s.screen);
  const phase = useStore((s) => s.phase);
  const cancelScan = useStore((s) => s.cancelScan);
  const results = useStore((s) => s.results);
  const setScreen = useStore((s) => s.setScreen);

  const current = NAV.find((n) => n.screen === screen);
  const scanning = isScanning(phase);

  return (
    <header
      // With the overlay title bar the window has no other drag affordance, so
      // the topbar's empty areas are what a user grabs to move the window.
      data-tauri-drag-region
      style={{
        height: "calc(var(--topbar-h) + var(--titlebar-h))",
        flex: "none",
        display: "flex",
        alignItems: "flex-end",
        justifyContent: "space-between",
        gap: 16,
        padding: "0 var(--gap-lg)",
        paddingBottom: "14px",
        borderBottom: "1px solid var(--border-subtle)",
        background: "var(--bg-surface)",
      }}
    >
      <div className="row" style={{ gap: 12, minWidth: 0 }}>
        <h1 style={{ fontSize: "var(--fs-lg)" }}>{current?.label}</h1>
        {results?.stats.truncated && (
          <span
            className="tag"
            style={{ background: "rgba(251,191,36,0.14)", color: "var(--warning)" }}
            title={results.stats.truncated}
          >
            Partial view
          </span>
        )}
        {results?.stats.deniedPaths ? (
          <span
            className="tag"
            style={{ background: "var(--bg-raised)" }}
            title={`${results.stats.deniedPaths} locations could not be read. The scan continued past them.`}
          >
            {results.stats.deniedPaths} unreadable
          </span>
        ) : null}
      </div>

      <div className="row" style={{ gap: 10 }}>
        {results && (
          <span className="muted" style={{ fontSize: "var(--fs-sm)" }}>
            Last scan: {formatDuration(results.stats.elapsedMs)}
          </span>
        )}
        {scanning ? (
          <Button variant="secondary" onClick={() => void cancelScan()}>
            Stop scan
          </Button>
        ) : (
          <>
            <Button variant="ghost" onClick={() => setScreen("export")} disabled={!results}>
              Export
            </Button>
            <Button variant="primary" onClick={onStartScan} icon={<Icon.scan size={16} />}>
              Scan
            </Button>
          </>
        )}
      </div>
    </header>
  );
}

/** A dismissible error strip. */
function ErrorStrip() {
  const error = useStore((s) => s.error);
  const clearError = useStore((s) => s.clearError);
  if (!error) return null;

  return (
    <div
      className="banner banner-danger enter"
      style={{ margin: "12px var(--gap-lg) 0", alignItems: "center" }}
      role="alert"
    >
      <span style={{ color: "var(--danger)", display: "flex" }}>
        <Icon.alert size={17} />
      </span>
      <span style={{ flex: 1 }}>{error}</span>
      {/* Must clear the error, not the phase. Setting the phase left the banner
          on screen forever, so the button looked dead, and it also wiped a
          genuine "Failed" status while the red banner stayed put. */}
      <Button variant="ghost" size="sm" onClick={clearError}>
        Dismiss
      </Button>
    </div>
  );
}

/** Shown while the first IPC round trip resolves. */
function BootScreen() {
  return (
    <div
      style={{
        height: "100%",
        display: "grid",
        placeItems: "center",
        color: "var(--text-tertiary)",
      }}
    >
      <div className="col" style={{ alignItems: "center", gap: 14 }}>
        <span className="spinner" style={{ width: 22, height: 22 }} />
        <span style={{ fontSize: "var(--fs-sm)" }}>Preparing…</span>
      </div>
    </div>
  );
}