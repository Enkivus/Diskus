/** The application store.
 *
 * One store, one source of truth. Screens read slices of it; nothing fetches on
 * its own. That matters during a scan, where progress events arrive 60 times a
 * second — if each component subscribed independently the same event would be
 * handled six times and the window would judder.
 */

import { create } from "zustand";
import * as ipc from "../lib/ipc";
import {
  DEFAULT_DETECTORS,
  defaultScanConfig,
} from "../lib/defaults";
import type {
  CompletePayload,
  Detector,
  ExportFormat,
  Finding,
  ProgressPayload,
  ResultsPayload,
  ScanConfig,
  ScanStatus,
  Severity,
  UserProfile,
  Volume,
} from "../lib/types";

// ─── Scan lifecycle ──────────────────────────────────────────────────────

/** Where the app is in the scan pipeline. */
export type ScanPhase =
  | "idle"
  | "starting"
  | "walking"
  | "hashing"
  | "detecting"
  | "cancelling"
  | "complete"
  | "cancelled"
  | "error";

/** Live scan progress, as shown in the sidebar. */
export interface ScanProgress {
  /** Files seen so far. */
  files: number;
  /** Directories seen so far. */
  dirs: number;
  /** Bytes seen so far. */
  bytes: number;
  /** The path currently being read. */
  currentPath: string;
  /** Milliseconds elapsed. */
  elapsedMs: number;
}

/** Which screen is showing. */
export type Screen = "dashboard" | "findings" | "scan" | "export" | "settings";

// ─── Filters ─────────────────────────────────────────────────────────────

/** Finding list filter state. */
export interface Filters {
  /** Severities to include. Empty means all. */
  severities: Severity[];
  /** Detectors to include. Empty means all. */
  detectors: Detector[];
  /** Free-text query across title, path and recommendation. */
  query: string;
  /** Only findings that are safe to delete. */
  safeOnly: boolean;
  /** Sort key. */
  sort: "reclaimable" | "severity" | "confidence" | "name";
}

const ALL_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Filters that show everything. */
export function emptyFilters(): Filters {
  return { severities: [], detectors: [], query: "", safeOnly: false, sort: "reclaimable" };
}

/** Export screen state. */
export interface ExportState {
  /** Which formats the user has ticked. */
  formats: ExportFormat[];
  /** Write full absolute paths into the report. */
  includeAbsolutePaths: boolean;
  /** Include duplicate content hashes. */
  includeHashes: boolean;
  /** Label shown in the report header. */
  machineLabel: string;
  /** Paths written by the last export. */
  lastWritten: string[];
  /** True while a write is in flight. */
  busy: boolean;
  /** Error from the last export, if any. */
  error: string | null;
}

function initialExportState(): ExportState {
  return {
    formats: ["html", "json"],
    includeAbsolutePaths: true,
    includeHashes: false,
    machineLabel: "",
    lastWritten: [],
    busy: false,
    error: null,
  };
}

// ─── Store ───────────────────────────────────────────────────────────────

interface AppStore {
  // Navigation
  screen: Screen;
  selectedFindingId: string | null;

  // Configuration
  config: ScanConfig;
  configLoaded: boolean;
  volumes: Volume[];
  profiles: UserProfile[];

  // Scan lifecycle
  phase: ScanPhase;
  runningScanId: string | null;
  progress: ScanProgress;
  status: ScanStatus | null;
  error: string | null;

  // Results
  results: ResultsPayload | null;
  loadingResults: boolean;

  // Findings
  filters: Filters;

  // Export
  exportState: ExportState;

  // Actions
  setScreen: (screen: Screen) => void;
  selectFinding: (id: string | null) => void;
  loadConfig: () => Promise<void>;
  patchConfig: (patch: Partial<ScanConfig>) => void;
  toggleDetector: (detector: Detector) => void;
  toggleRoot: (root: string) => void;
  addRoot: (root: string) => void;
  removeRoot: (root: string) => void;
  addExclusion: (path: string) => void;
  removeExclusion: (path: string) => void;
  startScan: () => Promise<void>;
  cancelScan: () => Promise<void>;
  refreshResults: (scanId?: string) => Promise<void>;
  rerunDetect: () => Promise<void>;
  setFilters: (patch: Partial<Filters>) => void;
  toggleSeverityFilter: (severity: Severity) => void;
  toggleDetectorFilter: (detector: Detector) => void;
  resetFilters: () => void;
  setExportState: (patch: Partial<ExportState>) => void;
  toggleExportFormat: (format: ExportFormat) => void;
  handleScanStarted: (e: { scanId: string; roots: string[] }) => void;
  handleProgress: (e: ProgressPayload) => void;
  handleComplete: (e: CompletePayload) => void;
  handleCancelled: () => void;
  handleError: (e: { message: string }) => void;
  setPhase: (phase: ScanPhase) => void;
  clearError: () => void;
}

export const useStore = create<AppStore>((set, get) => ({
  screen: "dashboard",
  selectedFindingId: null,

  config: defaultScanConfig(),
  configLoaded: false,
  volumes: [],
  profiles: [],

  phase: "idle",
  runningScanId: null,
  progress: { files: 0, dirs: 0, bytes: 0, currentPath: "", elapsedMs: 0 },
  status: null,
  error: null,

  results: null,
  loadingResults: false,

  filters: emptyFilters(),

  exportState: initialExportState(),

  // ─── Navigation ──────────────────────────────────────────────────────────

  setScreen: (screen) => set({ screen }),
  selectFinding: (selectedFindingId) => set({ selectedFindingId }),

  // ─── Configuration ───────────────────────────────────────────────────────

  loadConfig: async () => {
    try {
      const [config, volumes, profiles] = await Promise.all([
        ipc.getDefaultConfig(),
        ipc.listVolumes(),
        ipc.listUserProfiles(),
      ]);
      set({
        config: { ...config, detect: DEFAULT_DETECTORS },
        configLoaded: true,
        volumes,
        profiles,
      });
    } catch (error) {
      set({ error: (error as Error).message, configLoaded: true });
    }
  },

  patchConfig: (patch) => set((s) => ({ config: { ...s.config, ...patch } })),

  toggleDetector: (detector) =>
    set((s) => {
      const enabled = s.config.detect.includes(detector);
      const next = enabled
        ? s.config.detect.filter((d) => d !== detector)
        : [...s.config.detect, detector];
      return { config: { ...s.config, detect: next } };
    }),

  toggleRoot: (root) =>
    set((s) => ({
      config: {
        ...s.config,
        roots: s.config.roots.includes(root)
          ? s.config.roots.filter((r) => r !== root)
          : [...s.config.roots, root],
      },
    })),

  addRoot: (root) =>
    set((s) =>
      s.config.roots.includes(root)
        ? s
        : { config: { ...s.config, roots: [...s.config.roots, root] } },
    ),

  removeRoot: (root) =>
    set((s) => ({
      config: { ...s.config, roots: s.config.roots.filter((r) => r !== root) },
    })),

  addExclusion: (path) =>
    set((s) =>
      s.config.excludePaths.includes(path)
        ? s
        : { config: { ...s.config, excludePaths: [...s.config.excludePaths, path] } },
    ),

  removeExclusion: (path) =>
    set((s) => ({
      config: {
        ...s.config,
        excludePaths: s.config.excludePaths.filter((p) => p !== path),
      },
    })),

  // ─── Scan lifecycle ──────────────────────────────────────────────────────

  startScan: async () => {
    const { config } = get();
    if (config.roots.length === 0) {
      set({ error: "Choose at least one location to scan.", screen: "scan" });
      return;
    }
    set({
      phase: "starting",
      error: null,
      selectedFindingId: null,
      // Keeping the old results visible during the new scan looks like the scan
      // already finished, and invites exporting a report that does not match
      // what is on screen.
      results: null,
    });

    try {
      const scanId = await ipc.startScan(config);
      set({ runningScanId: scanId, phase: "walking" });
    } catch (error) {
      set({ phase: "error", error: (error as Error).message });
    }
  },

  cancelScan: async () => {
    const { runningScanId } = get();
    if (!runningScanId) return;
    try {
      await ipc.cancelScan(runningScanId);
      set({ phase: "cancelling", status: null });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  refreshResults: async (scanId?: string) => {
    // Resolution order matters. Preferring the *previous* results id meant the
    // second and every subsequent scan re-fetched scan 1's data: `handleComplete`
    // fired with the new scan's id, discarded it, and then asked for the old one.
    const target = scanId ?? get().runningScanId ?? get().results?.scanId;
    if (!target) return;

    set({ loadingResults: true });
    try {
      const payload = await ipc.getResults(target);

      // Bail if the world moved on while awaiting. A stale response landing
      // mid-scan would flip the phase back to "complete", hiding the Stop button
      // and replacing the live scan's data with an older one.
      const current = get();
      if (current.runningScanId !== null) return;
      if ((current.results?.scanId ?? target) !== target) return;

      set({ results: payload, loadingResults: false, phase: "complete" });
    } catch (error) {
      if (get().runningScanId === null) {
        set({ loadingResults: false, error: (error as Error).message });
      }
    }
  },

  rerunDetect: async () => {
    const { results, config } = get();
    if (!results) return;

    set({ phase: "detecting" });
    try {
      const detected = await ipc.rerunDetect(results.scanId, config);
      set((s) => ({
        results: s.results
          ? {
              ...s.results,
              findings: detected.findings,
              summary: detected.summary,
            }
          : s.results,
        phase: "complete",
      }));
    } catch (error) {
      set({ phase: "error", error: (error as Error).message });
    }
  },

  // ─── Filters ─────────────────────────────────────────────────────────────

  setFilters: (patch) => set((s) => ({ filters: { ...s.filters, ...patch } })),

  toggleSeverityFilter: (severity) =>
    set((s) => {
      const on = s.filters.severities.includes(severity);
      const severities = on
        ? s.filters.severities.filter((x) => x !== severity)
        : [...s.filters.severities, severity];
      // Re-selecting the full set is the same as selecting none; normalise so the
      // chip row does not show every chip lit when the user meant "everything".
      const normalised =
        severities.length === ALL_SEVERITIES.length ? [] : severities;
      return { filters: { ...s.filters, severities: normalised } };
    }),

  toggleDetectorFilter: (detector) =>
    set((s) => {
      const on = s.filters.detectors.includes(detector);
      const detectors = on
        ? s.filters.detectors.filter((x) => x !== detector)
        : [...s.filters.detectors, detector];
      return { filters: { ...s.filters, detectors } };
    }),

  resetFilters: () => set({ filters: emptyFilters() }),

  // ─── Export ──────────────────────────────────────────────────────────────

  setExportState: (patch) =>
    set((s) => ({ exportState: { ...s.exportState, ...patch } })),

  toggleExportFormat: (format) =>
    set((s) => {
      const on = s.exportState.formats.includes(format);
      const formats = on
        ? s.exportState.formats.filter((f) => f !== format)
        : [...s.exportState.formats, format];
      return { exportState: { ...s.exportState, formats, error: null } };
    }),

  // ─── Event handlers ──────────────────────────────────────────────────────

  handleScanStarted: (e) =>
    set({
      runningScanId: e.scanId,
      phase: "walking",
      progress: { files: 0, dirs: 0, bytes: 0, currentPath: "", elapsedMs: 0 },
    }),

  handleProgress: (e) =>
    set({
      progress: {
        files: e.files,
        dirs: e.dirs,
        bytes: e.bytes,
        currentPath: e.currentPath,
        elapsedMs: e.elapsedMs,
      },
    }),

  handleComplete: (e) => {
    // Fetched outside the reducer. Zustand runs an updater synchronously before
    // merging, so a `get()` inside one observes pre-update state — relying on
    // that ordering is how the wrong scan's results used to get loaded.
    void get().refreshResults(e.scanId);
    set({
      phase: "complete",
      runningScanId: null,
      status: null,
      progress: {
        files: e.totalFiles,
        dirs: e.totalDirs,
        bytes: e.totalBytes,
        currentPath: "",
        elapsedMs: e.elapsedMs,
      },
    });
  },

  handleCancelled: () =>
    set({ phase: "cancelled", runningScanId: null, status: null }),

  handleError: (e) =>
    set({ phase: "error", error: e.message, runningScanId: null, status: null }),

  setPhase: (phase) => set({ phase }),
  clearError: () => set({ error: null }),
}));

// ─── Derived selectors ───────────────────────────────────────────────────

/** Whether a scan is currently in flight. */
export function isScanning(phase: ScanPhase): boolean {
  return phase === "starting" || phase === "walking" || phase === "hashing" || phase === "detecting";
}

/** Whether the app should offer a cancel action. */
export function canCancel(phase: ScanPhase): boolean {
  return isScanning(phase) || phase === "cancelling";
}

/** A one-line description of the current phase, for the status pill. */
export function phaseLabel(phase: ScanPhase): string {
  switch (phase) {
    case "idle":
      return "Idle";
    case "starting":
      return "Starting…";
    case "walking":
      return "Reading folders…";
    case "hashing":
      return "Comparing duplicates…";
    case "detecting":
      return "Detecting waste…";
    case "cancelling":
      return "Stopping…";
    case "complete":
      return "Complete";
    case "cancelled":
      return "Stopped";
    case "error":
      return "Failed";
    default:
      return phase;
  }
}

/** Filter and sort findings according to the current filter state. */
export function selectFilteredFindings(
  findings: Finding[],
  filters: Filters,
): Finding[] {
  const query = filters.query.trim().toLowerCase();

  const filtered = findings.filter((f) => {
    if (filters.severities.length > 0 && !filters.severities.includes(f.severity)) {
      return false;
    }
    if (filters.detectors.length > 0 && !filters.detectors.includes(f.detector)) {
      return false;
    }
    if (filters.safeOnly && f.safety !== "safe_to_delete") return false;
    if (query) {
      const haystack =
        `${f.title} ${f.path} ${f.recommendation}`.toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });

  const rank = (s: Severity): number =>
    ({ critical: 5, high: 4, medium: 3, low: 2, info: 1 })[s];

  return filtered.sort((a, b) => {
    switch (filters.sort) {
      case "reclaimable":
        return b.reclaimable - a.reclaimable || rank(b.severity) - rank(a.severity);
      case "severity":
        return rank(b.severity) - rank(a.severity) || b.reclaimable - a.reclaimable;
      case "confidence":
        return b.confidence - a.confidence || b.reclaimable - a.reclaimable;
      case "name":
        return a.title.localeCompare(b.title);
      default:
        return 0;
    }
  });
}

/** Group filtered findings by detector, preserving severity order within each. */
export function groupByDetector(findings: Finding[]): Map<Detector, Finding[]> {
  const groups = new Map<Detector, Finding[]>();
  for (const f of findings) {
    const list = groups.get(f.detector) ?? [];
    list.push(f);
    groups.set(f.detector, list);
  }
  return groups;
}