/**
 * The complete TypeScript mirror of the Rust IPC surface.
 *
 * Every field name here must match a `#[serde(rename_all = "camelCase")]` struct
 * in `diskus-core`. If you change one side, change the other in the same commit —
 * there is no runtime validation, so a mismatch shows up as a silently `undefined`
 * value rather than an error.
 */

/** What kind of filesystem entry a node represents. */
export type FileKind = "file" | "dir" | "symlink" | "other";

/** One of Diskus's five detectors. */
export type Detector =
  | "growing_logs"
  | "abandoned_vms"
  | "oversized_profiles"
  | "old_installers"
  | "duplicates";

/** How much a finding matters, most severe first. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Whether deleting what a finding points at destroys data. */
export type Safety = "safe_to_delete" | "review_first" | "data_loss";

/** A report format. */
export type ExportFormat = "html" | "json" | "csv" | "markdown";

/** One filesystem entry from the scan. */
export interface ScanNode {
  path: string;
  name: string;
  parent?: string;
  depth: number;
  kind: FileKind;
  /** Apparent size: the file's own length, or the recursive sum for directories. */
  size: number;
  /** Bytes actually allocated. Differs from `size` for sparse and CoW files. */
  onDisk: number;
  modified?: string;
  accessed?: string;
  created?: string;
  extension?: string;
  hidden: boolean;
  symlinkTarget?: string;
  contentHash?: string;
  childCount: number;
  fileCount: number;
  dirCount: number;
  error?: string;
}

/** A completed filesystem walk. */
export interface ScanResult {
  id: string;
  startedAt: string;
  finishedAt?: string;
  roots: string[];
  nodes: ScanNode[];
  totalBytes: number;
  totalFiles: number;
  totalDirs: number;
  deniedPaths: string[];
  errorsSkipped: number;
  elapsedMs: number;
  cancelled: boolean;
  truncated?: string;
}

/** One actionable piece of wasted storage. */
export interface Finding {
  id: string;
  detector: Detector;
  severity: Severity;
  safety: Safety;
  title: string;
  path: string;
  relatedPaths?: string[];
  size: number;
  /** Bytes recoverable. May be less than `size`. */
  reclaimable: number;
  confidence: number;
  recommendation: string;
  /** Detector-specific structured detail, rendered as a key/value list. */
  detail: Record<string, unknown>;
  detectedAt: string;
}

/** Counts of findings at each severity. */
export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/** Per-detector rollup. */
export interface DetectorRollup {
  detector: Detector;
  findingCount: number;
  bytes: number;
}

/** Aggregate numbers for a detection run. */
export interface ScanSummary {
  totalScanned: number;
  totalReclaimable: number;
  countsBySeverity: SeverityCounts;
  countsByDetector: DetectorRollup[];
  elapsedMs: number;
}

/** A mounted volume. */
export interface Volume {
  name: string;
  mountPoint: string;
  totalBytes?: number;
  availableBytes?: number;
  isScannable: boolean;
}

/** A user home directory. */
export interface UserProfile {
  username: string;
  path: string;
  size?: number;
  totalBytes?: number;
  isCurrent: boolean;
}

/** How a scan should run. Mirrors `diskus_core::config::ScanConfig`. */
export interface ScanConfig {
  roots: string[];
  followSymlinks: boolean;
  includeHidden: boolean;
  excludeSystem: boolean;
  excludePaths: string[];
  maxDepth?: number | null;
  threads?: number | null;
  minFileSizeForDupes: number;
  profileSizeThreshold: number;
  profileVolumeFraction: number;
  logStaleDays: number;
  logActiveDays: number;
  installerStaleDays: number;
  minInstallerSize: number;
  vmStaleDays: number;
  duplicateSkipPrefixes: string[];
  maxNodes: number;
  detect: Detector[];
  label?: string | null;
}

/** One node of the bounded treemap tree. */
export interface VizNode {
  path: string;
  name: string;
  kind: FileKind;
  size: number;
  onDisk: number;
  fileCount: number;
  dirCount: number;
  children: VizNode[];
  /** Whether children were omitted because of the budget or depth limit. */
  truncated: boolean;
  omittedChildren: number;
}

/** A row in the largest-files table. */
export interface TopFile {
  path: string;
  name: string;
  size: number;
  onDisk: number;
  modified?: string;
  extension: string;
}

/** Options for shaping the treemap tree. */
export interface VizOptions {
  maxDepth: number;
  maxNodes: number;
  minSize: number;
}

/** What the scan actually saw. */
export interface ScanStats {
  totalBytes: number;
  totalOnDisk: number;
  totalFiles: number;
  totalDirs: number;
  elapsedMs: number;
  deniedPaths: number;
  errorsSkipped: number;
  truncated?: string;
  cancelled: boolean;
  roots: string[];
}

/** The dashboard's complete data set, in one round trip. */
export interface ResultsPayload {
  scanId: string;
  findings: Finding[];
  summary: ScanSummary;
  volumes: Volume[];
  profiles: UserProfile[];
  tree: VizNode;
  topFiles: TopFile[];
  stats: ScanStats;
}

/** Findings and rollups from a detection-only re-run. */
export interface DetectResult {
  findings: Finding[];
  summary: ScanSummary;
}

/** Status of a running scan. */
export interface ScanStatus {
  scanId: string;
  phase: "walking" | "hashing" | "detecting" | "done";
  walkingDone: boolean;
}

/** Live progress events. */
export interface ProgressPayload {
  files: number;
  dirs: number;
  bytes: number;
  currentPath: string;
  elapsedMs: number;
}

/** Live directory events, used to grow the treemap during a scan. */
export interface DirectoryPayload {
  path: string;
  name: string;
  depth: number;
  size: number;
  onDisk: number;
}

/** Fired when a scan finishes successfully. */
export interface CompletePayload {
  scanId: string;
  totalBytes: number;
  totalFiles: number;
  totalDirs: number;
  elapsedMs: number;
  findingCount: number;
  totalReclaimable: number;
  truncated?: string;
  deniedPaths: number;
  errorsSkipped: number;
}

/** A request to write one or more report files. */
export interface ExportRequest {
  scanId: string;
  findings: Finding[];
  summary: ScanSummary;
  volumes: Volume[];
  formats: ExportFormat[];
  includeAbsolutePaths: boolean;
  /**
   * The roots that were scanned.
   *
   * Required for relative-path rendering: the backend rewrites each path against
   * the deepest matching root, and a path outside every root stays absolute.
   */
  roots: string[];
  includeHashes: boolean;
  machineLabel?: string | null;
}

/** Every detector, in the order the UI shows them. */
export const DETECTORS: readonly Detector[] = [
  "growing_logs",
  "abandoned_vms",
  "oversized_profiles",
  "old_installers",
  "duplicates",
] as const;

/** Total findings across every severity.
 *
 * Rust exposes this as `SeverityCounts::total()`; TypeScript has no methods on
 * plain objects, so the equivalent lives here rather than being re-derived at
 * each of the dozen call sites.
 */
export function severityTotal(counts: SeverityCounts): number {
  return counts.critical + counts.high + counts.medium + counts.low + counts.info;
}

/** Human-readable detector names. */
export const DETECTOR_LABELS: Record<Detector, string> = {
  growing_logs: "Growing logs",
  abandoned_vms: "Abandoned VMs",
  oversized_profiles: "Oversized profiles",
  old_installers: "Old installers",
  duplicates: "Duplicates",
};

/** One-line explanations, shown in the scan-setup detector toggles. */
export const DETECTOR_BLURBS: Record<Detector, string> = {
  growing_logs: "Logs and rotated log sets that are consuming disk now.",
  abandoned_vms: "Virtual machines nobody has opened in months.",
  oversized_profiles: "User home directories that are too big, and why.",
  old_installers: "Stale installers and package-manager download caches.",
  duplicates: "Byte-identical files stored more than once.",
};

/** Severities, most severe first. */
export const SEVERITIES: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

/** Human-readable severity names. */
export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Numeric severity rank, so sorting descending actually works. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/** Human-readable safety verdicts. */
export const SAFETY_LABELS: Record<Safety, string> = {
  safe_to_delete: "Safe to delete",
  review_first: "Review first",
  data_loss: "Data loss",
};

/** All four export formats. */
export const EXPORT_FORMATS: readonly ExportFormat[] = [
  "html",
  "json",
  "csv",
  "markdown",
] as const;

/** Display names for export formats. */
export const EXPORT_LABELS: Record<ExportFormat, string> = {
  html: "HTML",
  json: "JSON",
  csv: "CSV",
  markdown: "Markdown",
};

/** One-line descriptions for the export format cards. */
export const EXPORT_DESCRIPTIONS: Record<ExportFormat, string> = {
  html: "Self-contained interactive page with charts. Opens anywhere, offline.",
  json: "Complete structured data for scripting and automation.",
  csv: "Spreadsheet-friendly tables for IT triage. Three files.",
  markdown: "Readable summary document with top findings and actions.",
};

/** How many files each format produces. */
export const EXPORT_FILE_COUNTS: Record<ExportFormat, number> = {
  html: 1,
  json: 1,
  csv: 3,
  markdown: 1,
};

/**
 * The categorical colour ramp, in order.
 *
 * Index 0 is `--cat-1` in `tokens.css`. Kept in one place so the treemap, the
 * charts, the findings list and the HTML report all agree on what "blue" means.
 */
export const CATEGORICAL: readonly string[] = [
  "#6E8BFF",
  "#34D399",
  "#FBBF24",
  "#F87171",
  "#C084FC",
  "#22D3EE",
  "#FB923C",
  "#A3E635",
  "#F472B6",
  "#818CF8",
  "#2DD4BF",
  "#EAB308",
] as const;

/**
 * Which ramp index each detector always uses.
 *
 * A detector getting the same colour everywhere in the product is what lets a
 * user learn "orange means duplicates" once instead of every time.
 */
export const DETECTOR_COLOR_INDEX: Record<Detector, number> = {
  oversized_profiles: 0,
  growing_logs: 2,
  abandoned_vms: 4,
  duplicates: 5,
  old_installers: 6,
};

/** The ramp colour for a detector. */
export function detectorColor(detector: Detector): string {
  return CATEGORICAL[DETECTOR_COLOR_INDEX[detector] % CATEGORICAL.length];
}

/** Severity colours, matching the CSS custom properties. */
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#FF4D6D",
  high: "#FF8A3D",
  medium: "#FBBF24",
  low: "#4ADE80",
  info: "#60A5FA",
};

/** Colour for a top-level path, derived from its name so it is stable. */
export function colorForPath(path: string): string {
  let hash = 0;
  for (let i = 0; i < path.length; i += 1) {
    hash = (hash * 31 + path.charCodeAt(i)) | 0;
  }
  return CATEGORICAL[Math.abs(hash) % CATEGORICAL.length];
}