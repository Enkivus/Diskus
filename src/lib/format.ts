/** Value formatting.
 *
 * Every size shown anywhere in the UI goes through `formatBytes`. Raw byte
 * counts are never rendered directly: `1099511627776` tells a user nothing,
 * and `1.00 TB` tells them everything. The backend uses the same binary
 * multiples and the same label set, so a figure in the app and the same figure
 * in a report are always identical.
 */

const UNITS = ["B", "KB", "MB", "GB", "TB", "PB"] as const;

/** One kibibyte. */
export const KIB = 1024;
/** One mebibyte. */
export const MIB = 1024 * KIB;
/** One gibibyte. */
export const GIB = 1024 * MIB;
/** One terabyte. */
export const TIB = 1024 * GIB;

/**
 * Format a byte count the way disk tools conventionally do.
 *
 * Binary multiples with decimal labels: `1073741824` becomes `"1.00 GB"`.
 * Precision drops as the number grows, because `1.00 GB` is more readable than
 * `1.0000 GB` and no one needs byte-exact precision on a terabyte figure.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${Math.round(bytes)} B`;

  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }

  if (value >= 100) return `${value.toFixed(0)} ${UNITS[unit]}`;
  if (value >= 10) return `${value.toFixed(1)} ${UNITS[unit]}`;
  return `${value.toFixed(2)} ${UNITS[unit]}`;
}

/** Format a percentage from a 0–1 fraction. */
export function formatPercent(fraction: number, digits = 0): string {
  if (!Number.isFinite(fraction)) return "—";
  return `${(fraction * 100).toFixed(digits)}%`;
}

/** Group an integer with thousands separators. */
export function formatCount(value: number): string {
  return Math.round(value).toLocaleString();
}

/** Compact count: `1234567` becomes `"1.23M"`. */
export function formatCountCompact(value: number): string {
  if (!Number.isFinite(value)) return "—";
  const units = ["", "K", "M", "B"];
  if (value < 1000) return String(Math.round(value));

  let scaled = value;
  let unit = 0;
  while (scaled >= 1000 && unit < units.length - 1) {
    scaled /= 1000;
    unit += 1;
  }
  if (scaled >= 100) return `${scaled.toFixed(0)}${units[unit]}`;
  if (scaled >= 10) return `${scaled.toFixed(1)}${units[unit]}`;
  return `${scaled.toFixed(2)}${units[unit]}`;
}

/** A short, readable duration: `1m 04s`. */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)}ms`;

  const totalSeconds = Math.floor(ms / 1000);
  const seconds = totalSeconds % 60;
  const minutes = Math.floor(totalSeconds / 60);
  if (minutes === 0) return `${totalSeconds}s`;
  if (minutes < 60) return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${String(minutes % 60).padStart(2, "0")}m`;
}

/** A relative time: `3 days ago`. */
export function formatRelative(iso: string | undefined): string {
  if (!iso) return "—";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "—";

  const seconds = Math.max(0, (Date.now() - then) / 1000);
  if (seconds < 60) return "just now";
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.floor(minutes)} min ago`;
  const hours = minutes / 60;
  if (hours < 24) return `${Math.floor(hours)} hr ago`;
  const days = hours / 24;
  if (days < 30) return `${Math.floor(days)} day${Math.floor(days) === 1 ? "" : "s"} ago`;
  const months = days / 30;
  if (months < 12) return `${Math.floor(months)} mo ago`;
  return `${Math.floor(days / 365)} yr ago`;
}

/** An absolute date, for tooltips. */
export function formatDate(iso: string | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * Collapse the middle of a long path.
 *
 * `/Users/jdoe/Library/Caches/com.docker.docker/Data/xyz` becomes
 * `…/Caches/com.docker.docker/…`. Enough to recognise, short enough to fit in a
 * table cell without wrapping.
 */
export function truncatePath(path: string, segments = 4): string {
  const parts = path.split(/[/\\]/).filter(Boolean);
  if (parts.length <= segments) return path;

  const head = Math.floor(segments / 2);
  const tail = segments - head;
  const prefix = path.startsWith("/") || /^[A-Za-z]:/.test(path) ? "" : "";
  const ellipsis = path.startsWith("/") ? "/" : "";
  return `${ellipsis}…/${parts.slice(0, head).join("/")}/…/${parts
    .slice(parts.length - tail)
    .join("/")}${prefix}`;
}

/** Shorten a single filename for a table cell. */
export function truncateName(name: string, max = 42): string {
  if (name.length <= max) return name;
  const keep = Math.floor((max - 1) / 2);
  return `${name.slice(0, keep)}…${name.slice(name.length - keep)}`;
}

/** The last two path components, e.g. `Caches/com.docker.docker`. */
export function shortLocation(path: string): string {
  const parts = path.split(/[/\\]/).filter(Boolean);
  return parts.slice(-2).join("/") || path;
}

/** Confidence as a percentage. */
export function formatConfidence(value: number): string {
  if (!Number.isFinite(value)) return "—";
  return `${Math.round(value * 100)}%`;
}

/** Bytes as a plain integer with separators, for table columns. */
export function formatBytesExact(bytes: number): string {
  return Math.round(bytes).toLocaleString();
}