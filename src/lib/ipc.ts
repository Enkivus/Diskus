/** Typed wrappers around the Tauri IPC surface.
 *
 * Every call the frontend makes to Rust goes through this file. Two reasons:
 *
 * * The payload types are declared once, so a Rust-side rename shows up as a
 *   TypeScript error rather than a runtime `undefined`.
 * * It is the single place that can be checked against the privacy guarantee.
 *   There is no `fetch`, no `XMLHttpRequest` and no WebSocket in this module,
 *   and there is no networking crate in the Rust half. File metadata never
 *   leaves the machine.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  CompletePayload,
  DetectResult,
  DirectoryPayload,
  ExportFormat,
  ExportRequest,
  ProgressPayload,
  ResultsPayload,
  ScanConfig,
  ScanStatus,
  UserProfile,
  Volume,
} from "./types";

/** A command that failed, carrying a message meant for the user. */
export interface IpcError {
  /** Human-readable explanation. */
  message: string;
}

function errorMessage(error: unknown): string {
  if (typeof error === "string") return error;
  if (error && typeof error === "object" && "message" in error) {
    return String((error as IpcError).message);
  }
  return "Something went wrong.";
}

/** Wrap an IPC call so rejections always carry a usable message. */
async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return (await invoke(command, args)) as T;
  } catch (error) {
    throw new Error(errorMessage(error));
  }
}

// ─── Commands ────────────────────────────────────────────────────────────

/** Default scan configuration, with the platform's roots filled in. */
export function getDefaultConfig(): Promise<ScanConfig> {
  return call<ScanConfig>("get_default_config");
}

/** Mounted volumes with free and total space. */
export function listVolumes(): Promise<Volume[]> {
  return call<Volume[]>("list_volumes");
}

/** User home directories found on this machine. */
export function listUserProfiles(): Promise<UserProfile[]> {
  return call<UserProfile[]>("list_user_profiles");
}

/**
 * Start a scan.
 *
 * Resolves as soon as the walk is under way — a full scan takes minutes and must
 * not block. Progress arrives on the `scan://progress` event.
 */
export function startScan(config: ScanConfig): Promise<string> {
  return call<string>("start_scan", { config });
}

/** Ask a scan to stop. Resolves to whether a matching scan was running. */
export function cancelScan(scanId: string): Promise<boolean> {
  return call<boolean>("cancel_scan", { scanId });
}

/** Current running-scan status, or `null` when idle. */
export function scanStatus(): Promise<ScanStatus | null> {
  return call<ScanStatus | null>("scan_status");
}

/** Re-run detection against a stored scan without re-walking the filesystem. */
export function rerunDetect(scanId: string, config: ScanConfig): Promise<DetectResult> {
  return call<DetectResult>("rerun_detect", { scanId, config });
}

/** Everything the dashboard needs for one scan, in a single round trip. */
export function getResults(scanId?: string): Promise<ResultsPayload> {
  return call<ResultsPayload>("get_results", scanId ? { scanId } : {});
}

/**
 * Write report files into `outputDir`.
 *
 * Resolves with the paths written. One format can produce several files — CSV
 * writes three — so the count is not the number of formats selected.
 */
export function exportReport(
  request: ExportRequest,
  outputDir: string,
): Promise<string[]> {
  return call<string[]>("export_report", { request, outputDir });
}

// ─── Events ──────────────────────────────────────────────────────────────

/** Fired when a scan begins. */
export interface StartedEvent {
  scanId: string;
  roots: string[];
}

/** Fired when a scan cannot continue. */
export interface ScanErrorEvent {
  message: string;
}

/** Subscribe to `scan://started`. */
export function onScanStarted(handler: (e: StartedEvent) => void): Promise<UnlistenFn> {
  return listen<StartedEvent>("scan://started", (e) => handler(e.payload));
}

/** Subscribe to `scan://progress`. Fires roughly 60×/second. */
export function onScanProgress(handler: (e: ProgressPayload) => void): Promise<UnlistenFn> {
  return listen<ProgressPayload>("scan://progress", (e) => handler(e.payload));
}

/** Subscribe to `scan://directory`. Fires roughly 30×/second. */
export function onScanDirectory(
  handler: (e: DirectoryPayload) => void,
): Promise<UnlistenFn> {
  return listen<DirectoryPayload>("scan://directory", (e) => handler(e.payload));
}

/** Subscribe to `scan://complete`. */
export function onScanComplete(handler: (e: CompletePayload) => void): Promise<UnlistenFn> {
  return listen<CompletePayload>("scan://complete", (e) => handler(e.payload));
}

/** Subscribe to `scan://cancelled`. */
export function onScanCancelled(handler: (e: { scanId: string }) => void): Promise<UnlistenFn> {
  return listen<{ scanId: string }>("scan://cancelled", (e) => handler(e.payload));
}

/** Subscribe to `scan://error`. */
export function onScanError(handler: (e: ScanErrorEvent) => void): Promise<UnlistenFn> {
  return listen<ScanErrorEvent>("scan://error", (e) => handler(e.payload));
}

/** Subscribe to `detect://started`. */
export function onDetectStarted(handler: (e: { scanId: string }) => void): Promise<UnlistenFn> {
  return listen<{ scanId: string }>("detect://started", (e) => handler(e.payload));
}

/**
 * Subscribe to every scan event at once.
 *
 * Returns a single unsubscribe function. Used by the store, which wants all of
 * them and should not have to remember to clean up five listeners.
 */
export async function subscribeToScanEvents(handlers: {
  onStarted?: (e: StartedEvent) => void;
  onProgress?: (e: ProgressPayload) => void;
  onDirectory?: (e: DirectoryPayload) => void;
  onComplete?: (e: CompletePayload) => void;
  onCancelled?: (e: { scanId: string }) => void;
  onError?: (e: ScanErrorEvent) => void;
}): Promise<UnlistenFn> {
  const unlisten = await Promise.all([
    onScanStarted((e) => handlers.onStarted?.(e)),
    onScanProgress((e) => handlers.onProgress?.(e)),
    onScanDirectory((e) => handlers.onDirectory?.(e)),
    onScanComplete((e) => handlers.onComplete?.(e)),
    onScanCancelled((e) => handlers.onCancelled?.(e)),
    onScanError((e) => handlers.onError?.(e)),
  ]);
  return () => unlisten.forEach((fn) => fn());
}

// ─── Convenience ─────────────────────────────────────────────────────────

/** A sensible export request for the given results. */
export function buildExportRequest(
  results: ResultsPayload,
  formats: ExportFormat[],
  options: {
    includeAbsolutePaths: boolean;
    includeHashes: boolean;
    machineLabel?: string;
  },
): ExportRequest {
  return {
    scanId: results.scanId,
    findings: results.findings,
    summary: results.summary,
    volumes: results.volumes,
    formats,
    includeAbsolutePaths: options.includeAbsolutePaths,
    roots: results.stats.roots,
    includeHashes: options.includeHashes,
    machineLabel: options.machineLabel ?? null,
  };
}