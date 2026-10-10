/** Defaults mirrored from `diskus_core::config`.
 *
 * These exist so the UI can render a usable form before the first IPC round trip
 * completes, which avoids a flash of empty controls on launch. They must match
 * the Rust defaults; `loadConfig` overwrites them with the authoritative values
 * as soon as it resolves.
 */

import { DETECTORS, type Detector, type ScanConfig } from "./types";

/** One kibibyte. */
const KIB = 1024;
/** One mebibyte. */
const MIB = 1024 * KIB;
/** One gibibyte. */
const GIB = 1024 * MIB;

/** Every detector enabled. */
export const DEFAULT_DETECTORS: Detector[] = [...DETECTORS];

/** Preset configurations offered on the scan-setup screen. */
export type ScanPreset = "quick" | "deep";

/** A scan configuration with every field at its default. */
export function defaultScanConfig(): ScanConfig {
  return {
    roots: [],
    followSymlinks: false,
    includeHidden: true,
    excludeSystem: true,
    excludePaths: [],
    maxDepth: null,
    threads: null,
    minFileSizeForDupes: MIB,
    profileSizeThreshold: 40 * GIB,
    profileVolumeFraction: 0.15,
    logStaleDays: 90,
    logActiveDays: 7,
    installerStaleDays: 180,
    minInstallerSize: 50 * MIB,
    vmStaleDays: 180,
    duplicateSkipPrefixes: [
      "/System",
      "/usr",
      "/bin",
      "/sbin",
      "/lib",
      "/Applications",
      "/Library/Frameworks",
      "/nix",
      "C:\\Windows",
      "C:\\Program Files",
      "C:\\Program Files (x86)",
    ],
    maxNodes: 3_000_000,
    detect: [...DEFAULT_DETECTORS],
    label: null,
  };
}

/** Thresholds grouped for the advanced settings panel. */
export interface ThresholdField {
  /** Setting key on `ScanConfig`. */
  key:
    | "profileSizeThreshold"
    | "logStaleDays"
    | "installerStaleDays"
    | "vmStaleDays"
    | "minInstallerSize"
    | "minFileSizeForDupes"
    | "profileVolumeFraction";
  /** Label shown to the user. */
  label: string;
  /** One-line explanation of the trade-off. */
  help: string;
  /** Minimum permitted value. */
  min: number;
  /** Maximum permitted value. */
  max: number;
  /** Step size for the slider. */
  step: number;
  /** How the value should be displayed. */
  kind: "bytes" | "days" | "percent";
}

/**
 * Every tunable threshold, with the reasoning shown to the user.
 *
 * The `help` text matters: a bare number labelled "log staleness" is not
 * actionable. Explaining that a lower value means "flag logs sooner, including
 * ones still in active rotation" is what lets someone tune this safely.
 */
export const THRESHOLDS: ThresholdField[] = [
  {
    key: "profileSizeThreshold",
    label: "Oversized profile",
    help: "A user profile at or above this size is flagged regardless of disk size.",
    min: 1,
    max: 500,
    step: 1,
    kind: "bytes",
  },
  {
    key: "profileVolumeFraction",
    label: "Or above this share of the disk",
    help:
      "A profile using more than this fraction of its volume is flagged even if it is below the size threshold.",
    min: 0.05,
    max: 0.75,
    step: 0.05,
    kind: "percent",
  },
  {
    key: "logStaleDays",
    label: "Stale logs after",
    help: "Logs untouched for this long are treated as safe to delete rather than archive.",
    min: 7,
    max: 730,
    step: 1,
    kind: "days",
  },
  {
    key: "installerStaleDays",
    label: "Stale installers after",
    help: "Installers older than this are reported. Lower means more aggressive.",
    min: 30,
    max: 1095,
    step: 30,
    kind: "days",
  },
  {
    key: "vmStaleDays",
    label: "Abandoned VMs after",
    help: "A virtual machine not opened for this long is reported as abandoned.",
    min: 30,
    max: 1095,
    step: 30,
    kind: "days",
  },
  {
    key: "minInstallerSize",
    label: "Minimum installer size",
    help: "Archives and installers below this size are not worth reporting.",
    min: 1,
    max: 2000,
    step: 1,
    kind: "bytes",
  },
  {
    key: "minFileSizeForDupes",
    label: "Minimum duplicate size",
    help:
      "Files below this size are never hashed. Raising this makes duplicate detection much faster.",
    min: 1,
    max: 1000,
    step: 1,
    kind: "bytes",
  },
];

/** Description of each preset, shown on the scan-setup screen. */
export const PRESETS: Record<ScanPreset, { label: string; description: string }> = {
  quick: {
    label: "Quick sweep",
    description:
      "Your profile and the platform data folders, every detector, standard thresholds. Usually a couple of minutes.",
  },
  deep: {
    label: "Deep audit",
    description:
      "Everything including hidden files, with a year-long staleness threshold. Thorough, and noticeably slower.",
  },
};

/** Build a config for a named preset, keeping the user's chosen roots. */
export function applyPreset(preset: ScanPreset, _base: ScanConfig): Partial<ScanConfig> {
  if (preset === "deep") {
    return {
      includeHidden: true,
      excludeSystem: true,
      logStaleDays: 365,
      installerStaleDays: 365,
      vmStaleDays: 365,
    };
  }
  return {
    includeHidden: true,
    excludeSystem: true,
    logStaleDays: 90,
    installerStaleDays: 180,
    vmStaleDays: 180,
  };
}