# Diskus

<p align="center">
  <img src="assets/diskus-icon.svg" alt="Diskus storage analysis icon" width="112" height="112">
</p>

[![CI](https://github.com/Enkivus/Diskus/actions/workflows/ci.yml/badge.svg)](https://github.com/Enkivus/Diskus/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Tauri](https://img.shields.io/badge/tauri-2-24C8DB.svg)](https://tauri.app)

Diskus scans a machine and reports what is consuming storage, then separates what is genuinely
wasted from what is merely large. It looks for five specific things: growing log files, abandoned
virtual machines, oversized user profiles, stale installers and package caches, and byte-identical
duplicate data. Findings can be exported as HTML, JSON, CSV and Markdown reports.

Diskus never deletes anything and never modifies anything. It produces findings with a reclaimable
size, a confidence score, a safety verdict and a recommendation, and leaves the decision to you.

All analysis runs locally. The analysis crate has no networking dependency at all, so there is no
code path that could transmit file contents, file names or statistics. Scanning reads filesystem
metadata only; the duplicate check hashes file contents in memory and retains only the digest.


## Status

Diskus is pre-1.0 (`0.1.0`) and macOS is the only platform the detectors have been exercised on.
The Windows and Linux backends exist and compile in CI, but nobody has run them against a live
machine yet. Two known limitations are worth knowing before you rely on it:

- Settings do not persist between launches. Changing a threshold or a scan root resets on restart.
- The treemap is drawn once a scan completes, not progressively while it runs.

Nothing here is a plan for later. It is what the code does today.


## The application

Five screens, reachable from the sidebar or by number key:

| Key | Screen | What it is for |
| --- | --- | --- |
| `1` | Dashboard | Totals, severity and category charts, and the treemap of the scanned tree. |
| `2` | Findings | Every finding, sortable and filterable by detector, severity and safety verdict. |
| `3` | Scan setup | Roots, exclusions, detectors and the threshold panel. |
| `4` | Export | Format selection, privacy controls and the report label. |
| `5` | Settings | Thresholds and the privacy statement. |

`Esc` closes the finding detail panel, and `Space` cancels a running scan. Shortcuts are suppressed
while a text field has focus, so typing a digit into a search box does not navigate away.

Scan setup offers two presets. **Quick sweep** covers your profile and the platform data folders with
standard thresholds. **Deep audit** additionally descends into hidden files and drops the staleness
thresholds to a year, which is slower and produces more findings. Every threshold is also adjustable
individually, and each one carries a sentence explaining what lowering it would mean — a bare number
labelled "log staleness" is not actionable, and tuning it blindly is how people delete the wrong
thing.

The treemap is an interactive squarified layout of the filesystem tree, built server-side in
`diskus-core` and bounded to 2,500 nodes and four levels deep. That cap is deliberate: an unbounded
layout over a multi-million-file scan is what freezes the window. Clicking a tile drills in, and the
breadcrumb walks back out.


## Supported platforms

The project contains scanning and analysis backends for macOS, Windows and Linux. Their coverage
differs, and only macOS has been built and exercised end to end so far:

- **macOS:** fully exercised. Volumes and free space are read through `sysinfo`. Log detection
  covers `/var/log`, `~/Library/Logs` and rotated sets. Abandoned-VM detection covers VMware,
  VirtualBox, Parallels, QEMU, UTM and Hyper-V images. System directories such as `/private/var/vm`
  and `/System` are excluded, because they are large but not reclaimable and reporting them as
  wasted space would be actively misleading.
- **Windows:** implemented but not verified on a Windows host. Volumes are enumerated through the
  same `sysinfo` backend and drive letters. Log detection covers `C:\Windows\Logs`, the Event
  Viewer logs and IIS. VM detection covers Hyper-V VHD/VHDX, VMware and VirtualBox. Path comparison
  is performed on normalised strings rather than `Path`, because Windows separators do not parse on
  Unix.
- **Linux:** implemented but not verified on a Linux host. Volumes come from the same backend.
  Log detection covers `/var/log`, systemd journal files and Docker container logs. Virtual machine
  detection covers QEMU/KVM images.

Matching is heuristic. Every finding carries a confidence score and the reasoning behind it. Read
the path, the size, the confidence and the recommendation before acting on any of it.


## Build and run

Install a recent stable Rust toolchain with the `rustfmt` and `clippy` components, and Node 20 or
newer, then run:

```sh
npm install

cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings

npx tsc --noEmit
npm run tauri dev
```

`npm run tauri dev` starts the Vite dev server and launches the application against it.

On Linux the Tauri build needs the WebKit stack installed first, or `tauri dev` will fail to link:

```sh
sudo apt-get install -y libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev \
  libxdo-dev libssl-dev build-essential
```

macOS and Windows need nothing beyond the toolchains above.

For a release build, `npm run tauri build` produces a native bundle and installer. Nothing is signed
or notarised yet, so expect Gatekeeper to object on macOS and SmartScreen to object on Windows until
code signing lands.

The analysis engine is a plain Rust library with no UI dependency and can be exercised without
launching the app. This writes every report format for a synthetic machine:

```sh
cargo run -p diskus-core --example export_demo -- /tmp/diskus-reports
```

`crates/diskus-core/tests/pipeline.rs` runs the whole product headlessly: it builds a synthetic
filesystem, walks it, runs all five detectors, writes every report format and asserts that the
totals are internally consistent. It is part of the normal test run, and it is where the two most
serious classes of bug were caught — a profile reporting more reclaimable space than the disk
held, and the relative-path privacy option that did nothing.

Platform-specific behaviour should still be exercised on each target operating system before release,
not just compiled. See [Status](#status).


## Project layout

```
crates/diskus-core/   The whole analysis engine. Plain Rust, no Tauri, no networking.
  src/scan/           Parallel filesystem walker, platform knowledge, cancellation.
  src/detect/         The five detectors, plus the shared classification rules they agree on.
  src/report/         HTML, JSON, CSV and Markdown writers.
  src/viz.rs          Bounded treemap tree construction.
  examples/           export_demo, for exercising the engine without a UI.
  tests/              pipeline.rs, the end-to-end test.

src-tauri/            The desktop shell. Commands, scan state, capabilities. Depends on diskus-core.
src/                  The frontend. React 19, TypeScript, zustand, Vite.
assets/               Source artwork for the app icon.
```

The split is the load-bearing part. `diskus-core` knows nothing about the UI and can be built, tested
and run headlessly on a machine with no display, which is why the privacy guarantee is structural
rather than aspirational — there is no networking crate in its dependency graph to begin with, and a
CI job asserts that stays true.


## Continuous integration

Every push and pull request runs three jobs:

- **`core`** — rustfmt, clippy with `-D warnings`, the test suite, `tsc --noEmit` and the Vite
  production build. This is the fast gate and the one to wait for. It needs no system libraries,
  because it never compiles the Tauri shell.
- **`build`** — a full `tauri build` on macOS, Windows and Linux. This is what proves the frontend,
  the Rust core and the platform layer still agree with each other. Unsigned by design: a compile is
  the point, and CI has no way to hold a signing certificate.
- **`audit`** — a grep that fails the build if `diskus-core` has gained an HTTP client, `cargo deny`
  for advisories, and `npm audit` at high severity. Currently non-blocking while the baseline is
  still being established.

If you add a dependency to `diskus-core`, the audit job will tell you whether you just broke the
offline guarantee. That is intentional.


## Reports

Reports are written to a folder you choose when exporting, and are named
`diskus-report-{machine}-{YYYYMMDD-HHMM}`.

- **HTML** — a single self-contained file with an inline treemap, severity and category charts and
  a sortable findings table. It embeds all CSS and JavaScript, loads no external assets and makes no
  network requests, so it opens correctly offline and on a locked-down network.
- **JSON** — the complete structured result, suitable for scripting. Content hashes are omitted
  unless explicitly enabled for that export.
- **CSV** — up to three files: findings, duplicate clusters, and largest files. The last two are
  written only when there is something to put in them, so a machine with no duplicates produces
  two CSV files rather than an empty third. Written with a UTF-8 byte order mark and CRLF line
  endings so spreadsheets open them without manual reformatting.
- **Markdown** — a human-readable summary grouped by the action required.

Selecting more than one format writes one file per format. Whenever more than one *file* is written
— which includes a single-format CSV export that produced three files — a
`diskus-report-{machine}-{stamp}-manifest.json` is written alongside them, listing every file, its
size and format. It is written last, and it carries the timestamped stem rather than the bare
`manifest.json` so it cannot silently overwrite the JSON report.

Reclaimable totals are the sum of individual findings; a single file can be claimed by more than one
detector, so the total is an upper bound rather than a guaranteed amount of free space. Every report
states this in its footer.


## Privacy controls on export

Reports carry paths, sizes, timestamps and severities. Two controls decide how much of that leaves
the machine, both exposed on the export screen and both defaulting to the safer setting:

- **Full paths off (the default).** Paths are rendered relative to the scanned root, and the
  redaction applies everywhere a path can hide — the displayed path, the structured `basePath` and
  `keepSuggestion` fields, and detector prose in the recommendation text. A report passed to a
  colleague does not disclose your home directory layout. This is enforced by
  `tests/pipeline.rs::relative_path_mode_leaks_no_absolute_paths`, which greps the generated JSON for
  the scan root and fails if it appears on any line.
- **Content hashes off (the default).** Duplicate findings carry a blake3 digest proving two files
  are byte-identical. The digest reveals nothing about the contents and is never transmitted, but a
  shared report rarely needs it, so it is included only when explicitly enabled for that export.

Every report embeds the same privacy statement, and every report states the counting caveat in its
footer.


## License

Diskus is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If
not, see <https://www.gnu.org/licenses/>.

SPDX identifier: `GPL-3.0-or-later`. Full text in [LICENSE](LICENSE).

This is the viral copyleft: anyone who distributes a modified build of Diskus, in source or binary
form, must publish their modifications under the same terms.
