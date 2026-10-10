# Diskus

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

Platform-specific behaviour should be compiled and exercised on each target operating system
before release. Only macOS has been verified.


## Reports

Reports are written to a folder you choose when exporting, and are named
`diskus-report-{machine}-{YYYYMMDD-HHMM}`.

- **HTML** — a single self-contained file with an inline treemap, severity and category charts and
  a sortable findings table. It embeds all CSS and JavaScript, loads no external assets and makes no
  network requests, so it opens correctly offline and on a locked-down network.
- **JSON** — the complete structured result, suitable for scripting. Content hashes are omitted
  unless explicitly enabled for that export.
- **CSV** — three files: findings, duplicate clusters, and largest files. Written with a UTF-8 byte
  order mark and CRLF line endings so spreadsheets open them without manual reformatting.
- **Markdown** — a human-readable summary grouped by the action required.

Selecting more than one format writes one file per format, plus a `manifest.json` listing what was
produced. Reclaimable totals are the sum of individual findings; a single file can be claimed by
more than one detector, so the total is an upper bound rather than a guaranteed amount of free space.
Every report states this in its footer.


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