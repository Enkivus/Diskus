//! # diskus-core
//!
//! The analysis engine behind **Diskus** — a cross-platform tool that finds
//! exactly what is consuming storage on a machine, and specifically what is
//! *wasted*.
//!
//! ## Architectural contract
//!
//! This crate deliberately has two hard restrictions, enforced by review and by
//! the dependency list in `Cargo.toml`:
//!
//! 1. **No Tauri.** This crate is a plain Rust library so the entire analysis
//!    pipeline can be unit-tested headlessly.
//! 2. **No networking.** Diskus never uploads file contents, nor anything else,
//!    anywhere. There is no HTTP client in the dependency tree, so there is no
//!    code path that could leak data even by accident.
//!
//! ## Pipeline
//!
//! ```text
//! config::ScanConfig
//!     -> scan::walker::walk()      // build model::ScanResult
//!     -> detect::run_all()         // model::ScanResult -> Vec<model::Finding>
//!     -> viz::build_tree()         // bounded tree for the treemap
//!     -> report::write_reports()   // html / json / csv / markdown
//! ```
//!
//! Every detector is a pure function over [`model::ScanResult`], which makes
//! each one independently testable with a synthetic tree built in a temp dir.

#![deny(missing_docs)]
#![deny(clippy::doc_markdown)]
#![forbid(unsafe_code)]

pub mod config;
pub mod detect;
pub mod model;
pub mod report;
pub mod scan;
pub mod util;
pub mod viz;
