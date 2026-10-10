//! Small shared helpers: byte and count formatting, time conversion, hashing and
//! path display.

use crate::model::Bytes;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::SystemTime;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Current local time, falling back to UTC when the platform has no timezone
/// database available (common in minimal containers).
#[must_use]
pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc())
}

/// Convert a [`SystemTime`] from a filesystem metadata call into a timestamp.
#[must_use]
pub fn to_offset(dt: SystemTime) -> OffsetDateTime {
    OffsetDateTime::from(dt)
}

/// Render a timestamp as RFC 3339, or a dash if absent.
#[must_use]
pub fn fmt_rfc3339(dt: Option<OffsetDateTime>) -> String {
    dt.map(|d| {
        d.format(&Rfc3339)
            .unwrap_or_else(|_| d.unix_timestamp().to_string())
    })
    .unwrap_or_else(|| "-".to_string())
}

/// Render a timestamp as a compact filesystem-safe stamp: `20261010-1432`.
///
/// Used to build report filenames.
#[must_use]
pub fn compact_stamp(dt: OffsetDateTime) -> String {
    let month = dt.month();
    let day = dt.day();
    let hour = dt.hour();
    let minute = dt.minute();
    format!(
        "{:04}{:02}{:02}-{:02}{:02}",
        dt.year(),
        month,
        day,
        hour,
        minute
    )
}

/// Whole days elapsed since `dt`. `None` when `dt` is in the future.
#[must_use]
pub fn days_since(dt: Option<OffsetDateTime>, now: OffsetDateTime) -> Option<i64> {
    let dt = dt?;
    let diff = now - dt;
    if diff.is_negative() {
        None
    } else {
        Some(diff.whole_days())
    }
}

/// Format a byte count the way disk tools conventionally do: binary multiples,
/// decimal labels. `1_073_741_824` becomes `"1 GB"`.
#[must_use]
pub fn human_bytes(bytes: Bytes) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];

    if bytes < 1024 {
        return format!("{bytes} B");
    }

    let mut value = bytes as f64;
    let mut unit = 0_usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

/// Format a count with thousands separators: `1234567` becomes `"1,234,567"`.
#[must_use]
pub fn human_count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Format a count compactly: `1234567` becomes `"1.2M"`.
#[must_use]
pub fn human_count_compact(n: u64) -> String {
    const UNITS: [&str; 4] = ["", "K", "M", "B"];
    if n < 1000 {
        return n.to_string();
    }
    let mut value = n as f64;
    let mut unit = 0_usize;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0}{}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1}{}", UNITS[unit])
    } else {
        format!("{value:.2}{}", UNITS[unit])
    }
}

/// Format a millisecond duration as a short human string: `1m 04s`.
#[must_use]
pub fn human_duration(ms: u64) -> String {
    if ms < 1000 {
        return format!("{ms}ms");
    }
    let total_secs = ms / 1000;
    let secs = total_secs % 60;
    let mins = total_secs / 60;
    if mins == 0 {
        format!("{total_secs}s")
    } else if mins < 60 {
        format!("{mins}m {secs:02}s")
    } else {
        let hours = mins / 60;
        format!("{hours}h {:02}m", mins % 60)
    }
}

/// Shorten a path for display by collapsing the middle.
///
/// `"/Users/jdoe/Library/Caches/com.docker.docker/Data/xyz"` becomes
/// `"…/Caches/com.docker.docker/…"` — enough to recognise, short enough to fit.
#[must_use]
pub fn mid_truncate(path: &Path, max_segments: usize) -> String {
    let text = path.to_string_lossy();
    let sep = std::path::MAIN_SEPARATOR;
    let segments: Vec<&str> = text.split(sep).filter(|s| !s.is_empty()).collect();
    if segments.len() <= max_segments {
        return text.to_string();
    }
    let head = max_segments / 2;
    let tail = max_segments - head;
    let prefix = if text.starts_with(sep) {
        format!("{sep}")
    } else {
        String::new()
    };
    format!(
        "{prefix}{}…{}{}",
        segments[..head].join(&sep.to_string()),
        sep,
        segments[segments.len() - tail..].join(&sep.to_string())
    )
}

/// Lowercase extension of a path including the leading dot, if any.
///
/// Dotfiles with no other dot (`.bashrc`) return `None`, not `Some(".bashrc")`,
/// because there is no extension to speak of.
#[must_use]
pub fn extension_of(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let idx = name.rfind('.')?;
    // A leading dot means a dotfile, not an extension.
    if idx == 0 || idx + 1 >= name.len() {
        return None;
    }
    Some(name[idx..].to_ascii_lowercase())
}

/// Lowercase extension of a filename string, tolerating rotation suffixes.
///
/// `"app.log.3.gz"` has extension `".gz"` from [`extension_of`], but detectors
/// care that it is really `".log.3.gz"`. This returns the full dotted tail that
/// starts at the first dot: `".log.3.gz"`.
#[must_use]
pub fn compound_extension(name: &str) -> Option<String> {
    let idx = name.find('.')?;
    if idx == 0 || idx + 1 >= name.len() {
        return None;
    }
    Some(name[idx..].to_ascii_lowercase())
}

/// The filename with any `.N` / `.gz` rotation suffix stripped, plus a flag
/// saying whether anything was stripped.
///
/// `"server.log.3.gz"` becomes `("server.log", true)`. This is the key that
/// groups a rotation set into one finding rather than N findings.
#[must_use]
pub fn strip_rotation_suffix(name: &str) -> (String, bool) {
    let mut base = name;
    let mut stripped = false;
    while let Some(idx) = base.rfind('.') {
        let suffix = &base[idx + 1..];
        if suffix.is_empty() {
            break;
        }
        let lower = suffix.to_ascii_lowercase();
        let is_rotation = lower
            .trim_start_matches('0')
            .chars()
            .all(|c| c.is_ascii_digit())
            && lower.chars().any(|c| c.is_ascii_digit())
            && idx > 0;
        let is_compression = matches!(lower.as_str(), "gz" | "bz2" | "xz" | "zst" | "zip" | "lz4");
        if is_rotation || is_compression {
            base = &base[..idx];
            stripped = true;
        } else {
            break;
        }
    }
    (base.to_string(), stripped)
}

/// Stream a file through blake3 and return the hex digest.
///
/// Reads in fixed 64 KiB chunks so a 40 GiB VM image never has to fit in memory.
/// Errors are swallowed and reported as `None` — a file we cannot read is simply
/// not a hashable duplicate candidate, and one unreadable file must never abort
/// the duplicate pass.
#[must_use]
pub fn blake3_file(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0_u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(hasher.finalize().to_hex().to_string())
}

/// Best-effort machine label used in report headers.
///
/// Reads `COMPUTERNAME`, `HOSTNAME` or `HOST`, else returns `unknown-machine`.
#[must_use]
pub fn hostname() -> String {
    for key in ["COMPUTERNAME", "HOSTNAME", "HOST"] {
        if let Ok(v) = std::env::var(key) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return sanitise_hostname(&v);
            }
        }
    }
    let detected = sysinfo::System::host_name().unwrap_or_default();
    let detected = detected.trim();
    if detected.is_empty() {
        "unknown-machine".to_string()
    } else {
        sanitise_hostname(detected)
    }
}

/// Reduce arbitrary text to characters that are safe in a filename on every
/// supported platform.
///
/// Collapses runs of unsafe characters into a single dash so
/// `"Alice's Laptop (2024)"` becomes `"Alice-s-Laptop-2024"` rather than a
/// trail of dashes.
#[must_use]
pub fn sanitise_filename_part(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_was_dash = false;
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
            last_was_dash = false;
        } else if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "machine".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Reduce a hostname to characters that are safe in a filename.
#[must_use]
pub fn sanitise_hostname(raw: &str) -> String {
    sanitise_filename_part(raw)
}

/// Clamp a confidence score into `0.0..=1.0`.
///
/// Also maps NaN to `0.0`, which matters because NaN would otherwise serialise
/// as `null` and break report sorting.
#[must_use]
pub fn clamp_confidence(value: f32) -> f32 {
    if value.is_nan() {
        0.0
    } else {
        value.clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn human_bytes_uses_binary_multiples() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.00 KB");
        assert_eq!(human_bytes(1536), "1.50 KB");
        assert_eq!(human_bytes(1_073_741_824), "1.00 GB");
        assert_eq!(human_bytes(2 * 1_073_741_824), "2.00 GB");
        assert_eq!(human_bytes(15 * 1_073_741_824), "15.0 GB");
        assert_eq!(human_bytes(150 * 1_073_741_824), "150 GB");
    }

    #[test]
    fn human_counts_are_grouped() {
        assert_eq!(human_count(0), "0");
        assert_eq!(human_count(999), "999");
        assert_eq!(human_count(1000), "1,000");
        assert_eq!(human_count(1_234_567), "1,234,567");
    }

    #[test]
    fn human_count_compact_is_compact() {
        assert_eq!(human_count_compact(999), "999");
        assert_eq!(human_count_compact(1500), "1.50K");
        assert_eq!(human_count_compact(1_234_567), "1.23M");
    }

    #[test]
    fn human_duration_reads_naturally() {
        assert_eq!(human_duration(450), "450ms");
        assert_eq!(human_duration(1500), "1s");
        assert_eq!(human_duration(65_000), "1m 05s");
        assert_eq!(human_duration(3_725_000), "1h 02m");
    }

    #[test]
    fn extension_of_ignores_dotfiles() {
        assert_eq!(extension_of(Path::new("/a/b.txt")), Some(".txt".into()));
        assert_eq!(extension_of(Path::new("/a/b.TXT")), Some(".txt".into()));
        assert_eq!(extension_of(Path::new("/a/.bashrc")), None);
        assert_eq!(extension_of(Path::new("/a/b")), None);
        assert_eq!(extension_of(Path::new("/a/b.")), None);
    }

    #[test]
    fn compound_extension_keeps_full_dotted_tail() {
        assert_eq!(compound_extension("app.log.3.gz"), Some(".log.3.gz".into()));
        assert_eq!(compound_extension("app.txt"), Some(".txt".into()));
        assert_eq!(compound_extension(".bashrc"), None);
    }

    #[test]
    fn strip_rotation_suffix_groups_rotation_sets() {
        assert_eq!(
            strip_rotation_suffix("server.log"),
            ("server.log".into(), false)
        );
        assert_eq!(
            strip_rotation_suffix("server.log.1"),
            ("server.log".into(), true)
        );
        assert_eq!(
            strip_rotation_suffix("server.log.12.gz"),
            ("server.log".into(), true)
        );
        assert_eq!(
            strip_rotation_suffix("app.log.3.gz"),
            ("app.log".into(), true)
        );
    }

    #[test]
    fn mid_truncate_collapses_the_middle() {
        let p = PathBuf::from("/Users/jdoe/Library/Caches/com.docker.docker/Data/xyz");
        let out = mid_truncate(&p, 4);
        assert!(out.starts_with('/'), "keeps the leading separator: {out}");
        assert!(out.contains('…'), "collapses the middle: {out}");
        assert!(out.len() < p.to_string_lossy().len());

        let short = PathBuf::from("/a/b");
        assert_eq!(mid_truncate(&short, 4), "/a/b", "short paths pass through");
    }

    #[test]
    fn clamp_confidence_handles_nan() {
        assert_eq!(clamp_confidence(0.5), 0.5);
        assert_eq!(clamp_confidence(1.9), 1.0);
        assert_eq!(clamp_confidence(-3.0), 0.0);
        assert_eq!(clamp_confidence(f32::NAN), 0.0);
    }

    #[test]
    fn blake3_matches_known_input() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("a.txt");
        std::fs::write(&f, b"hello diskus").expect("write");
        let hash = blake3_file(&f).expect("hash should succeed");
        let expected = blake3::hash(b"hello diskus").to_hex().to_string();
        assert_eq!(hash, expected);
    }

    #[test]
    fn blake3_returns_none_for_missing_file() {
        assert!(blake3_file(Path::new("/definitely/not/here.bin")).is_none());
    }

    #[test]
    fn hostnames_are_filename_safe() {
        assert_eq!(sanitise_hostname("My MacBook Pro"), "My-MacBook-Pro");
        assert_eq!(sanitise_hostname("a/b:c"), "a-b-c");
        assert_eq!(sanitise_hostname("---"), "machine");
        assert_eq!(
            sanitise_filename_part("Alice's Laptop (2024)"),
            "Alice-s-Laptop-2024",
            "unsafe runs collapse to one dash"
        );
    }
}
