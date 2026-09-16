//! Human readable units.

use std::time::Duration;

/// `bit/s` → `1.23 Mbit/s`.
pub fn fmt_bps(bps: f64) -> String {
    if bps >= 1e9 {
        format!("{:.2} Gbit/s", bps / 1e9)
    } else if bps >= 1e6 {
        format!("{:.2} Mbit/s", bps / 1e6)
    } else if bps >= 1e3 {
        format!("{:.1} kbit/s", bps / 1e3)
    } else {
        format!("{bps:.0} bit/s")
    }
}

/// Bytes → `1.5 MiB`.
pub fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Duration → `1h02m03s` / `02m03s` / `3s`.
pub fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}h{m:02}m{sec:02}s")
    } else if m > 0 {
        format!("{m}m{sec:02}s")
    } else {
        format!("{sec}s")
    }
}

/// Local wall-clock time `HH:MM:SS` without pulling in a date crate.
pub fn now_hms() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let local = secs as i64 + local_utc_offset_secs();
    let day = local.rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", day / 3600, (day % 3600) / 60, day % 60)
}

/// UTC offset of the local time zone in seconds (0 if unknown).
fn local_utc_offset_secs() -> i64 {
    #[cfg(unix)]
    {
        use std::sync::OnceLock;
        static OFFSET: OnceLock<i64> = OnceLock::new();
        *OFFSET.get_or_init(|| {
            // `date +%z` prints e.g. `-0400`; cheap and avoids libc tm plumbing.
            let out = std::process::Command::new("date").arg("+%z").output().ok();
            let text = out
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            parse_utc_offset(&text).unwrap_or(0)
        })
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// `+0800` → 28800, `-0430` → -16200.
pub fn parse_utc_offset(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    if bytes.len() != 5 {
        return None;
    }
    let sign = match bytes[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let h: i64 = s[1..3].parse().ok()?;
    let m: i64 = s[3..5].parse().ok()?;
    Some(sign * (h * 3600 + m * 60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bps_units() {
        assert_eq!(fmt_bps(0.0), "0 bit/s");
        assert_eq!(fmt_bps(999.0), "999 bit/s");
        assert_eq!(fmt_bps(1_500.0), "1.5 kbit/s");
        assert_eq!(fmt_bps(2_500_000.0), "2.50 Mbit/s");
        assert_eq!(fmt_bps(1e9), "1.00 Gbit/s");
    }

    #[test]
    fn byte_units() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1024), "1.0 KiB");
        assert_eq!(fmt_bytes(1536 * 1024), "1.5 MiB");
    }

    #[test]
    fn durations() {
        assert_eq!(fmt_duration(Duration::from_secs(3)), "3s");
        assert_eq!(fmt_duration(Duration::from_secs(123)), "2m03s");
        assert_eq!(fmt_duration(Duration::from_secs(3723)), "1h02m03s");
    }

    #[test]
    fn utc_offsets() {
        assert_eq!(parse_utc_offset("+0800"), Some(28_800));
        assert_eq!(parse_utc_offset("-0430"), Some(-16_200));
        assert_eq!(parse_utc_offset("+00:00"), None);
        assert_eq!(parse_utc_offset(""), None);
    }

    #[test]
    fn hms_shape() {
        let s = now_hms();
        assert_eq!(s.len(), 8);
        assert_eq!(&s[2..3], ":");
    }
}
