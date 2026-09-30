//! ISO 8601 UTC timestamps, replacing `new Date().toISOString()`, and the
//! millisecond stopwatch the benchmark loops share.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Milliseconds elapsed since `started`, as the benchmark loops report them.
#[inline]
pub fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1e3
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn iso8601_now() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    iso8601_from_unix_millis(millis as i128)
}

/// The same instant with `:` replaced by `-`, for use in file names.
pub fn iso8601_now_for_filename() -> String {
    iso8601_now().replace(':', "-")
}

fn iso8601_from_unix_millis(millis: i128) -> String {
    let (days, ms_of_day) = (millis.div_euclid(86_400_000), millis.rem_euclid(86_400_000));
    let (year, month, day) = civil_from_days(days as i64);
    let seconds = ms_of_day / 1000;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60,
        ms_of_day % 1000,
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a civil date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (year + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(iso8601_from_unix_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            iso8601_from_unix_millis(1_710_000_000_000),
            "2024-03-09T16:00:00.000Z"
        );
        assert_eq!(
            iso8601_from_unix_millis(1_709_164_800_123),
            "2024-02-29T00:00:00.123Z"
        );
    }

    #[test]
    fn filename_form_has_no_colons() {
        assert!(!iso8601_now_for_filename().contains(':'));
    }
}
