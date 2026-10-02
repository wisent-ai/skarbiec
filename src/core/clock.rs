// Format timestamps in process so obtaining the time does not compete with
// cryptographic work for subprocess capacity. Preserve the documented UTC
// formats used by stored records and audit entries.

use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

/// `date -u +%Y-%m-%dT%H:%M:%SZ`
const ISO: &[BorrowedFormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

/// `date -u +%Y%m%dT%H%M%SZ`
const COMPACT: &[BorrowedFormatItem<'_>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");

/// UTC now, as `2026-09-20T03:14:15Z`.
pub fn now_iso() -> String {
    OffsetDateTime::now_utc().format(ISO).unwrap_or_default()
}

/// UTC now, as `20260920T031415Z` — the shape a file name carries.
pub fn now_stamp() -> String {
    OffsetDateTime::now_utc()
        .format(COMPACT)
        .unwrap_or_default()
}

/// UTC now, in whole seconds since the Unix epoch — the unit a schedule
/// adds intervals to.
pub fn now_epoch() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// `epoch` in the same `2026-09-20T03:14:15Z` shape as [`now_iso`]; empty
/// when the second is outside the calendar the formatter knows.
pub fn iso_at(epoch: i64) -> String {
    OffsetDateTime::from_unix_timestamp(epoch)
        .ok()
        .and_then(|moment| moment.format(ISO).ok())
        .unwrap_or_default()
}
