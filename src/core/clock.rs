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

/// UTC now, as `2026-09-20T03:14:15Z`. The format has a four-digit year, so
/// it fails only for a clock past the year 9999, which is no time a record
/// can carry: that is a broken host, said as such, never an empty stamp.
pub fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(ISO)
        .expect("the system clock is past the year 9999, which no Skarbiec record can carry")
}

/// UTC now, as `20260920T031415Z` — the shape a file name carries; it fails
/// only as [`now_iso`] does.
pub fn now_stamp() -> String {
    OffsetDateTime::now_utc()
        .format(COMPACT)
        .expect("the system clock is past the year 9999, which no Skarbiec file name can carry")
}

/// UTC now, in whole seconds since the Unix epoch — the unit a schedule
/// adds intervals to.
pub fn now_epoch() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// `epoch` in the same `2026-09-20T03:14:15Z` shape as [`now_iso`]; none
/// when the second lies outside the four-digit-year calendar, so a reader
/// shows no time instead of an empty one.
pub fn iso_at(epoch: i64) -> Option<String> {
    let Ok(moment) = OffsetDateTime::from_unix_timestamp(epoch) else {
        return None;
    };
    let Ok(text) = moment.format(ISO) else {
        return None;
    };
    Some(text)
}
