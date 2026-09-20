// The one clock. Seven modules each spawned `/bin/date` to learn the time,
// and every one of those spawns was a process the vault's bounded crypto pool
// had to make room for: a timestamp competed with a decryption for the same
// capacity, which is how a metadata call that decrypts nothing took 14.4s on
// 2026-09-05 while four verifier sweeps held the pool.
//
// The formats are the exact strings those `date` calls produced, so a
// timestamp written before this module and one written after it are the same
// bytes. `runtime::audit::journal` already did this in process; this is that
// decision applied to the rest.

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
