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

/// Whether `text` has the shape [`now_iso`] writes: the same length, a digit
/// wherever that stamp has one and the same separator everywhere else.
/// Stored stamps are compared as text, which orders them in time only when
/// both carry this shape; a value of any other shape (`tomorrow`, a local
/// offset, a date without a time) would compare as a time it does not name.
pub fn is_iso(text: &str) -> bool {
    let template = now_iso();
    text.len() == template.len()
        && text.chars().zip(template.chars()).all(|(given, shape)| {
            if shape.is_ascii_digit() {
                given.is_ascii_digit()
            } else {
                given == shape
            }
        })
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

/// UTC now, in whole seconds since the Unix epoch, as the unsigned instant a
/// grant or capability expires at. A system clock that reads before the
/// epoch is refused naming the clock, so no expiry is computed from it.
pub fn epoch_seconds() -> anyhow::Result<u64> {
    use anyhow::Context;
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .context("the system clock reads a time before the Unix epoch")
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
