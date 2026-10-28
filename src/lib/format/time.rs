use super::number::{bin_to_number_uint32_le, number_to_bin_uint32_le};

const MS_PER_LOCKTIME_SECOND: i64 = 1000;

/// The minimum Unix timestamp (inclusive) that can be encoded by a
/// transaction's `locktime`.
pub const minimumLocktimeTimestamp: u32 = 500_000_000;

/// The maximum Unix timestamp (inclusive) that can be encoded by a
/// transaction's `locktime`.
pub const maximumLocktimeTimestamp: u32 = 0xffff_ffff;

/// The minimum Date (inclusive) that can be encoded by a transaction's
/// `locktime`, as milliseconds since the Unix epoch (a JavaScript `Date`).
pub const minimumLocktimeDate: i64 = minimumLocktimeTimestamp as i64 * MS_PER_LOCKTIME_SECOND;

/// The maximum Date (inclusive) that can be encoded by a transaction's
/// `locktime`, as milliseconds since the Unix epoch (a JavaScript `Date`).
pub const maximumLocktimeDate: i64 = maximumLocktimeTimestamp as i64 * MS_PER_LOCKTIME_SECOND;

/// Errors produced by the locktime conversion functions.
pub struct LocktimeError;

impl LocktimeError {
    pub const dateOutOfRange: &'static str =
        "The provided Date is outside of the range that can be encoded in locktime.";
    pub const locktimeOutOfRange: &'static str = "The provided locktime is outside of the range that can be encoded as a Date (greater than or equal to 500000000 and less than or equal to 4294967295).";
    pub const incorrectLength: &'static str =
        "The provided locktime is not the correct length (4 bytes).";
}

/// Convert a JavaScript `Date` object (milliseconds since the Unix epoch) to its
/// equivalent transaction `locktime` representation. The `date` is rounded to
/// the nearest second (the precision of `locktime` Dates).
///
/// See {@link Transaction.locktime} for details.
pub fn date_to_locktime(date: i64) -> Result<u32, String> {
    if !(minimumLocktimeDate..=maximumLocktimeDate).contains(&date) {
        return Err(LocktimeError::dateOutOfRange.to_string());
    }
    Ok((date as f64 / MS_PER_LOCKTIME_SECOND as f64).round() as u32)
}

/// Convert a locktime to the equivalent JavaScript `Date` object (milliseconds
/// since the Unix epoch). If locktime is outside the possible range
/// (greater than or equal to `500000000` and less than or equal to
/// `4294967295`), an error message is returned.
pub fn locktime_to_date(locktime: u32) -> Result<i64, String> {
    if locktime < minimumLocktimeTimestamp {
        return Err(LocktimeError::locktimeOutOfRange.to_string());
    }
    Ok(locktime as i64 * MS_PER_LOCKTIME_SECOND)
}

/// Convert a JavaScript `Date` object (milliseconds since the Unix epoch) to its
/// equivalent transaction `locktime` bytecode representation. The `date` is
/// rounded to the nearest second (the precision of `locktime` Dates).
///
/// Note: a block-based locktime can simply be encoded with
/// {@link numberToBinUint32LE} (provided it is no larger than the maximum,
/// `499999999`).
pub fn date_to_locktime_bin(date: i64) -> Result<Vec<u8>, String> {
    date_to_locktime(date).map(number_to_bin_uint32_le)
}

const LOCKTIME_BYTE_LENGTH: usize = 4;

/// The result of {@link decodeLocktime}: a `Date` for timestamp-based locktimes
/// or a block height for height-based locktimes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedLocktime {
    /// A timestamp-based locktime, as milliseconds since the Unix epoch.
    Date(i64),
    /// A block height-based locktime.
    BlockHeight(u32),
}

/// Parse a locktime, returning a `number` for block heights, a `Date` for block
/// times, or a string for parsing errors.
pub fn decode_locktime(bin: &[u8]) -> Result<DecodedLocktime, String> {
    if bin.len() != LOCKTIME_BYTE_LENGTH {
        return Err(LocktimeError::incorrectLength.to_string());
    }
    let parsed = bin_to_number_uint32_le(bin);
    Ok(if parsed >= minimumLocktimeTimestamp {
        DecodedLocktime::Date(parsed as i64 * MS_PER_LOCKTIME_SECOND)
    } else {
        DecodedLocktime::BlockHeight(parsed)
    })
}
