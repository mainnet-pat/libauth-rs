//! Port of `format/time.spec.ts`.
//!
//! JavaScript `Date`s are milliseconds since the UNIX epoch (`i64`) in Rust.

#[path = "../../../tests/fast-check.rs"]
mod fc;

use libauth::{
    date_to_locktime, date_to_locktime_bin, decode_locktime, hex_to_bin, locktime_to_date,
    maximumLocktimeDate, maximumLocktimeTimestamp, minimumLocktimeDate, minimumLocktimeTimestamp,
    DecodedLocktime, LocktimeError,
};

/// `new Date('2019-10-13')`
const DATE_2019_10_13: i64 = 1_570_924_800_000;
/// `new Date('2107-01-01')`
const DATE_2107_01_01: i64 = 4_323_283_200_000;

#[test]
fn date_to_locktime_() {
    assert_eq!(date_to_locktime(DATE_2019_10_13), Ok(1570924800));
    assert_eq!(
        date_to_locktime(DATE_2107_01_01),
        Err(LocktimeError::dateOutOfRange.to_string())
    );
}

#[test]
fn date_to_locktime_bin_() {
    assert_eq!(date_to_locktime_bin(DATE_2019_10_13), Ok(hex_to_bin("0069a25d")));
    assert_eq!(
        date_to_locktime_bin(DATE_2107_01_01),
        Err(LocktimeError::dateOutOfRange.to_string())
    );
}

#[test]
fn parse_lock_time() {
    assert_eq!(
        decode_locktime(&hex_to_bin("0069a25d")),
        Ok(DecodedLocktime::Date(DATE_2019_10_13))
    );
    assert_eq!(
        decode_locktime(&hex_to_bin("d090371c")),
        Ok(DecodedLocktime::BlockHeight(473403600))
    );
    assert_eq!(
        decode_locktime(&hex_to_bin("")),
        Err(LocktimeError::incorrectLength.to_string())
    );
    assert_eq!(
        decode_locktime(&hex_to_bin("00")),
        Err(LocktimeError::incorrectLength.to_string())
    );
    assert_eq!(
        decode_locktime(&hex_to_bin("0000000000")),
        Err(LocktimeError::incorrectLength.to_string())
    );
}

#[test]
fn fast_check_date_to_locktime_locktime_to_date() {
    fc::test_prop(
        fc::integer(
            Some(i64::from(minimumLocktimeTimestamp)),
            Some(i64::from(maximumLocktimeTimestamp)),
        ),
        |timestamp| {
            let timestamp = *timestamp as u32;
            // `locktimeToDate(timestamp) as Date`
            assert_eq!(
                date_to_locktime(locktime_to_date(timestamp).expect("a Date")),
                Ok(timestamp)
            );
        },
    );
}

#[test]
fn fast_check_date_to_locktime_bin_decode_locktime() {
    fc::test_prop(
        fc::date(Some(minimumLocktimeDate), Some(maximumLocktimeDate)),
        |date| {
            // new Date(Math.round(date.getTime() / 1000) * 1000)
            let with_second_resolution = (*date as f64 / 1000.0).round() as i64 * 1000;
            // `(decodeLocktime(dateToLocktimeBin(withSecondResolution) as Uint8Array) as Date).getTime()`
            let decoded = decode_locktime(&date_to_locktime_bin(with_second_resolution).expect("a Uint8Array"));
            let time = match decoded {
                Ok(DecodedLocktime::Date(time)) => time,
                other => panic!("expected a Date: {other:?}"),
            };
            assert_eq!(time, with_second_resolution);
        },
    );
}
