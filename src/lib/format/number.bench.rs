//! Port of `format/number.bench.ts`.
//!
//! Each benchmark compares two libauth functions (or a libauth function and a
//! JavaScript built-in, `BigInt()`, which the port provides as
//! `libauth::runtime::bigint::BigInt::parse`), so both sides are timed
//! (`std::time::Instant`). Each benchmark runs a few cycles; each cycle times
//! each benchmarked call for roughly `CYCLE_DURATION` (at least once) with
//! fresh random inputs, then checks the result, as libauth's `s.cycle` does.

use std::hint::black_box;
use std::time::{Duration, Instant};

use libauth::runtime::bigint::BigInt;
use libauth::runtime::crypto::get_random_values;
use libauth::{
    big_int_to_bin_uint64_le, big_int_to_bin_uint64_le_clamped, bin_to_big_int_uint64_le,
    bin_to_big_int_uint_be, bin_to_hex, bin_to_number_uint16_le, bin_to_number_uint32_le,
    number_to_bin_uint16_le, number_to_bin_uint16_le_clamped, number_to_bin_uint32_le,
    number_to_bin_uint32_le_clamped,
};

/// The minimum duration of one benchmark cycle.
const CYCLE_DURATION: Duration = Duration::from_millis(50);
/// The number of cycles run by each benchmark.
const CYCLES: usize = 2;

/// `Uint8Array.from(randomBytes(length))` (Node.js's `crypto`), via the
/// runtime's `crypto.getRandomValues`.
fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    get_random_values(&mut bytes).expect("random bytes");
    bytes
}

/// Time `function` for one cycle, returning the number of calls and the
/// elapsed time.
fn time_cycle(mut function: impl FnMut()) -> (u32, Duration) {
    let start = Instant::now();
    let mut calls = 0_u32;
    while calls == 0 || start.elapsed() < CYCLE_DURATION {
        function();
        calls += 1;
    }
    (calls, start.elapsed())
}

fn report(title: &str, name: &str, calls: u32, elapsed: Duration) {
    println!(
        "{title}: {name}: {:.0} ops/sec ({calls} calls, {:?} per call)",
        f64::from(calls) / elapsed.as_secs_f64(),
        elapsed / calls
    );
}

/// `` test(`node: binToBigIntUintBE vs. binToHex -> BigInt()`, ...) ``
fn bin_to_big_int_uint_be_vs_bin_to_hex_big_int() {
    let title = "node: binToBigIntUintBE vs. binToHex -> BigInt()";
    for _ in 0..CYCLES {
        // nextCycle
        let uint256_length = 32;
        let source_bin = random_bytes(uint256_length);
        let num = bin_to_big_int_uint_be(&source_bin, None);
        let mut result = BigInt::zero();
        let (calls, elapsed) = time_cycle(|| {
            result = bin_to_big_int_uint_be(black_box(&source_bin), None);
        });
        report(title, "binToBigIntUintBE", calls, elapsed);
        // s.cycle
        assert_eq!(result, num);
        let (calls, elapsed) = time_cycle(|| {
            result = BigInt::parse(&format!("0x{}", bin_to_hex(black_box(&source_bin)))).expect("a valid BigInt");
        });
        report(title, "binToHex -> BigInt()", calls, elapsed);
        // s.cycle
        assert_eq!(result, num);
    }
}

/// `` test(`node: numberToBinUint16LE vs. numberToBinUint16LEClamped`, ...) ``
fn number_to_bin_uint16_le_vs_number_to_bin_uint16_le_clamped() {
    let title = "node: numberToBinUint16LE vs. numberToBinUint16LEClamped";
    for _ in 0..CYCLES {
        // nextCycle
        let uint16_length = 2;
        let expected_bin = random_bytes(uint16_length);
        let num = bin_to_number_uint16_le(&expected_bin);
        let mut result_bin = Vec::new();
        let (calls, elapsed) = time_cycle(|| {
            result_bin = number_to_bin_uint16_le(black_box(num));
        });
        report(title, "numberToBinUint16LE", calls, elapsed);
        // s.cycle
        assert_eq!(result_bin, expected_bin);
        let (calls, elapsed) = time_cycle(|| {
            result_bin = number_to_bin_uint16_le_clamped(black_box(i64::from(num)));
        });
        report(title, "numberToBinUint16LEClamped", calls, elapsed);
        // s.cycle
        assert_eq!(result_bin, expected_bin);
    }
}

/// `` test(`node: numberToBinUint32LE vs. numberToBinUint32LEClamped`, ...) ``
fn number_to_bin_uint32_le_vs_number_to_bin_uint32_le_clamped() {
    let title = "node: numberToBinUint32LE vs. numberToBinUint32LEClamped";
    for _ in 0..CYCLES {
        // nextCycle
        let uint32_length = 4;
        let expected_bin = random_bytes(uint32_length);
        let num = bin_to_number_uint32_le(&expected_bin);
        let mut result_bin = Vec::new();
        let (calls, elapsed) = time_cycle(|| {
            result_bin = number_to_bin_uint32_le(black_box(num));
        });
        report(title, "numberToBinUint32LE", calls, elapsed);
        // s.cycle
        assert_eq!(result_bin, expected_bin);
        let (calls, elapsed) = time_cycle(|| {
            result_bin = number_to_bin_uint32_le_clamped(black_box(i64::from(num)));
        });
        report(title, "numberToBinUint32LEClamped", calls, elapsed);
        // s.cycle
        assert_eq!(result_bin, expected_bin);
    }
}

/// `` test(`node: bigIntToBinUint64LE vs. bigIntToBinUint64LEClamped`, ...) ``
fn big_int_to_bin_uint64_le_vs_big_int_to_bin_uint64_le_clamped() {
    let title = "node: bigIntToBinUint64LE vs. bigIntToBinUint64LEClamped";
    for _ in 0..CYCLES {
        // nextCycle
        let uint64_length = 8;
        let expected_bin = random_bytes(uint64_length);
        let num = bin_to_big_int_uint64_le(&expected_bin);
        let mut result_bin = Vec::new();
        let (calls, elapsed) = time_cycle(|| {
            result_bin = big_int_to_bin_uint64_le(black_box(num));
        });
        report(title, "bigIntToBinUint64LE", calls, elapsed);
        // s.cycle
        assert_eq!(result_bin, expected_bin);
        // (`bigIntToBinUint64LEClamped` takes a `BigInt` in this port)
        let num_big_int = BigInt::from_u64(num);
        let (calls, elapsed) = time_cycle(|| {
            result_bin = big_int_to_bin_uint64_le_clamped(black_box(&num_big_int));
        });
        report(title, "bigIntToBinUint64LEClamped", calls, elapsed);
        // s.cycle
        assert_eq!(result_bin, expected_bin);
    }
}

fn main() {
    bin_to_big_int_uint_be_vs_bin_to_hex_big_int();
    number_to_bin_uint16_le_vs_number_to_bin_uint16_le_clamped();
    number_to_bin_uint32_le_vs_number_to_bin_uint32_le_clamped();
    big_int_to_bin_uint64_le_vs_big_int_to_bin_uint64_le_clamped();
}
