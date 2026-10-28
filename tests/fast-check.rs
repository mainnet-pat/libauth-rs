//! A minimal, deterministic stand-in for libauth's `fast-check` and
//! `@fast-check/ava` dev-dependencies, used by the ported `*.spec.rs` tests
//! (this crate has no dependencies, including dev-dependencies).
//!
//! Spec targets include this file with `#[path = ".../tests/fast-check.rs"]
//! mod fc;`. Arbitraries are plain closures over a seeded [`Random`]; a
//! property runs its predicate against `runs` generated values (default 100,
//! like `fast-check`) and panics with the seed and the counterexample on the
//! first failure. Inputs are not shrunk. Set `FC_SEED` to reproduce or vary a
//! run.
#![allow(dead_code)]

use std::fmt::Debug;

use libauth::runtime::bigint::BigInt;

/// The number of runs used by `fc.assert` when `numRuns` is not provided.
pub const DEFAULT_NUM_RUNS: usize = 100;

/// A small, seeded pseudo-random number generator (SplitMix64).
#[derive(Clone, Debug)]
pub struct Random {
    state: u64,
}

impl Random {
    pub fn new(seed: u64) -> Self {
        Random { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A uniformly-distributed value in `0..bound` (`bound` must be non-zero).
    pub fn below(&mut self, bound: u64) -> u64 {
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let value = self.next_u64();
            if value < zone {
                return value % bound;
            }
        }
    }

    /// A uniformly-distributed value in `min..=max`.
    pub fn in_range(&mut self, min: i64, max: i64) -> i64 {
        assert!(min <= max, "invalid range: {min}..={max}");
        let span = (max as i128 - min as i128 + 1) as u128;
        if span > u64::MAX as u128 {
            return self.next_u64() as i64;
        }
        (min as i128 + self.below(span as u64) as i128) as i64
    }
}

fn seed() -> u64 {
    std::env::var("FC_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(0x6c69_6261_7574_6800)
}

/// `fc.uint8Array({ minLength, maxLength })` (lengths default to `0` and `10`,
/// like `fast-check`).
pub fn uint8_array(min_length: Option<usize>, max_length: Option<usize>) -> impl Fn(&mut Random) -> Vec<u8> {
    let min_length = min_length.unwrap_or(0);
    let max_length = max_length.unwrap_or(min_length.max(10));
    move |random| {
        let length = random.in_range(min_length as i64, max_length as i64) as usize;
        (0..length).map(|_| random.below(256) as u8).collect()
    }
}

/// `fc.integer({ min, max })` (defaults to the 32-bit signed range).
pub fn integer(min: Option<i64>, max: Option<i64>) -> impl Fn(&mut Random) -> i64 {
    let min = min.unwrap_or(i64::from(i32::MIN));
    let max = max.unwrap_or(i64::from(i32::MAX));
    move |random| random.in_range(min, max)
}

/// `fc.nat(max)` (defaults to `0x7fffffff`).
pub fn nat(max: Option<u64>) -> impl Fn(&mut Random) -> u64 {
    let max = max.unwrap_or(0x7fff_ffff);
    move |random| random.below(max + 1)
}

/// `fc.boolean()`.
pub fn boolean() -> impl Fn(&mut Random) -> bool {
    |random| random.next_u64() & 1 == 1
}

/// `fc.bigUintN(bits)`: a `BigInt` in `0..2^bits`.
pub fn big_uint_n(bits: u32) -> impl Fn(&mut Random) -> BigInt {
    move |random| {
        let bytes = bits.div_ceil(8) as usize;
        let mut little_endian: Vec<u8> = (0..bytes).map(|_| random.below(256) as u8).collect();
        let excess = bytes as u32 * 8 - bits;
        if let Some(last) = little_endian.last_mut() {
            *last &= 0xff_u8.checked_shr(excess).unwrap_or(0);
        }
        BigInt::from_bytes_le(&little_endian)
    }
}

/// `fc.string({ minLength, maxLength })`: printable ASCII characters (lengths
/// default to `0` and `10`).
pub fn string(min_length: Option<usize>, max_length: Option<usize>) -> impl Fn(&mut Random) -> String {
    let min_length = min_length.unwrap_or(0);
    let max_length = max_length.unwrap_or(min_length.max(10));
    move |random| {
        let length = random.in_range(min_length as i64, max_length as i64) as usize;
        (0..length).map(|_| char::from(0x20 + random.below(0x5f) as u8)).collect()
    }
}

/// `fc.array(arbitrary, { minLength, maxLength })` (lengths default to `0` and
/// `10`).
pub fn array<T>(
    arbitrary: impl Fn(&mut Random) -> T,
    min_length: Option<usize>,
    max_length: Option<usize>,
) -> impl Fn(&mut Random) -> Vec<T> {
    let min_length = min_length.unwrap_or(0);
    let max_length = max_length.unwrap_or(min_length.max(10));
    move |random| {
        let length = random.in_range(min_length as i64, max_length as i64) as usize;
        (0..length).map(|_| arbitrary(random)).collect()
    }
}

/// `fc.date({ min, max })` as milliseconds since the UNIX epoch (defaults to
/// the full range of JavaScript dates).
pub fn date(min: Option<i64>, max: Option<i64>) -> impl Fn(&mut Random) -> i64 {
    const MAXIMUM_DATE: i64 = 8_640_000_000_000_000;
    integer(Some(min.unwrap_or(-MAXIMUM_DATE)), Some(max.unwrap_or(MAXIMUM_DATE)))
}

/// `fc.constantFrom(...values)`.
pub fn constant_from<T: Clone>(values: Vec<T>) -> impl Fn(&mut Random) -> T {
    move |random| values[random.below(values.len() as u64) as usize].clone()
}

/// A property: an arbitrary and a predicate (`fc.property`).
pub struct Property<T> {
    arbitrary: Box<dyn Fn(&mut Random) -> T>,
    predicate: Box<dyn Fn(&T) -> bool>,
}

/// `fc.property(arbitraries..., predicate)`: combine multiple arbitraries by
/// returning a tuple from `arbitrary`.
pub fn property<T: 'static>(
    arbitrary: impl Fn(&mut Random) -> T + 'static,
    predicate: impl Fn(&T) -> bool + 'static,
) -> Property<T> {
    Property {
        arbitrary: Box::new(arbitrary),
        predicate: Box::new(predicate),
    }
}

/// `fc.assert(property, { numRuns })`.
pub fn assert<T: Debug>(property: Property<T>, num_runs: Option<usize>) {
    let seed = seed();
    let mut random = Random::new(seed);
    for run in 0..num_runs.unwrap_or(DEFAULT_NUM_RUNS) {
        let value = (property.arbitrary)(&mut random);
        let passed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (property.predicate)(&value)));
        match passed {
            Ok(true) => {}
            Ok(false) => panic!("Property failed after {} run(s) (FC_SEED={seed}). Counterexample: {value:?}", run + 1),
            Err(error) => {
                eprintln!("Property failed after {} run(s) (FC_SEED={seed}). Counterexample: {value:?}", run + 1);
                std::panic::resume_unwind(error);
            }
        }
    }
}

/// `testProp(title, arbitraries, predicate)`: like [`assert`] with the default
/// number of runs, for predicates which use assertions.
pub fn test_prop<T: Debug + 'static>(
    arbitrary: impl Fn(&mut Random) -> T + 'static,
    predicate: impl Fn(&T) + 'static,
) {
    assert(
        property(arbitrary, move |value| {
            predicate(value);
            true
        }),
        None,
    );
}
