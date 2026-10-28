//! Numeric VMB test-case generators (`bch-vmb-test-mixins.bigint.ts`).

use std::sync::LazyLock;
use crate::format::{bin_to_hex, hex_to_bin};
use crate::vmb_tests::bch_vmb_test_mixins::repeat;
use crate::vmb_tests::bch_vmb_test_utils::{generate_combinations, PossibleTestValue, TestValues};
use crate::runtime::bigint::BigInt;
use crate::vm::{big_int_to_vm_number, vm_number_to_big_int};

/// `positiveZeros`.
pub static positiveZeros: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    vec![
        ("zero".to_string(), "0".to_string()),
        ("padded zero".to_string(), "0x00".to_string()),
    ]
});

/// `zeros`.
pub static zeros: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    let mut values = positiveZeros.clone();
    values.push(("negative zero".to_string(), "0x80".to_string()));
    values.push(("padded negative zero".to_string(), "0x0080".to_string()));
    values
});

/// `giantZeros`.
pub static giantZeros: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    vec![
        (
            "padded zero (520 bytes)".to_string(),
            repeat("0x00", 520),
        ),
        (
            "padded negative zero (520 bytes)".to_string(),
            format!("{} 0x80", repeat("0x00", 519)),
        ),
        (
            "padded zero (521 bytes)".to_string(),
            repeat("0x00", 521),
        ),
        (
            "padded negative zero (521 bytes)".to_string(),
            format!("{} 0x80", repeat("0x00", 520)),
        ),
    ]
});

/// `allZeros`.
pub static allZeros: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    let mut values = zeros.clone();
    values.extend(giantZeros.clone());
    values
});

/// `ones`.
pub static ones: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    vec![
        ("one".to_string(), "1".to_string()),
        ("padded one".to_string(), "0x0100".to_string()),
        ("negative one".to_string(), "-1".to_string()),
        ("padded negative one".to_string(), "0x0180".to_string()),
    ]
});

/// `giantOnes`.
pub static giantOnes: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    vec![
        (
            "padded one (520 bytes)".to_string(),
            format!("0x01 {}", repeat("0x00", 519)),
        ),
        (
            "padded negative one (520 bytes)".to_string(),
            format!("0x01 {} 0x80", repeat("0x00", 518)),
        ),
        (
            "padded one (521 bytes)".to_string(),
            format!("0x01 {}", repeat("0x00", 520)),
        ),
        (
            "padded negative one (521 bytes)".to_string(),
            format!("0x01 {} 0x80", repeat("0x00", 519)),
        ),
    ]
});

/// `smallZerosAndOnes`.
pub static smallZerosAndOnes: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    let mut values = zeros.clone();
    values.extend(ones.clone());
    values
});

/// `zerosAndOnes`.
pub static zerosAndOnes: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    let mut values = smallZerosAndOnes.clone();
    values.extend(giantZeros.clone());
    values.extend(giantOnes.clone());
    values
});

/// `justZeroAndOne`.
pub static justZeroAndOne: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    vec![
        ("zero".to_string(), "0".to_string()),
        ("one".to_string(), "1".to_string()),
    ]
});

fn opcode_values(opcodes: &[&str]) -> Vec<PossibleTestValue> {
    opcodes
        .iter()
        .map(|opcode| (opcode.to_string(), opcode.to_string()))
        .collect()
}

/// `unaryOpcodes`.
pub static unaryOpcodes: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    opcode_values(&[
        "OP_BIN2NUM",
        "OP_INVERT",
        "OP_1ADD",
        "OP_1SUB",
        "OP_NEGATE",
        "OP_ABS",
        "OP_NOT",
        "OP_0NOTEQUAL",
    ])
});

/// `binaryOpcodes`.
pub static binaryOpcodes: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    opcode_values(&[
        "OP_NUM2BIN",
        "OP_LSHIFTNUM",
        "OP_RSHIFTNUM",
        "OP_LSHIFTBIN",
        "OP_RSHIFTBIN",
        "OP_ADD",
        "OP_SUB",
        "OP_BOOLAND",
        "OP_BOOLOR",
        "OP_NUMEQUAL",
        "OP_NUMEQUALVERIFY",
        "OP_NUMNOTEQUAL",
        "OP_LESSTHAN",
        "OP_LESSTHANOREQUAL",
        "OP_GREATERTHAN",
        "OP_GREATERTHANOREQUAL",
        "OP_MIN",
        "OP_MAX",
        "OP_MUL",
        "OP_DIV",
        "OP_MOD",
    ])
});

/// `ternaryOpcodes`.
pub static ternaryOpcodes: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| {
    opcode_values(&["OP_WITHIN"])
});

/// `bigintNumberLengths`.
pub const bigintNumberLengths: [usize; 6] = [1, 8, 64, 512, 4096, 8192];

/// `generateBenchmarkNumbers`.
pub fn generate_benchmark_numbers(
    fill: (&str, &str),
    set_high_bit: Option<bool>,
) -> Vec<PossibleTestValue> {
    let set_high_bit = set_high_bit.unwrap_or(false);
    bigintNumberLengths
        .iter()
        .map(|length| {
            let value = fill.1.repeat(*length);
            let valid = if set_high_bit {
                format!("{}01", &value[..value.len() - 2])
            } else {
                value
            };
            (
                format!("{length}-byte number ({})", fill.0),
                valid,
            )
        })
        .collect()
}

/// The type of `benchmarkNumberPossibilities`.
#[derive(Clone, Debug)]
pub struct BenchmarkNumberPossibilities {
    pub all_bits: Vec<PossibleTestValue>,
    pub alternating_bits: Vec<PossibleTestValue>,
    pub highest_bit: Vec<PossibleTestValue>,
    pub one_bit_per_byte: Vec<PossibleTestValue>,
}

/// `benchmarkNumberPossibilities`.
pub static benchmarkNumberPossibilities: LazyLock<BenchmarkNumberPossibilities> = LazyLock::new(|| {
    BenchmarkNumberPossibilities {
        all_bits: generate_benchmark_numbers(("all bits set", "ff"), None),
        alternating_bits: generate_benchmark_numbers(("alternating bits set", "55"), None),
        highest_bit: generate_benchmark_numbers(("highest-bit set", "00"), Some(true)),
        one_bit_per_byte: generate_benchmark_numbers(("one bit set per byte", "01"), None),
    }
});

/// `benchmarkNumberPossibilitiesAll`.
pub static benchmarkNumberPossibilitiesAll: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    let possibilities = benchmarkNumberPossibilities.clone();
    possibilities
        .all_bits
        .into_iter()
        .chain(possibilities.alternating_bits)
        .chain(possibilities.highest_bit)
        .chain(possibilities.one_bit_per_byte)
        .map(|test_case| vec![test_case])
        .collect()
});

fn parse_vm_number(test_case: &PossibleTestValue) -> BigInt {
    let (description, value) = test_case;
    let bin = hex_to_bin(value);
    vm_number_to_big_int(&bin, Some(crate::vm::ConsensusBch2025.maximum_vm_number_byte_length), None).unwrap_or_else(|error| {
        panic!(
            "Libauth VMB test generation error while parsing number: \"{description}\". Error: {error:?}"
        )
    })
}

/// `appendNumericResult`.
pub fn append_numeric_result(
    test_values: Vec<TestValues>,
    operation: impl Fn(&[BigInt]) -> BigInt,
    expected_length: usize,
) -> Vec<TestValues> {
    test_values
        .into_iter()
        .map(|mut possibilities| {
            assert_eq!(
                possibilities.len(),
                expected_length,
                "Libauth VMB test generation error: Expected {expected_length} values, but got {}",
                possibilities.len()
            );
            let values: Vec<BigInt> = possibilities.iter().map(parse_vm_number).collect();
            let result = operation(&values);
            possibilities.push((
                "result".to_string(),
                bin_to_hex(&big_int_to_vm_number(&result)),
            ));
            possibilities
        })
        .collect()
}

/// `appendUnaryNumericResult`.
pub fn append_unary_numeric_result(
    test_values: Vec<TestValues>,
    operation: impl Fn(&BigInt) -> BigInt,
) -> Vec<TestValues> {
    append_numeric_result(test_values, move |values| operation(&values[0]), 1)
}

/// `appendBinaryNumericResult`.
pub fn append_binary_numeric_result(
    test_values: Vec<TestValues>,
    operation: impl Fn(&BigInt, &BigInt) -> BigInt,
) -> Vec<TestValues> {
    append_numeric_result(
        test_values,
        move |values| operation(&values[0], &values[1]),
        2,
    )
}

/// `appendTernaryNumericResult`.
pub fn append_ternary_numeric_result(
    test_values: Vec<TestValues>,
    operation: impl Fn(&BigInt, &BigInt, &BigInt) -> BigInt,
) -> Vec<TestValues> {
    append_numeric_result(
        test_values,
        move |values| operation(&values[0], &values[1], &values[2]),
        3,
    )
}

fn combinations(possibilities: &[Vec<PossibleTestValue>]) -> Vec<TestValues> {
    generate_combinations(possibilities)
}

/// `numberCombinationsAllBits`.
pub static numberCombinationsAllBits: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    let p = benchmarkNumberPossibilities.clone();
    combinations(&[p.all_bits.clone(), p.all_bits])
});

/// `numberCombinationsAlternatingBits`.
pub static numberCombinationsAlternatingBits: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    let p = benchmarkNumberPossibilities.clone();
    combinations(&[p.alternating_bits.clone(), p.alternating_bits])
});

/// `numberCombinationsHighestBit`.
pub static numberCombinationsHighestBit: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    let p = benchmarkNumberPossibilities.clone();
    combinations(&[p.highest_bit.clone(), p.highest_bit])
});

/// `numberCombinationsOneBitPerByte`.
pub static numberCombinationsOneBitPerByte: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    let p = benchmarkNumberPossibilities.clone();
    combinations(&[p.one_bit_per_byte.clone(), p.one_bit_per_byte])
});

/// `allBinaryNumberCombinations`.
pub static allBinaryNumberCombinations: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    let mut values = numberCombinationsAllBits.clone();
    values.extend(numberCombinationsAlternatingBits.clone());
    values.extend(numberCombinationsHighestBit.clone());
    values.extend(numberCombinationsOneBitPerByte.clone());
    values
});

/// `allTernaryNumberCombinations`.
pub static allTernaryNumberCombinations: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    let p = benchmarkNumberPossibilities.clone();
    let mut values = combinations(&[p.all_bits.clone(), p.all_bits.clone(), p.all_bits]);
    values.extend(combinations(&[
        p.alternating_bits.clone(),
        p.alternating_bits.clone(),
        p.alternating_bits,
    ]));
    values.extend(combinations(&[
        p.highest_bit.clone(),
        p.highest_bit.clone(),
        p.highest_bit,
    ]));
    values.extend(combinations(&[
        p.one_bit_per_byte.clone(),
        p.one_bit_per_byte.clone(),
        p.one_bit_per_byte,
    ]));
    values
});

fn one() -> BigInt {
    BigInt::from_i64(1)
}

fn zero() -> BigInt {
    BigInt::from_i64(0)
}

fn boolean(value: bool) -> BigInt {
    if value {
        one()
    } else {
        zero()
    }
}

fn unary_tests(operation: impl Fn(&BigInt) -> BigInt) -> Vec<TestValues> {
    append_unary_numeric_result(benchmarkNumberPossibilitiesAll.clone(), operation)
}

fn binary_tests(operation: impl Fn(&BigInt, &BigInt) -> BigInt) -> Vec<TestValues> {
    append_binary_numeric_result(allBinaryNumberCombinations.clone(), operation)
}

fn ternary_tests(
    operation: impl Fn(&BigInt, &BigInt, &BigInt) -> BigInt,
) -> Vec<TestValues> {
    append_ternary_numeric_result(allTernaryNumberCombinations.clone(), operation)
}

/// `add1Tests`.
pub static add1Tests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    unary_tests(|value| value.add(&one()))
});

/// `sub1Tests`.
pub static sub1Tests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    unary_tests(|value| value.sub(&one()))
});

/// `negateTests`.
pub static negateTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    unary_tests(BigInt::negate)
});

/// `absTests`.
pub static absTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    unary_tests(BigInt::abs)
});

/// `notTests`.
pub static notTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    unary_tests(|value| boolean(value.is_zero()))
});

/// `zeroNotEqualTests`.
pub static zeroNotEqualTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    unary_tests(|value| boolean(!value.is_zero()))
});

/// `addTests`.
pub static addTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| a.add(b))
});

/// `subTests`.
pub static subTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| a.sub(b))
});

/// `boolAndTests`.
pub static boolAndTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| boolean(!a.is_zero() && !b.is_zero()))
});

/// `boolOrTests`.
pub static boolOrTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| boolean(!a.is_zero() || !b.is_zero()))
});

/// `numEqualTests`.
pub static numEqualTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| boolean(a.cmp(b).is_eq()))
});

/// `numNotEqualTests`.
pub static numNotEqualTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| boolean(!a.cmp(b).is_eq()))
});

/// `lessThanTests`.
pub static lessThanTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| boolean(a.cmp(b).is_lt()))
});

/// `greaterThanTests`.
pub static greaterThanTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| boolean(a.cmp(b).is_gt()))
});

/// `lessThanOrEqualTests`.
pub static lessThanOrEqualTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| boolean(!a.cmp(b).is_gt()))
});

/// `greaterThanOrEqualTests`.
pub static greaterThanOrEqualTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| boolean(!a.cmp(b).is_lt()))
});

/// `minTests`.
pub static minTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| if a.cmp(b).is_lt() { a.clone() } else { b.clone() })
});

/// `maxTests`.
pub static maxTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| if a.cmp(b).is_gt() { a.clone() } else { b.clone() })
});

/// `withinTests`.
pub static withinTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    ternary_tests(|a, b, c| {
        boolean(!b.cmp(a).is_gt() && a.cmp(c).is_lt())
    })
});

/// `mulTests`.
pub static mulTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| a.mul(b))
});

/// `divTests`.
pub static divTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| a.div_mod(b).0)
});

/// `modTests`.
pub static modTests: LazyLock<Vec<TestValues>> = LazyLock::new(|| {
    binary_tests(|a, b| a.div_mod(b).1)
});
