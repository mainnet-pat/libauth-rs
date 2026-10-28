//! Port of `vmb-tests/sources/core.benchmarks.hashing.ts`.

use std::sync::LazyLock;

use crate::vmb_tests::bch_vmb_test_mixins::{
    minimalScenarioStandard, minimal_scenario_standard_plus_bytes, repeat,
};
use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, PossibleTestValue, TestValues, VmbTestDefinitionGroup,
    generate_test_cases, map_test_cases, set_expected_results,
};

/// Build a `setExpectedResults` result dictionary (test description → test
/// set override labels).
fn results(entries: &[(&str, &[&str])]) -> ExpectedResultsDictionary {
    entries
        .iter()
        .map(|(description, labels)| {
            (description.to_string(), labels.iter().map(|label| label.to_string()).collect())
        })
        .collect()
}

const hashOpcodes: [&str; 5] = ["OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160", "OP_HASH256"];

static hashOps: LazyLock<Vec<TestValues>> = LazyLock::new(|| hashOpcodes.into_iter().map(|value| vec![(value.to_string(), value.to_string())]).collect::<Vec<TestValues>>());

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Transaction validation benchmarks".to_string(),
            [
                set_expected_results(map_test_cases(["<1>", &format!("<0> {} OP_DROP", repeat("<520> OP_NUM2BIN $0", 100)), "Within BCH_2023_05 P2SH/standard, single-input limits, maximize bytes $0 hashed"], &hashOps, None, None, Some(&minimalScenarioStandard)), &results(&[
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize bytes OP_HASH160 hashed", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize bytes OP_HASH256 hashed", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize bytes OP_RIPEMD160 hashed", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize bytes OP_SHA1 hashed", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH/standard, single-input limits, maximize bytes OP_SHA256 hashed", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(map_test_cases(["<1>", &format!("<0> {} OP_DROP", repeat("<520> OP_NUM2BIN $0", 100)), "Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize bytes $0 hashed"], &hashOps, None, None, Some(&minimal_scenario_standard_plus_bytes(2))), &results(&[
                    ("Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize bytes OP_HASH160 hashed", &["invalid", "p2sh_ignore", "2023_p2s_nonstandard"]),
                    ("Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize bytes OP_HASH256 hashed", &["invalid", "p2sh_ignore", "2023_p2s_nonstandard"]),
                    ("Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize bytes OP_RIPEMD160 hashed", &["invalid", "p2sh_ignore", "2023_p2s_nonstandard"]),
                    ("Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize bytes OP_SHA1 hashed", &["invalid", "p2sh_ignore", "2023_p2s_nonstandard"]),
                    ("Within BCH_2023_05 P2S/nonstandard, single-input limits, maximize bytes OP_SHA256 hashed", &["invalid", "p2sh_ignore", "2023_p2s_nonstandard"]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(map_test_cases(["<1>", &format!("<0> <488> OP_NUM2BIN OP_DUP OP_2DUP {} {} $0 OP_DROP", repeat("OP_3DUP", 27), repeat("$0 OP_CAT", 84)), "Within BCH_2023_05 P2SH20/standard limits, maximize hash digests per byte, then total bytes $0 hashed"], &hashOps, None, None, Some(&minimalScenarioStandard)), &results(&[
                    ("Within BCH_2023_05 P2SH20/standard limits, maximize hash digests per byte, then total bytes OP_HASH160 hashed", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH20/standard limits, maximize hash digests per byte, then total bytes OP_HASH256 hashed", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH20/standard limits, maximize hash digests per byte, then total bytes OP_RIPEMD160 hashed", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH20/standard limits, maximize hash digests per byte, then total bytes OP_SHA1 hashed", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                    ("Within BCH_2023_05 P2SH20/standard limits, maximize hash digests per byte, then total bytes OP_SHA256 hashed", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(map_test_cases(["<1>", &format!("<0> <488> OP_NUM2BIN OP_DUP OP_2DUP {} {} $0 OP_DROP", repeat("OP_3DUP", 27), repeat("$0 OP_CAT", 84)), "Within BCH_2023_05 P2S/nonstandard limits, maximize hash digests per byte, then total bytes $0 hashed"], &hashOps, None, None, Some(&minimal_scenario_standard_plus_bytes(2))), &results(&[
                    ("Within BCH_2023_05 P2S/nonstandard limits, maximize hash digests per byte, then total bytes OP_HASH160 hashed", &["invalid", "p2sh_ignore", "2023_p2s_nonstandard"]),
                    ("Within BCH_2023_05 P2S/nonstandard limits, maximize hash digests per byte, then total bytes OP_HASH256 hashed", &["invalid", "p2sh_ignore", "2023_p2s_nonstandard"]),
                    ("Within BCH_2023_05 P2S/nonstandard limits, maximize hash digests per byte, then total bytes OP_RIPEMD160 hashed", &["invalid", "p2sh_ignore", "2023_p2s_nonstandard"]),
                    ("Within BCH_2023_05 P2S/nonstandard limits, maximize hash digests per byte, then total bytes OP_SHA1 hashed", &["invalid", "p2sh_ignore", "2023_p2s_nonstandard"]),
                    ("Within BCH_2023_05 P2S/nonstandard limits, maximize hash digests per byte, then total bytes OP_SHA256 hashed", &["invalid", "p2sh_ignore", "2023_p2s_nonstandard"]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(generate_test_cases(["<1> <$1>", "OP_NUM2BIN $0", "$0 hash $1 bytes"], &[hashOpcodes.into_iter().map(|value| (value.to_string(), value.to_string())).collect::<Vec<PossibleTestValue>>(), ["1335", "1336", "1399", "1400", "9975", "9976", "10000"].into_iter().map(|value| (value.to_string(), value.to_string())).collect::<Vec<PossibleTestValue>>()], None, Some(&minimalScenarioStandard)), &results(&[
                    ("OP_HASH160 hash 10000 bytes", &["p2sh_nonstandard", "p2s_invalid", "2023_invalid"]),
                    ("OP_HASH160 hash 1335 bytes", &["2023_invalid"]),
                    ("OP_HASH160 hash 1336 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_HASH160 hash 1399 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_HASH160 hash 1400 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_HASH160 hash 9975 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_HASH160 hash 9976 bytes", &["p2sh_nonstandard", "p2s_invalid", "2023_invalid"]),
                    ("OP_HASH256 hash 10000 bytes", &["p2sh_nonstandard", "p2s_invalid", "2023_invalid"]),
                    ("OP_HASH256 hash 1335 bytes", &["2023_invalid"]),
                    ("OP_HASH256 hash 1336 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_HASH256 hash 1399 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_HASH256 hash 1400 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_HASH256 hash 9975 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_HASH256 hash 9976 bytes", &["p2sh_nonstandard", "p2s_invalid", "2023_invalid"]),
                    ("OP_RIPEMD160 hash 10000 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_RIPEMD160 hash 1335 bytes", &["2023_invalid"]),
                    ("OP_RIPEMD160 hash 1336 bytes", &["2023_invalid"]),
                    ("OP_RIPEMD160 hash 1399 bytes", &["2023_invalid"]),
                    ("OP_RIPEMD160 hash 1400 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_RIPEMD160 hash 9975 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_RIPEMD160 hash 9976 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_SHA1 hash 10000 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_SHA1 hash 1335 bytes", &["2023_invalid"]),
                    ("OP_SHA1 hash 1336 bytes", &["2023_invalid"]),
                    ("OP_SHA1 hash 1399 bytes", &["2023_invalid"]),
                    ("OP_SHA1 hash 1400 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_SHA1 hash 9975 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_SHA1 hash 9976 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_SHA256 hash 10000 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_SHA256 hash 1335 bytes", &["2023_invalid"]),
                    ("OP_SHA256 hash 1336 bytes", &["2023_invalid"]),
                    ("OP_SHA256 hash 1399 bytes", &["2023_invalid"]),
                    ("OP_SHA256 hash 1400 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_SHA256 hash 9975 bytes", &["nonstandard", "2023_invalid"]),
                    ("OP_SHA256 hash 9976 bytes", &["nonstandard", "2023_invalid"]),
                ]), None).expect("setExpectedResults"),
            ]
            .concat(),
        ),
    ]
});
