//! Port of `vmb-tests/sources/core.benchmarks.hashing-bytes.packed.ts`.

use std::sync::LazyLock;

use crate::vmb_tests::bch_vmb_test_mixins::{packed_transaction_scenario, repeat};
use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, TestValues, VmbTestDefinitionGroup, map_test_cases,
    set_expected_results,
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

static hashOps: LazyLock<Vec<TestValues>> = LazyLock::new(|| ["OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160", "OP_HASH256"].into_iter().map(|value| vec![(value.to_string(), value.to_string())]).collect::<Vec<TestValues>>());

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Transaction validation benchmarks".to_string(),
            set_expected_results(map_test_cases(["<1>", &format!("<0> {} OP_DROP", repeat("<520> OP_NUM2BIN $0", 100)), "Within BCH_2023_05 P2SH20/standard, single-input limits, maximize bytes $0 hashed (packed transaction)"], &hashOps, None, None, Some(&packed_transaction_scenario("p2sh20", 181))), &results(&[
                ("Within BCH_2023_05 P2SH20/standard, single-input limits, maximize bytes OP_HASH160 hashed (packed transaction)", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                ("Within BCH_2023_05 P2SH20/standard, single-input limits, maximize bytes OP_HASH256 hashed (packed transaction)", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                ("Within BCH_2023_05 P2SH20/standard, single-input limits, maximize bytes OP_RIPEMD160 hashed (packed transaction)", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                ("Within BCH_2023_05 P2SH20/standard, single-input limits, maximize bytes OP_SHA1 hashed (packed transaction)", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
                ("Within BCH_2023_05 P2SH20/standard, single-input limits, maximize bytes OP_SHA256 hashed (packed transaction)", &["nonstandard", "2023_p2sh_standard", "p2s_ignore"]),
            ]), None).expect("setExpectedResults"),
        ),
    ]
});
