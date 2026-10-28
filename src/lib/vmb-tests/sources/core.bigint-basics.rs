//! Port of `vmb-tests/sources/core.bigint-basics.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
use crate::vmb_tests::bch_vmb_test_mixins_bigint::{
    binaryOpcodes, justZeroAndOne, ternaryOpcodes, unaryOpcodes, zerosAndOnes,
};
use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, VmbTestDefinition, VmbTestDefinitionGroup, generate_test_cases,
    set_expected_results,
};

/// Build a [`VmbTestDefinition`] from the elements of libauth's
/// `VmbTestDefinition` tuple: `[unlockingScript, redeemOrLockingScript,
/// testDescription, testSetOverrideLabels?, scenario?, additionalScripts?]`.
fn definition(
    unlocking_script: &str,
    redeem_or_locking_script: &str,
    test_description: &str,
    test_set_override_labels: &[&str],
    scenario: Option<WalletTemplateScenario>,
    additional_scripts: Option<BTreeMap<String, WalletTemplateScriptDefinition>>,
) -> VmbTestDefinition {
    VmbTestDefinition {
        unlocking_script: unlocking_script.to_string(),
        redeem_or_locking_script: redeem_or_locking_script.to_string(),
        test_description: test_description.to_string(),
        test_set_override_labels: test_set_override_labels.iter().map(|label| label.to_string()).collect(),
        scenario,
        additional_scripts,
    }
}

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

// TODO: test acceptance of smallZerosAndOnes for all ops (core.minimal-data.ts)
// TODO: generate seeded-random test vectors for all ops
pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "BigInt".to_string(),
            [
                set_expected_results(generate_test_cases(["<$0>", "", "$0 is truthy"], &[zerosAndOnes.clone()], None, None), &results(&[
                    ("negative one is truthy", &[]),
                    ("negative zero is truthy", &["invalid"]),
                    ("one is truthy", &["skip"]),
                    ("padded negative one (520 bytes) is truthy", &[]),
                    ("padded negative one (521 bytes) is truthy", &["2023_invalid"]),
                    ("padded negative one is truthy", &[]),
                    ("padded negative zero (520 bytes) is truthy", &["invalid"]),
                    ("padded negative zero (521 bytes) is truthy", &["invalid"]),
                    ("padded negative zero is truthy", &["invalid"]),
                    ("padded one (520 bytes) is truthy", &[]),
                    ("padded one (521 bytes) is truthy", &["2023_invalid"]),
                    ("padded one is truthy", &[]),
                    ("padded zero (520 bytes) is truthy", &["invalid"]),
                    ("padded zero (521 bytes) is truthy", &["invalid"]),
                    ("padded zero is truthy", &["invalid"]),
                    ("zero is truthy", &["skip"]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(generate_test_cases(["", "$0 <1>", "$0 on empty stack"], &[unaryOpcodes.clone()], None, None), &results(&[
                    ("OP_0NOTEQUAL on empty stack", &["invalid"]),
                    ("OP_1ADD on empty stack", &["invalid"]),
                    ("OP_1SUB on empty stack", &["invalid"]),
                    ("OP_ABS on empty stack", &["invalid"]),
                    ("OP_BIN2NUM on empty stack", &["invalid"]),
                    ("OP_INVERT on empty stack", &["invalid"]),
                    ("OP_NEGATE on empty stack", &["invalid"]),
                    ("OP_NOT on empty stack", &["invalid"]),
                ]), None).expect("setExpectedResults"),
                vec![definition("", "OP_BIN2NUM OP_NOT", "OP_BIN2NUM OP_NOT on empty stack", &["invalid"], None, None)],
                set_expected_results(generate_test_cases(["<$0>", "$1 <1>", "$1 on 1-item stack of $0"], &[justZeroAndOne.clone(), [unaryOpcodes.clone(), binaryOpcodes.clone(), ternaryOpcodes.clone()].concat()], None, None), &results(&[
                    ("OP_0NOTEQUAL on 1-item stack of one", &["invalid"]),
                    ("OP_0NOTEQUAL on 1-item stack of zero", &["invalid"]),
                    ("OP_1ADD on 1-item stack of one", &["invalid"]),
                    ("OP_1ADD on 1-item stack of zero", &["invalid"]),
                    ("OP_1SUB on 1-item stack of one", &["invalid"]),
                    ("OP_1SUB on 1-item stack of zero", &["invalid"]),
                    ("OP_ABS on 1-item stack of one", &["invalid"]),
                    ("OP_ABS on 1-item stack of zero", &["invalid"]),
                    ("OP_ADD on 1-item stack of one", &["invalid"]),
                    ("OP_ADD on 1-item stack of zero", &["invalid"]),
                    ("OP_BIN2NUM on 1-item stack of one", &["invalid"]),
                    ("OP_BIN2NUM on 1-item stack of zero", &["invalid"]),
                    ("OP_BOOLAND on 1-item stack of one", &["invalid"]),
                    ("OP_BOOLAND on 1-item stack of zero", &["invalid"]),
                    ("OP_BOOLOR on 1-item stack of one", &["invalid"]),
                    ("OP_BOOLOR on 1-item stack of zero", &["invalid"]),
                    ("OP_DIV on 1-item stack of one", &["invalid"]),
                    ("OP_DIV on 1-item stack of zero", &["invalid"]),
                    ("OP_GREATERTHAN on 1-item stack of one", &["invalid"]),
                    ("OP_GREATERTHAN on 1-item stack of zero", &["invalid"]),
                    ("OP_GREATERTHANOREQUAL on 1-item stack of one", &["invalid"]),
                    ("OP_GREATERTHANOREQUAL on 1-item stack of zero", &["invalid"]),
                    ("OP_INVERT on 1-item stack of one", &["invalid"]),
                    ("OP_INVERT on 1-item stack of zero", &["invalid"]),
                    ("OP_LESSTHAN on 1-item stack of one", &["invalid"]),
                    ("OP_LESSTHAN on 1-item stack of zero", &["invalid"]),
                    ("OP_LESSTHANOREQUAL on 1-item stack of one", &["invalid"]),
                    ("OP_LESSTHANOREQUAL on 1-item stack of zero", &["invalid"]),
                    ("OP_LSHIFTBIN on 1-item stack of one", &["invalid"]),
                    ("OP_LSHIFTBIN on 1-item stack of zero", &["invalid"]),
                    ("OP_LSHIFTNUM on 1-item stack of one", &["invalid"]),
                    ("OP_LSHIFTNUM on 1-item stack of zero", &["invalid"]),
                    ("OP_MAX on 1-item stack of one", &["invalid"]),
                    ("OP_MAX on 1-item stack of zero", &["invalid"]),
                    ("OP_MIN on 1-item stack of one", &["invalid"]),
                    ("OP_MIN on 1-item stack of zero", &["invalid"]),
                    ("OP_MOD on 1-item stack of one", &["invalid"]),
                    ("OP_MOD on 1-item stack of zero", &["invalid"]),
                    ("OP_MUL on 1-item stack of one", &["invalid"]),
                    ("OP_MUL on 1-item stack of zero", &["invalid"]),
                    ("OP_NEGATE on 1-item stack of one", &["invalid"]),
                    ("OP_NEGATE on 1-item stack of zero", &["invalid"]),
                    ("OP_NOT on 1-item stack of one", &["invalid"]),
                    ("OP_NOT on 1-item stack of zero", &["invalid"]),
                    ("OP_NUM2BIN on 1-item stack of one", &["invalid"]),
                    ("OP_NUM2BIN on 1-item stack of zero", &["invalid"]),
                    ("OP_NUMEQUAL on 1-item stack of one", &["invalid"]),
                    ("OP_NUMEQUAL on 1-item stack of zero", &["invalid"]),
                    ("OP_NUMEQUALVERIFY on 1-item stack of one", &["invalid"]),
                    ("OP_NUMEQUALVERIFY on 1-item stack of zero", &["invalid"]),
                    ("OP_NUMNOTEQUAL on 1-item stack of one", &["invalid"]),
                    ("OP_NUMNOTEQUAL on 1-item stack of zero", &["invalid"]),
                    ("OP_RSHIFTBIN on 1-item stack of one", &["invalid"]),
                    ("OP_RSHIFTBIN on 1-item stack of zero", &["invalid"]),
                    ("OP_RSHIFTNUM on 1-item stack of one", &["invalid"]),
                    ("OP_RSHIFTNUM on 1-item stack of zero", &["invalid"]),
                    ("OP_SUB on 1-item stack of one", &["invalid"]),
                    ("OP_SUB on 1-item stack of zero", &["invalid"]),
                    ("OP_WITHIN on 1-item stack of one", &["invalid"]),
                    ("OP_WITHIN on 1-item stack of zero", &["invalid"]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(generate_test_cases(["<$0> <$1>", "$2 <1>", "$2 on 2-item stack of $0 and $1"], &[justZeroAndOne.clone(), justZeroAndOne.clone(), ternaryOpcodes.clone()], None, None), &results(&[
                    ("OP_WITHIN on 2-item stack of one and one", &["invalid"]),
                    ("OP_WITHIN on 2-item stack of one and zero", &["invalid"]),
                    ("OP_WITHIN on 2-item stack of zero and one", &["invalid"]),
                    ("OP_WITHIN on 2-item stack of zero and zero", &["invalid"]),
                ]), None).expect("setExpectedResults"),
            ]
            .concat(),
        ),
    ]
});
