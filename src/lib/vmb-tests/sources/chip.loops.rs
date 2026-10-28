//! Port of `vmb-tests/sources/chip.loops.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
use crate::vmb_tests::bch_vmb_test_mixins::packed_transaction_scenario;
use crate::vmb_tests::bch_vmb_test_utils::{VmbTestDefinition, VmbTestDefinitionGroup};

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

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Transaction validation benchmarks".to_string(),
            vec![
                definition("", "<0> OP_BEGIN OP_DUP OP_UNTIL", "infinite loop, packed inputs", &["chip_loops_invalid", "p2sh_ignore"], Some(packed_transaction_scenario("p2s", 2437)), None),
                definition("", "<0> <10000> OP_NUM2BIN OP_BEGIN OP_DUP OP_UNTIL", "infinite loop of max duplication, packed inputs", &["chip_loops_invalid", "p2sh_ignore"], Some(packed_transaction_scenario("p2s", 2437)), None),
            ],
        ),
        (
            "OP_BEGIN/OP_UNTIL".to_string(),
            vec![
                definition("<0>", "OP_BEGIN OP_DUP OP_UNTIL", "infinite loop", &["chip_loops_invalid"], None, None),
                definition("<1>", "OP_BEGIN", "no matching OP_UNTIL", &["chip_loops_invalid"], None, None),
                definition("<1>", "OP_UNTIL", "no matching OP_BEGIN", &["chip_loops_invalid"], None, None),
                definition("<1> <1>", "OP_BEGIN OP_DUP OP_UNTIL OP_DROP", "loop until the first 0x01", &["chip_loops"], None, None),
                definition("<1> <0>", "OP_BEGIN OP_DUP OP_UNTIL OP_DROP", "infinite loop, attempt success", &["chip_loops_invalid"], None, None),
                definition("<1> <2> <3> <4>", "OP_BEGIN OP_ADD OP_DEPTH <1> OP_EQUAL OP_UNTIL <10> OP_EQUAL", "sum stack (1 + 2 + 3 + 4 == 10)", &["chip_loops"], None, None),
                definition("<2> <3> <5>", "OP_BEGIN OP_ADD OP_DEPTH <1> OP_EQUAL OP_UNTIL <10> OP_EQUAL", "sum stack (2 + 3 + 5 == 10)", &["chip_loops"], None, None),
                definition("<2> <3> <4>", "OP_BEGIN OP_ADD OP_DEPTH <1> OP_EQUAL OP_UNTIL <10> OP_EQUAL", "sum stack (2 + 3 + 4 == 10)", &["chip_loops_invalid"], None, None),
                definition("<1> <9>", "OP_BEGIN OP_ADD OP_DEPTH <1> OP_EQUAL OP_UNTIL <10> OP_EQUAL", "sum stack (1 + 9 == 10)", &["chip_loops"], None, None),
                definition("<0> <9>", "OP_BEGIN OP_ADD OP_DEPTH <1> OP_EQUAL OP_UNTIL <10> OP_EQUAL", "sum stack (0 + 9 == 10)", &["chip_loops_invalid"], None, None),
                definition("<2> <31>", "OP_BEGIN OP_1SUB OP_TOALTSTACK <2> OP_MUL OP_FROMALTSTACK OP_IFDUP OP_NOT OP_UNTIL <$(<2> <32> OP_POW)> OP_EQUAL", "2**32 == 2**32", &["chip_loops"], None, None),
                definition("<2> <31>", "OP_BEGIN OP_1SUB OP_TOALTSTACK <2> OP_MUL OP_FROMALTSTACK OP_IFDUP OP_NOT OP_UNTIL <$(<2> <32> OP_POW OP_1SUB)> OP_EQUAL", "2**32 == 2**32 - 1", &["chip_loops_invalid"], None, None),
                definition("<6>", "<0> <1> OP_ROT OP_BEGIN OP_1SUB OP_TOALTSTACK OP_SWAP OP_OVER OP_ADD OP_FROMALTSTACK OP_IFDUP OP_NOT OP_UNTIL OP_NIP <13> OP_EQUAL", "Fibonacci to 13", &["chip_loops"], None, None),
            ],
        ),
    ]
});
