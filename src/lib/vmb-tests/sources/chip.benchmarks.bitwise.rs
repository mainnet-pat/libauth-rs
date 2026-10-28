//! Port of `vmb-tests/sources/chip.benchmarks.bitwise.ts`.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::engine::{WalletTemplateScenario, WalletTemplateScriptDefinition};
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

// import { packedTransactionScenario } from '../bch-vmb-test-mixins.js';
const maxNumberBase: &str = "<0> <9999> OP_NUM2BIN OP_INVERT";

const maxNumberSuffix: &str = "<0x7f> OP_CAT";

static maxNumber: LazyLock<String> = LazyLock::new(|| format!("{} {}", maxNumberBase, maxNumberSuffix));

const minNumber: &str = "<0> <10000> OP_NUM2BIN OP_INVERT";

static minNumberMaxNumber: LazyLock<String> = LazyLock::new(|| format!("{} OP_DUP <0xff> OP_CAT OP_SWAP  {}", maxNumberBase, maxNumberSuffix));

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Transaction validation benchmarks".to_string(),
            vec![
                definition("", "<0> <8049> OP_NUM2BIN OP_INVERT OP_INVERT OP_INVERT", "max-cost OP_INVERT", &["chip_bitwise", "p2sh_ignore"], None, None),
                // ['', '<0> <8049> OP_NUM2BIN OP_INVERT OP_INVERT OP_INVERT', 'max-cost OP_INVERT, packed inputs', ['chip_bitwise', 'p2sh_ignore'], packedTransactionScenario('p2s', 2437)],
                definition("", "<0> <10000> OP_NUM2BIN OP_BEGIN OP_INVERT <0> OP_UNTIL", "infinite loop of OP_INVERT", &["chip_bitwise_invalid", "p2sh_ignore"], None, None),
                definition("", "<0> <79998> OP_LSHIFTNUM OP_DROP <1> <48366> OP_LSHIFTNUM", "max-cost OP_LSHIFTNUM", &["chip_bitwise", "p2sh_ignore"], None, None),
                // ['', '<1> <79998> OP_LSHIFTNUM OP_DROP <1> <48366> OP_LSHIFTNUM', 'max-cost OP_LSHIFTNUM, packed inputs', ['chip_bitwise', 'p2sh_ignore'], packedTransactionScenario('p2s', 2437)],
                definition("", &format!("<1> {} OP_LSHIFTNUM", minNumber), " invalid OP_LSHIFTNUM (by min_number)", &["chip_bitwise_invalid", "p2sh_ignore"], None, None),
                definition("", "OP_BEGIN <1> <79998> OP_LSHIFTNUM <0> OP_UNTIL", "infinite loop of max OP_LSHIFTNUM (1 << 79998)", &["chip_bitwise_invalid", "p2sh_ignore"], None, None),
                definition("", "OP_BEGIN <0> <18446744073709551615> OP_LSHIFTNUM <0> OP_UNTIL", "infinite loop of max OP_LSHIFTNUM (0 << 18446744073709551615)", &["chip_bitwise_invalid", "p2sh_ignore"], None, None),
                definition("", "OP_BEGIN <1> <18446744073709551615> OP_LSHIFTNUM <0> OP_UNTIL", "infinite loop of max OP_LSHIFTNUM (1 << 18446744073709551615)", &["chip_bitwise_invalid", "p2sh_ignore"], None, None),
                definition("", &format!("OP_BEGIN <0> {} OP_LSHIFTNUM <0> OP_UNTIL", *maxNumber), "infinite loop of max OP_LSHIFTNUM (0 << max_number)", &["chip_bitwise_invalid", "p2sh_ignore"], None, None),
                definition("", &format!("OP_BEGIN <1> {} OP_LSHIFTNUM <0> OP_UNTIL", *maxNumber), "infinite loop of max OP_LSHIFTNUM (1 << max_number)", &["chip_bitwise_invalid", "p2sh_ignore"], None, None),
                definition("", &format!("OP_BEGIN <0> {} OP_DUP OP_LSHIFTNUM <0> OP_UNTIL", *maxNumber), "infinite loop of max OP_LSHIFTNUM (max_number << max_number)", &["chip_bitwise_invalid", "p2sh_ignore"], None, None),
                definition("", &format!("OP_BEGIN <1> {} OP_LSHIFTNUM <0> OP_UNTIL", *minNumberMaxNumber), "infinite loop of max OP_LSHIFTNUM (min_number << max_number)", &["chip_bitwise_invalid", "p2sh_ignore"], None, None),
                // ['<$(<0> <10> OP_NUM2BIN)>', `OP_DROP ${maxNumber} OP_DUP OP_RSHIFTNUM <0> OP_EQUAL`, 'max-cost OP_RSHIFTNUM (max_number >> max_number), packed inputs', ['chip_bitwise', 'p2sh_ignore'], packedTransactionScenario('p2s', 1921)],
                definition("<$(<0> <23> OP_NUM2BIN)>", &format!("OP_DROP {} OP_RSHIFTNUM <-1> OP_EQUAL", *minNumberMaxNumber), "max-cost OP_RSHIFTNUM (min_number >> max_number)", &["chip_bitwise", "p2sh_ignore"], None, None),
                definition("", &format!("<0> {} OP_RSHIFTNUM <0> OP_EQUAL", *maxNumber), "max-cost OP_RSHIFTNUM (0 >> max_number)", &["chip_bitwise", "p2sh_ignore"], None, None),
                // ['', `<0> ${maxNumber} OP_RSHIFTNUM <0> OP_EQUAL`, 'max-cost OP_RSHIFTNUM (0 >> max_number), packed inputs', ['chip_bitwise', 'p2sh_ignore'], packedTransactionScenario('p2s', 2437)],
                definition("", &format!("OP_BEGIN <0> {} OP_RSHIFTNUM <0> OP_UNTIL", *maxNumber), "infinite loop of max OP_RSHIFTNUM (0 >> max_number)", &["chip_bitwise_invalid", "p2sh_ignore"], None, None),
                definition("", &format!("OP_BEGIN <0> {} OP_RSHIFTNUM <0> OP_UNTIL", minNumber), "infinite loop of max OP_RSHIFTNUM (0 >> minNumber)", &["chip_bitwise_invalid", "p2sh_ignore"], None, None),
            ],
        ),
    ]
});
