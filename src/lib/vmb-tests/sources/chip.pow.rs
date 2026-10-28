//! Port of `vmb-tests/sources/chip.pow.ts`.

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

// Note that OP_POW is not from an active CHIP proposed for network activation.
// This OP_POW implementation is just a convenience utility for use in
// CashAssembly compilations.
pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "OP_POW".to_string(),
            vec![
                definition("<2>", "<0> OP_POW <1> OP_EQUAL", "2 ** 0 === 1", &["chip_pow"], None, None),
                definition("<2>", "<0> OP_POW", "2 ** 0", &["chip_pow"], None, None),
                definition("", "OP_POW", "No stack items", &["chip_pow_invalid"], None, None),
                definition("<2>", "OP_POW", "1 stack item", &["chip_pow_invalid"], None, None),
                definition("<2>", "<32> OP_POW <4_294_967_296> OP_EQUAL", "2 ** 32", &["chip_pow"], None, None),
                definition("<3>", "<32> OP_POW <1_853_020_188_851_841> OP_EQUAL", "3 ** 32", &["chip_pow"], None, None),
            ],
        ),
    ]
});
