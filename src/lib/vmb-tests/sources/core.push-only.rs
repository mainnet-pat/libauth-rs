//! Port of `vmb-tests/sources/core.push-only.ts`.

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

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "Standard and P2SH transaction inputs may only include push operations".to_string(),
            vec![
                // TODO: ensure all non-push opcodes are invalid when found in unlocking bytecode
                definition("<0> OP_UTXOTOKENCATEGORY", "<0> OP_EQUAL", "OP_UTXOTOKENCATEGORY is invalid in unlocking bytecode", &["invalid"], None, None),
                definition("<0> OP_OUTPUTTOKENCATEGORY", "<0> OP_EQUAL", "OP_OUTPUTTOKENCATEGORY is invalid in unlocking bytecode", &["invalid"], None, None),
                definition("<0> OP_UTXOTOKENCOMMITMENT", "<0> OP_EQUAL", "OP_UTXOTOKENCOMMITMENT is invalid in unlocking bytecode", &["invalid"], None, None),
                definition("<0> OP_OUTPUTTOKENCOMMITMENT", "<0> OP_EQUAL", "OP_OUTPUTTOKENCOMMITMENT is invalid in unlocking bytecode", &["invalid"], None, None),
                definition("<0> OP_UTXOTOKENAMOUNT", "<0> OP_EQUAL", "OP_UTXOTOKENAMOUNT is invalid in unlocking bytecode", &["invalid"], None, None),
                definition("<0> OP_OUTPUTTOKENAMOUNT", "<0> OP_EQUAL", "OP_OUTPUTTOKENAMOUNT is invalid in unlocking bytecode", &["invalid"], None, None),
            ],
        ),
    ]
});
