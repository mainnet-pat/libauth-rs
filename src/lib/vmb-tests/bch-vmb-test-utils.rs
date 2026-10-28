//! VMB test definition utilities (port of libauth's `bch-vmb-test-utils.ts`).
//!
//! These helpers generate VMB test vectors from compact test definitions: a
//! combinatoric test-case generator, the BCH test-set override plans, and the
//! scenario-driven expansion of test definitions and groups into test vectors.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::address::{encode_bech32, regroup_bits};
use crate::compiler::{create_compiler_bch, wallet_template_to_compiler_configuration};
use crate::engine::{
    AuthenticationVirtualMachineIdentifier, WalletTemplate, WalletTemplateEntity, WalletTemplateHdKey,
    WalletTemplateLockingType, WalletTemplateScenario, WalletTemplateScript, WalletTemplateScriptDefinition,
    WalletTemplateScriptLocking, WalletTemplateScriptUnlocking, WalletTemplateVariable,
    WalletTemplateVariableType,
};
use crate::vmb_tests::bch_vmb_test_mixins::slot1Scenario;
use crate::crypto::sha256;
use crate::message::{encode_transaction, encode_transaction_outputs};
use crate::format::{bin_to_hex, flatten_bin_array};

/// A test set identifier, e.g. `2023_standard`.
pub type TestSetIdBch = String;

/// A test set override label, e.g. `2023_p2sh20_invalid`.
type TestSetOverrideLabelBch = String;

/// A test vector in the "master" test list format (libauth's
/// `VmbTestMasterBch`).
///
/// The `input_index` is only present for tests whose input under test is not
/// the first input (`0`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VmbTestMasterBch {
    pub short_id: String,
    pub test_description: String,
    pub unlocking_script_asm: String,
    pub redeem_or_locking_script_asm: String,
    pub test_transaction_hex: String,
    pub source_outputs_hex: String,
    pub test_sets: Vec<TestSetIdBch>,
    pub input_index: Option<usize>,
}

/// A single VMB test (libauth's `VmbTest`), as partitioned into test sets.
///
/// Note that this differs from [`crate::vmb_tests::VmbTest`], which is the
/// decoded form of a generated VMB test fixture.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VmbTest {
    pub short_id: String,
    pub test_description: String,
    pub unlocking_script_asm: String,
    pub redeem_or_locking_script_asm: String,
    pub test_transaction_hex: String,
    pub source_outputs_hex: String,
    pub input_index: Option<usize>,
}

/// The default test sets, which inform
/// [`supportedTestSetOverridesBch`].
pub const vmbTestDefinitionDefaultBehaviorBch: &[&str] = &[
    "p2s_nonstandard",
    "p2sh20_standard",
    "p2sh32_standard",
    "2026_p2s_standard",
];

/// The VM mode of a single test generation plan item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestPlanMode {
    P2s,
    P2sh20,
    P2sh32,
}

impl TestPlanMode {
    /// The label used in generated test descriptions.
    pub fn as_str(self) -> &'static str {
        match self {
            TestPlanMode::P2s => "P2S",
            TestPlanMode::P2sh20 => "P2SH20",
            TestPlanMode::P2sh32 => "P2SH32",
        }
    }
}

/// One item of a test generation [`TestPlan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestPlanItem {
    pub mode: TestPlanMode,
    pub sets: Vec<TestSetIdBch>,
}

/// The test sets generated for a test definition, by VM mode.
pub type TestPlan = Vec<TestPlanItem>;

/// The base `P2S` test sets.
const BASE_P2S: &[&str] = &["2023_nonstandard", "2025_nonstandard", "2026_standard"];
/// The `standard` test sets.
const STANDARD: &[&str] = &["2023_standard", "2025_standard", "2026_standard"];
/// The `invalid` test sets.
const INVALID: &[&str] = &["2023_invalid", "2025_invalid", "2026_invalid"];
/// The `nonstandard` test sets.
const NONSTANDARD: &[&str] = &["2023_nonstandard", "2025_nonstandard", "2026_nonstandard"];

fn plan(items: &[(TestPlanMode, &'static [&'static str])]) -> TestPlan {
    items
        .iter()
        .map(|(mode, sets)| TestPlanItem {
            mode: *mode,
            sets: sets.iter().map(|set| (*set).to_string()).collect(),
        })
        .collect()
}

/// The list of test set overrides currently supported.
///
/// Test sets for a particular test definition are found by `join`ing the
/// definition's labels and looking up the result in this map.
pub static supportedTestSetOverridesBch: LazyLock<BTreeMap<&'static str, TestPlan>> = LazyLock::new(|| {
        BTreeMap::from([
            (
                "",
                plan(&[
                    (TestPlanMode::P2s, BASE_P2S),
                    (TestPlanMode::P2sh20, STANDARD),
                    (TestPlanMode::P2sh32, STANDARD),
                ]),
            ),
            (
                "2023_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_invalid", "2025_nonstandard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                ]),
            ),
            (
                "2023_invalid,2025_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_invalid", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_invalid", "2026_standard"],
                    ),
                ]),
            ),
            (
                "2023_invalid,2025_p2sh_nonstandard",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_invalid", "2025_nonstandard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_nonstandard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_nonstandard", "2026_standard"],
                    ),
                ]),
            ),
            (
                "2023_invalid,p2s_ignore",
                plan(&[
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                ]),
            ),
            (
                "2023_invalid,p2s_ignore,p2sh20_ignore",
                plan(&[(
                    TestPlanMode::P2sh32,
                    &["2023_invalid", "2025_standard", "2026_standard"],
                )]),
            ),
            (
                "2023_invalid,p2s_ignore,p2sh32_ignore",
                plan(&[(
                    TestPlanMode::P2sh20,
                    &["2023_invalid", "2025_standard", "2026_standard"],
                )]),
            ),
            (
                "2023_invalid,p2sh_ignore",
                plan(&[(
                    TestPlanMode::P2s,
                    &["2023_invalid", "2025_nonstandard", "2026_standard"],
                )]),
            ),
            (
                "2023_p2sh_invalid",
                plan(&[
                    (TestPlanMode::P2s, BASE_P2S),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                ]),
            ),
            (
                "2023_p2sh_nonstandard,2025_p2sh_nonstandard",
                plan(&[
                    (TestPlanMode::P2s, BASE_P2S),
                    (TestPlanMode::P2sh20, BASE_P2S),
                    (TestPlanMode::P2sh32, BASE_P2S),
                ]),
            ),
            (
                "2025_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_invalid", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_invalid", "2026_standard"],
                    ),
                ]),
            ),
            (
                "chip_bitwise",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["chip_bitwise_standard", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["chip_bitwise_standard", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["chip_bitwise_standard", "2025_invalid", "2026_standard"],
                    ),
                ]),
            ),
            (
                "chip_bitwise,p2s_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["chip_bitwise_invalid", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["chip_bitwise_standard", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["chip_bitwise_standard", "2025_invalid", "2026_standard"],
                    ),
                ]),
            ),
            (
                "chip_bitwise,p2s_nonstandard",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &[
                            "chip_bitwise_nonstandard",
                            "2025_invalid",
                            "2026_nonstandard",
                        ],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["chip_bitwise_standard", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["chip_bitwise_standard", "2025_invalid", "2026_standard"],
                    ),
                ]),
            ),
            (
                "chip_bitwise,p2sh_ignore",
                plan(&[(
                    TestPlanMode::P2s,
                    &["chip_bitwise_standard", "2025_invalid", "2026_standard"],
                )]),
            ),
            (
                "chip_bitwise_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["chip_bitwise_invalid", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["chip_bitwise_invalid", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["chip_bitwise_invalid", "2025_invalid", "2026_invalid"],
                    ),
                ]),
            ),
            (
                "chip_bitwise_invalid,p2sh_ignore",
                plan(&[(
                    TestPlanMode::P2s,
                    &["chip_bitwise_invalid", "2025_invalid", "2026_invalid"],
                )]),
            ),
            (
                "chip_eval",
                plan(&[
                    (TestPlanMode::P2s, &["chip_eval_standard"]),
                    (TestPlanMode::P2sh20, &["chip_eval_standard"]),
                    (TestPlanMode::P2sh32, &["chip_eval_standard"]),
                ]),
            ),
            (
                "chip_eval,p2s_nonstandard",
                plan(&[
                    (TestPlanMode::P2s, &["chip_eval_nonstandard"]),
                    (TestPlanMode::P2sh20, &["chip_eval_standard"]),
                    (TestPlanMode::P2sh32, &["chip_eval_standard"]),
                ]),
            ),
            (
                "chip_eval,p2sh_ignore",
                plan(&[(TestPlanMode::P2s, &["chip_eval_standard"])]),
            ),
            (
                "chip_eval_invalid",
                plan(&[
                    (TestPlanMode::P2s, &["chip_eval_invalid"]),
                    (TestPlanMode::P2sh20, &["chip_eval_invalid"]),
                    (TestPlanMode::P2sh32, &["chip_eval_invalid"]),
                ]),
            ),
            (
                "chip_eval_invalid,p2sh_ignore",
                plan(&[(TestPlanMode::P2s, &["chip_eval_invalid"])]),
            ),
            (
                "chip_functions",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["chip_functions_standard", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["chip_functions_standard", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["chip_functions_standard", "2025_invalid", "2026_standard"],
                    ),
                ]),
            ),
            (
                "chip_functions,p2sh_ignore",
                plan(&[(
                    TestPlanMode::P2s,
                    &["chip_functions_standard", "2025_invalid", "2026_standard"],
                )]),
            ),
            (
                "chip_functions,p2sh_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["chip_functions_standard", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["chip_functions_invalid", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["chip_functions_invalid", "2025_invalid", "2026_invalid"],
                    ),
                ]),
            ),
            (
                "chip_functions_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["chip_functions_invalid", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["chip_functions_invalid", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["chip_functions_invalid", "2025_invalid", "2026_invalid"],
                    ),
                ]),
            ),
            (
                "chip_functions_invalid,p2sh_ignore",
                plan(&[(
                    TestPlanMode::P2s,
                    &["chip_functions_invalid", "2025_invalid", "2026_invalid"],
                )]),
            ),
            (
                "chip_loops",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["chip_loops_standard", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["chip_loops_standard", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["chip_loops_standard", "2025_invalid", "2026_standard"],
                    ),
                ]),
            ),
            (
                "chip_loops_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["chip_loops_invalid", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["chip_loops_invalid", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["chip_loops_invalid", "2025_invalid", "2026_invalid"],
                    ),
                ]),
            ),
            (
                "chip_loops_invalid,p2sh_ignore",
                plan(&[(
                    TestPlanMode::P2s,
                    &["chip_loops_invalid", "2025_invalid", "2026_invalid"],
                )]),
            ),
            (
                "chip_p2s",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["chip_p2s_standard", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["chip_p2s_standard", "2025_invalid", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["chip_p2s_standard", "2025_invalid", "2026_standard"],
                    ),
                ]),
            ),
            (
                "chip_p2s,p2sh_ignore",
                plan(&[(
                    TestPlanMode::P2s,
                    &["chip_p2s_standard", "2025_invalid", "2026_standard"],
                )]),
            ),
            (
                "chip_p2s_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["chip_p2s_invalid", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["chip_p2s_invalid", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["chip_p2s_invalid", "2025_invalid", "2026_invalid"],
                    ),
                ]),
            ),
            (
                "chip_pow",
                plan(&[
                    (TestPlanMode::P2s, &["chip_pow_standard"]),
                    (TestPlanMode::P2sh20, &["chip_pow_standard"]),
                    (TestPlanMode::P2sh32, &["chip_pow_standard"]),
                ]),
            ),
            (
                "chip_pow_invalid",
                plan(&[
                    (TestPlanMode::P2s, &["chip_pow_invalid"]),
                    (TestPlanMode::P2sh20, &["chip_pow_invalid"]),
                    (TestPlanMode::P2sh32, &["chip_pow_invalid"]),
                ]),
            ),
            (
                "invalid",
                plan(&[
                    (TestPlanMode::P2s, INVALID),
                    (TestPlanMode::P2sh20, INVALID),
                    (TestPlanMode::P2sh32, INVALID),
                ]),
            ),
            (
                "invalid,2023_nonstandard",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_nonstandard", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_nonstandard", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_nonstandard", "2025_invalid", "2026_invalid"],
                    ),
                ]),
            ),
            (
                "invalid,2023_nonstandard,p2sh_ignore",
                plan(&[(
                    TestPlanMode::P2s,
                    &["2023_nonstandard", "2025_invalid", "2026_invalid"],
                )]),
            ),
            (
                "invalid,p2s_ignore",
                plan(&[
                    (TestPlanMode::P2sh20, INVALID),
                    (TestPlanMode::P2sh32, INVALID),
                ]),
            ),
            (
                "invalid,p2s_nonstandard",
                plan(&[
                    (TestPlanMode::P2s, NONSTANDARD),
                    (TestPlanMode::P2sh20, INVALID),
                    (TestPlanMode::P2sh32, INVALID),
                ]),
            ),
            (
                "invalid,p2sh20_standard",
                plan(&[
                    (TestPlanMode::P2s, INVALID),
                    (TestPlanMode::P2sh20, STANDARD),
                    (TestPlanMode::P2sh32, INVALID),
                ]),
            ),
            (
                "invalid,p2sh32_standard",
                plan(&[
                    (TestPlanMode::P2s, INVALID),
                    (TestPlanMode::P2sh20, INVALID),
                    (TestPlanMode::P2sh32, STANDARD),
                ]),
            ),
            ("invalid,p2sh_ignore", plan(&[(TestPlanMode::P2s, INVALID)])),
            (
                "invalid,p2sh_ignore,2023_p2s_nonstandard",
                plan(&[(
                    TestPlanMode::P2s,
                    &["2023_nonstandard", "2025_invalid", "2026_invalid"],
                )]),
            ),
            (
                "invalid,spec_standard",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &[
                            "2023_invalid",
                            "2025_invalid",
                            "2026_invalid",
                            "spec_standard",
                        ],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &[
                            "2023_invalid",
                            "2025_invalid",
                            "2026_invalid",
                            "spec_standard",
                        ],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &[
                            "2023_invalid",
                            "2025_invalid",
                            "2026_invalid",
                            "spec_standard",
                        ],
                    ),
                ]),
            ),
            (
                "nonstandard",
                plan(&[
                    (TestPlanMode::P2s, NONSTANDARD),
                    (TestPlanMode::P2sh20, NONSTANDARD),
                    (TestPlanMode::P2sh32, NONSTANDARD),
                ]),
            ),
            (
                "nonstandard,2023_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_invalid", "2025_nonstandard", "2026_nonstandard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_nonstandard", "2026_nonstandard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_nonstandard", "2026_nonstandard"],
                    ),
                ]),
            ),
            (
                "nonstandard,2023_invalid,p2sh_ignore",
                plan(&[(
                    TestPlanMode::P2s,
                    &["2023_invalid", "2025_nonstandard", "2026_nonstandard"],
                )]),
            ),
            (
                "nonstandard,2023_p2sh_standard,p2s_ignore",
                plan(&[
                    (
                        TestPlanMode::P2sh20,
                        &["2023_standard", "2025_nonstandard", "2026_nonstandard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_standard", "2025_nonstandard", "2026_nonstandard"],
                    ),
                ]),
            ),
            (
                "nonstandard,p2sh_ignore",
                plan(&[(TestPlanMode::P2s, NONSTANDARD)]),
            ),
            (
                "nonstandard,p2sh_invalid,2023_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_invalid", "2025_nonstandard", "2026_nonstandard"],
                    ),
                    (TestPlanMode::P2sh20, INVALID),
                    (TestPlanMode::P2sh32, INVALID),
                ]),
            ),
            (
                "p2s_ignore",
                plan(&[
                    (TestPlanMode::P2sh20, STANDARD),
                    (TestPlanMode::P2sh32, STANDARD),
                ]),
            ),
            (
                "p2s_invalid",
                plan(&[
                    (TestPlanMode::P2s, INVALID),
                    (TestPlanMode::P2sh20, STANDARD),
                    (TestPlanMode::P2sh32, STANDARD),
                ]),
            ),
            (
                "p2s_invalid,2023_invalid",
                plan(&[
                    (TestPlanMode::P2s, INVALID),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                ]),
            ),
            (
                "p2s_invalid,2023_invalid,2025_p2sh_nonstandard",
                plan(&[
                    (TestPlanMode::P2s, INVALID),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_nonstandard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_nonstandard", "2026_standard"],
                    ),
                ]),
            ),
            (
                "p2s_invalid,2023_p2s_nonstandard",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_nonstandard", "2025_invalid", "2026_invalid"],
                    ),
                    (TestPlanMode::P2sh20, STANDARD),
                    (TestPlanMode::P2sh32, STANDARD),
                ]),
            ),
            (
                "p2s_invalid,2023_p2s_nonstandard,2023_p2sh_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_nonstandard", "2025_invalid", "2026_invalid"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                ]),
            ),
            (
                "p2s_nonstandard",
                plan(&[
                    (TestPlanMode::P2s, NONSTANDARD),
                    (TestPlanMode::P2sh20, STANDARD),
                    (TestPlanMode::P2sh32, STANDARD),
                ]),
            ),
            (
                "p2s_nonstandard,2023_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_invalid", "2025_nonstandard", "2026_nonstandard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                ]),
            ),
            (
                "p2s_nonstandard,2023_invalid,2025_p2sh_nonstandard",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_invalid", "2025_nonstandard", "2026_nonstandard"],
                    ),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_nonstandard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_nonstandard", "2026_standard"],
                    ),
                ]),
            ),
            (
                "p2s_nonstandard,2023_invalid,p2sh_ignore",
                plan(&[(
                    TestPlanMode::P2s,
                    &["2023_invalid", "2025_nonstandard", "2026_nonstandard"],
                )]),
            ),
            (
                "p2s_nonstandard,2023_p2sh_invalid",
                plan(&[
                    (TestPlanMode::P2s, NONSTANDARD),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_standard", "2026_standard"],
                    ),
                ]),
            ),
            (
                "p2s_nonstandard,p2sh_ignore",
                plan(&[(TestPlanMode::P2s, NONSTANDARD)]),
            ),
            (
                "p2s_nonstandard,p2sh_invalid",
                plan(&[
                    (TestPlanMode::P2s, NONSTANDARD),
                    (TestPlanMode::P2sh20, INVALID),
                    (TestPlanMode::P2sh32, INVALID),
                ]),
            ),
            (
                "p2s_nonstandard,p2sh_invalid,2023_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_invalid", "2025_nonstandard", "2026_nonstandard"],
                    ),
                    (TestPlanMode::P2sh20, INVALID),
                    (TestPlanMode::P2sh32, INVALID),
                ]),
            ),
            (
                "p2s_standard",
                plan(&[
                    (TestPlanMode::P2s, STANDARD),
                    (TestPlanMode::P2sh20, STANDARD),
                    (TestPlanMode::P2sh32, STANDARD),
                ]),
            ),
            (
                "p2s_standard,p2sh_ignore",
                plan(&[(TestPlanMode::P2s, STANDARD)]),
            ),
            (
                "p2s_standard,spec_standard,p2sh_ignore",
                plan(&[(
                    TestPlanMode::P2s,
                    &[
                        "2023_standard",
                        "2025_standard",
                        "2026_standard",
                        "spec_standard",
                    ],
                )]),
            ),
            (
                "p2sh32_nonstandard",
                plan(&[
                    (TestPlanMode::P2s, BASE_P2S),
                    (TestPlanMode::P2sh20, STANDARD),
                    (TestPlanMode::P2sh32, NONSTANDARD),
                ]),
            ),
            ("p2sh_ignore", plan(&[(TestPlanMode::P2s, BASE_P2S)])),
            (
                "p2sh_invalid",
                plan(&[
                    (TestPlanMode::P2s, BASE_P2S),
                    (TestPlanMode::P2sh20, INVALID),
                    (TestPlanMode::P2sh32, INVALID),
                ]),
            ),
            (
                "p2sh_invalid,2023_invalid",
                plan(&[
                    (
                        TestPlanMode::P2s,
                        &["2023_invalid", "2025_nonstandard", "2026_standard"],
                    ),
                    (TestPlanMode::P2sh20, INVALID),
                    (TestPlanMode::P2sh32, INVALID),
                ]),
            ),
            (
                "p2sh_nonstandard",
                plan(&[
                    (TestPlanMode::P2s, BASE_P2S),
                    (TestPlanMode::P2sh20, NONSTANDARD),
                    (TestPlanMode::P2sh32, NONSTANDARD),
                ]),
            ),
            (
                "p2sh_nonstandard,p2s_invalid,2023_invalid",
                plan(&[
                    (TestPlanMode::P2s, INVALID),
                    (
                        TestPlanMode::P2sh20,
                        &["2023_invalid", "2025_nonstandard", "2026_nonstandard"],
                    ),
                    (
                        TestPlanMode::P2sh32,
                        &["2023_invalid", "2025_nonstandard", "2026_nonstandard"],
                    ),
                ]),
            ),
            (
                "spec",
                plan(&[
                    (TestPlanMode::P2s, &["spec_standard"]),
                    (TestPlanMode::P2sh20, &["spec_standard"]),
                    (TestPlanMode::P2sh32, &["spec_standard"]),
                ]),
            ),
        ])
});

/// A possible value for a test-case template: a description label and the
/// value inserted into the generated script.
pub type PossibleTestValue = (String, String);

/// The values substituted into a single test case, in template index order.
pub type TestValues = Vec<PossibleTestValue>;

/// A VMB test definition, the input to
/// [`vmb_test_definition_to_vmb_tests`] (libauth's `VmbTestDefinition`).
///
#[derive(Clone, Debug, Default)]
pub struct VmbTestDefinition {
    /// Compiled to `unlockingBytecode` in the generated test transaction.
    pub unlocking_script: String,
    /// Compiled to the `redeemBytecode` and/or `lockingBytecode` to be
    /// satisfied by `unlockingScript`.
    pub redeem_or_locking_script: String,
    pub test_description: String,
    /// The test set override labels for this definition.
    pub test_set_override_labels: Vec<TestSetOverrideLabelBch>,
    /// A scenario that extends `vmb_default` for use with this test.
    pub scenario: Option<WalletTemplateScenario>,
    /// Additional scripts to make available during scenario generation.
    pub additional_scripts: Option<BTreeMap<String, WalletTemplateScriptDefinition>>,
}

/// A named group of [`VmbTestDefinition`]s.
pub type VmbTestDefinitionGroup = (String, Vec<VmbTestDefinition>);

/// Short IDs use bech32 encoding, so birthday collisions will happen
/// approximately every `sqrt(2 * (32 ** defaultShortIdLength))` tests.
const DEFAULT_SHORT_ID_LENGTH: usize = 6;

fn plan_tests_bch(labels: &[TestSetOverrideLabelBch]) -> Result<&'static TestPlan, String> {
    let label_list = labels.join(",");
    supportedTestSetOverridesBch
        .get(label_list.as_str())
        .ok_or_else(|| {
            format!("Missing label list: {label_list} in 'supportedTestSetOverridesBch'.")
        })
}

/// Replace each `$<index>` in `template` with the corresponding value.
fn apply_template(
    template: &str,
    values: &TestValues,
    use_label: bool,
    prefix_as_hex_literals: bool,
) -> String {
    let mut result = String::with_capacity(template.len());
    let mut characters = template.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '$' {
            result.push(character);
            continue;
        }
        let mut digits = String::new();
        while let Some(next) = characters.peek() {
            if next.is_ascii_digit() {
                digits.push(*next);
                characters.next();
            } else {
                break;
            }
        }
        if digits.is_empty() {
            result.push('$');
            continue;
        }
        let value = digits
            .parse::<usize>()
            .ok()
            .and_then(|index| values.get(index));
        let raw = format!(
            "{}{}",
            if prefix_as_hex_literals && !use_label { "0x" } else { "" },
            match value {
                Some((label, value)) => if use_label { label } else { value },
                None => "LIBAUTH_GENERATION_ERROR_UNKNOWN_INDEX",
            }
        );
        if raw == "0x" {
            result.push('0');
        } else {
            result.push_str(&raw);
        }
    }
    result
}

/// Map an array of value arrays onto a template test case.
///
/// `prefix_as_hex_literals` defaults to `false`.
pub fn map_test_cases(
    templates: [&str; 3],
    combinations: &[TestValues],
    additional_scripts: Option<&BTreeMap<String, WalletTemplateScriptDefinition>>,
    prefix_as_hex_literals: Option<bool>,
    scenario: Option<&WalletTemplateScenario>,
) -> Vec<VmbTestDefinition> {
    let prefix_as_hex_literals = prefix_as_hex_literals.unwrap_or(false);
    combinations
        .iter()
        .map(|values| VmbTestDefinition {
            unlocking_script: apply_template(
                templates[0],
                values,
                false,
                prefix_as_hex_literals,
            ),
            redeem_or_locking_script: apply_template(
                templates[1],
                values,
                false,
                prefix_as_hex_literals,
            ),
            test_description: apply_template(
                templates[2],
                values,
                true,
                prefix_as_hex_literals,
            ),
            test_set_override_labels: Vec::new(),
            scenario: scenario.cloned(),
            additional_scripts: additional_scripts.cloned(),
        })
        .collect()
}

/// Given an array of arrays, produce an array of all possible combinations.
///
/// E.g.: `[['a', 'b'], ['1', '2'], ['x']]` produces:
/// `[['a', '1', 'x'], ['a', '2', 'x'], ['b', '1', 'x'], ['b', '2', 'x']]`.
pub fn generate_combinations<T: Clone>(arrays: &[Vec<T>]) -> Vec<Vec<T>> {
    arrays
        .iter()
        .fold(vec![Vec::new()], |accumulated, current| {
            accumulated
                .into_iter()
                .flat_map(|combination| {
                    current.iter().map(move |item| {
                        let mut next = combination.clone();
                        next.push(item.clone());
                        next
                    })
                })
                .collect()
        })
}

/// Given a template test case and an array of possible-value arrays, produce a
/// combinatorial set of test cases.
pub fn generate_test_cases(
    templates: [&str; 3],
    possible_values: &[Vec<PossibleTestValue>],
    additional_scripts: Option<&BTreeMap<String, WalletTemplateScriptDefinition>>,
    scenario: Option<&WalletTemplateScenario>,
) -> Vec<VmbTestDefinition> {
    let combinations = generate_combinations(possible_values);
    map_test_cases(templates, &combinations, additional_scripts, None, scenario)
}

/// The error returned by [`set_expected_results`] when one or more test cases
/// have not been reviewed.
const SET_EXPECTED_RESULTS_ERROR: &str = "Libauth test generation error: one or more test cases in the above set have not been reviewed for expected behavior. Please update the above result dictionary for the relevant \"setExpectedResults\" and regenerate the tests.";

/// The dictionary of expected results provided to
/// [`set_expected_results`], keyed by test description.
pub type ExpectedResultsDictionary = BTreeMap<String, Vec<TestSetOverrideLabelBch>>;

fn is_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' || first == '$' => {}
        _ => return false,
    }
    characters
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '$')
}

fn inspect_string(text: &str) -> String {
    if text.contains('\'') && !text.contains('"') {
        format!("\"{text}\"")
    } else {
        format!("'{text}'")
    }
}

fn inspect_string_array(values: &[String]) -> String {
    if values.is_empty() {
        return "[]".to_string();
    }
    format!(
        "[ {} ]",
        values
            .iter()
            .map(|value| inspect_string(value))
            .collect::<Vec<String>>()
            .join(", ")
    )
}

/// Format a results dictionary like Node's `console.log` does for objects of
/// string arrays (including its 80-character break length).
fn format_results_dictionary(dictionary: &ExpectedResultsDictionary) -> String {
    let entries: Vec<String> = dictionary
        .iter()
        .map(|(description, sets)| {
            format!(
                "{}: {}",
                if is_identifier(description) {
                    description.clone()
                } else {
                    inspect_string(description)
                },
                inspect_string_array(sets)
            )
        })
        .collect();
    if entries.is_empty() {
        return "{}".to_string();
    }
    let single_line = format!("{{ {} }}", entries.join(", "));
    if single_line.chars().count() <= 80 {
        return single_line;
    }
    format!("{{\n  {}\n}}", entries.join(",\n  "))
}

/// Given a generated set of tests, set expected results using a dictionary of
/// descriptions.
///
/// To make updating tests easier, the test definitions include tests that
/// aren't included in the dictionary; this function logs the new dictionary
/// and returns an error (to exit early).
///
/// To exclude a particular case from the resulting set, mark it as `["skip"]`,
/// (e.g. if that particular test is already manually defined elsewhere.)
pub fn set_expected_results(
    generated_definitions: Vec<VmbTestDefinition>,
    result_dictionary: &ExpectedResultsDictionary,
    macro_edit: Option<&dyn Fn(&str, &[String]) -> Vec<String>>,
) -> Result<Vec<VmbTestDefinition>, String> {
    let mut results = generated_definitions;
    for definition in &mut results {
        definition.test_set_override_labels = result_dictionary
            .get(&definition.test_description)
            .cloned()
            .unwrap_or_else(|| vec!["unknown".to_string()]);
    }
    let descriptions: Vec<&str> = results
        .iter()
        .map(|definition| definition.test_description.as_str())
        .collect();
    let extra_keys = result_dictionary
        .keys()
        .filter(|key| !descriptions.contains(&key.as_str()))
        .count();
    let has_unknown_results = results.iter().any(|definition| {
        definition
            .test_set_override_labels
            .first()
            .map(String::as_str)
            == Some("unknown")
    });
    if macro_edit.is_some() || extra_keys > 0 || has_unknown_results {
        let new_dictionary = corrected_results_dictionary(&results, macro_edit);
        println!("{}", format_results_dictionary(&new_dictionary));
        println!("Generated test count: {}", new_dictionary.len());
        return Err(SET_EXPECTED_RESULTS_ERROR.to_string());
    }
    Ok(results
        .into_iter()
        .filter(|definition| {
            definition
                .test_set_override_labels
                .first()
                .map(String::as_str)
                != Some("skip")
        })
        .collect())
}

/// Build the corrected results dictionary logged by [`set_expected_results`]
/// when the provided dictionary needs review.
fn corrected_results_dictionary(
    results: &[VmbTestDefinition],
    macro_edit: Option<&dyn Fn(&str, &[String]) -> Vec<String>>,
) -> ExpectedResultsDictionary {
    let mut dictionary: ExpectedResultsDictionary = BTreeMap::new();
    for definition in results {
        let sets = match macro_edit {
            Some(macro_edit) => macro_edit(
                &definition.test_description,
                &definition.test_set_override_labels,
            ),
            None => definition.test_set_override_labels.clone(),
        };
        dictionary.insert(definition.test_description.clone(), sets);
    }
    dictionary
}

/// Partition a master test list (produced by [`vmb_test_group_to_vmb_tests`]
/// or [`vmb_test_definition_to_vmb_tests`]) into sets.
///
/// Tests are aggregated by set into a map of test sets (e.g. to export to
/// separate files).
pub fn vmb_test_partition_master_test_list(
    master_test_list: &[VmbTestMasterBch],
) -> BTreeMap<TestSetIdBch, Vec<VmbTest>> {
    let mut accumulated_test_sets: BTreeMap<TestSetIdBch, Vec<VmbTest>> = BTreeMap::new();
    for test_case in master_test_list {
        let without_sets = VmbTest {
            short_id: test_case.short_id.clone(),
            test_description: test_case.test_description.clone(),
            unlocking_script_asm: test_case.unlocking_script_asm.clone(),
            redeem_or_locking_script_asm: test_case.redeem_or_locking_script_asm.clone(),
            test_transaction_hex: test_case.test_transaction_hex.clone(),
            source_outputs_hex: test_case.source_outputs_hex.clone(),
            input_index: test_case.input_index,
        };
        for test_set in &test_case.test_sets {
            accumulated_test_sets
                .entry(test_set.clone())
                .or_default()
                .push(without_sets.clone());
        }
    }
    accumulated_test_sets
}

/// Apply `{ extends: 'vmb_default', ...scenario_override }`.
fn extend_default_scenario(scenario_override: Option<&WalletTemplateScenario>) -> WalletTemplateScenario {
    let scenario_override = scenario_override.cloned().unwrap_or(WalletTemplateScenario {
        data: None,
        description: None,
        extends: None,
        name: None,
        source_outputs: None,
        transaction: None,
    });
    WalletTemplateScenario {
        extends: scenario_override.extends.clone().or_else(|| Some("vmb_default".to_string())),
        ..scenario_override
    }
}

fn wallet_template_script(script: &str, locking_type: Option<WalletTemplateLockingType>) -> WalletTemplateScriptDefinition {
    match locking_type {
        None => WalletTemplateScriptDefinition::Script(WalletTemplateScript {
            name: None,
            script: script.to_string(),
        }),
        Some(locking_type) => WalletTemplateScriptDefinition::Locking(WalletTemplateScriptLocking {
            locking_type,
            name: None,
            script: script.to_string(),
        }),
    }
}

fn unlocking_script(script: &str, unlocks: &str) -> WalletTemplateScriptDefinition {
    WalletTemplateScriptDefinition::Unlocking(WalletTemplateScriptUnlocking {
        age_lock: None,
        estimate: None,
        fails: None,
        invalid: None,
        name: None,
        passes: None,
        script: script.to_string(),
        time_lock_type: None,
        unlocks: unlocks.to_string(),
    })
}

fn hd_key(private_derivation_path: Option<String>) -> WalletTemplateVariable {
    WalletTemplateVariable::HdKey(WalletTemplateHdKey {
        address_offset: None,
        description: None,
        hd_public_key_derivation_path: None,
        name: None,
        never_sign_twice: None,
        private_derivation_path,
        public_derivation_path: None,
        r#type: WalletTemplateVariableType::HdKey,
    })
}

fn tester_variables() -> BTreeMap<String, WalletTemplateVariable> {
    let mut variables = BTreeMap::new();
    variables.insert("key1".to_string(), hd_key(None));
    for index in 2..=20 {
        // As in libauth, `key19` uses the `m/18/i` derivation path.
        let path = if index == 19 {
            "m/18/i".to_string()
        } else {
            format!("m/{index}/i")
        };
        variables.insert(format!("key{index}"), hd_key(Some(path)));
    }
    variables
}

/// Given a VMB test definition, generate a full VMB test vector. Note, this
/// method returns an error immediately on the first test vector generation
/// failure.
///
/// `group_name` defaults to `''`, and `short_id_length` to `6`.
pub fn vmb_test_definition_to_vmb_tests(
    test_definition: &VmbTestDefinition,
    group_name: Option<&str>,
    short_id_length: Option<usize>,
) -> Result<Vec<VmbTestMasterBch>, String> {
    let group_name = group_name.unwrap_or("");
    let short_id_length = short_id_length.unwrap_or(DEFAULT_SHORT_ID_LENGTH);
    let unlocking_script_asm = test_definition.unlocking_script.as_str();
    let redeem_or_locking_script = test_definition.redeem_or_locking_script.as_str();
    let test_description = test_definition.test_description.as_str();
    let scenario_id = "test";

    let test_generation_plan = plan_tests_bch(&test_definition.test_set_override_labels)?;

    let scenario_definition = extend_default_scenario(test_definition.scenario.as_ref());

    let mut scripts: BTreeMap<String, WalletTemplateScriptDefinition> = test_definition
        .additional_scripts
        .clone()
        .unwrap_or_default();
    scripts.insert(
        "LIB_REPEAT".to_string(),
        wallet_template_script(
            "/* usage: <$( <pattern> <repeat_count> LIB_REPEAT )> */ <> OP_SWAP OP_BEGIN OP_1SUB OP_TOALTSTACK OP_OVER OP_CAT OP_FROMALTSTACK OP_IFDUP OP_NOT OP_UNTIL OP_NIP",
            None,
        ),
    );
    scripts.insert(
        "lockBareMultisig1of3".to_string(),
        wallet_template_script(
            "<1> <key1.public_key> <key2.public_key> <key3.public_key> OP_3 OP_CHECKMULTISIG",
            Some(WalletTemplateLockingType::Standard),
        ),
    );
    scripts.insert(
        "lockEmptyP2sh20".to_string(),
        wallet_template_script("", Some(WalletTemplateLockingType::P2sh20)),
    );
    scripts.insert(
        "lockP2pk".to_string(),
        wallet_template_script(
            "<key1.public_key> OP_CHECKSIG",
            Some(WalletTemplateLockingType::Standard),
        ),
    );
    scripts.insert(
        "lockP2pkh".to_string(),
        wallet_template_script(
            "OP_DUP OP_HASH160 <$(<key1.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG",
            Some(WalletTemplateLockingType::Standard),
        ),
    );
    scripts.insert(
        "lockP2sh20".to_string(),
        wallet_template_script(redeem_or_locking_script, Some(WalletTemplateLockingType::P2sh20)),
    );
    scripts.insert(
        "lockP2sh32".to_string(),
        wallet_template_script(redeem_or_locking_script, Some(WalletTemplateLockingType::P2sh32)),
    );
    scripts.insert(
        "lockStandard".to_string(),
        wallet_template_script(redeem_or_locking_script, Some(WalletTemplateLockingType::Standard)),
    );
    scripts.insert(
        "unlockBareMultisig1of3Ecdsa".to_string(),
        unlocking_script(
            "<0> <key1.ecdsa_signature.all_outputs>",
            "lockBareMultisig1of3",
        ),
    );
    scripts.insert(
        "unlockBareMultisig1of3Schnorr".to_string(),
        unlocking_script(
            "<0b001> <key1.schnorr_signature.all_outputs>",
            "lockBareMultisig1of3",
        ),
    );
    scripts.insert(
        "unlockEmptyP2sh20".to_string(),
        unlocking_script("<1>", "lockEmptyP2sh20"),
    );
    scripts.insert(
        "unlockP2pkStandardEcdsa".to_string(),
        unlocking_script("<key1.ecdsa_signature.all_outputs>", "lockP2pk"),
    );
    scripts.insert(
        "unlockP2pkStandardSchnorr".to_string(),
        unlocking_script("<key1.schnorr_signature.all_outputs>", "lockP2pk"),
    );
    scripts.insert(
        "unlockP2pkh".to_string(),
        unlocking_script(
            "<key1.schnorr_signature.corresponding_output_single_input> <key1.public_key>",
            "lockP2pkh",
        ),
    );
    scripts.insert(
        "unlockP2pkhStandardEcdsa".to_string(),
        unlocking_script(
            "<key1.ecdsa_signature.all_outputs> <key1.public_key>",
            "lockP2pkh",
        ),
    );
    scripts.insert(
        "unlockP2pkhStandardSchnorr".to_string(),
        unlocking_script(
            "<key1.schnorr_signature.all_outputs> <key1.public_key>",
            "lockP2pkh",
        ),
    );
    scripts.insert(
        "unlockP2sh20".to_string(),
        unlocking_script(unlocking_script_asm, "lockP2sh20"),
    );
    scripts.insert(
        "unlockP2sh32".to_string(),
        unlocking_script(unlocking_script_asm, "lockP2sh32"),
    );
    scripts.insert(
        "unlockStandard".to_string(),
        unlocking_script(unlocking_script_asm, "lockStandard"),
    );
    scripts.insert(
        "vmbTestNullData".to_string(),
        wallet_template_script(
            "OP_RETURN <\"vmb_test\">",
            Some(WalletTemplateLockingType::Standard),
        ),
    );

    let mut scenarios = BTreeMap::new();
    scenarios.insert(scenario_id.to_string(), scenario_definition);
    scenarios.insert("vmb_default".to_string(), slot1Scenario.clone());

    let mut entities = BTreeMap::new();
    entities.insert(
        "tester".to_string(),
        WalletTemplateEntity {
            description: None,
            name: None,
            scripts: None,
            variables: Some(tester_variables()),
        },
    );

    let configuration = wallet_template_to_compiler_configuration(&WalletTemplate {
        schema: None,
        description: None,
        entities,
        name: None,
        scenarios: Some(scenarios),
        scripts,
        supported: vec![AuthenticationVirtualMachineIdentifier::Bch2022_05],
        version: None,
    });
    let compiler = create_compiler_bch(configuration);

    let mut tests = Vec::with_capacity(test_generation_plan.len());
    for plan_item in test_generation_plan {
        let description = format!(
            "{group_name}: {test_description} ({})",
            plan_item.mode.as_str()
        );
        let unlocking_script_id = match plan_item.mode {
            TestPlanMode::P2s => "unlockStandard",
            TestPlanMode::P2sh20 => "unlockP2sh20",
            TestPlanMode::P2sh32 => "unlockP2sh32",
        };
        let result = compiler
            .generate_scenario_debug(None, Some(scenario_id), Some(unlocking_script_id))
            .map_err(|result| format!("Error while generating \"{description}\" - {result}"))?;
        let scenario = result.scenario.map_err(|scenario| {
            format!(
                "Error while generating \"{description}\" - {scenario}. Unlocking script: {unlocking_script_asm}. Redeem or locking script: {redeem_or_locking_script}."
            )
        })?;
        let encoded_transaction = encode_transaction(&scenario.program.transaction);
        let encoded_source_outputs = encode_transaction_outputs(&scenario.program.source_outputs);
        let hash = sha256.hash(&flatten_bin_array(&[
            encoded_transaction.clone(),
            encoded_source_outputs.clone(),
        ]));
        let regrouped = regroup_bits(&hash, 8, 5, Some(true))
            .map_err(|error| format!("Error while generating \"{description}\" - {error}"))?;
        let short_id = encode_bech32(&regrouped)
            .chars()
            .take(short_id_length)
            .collect::<String>();

        tests.push(VmbTestMasterBch {
            short_id,
            test_description: description,
            unlocking_script_asm: unlocking_script_asm.to_string(),
            redeem_or_locking_script_asm: redeem_or_locking_script.to_string(),
            test_transaction_hex: bin_to_hex(&encoded_transaction),
            source_outputs_hex: bin_to_hex(&encoded_source_outputs),
            test_sets: plan_item.sets.clone(),
            input_index: if scenario.program.input_index == 0 {
                None
            } else {
                Some(scenario.program.input_index)
            },
        });
    }

    Ok(tests)
}

/// Generate the test vectors for every definition in a test group.
pub fn vmb_test_group_to_vmb_tests(
    test_group: &VmbTestDefinitionGroup,
) -> Result<Vec<Vec<VmbTestMasterBch>>, String> {
    test_group
        .1
        .iter()
        .map(|test_definition| {
            vmb_test_definition_to_vmb_tests(test_definition, Some(&test_group.0), None)
        })
        .collect()
}
