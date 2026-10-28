//! Port of `vmb-tests/sources/core.nop.ts`.

use std::sync::LazyLock;

use crate::vmb_tests::bch_vmb_test_utils::{
    ExpectedResultsDictionary, PossibleTestValue, VmbTestDefinitionGroup, generate_test_cases,
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

static nopOps: LazyLock<Vec<PossibleTestValue>> = LazyLock::new(|| vec![
    ("OP_NOP".to_string(), "OP_NOP".to_string()),
    ("OP_NOP1".to_string(), "OP_NOP1".to_string()),
    ("OP_NOP4".to_string(), "OP_NOP4".to_string()),
    ("OP_NOP5".to_string(), "OP_NOP5".to_string()),
    ("OP_NOP6".to_string(), "OP_NOP6".to_string()),
    ("OP_NOP7".to_string(), "OP_NOP7".to_string()),
    ("OP_NOP8".to_string(), "OP_NOP8".to_string()),
    ("OP_NOP9".to_string(), "OP_NOP9".to_string()),
    ("OP_NOP10".to_string(), "OP_NOP10".to_string()),
]);

pub static default: LazyLock<Vec<VmbTestDefinitionGroup>> = LazyLock::new(|| {
    vec![
        (
            "OP_NOP1-OP_NOP10 expansion range".to_string(),
            [
                set_expected_results(generate_test_cases(["<1>", "$0", "$0 in locking bytecode"], &[nopOps.clone()], None, None), &results(&[
                    ("OP_NOP in locking bytecode", &[]),
                    ("OP_NOP1 in locking bytecode", &["nonstandard"]),
                    ("OP_NOP10 in locking bytecode", &["nonstandard"]),
                    ("OP_NOP4 in locking bytecode", &["nonstandard"]),
                    ("OP_NOP5 in locking bytecode", &["nonstandard"]),
                    ("OP_NOP6 in locking bytecode", &["nonstandard"]),
                    ("OP_NOP7 in locking bytecode", &["nonstandard"]),
                    ("OP_NOP8 in locking bytecode", &["nonstandard"]),
                    ("OP_NOP9 in locking bytecode", &["nonstandard"]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(generate_test_cases(["<0>", "OP_IF $0 OP_ENDIF <1>", "Unexecuted $0 in locking bytecode"], &[nopOps.clone()], None, None), &results(&[
                    ("Unexecuted OP_NOP in locking bytecode", &[]),
                    ("Unexecuted OP_NOP1 in locking bytecode", &[]),
                    ("Unexecuted OP_NOP10 in locking bytecode", &[]),
                    ("Unexecuted OP_NOP4 in locking bytecode", &[]),
                    ("Unexecuted OP_NOP5 in locking bytecode", &[]),
                    ("Unexecuted OP_NOP6 in locking bytecode", &[]),
                    ("Unexecuted OP_NOP7 in locking bytecode", &[]),
                    ("Unexecuted OP_NOP8 in locking bytecode", &[]),
                    ("Unexecuted OP_NOP9 in locking bytecode", &[]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(generate_test_cases(["$0", "<1>", "$0 in unlocking bytecode"], &[nopOps.clone()], None, None), &results(&[
                    ("OP_NOP in unlocking bytecode", &["invalid"]),
                    ("OP_NOP1 in unlocking bytecode", &["invalid"]),
                    ("OP_NOP10 in unlocking bytecode", &["invalid"]),
                    ("OP_NOP4 in unlocking bytecode", &["invalid"]),
                    ("OP_NOP5 in unlocking bytecode", &["invalid"]),
                    ("OP_NOP6 in unlocking bytecode", &["invalid"]),
                    ("OP_NOP7 in unlocking bytecode", &["invalid"]),
                    ("OP_NOP8 in unlocking bytecode", &["invalid"]),
                    ("OP_NOP9 in unlocking bytecode", &["invalid"]),
                ]), None).expect("setExpectedResults"),
                set_expected_results(generate_test_cases(["<0> OP_IF $0 OP_ENDIF", "<1>", "Unexecuted $0 in unlocking bytecode"], &[nopOps.clone()], None, None), &results(&[
                    ("Unexecuted OP_NOP in unlocking bytecode", &["invalid"]),
                    ("Unexecuted OP_NOP1 in unlocking bytecode", &["invalid"]),
                    ("Unexecuted OP_NOP10 in unlocking bytecode", &["invalid"]),
                    ("Unexecuted OP_NOP4 in unlocking bytecode", &["invalid"]),
                    ("Unexecuted OP_NOP5 in unlocking bytecode", &["invalid"]),
                    ("Unexecuted OP_NOP6 in unlocking bytecode", &["invalid"]),
                    ("Unexecuted OP_NOP7 in unlocking bytecode", &["invalid"]),
                    ("Unexecuted OP_NOP8 in unlocking bytecode", &["invalid"]),
                    ("Unexecuted OP_NOP9 in unlocking bytecode", &["invalid"]),
                ]), None).expect("setExpectedResults"),
            ]
            .concat(),
        ),
    ]
});
