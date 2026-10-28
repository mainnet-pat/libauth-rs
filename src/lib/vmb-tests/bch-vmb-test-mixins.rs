//! Reusable VMB test scenarios and helpers (`bch-vmb-test-mixins.ts`).

use std::sync::LazyLock;
use crate::compiler::cash_assembly_to_bin;
use crate::engine::{
    WalletTemplateScenario, WalletTemplateScenarioBytecode, WalletTemplateScenarioBytecodeDefinition,
    WalletTemplateScenarioBytecodeScript, WalletTemplateScenarioInput,
    WalletTemplateScenarioOutput, WalletTemplateScenarioOutputLockingBytecode,
    WalletTemplateScenarioSourceOutput, WalletTemplateScenarioTransaction,
    WalletTemplateScenarioTransactionOutput, WalletTemplateScenarioUnlockingBytecode,
    WalletTemplateScenarioValueSatoshis,
};
use crate::format::bin_to_hex;

fn definition(script: &str) -> WalletTemplateScenarioBytecode {
    WalletTemplateScenarioBytecode::Definition(WalletTemplateScenarioBytecodeDefinition {
        script: Some(WalletTemplateScenarioBytecodeScript::Id(script.to_string())),
        overrides: None,
    })
}

fn hex_bytecode(hex: String) -> WalletTemplateScenarioBytecode {
    WalletTemplateScenarioBytecode::Hex(hex)
}

fn satoshis(value: f64) -> Option<WalletTemplateScenarioValueSatoshis> {
    Some(WalletTemplateScenarioValueSatoshis::Number(value))
}

fn source_output(
    locking_bytecode: WalletTemplateScenarioOutputLockingBytecode<true>,
    value_satoshis: f64,
) -> WalletTemplateScenarioSourceOutput {
    WalletTemplateScenarioOutput {
        locking_bytecode: Some(locking_bytecode),
        value_satoshis: satoshis(value_satoshis),
        token: None,
    }
}

fn transaction_output(
    locking_bytecode: WalletTemplateScenarioOutputLockingBytecode<false>,
    value_satoshis: f64,
) -> WalletTemplateScenarioTransactionOutput {
    WalletTemplateScenarioOutput {
        locking_bytecode: Some(locking_bytecode),
        value_satoshis: satoshis(value_satoshis),
        token: None,
    }
}

fn input(unlocking_bytecode: WalletTemplateScenarioUnlockingBytecode) -> WalletTemplateScenarioInput {
    WalletTemplateScenarioInput {
        outpoint_index: None,
        outpoint_transaction_hash: None,
        sequence_number: None,
        unlocking_bytecode: Some(unlocking_bytecode),
    }
}

/// The input under test (`slotInput`).
pub static slotInput: LazyLock<WalletTemplateScenarioInput> = LazyLock::new(|| {
    input(WalletTemplateScenarioUnlockingBytecode::Slot)
});

fn script_input(script: &str) -> WalletTemplateScenarioInput {
    input(WalletTemplateScenarioUnlockingBytecode::Bytecode(definition(script)))
}

fn scenario(
    source_outputs: Vec<WalletTemplateScenarioSourceOutput>,
    inputs: Vec<WalletTemplateScenarioInput>,
    outputs: Vec<WalletTemplateScenarioTransactionOutput>,
) -> WalletTemplateScenario {
    WalletTemplateScenario {
        data: None,
        description: None,
        extends: None,
        name: None,
        transaction: Some(WalletTemplateScenarioTransaction {
            inputs: Some(inputs),
            locktime: None,
            outputs: Some(outputs),
            version: None,
        }),
        source_outputs: Some(source_outputs),
    }
}

/// The standard P2PKH source output (`simpleP2pkhOutput`).
pub static simpleP2pkhOutput: LazyLock<WalletTemplateScenarioSourceOutput> = LazyLock::new(|| {
    source_output(
        WalletTemplateScenarioOutputLockingBytecode::Bytecode(definition("lockP2pkh")),
        10_000.0,
    )
});

/// The standard P2PKH input (`simpleP2pkhInput`).
pub static simpleP2pkhInput: LazyLock<WalletTemplateScenarioInput> = LazyLock::new(|| {
    script_input("unlockP2pkh")
});

/// A source output encumbered by the empty P2SH20 template (`emptyP2sh20Output`).
pub static emptyP2sh20Output: LazyLock<WalletTemplateScenarioSourceOutput> = LazyLock::new(|| {
    source_output(
        WalletTemplateScenarioOutputLockingBytecode::Bytecode(definition("lockEmptyP2sh20")),
        10_000.0,
    )
});

/// An input spending the empty P2SH20 template (`emptyP2sh20Input`).
pub static emptyP2sh20Input: LazyLock<WalletTemplateScenarioInput> = LazyLock::new(|| {
    script_input("unlockEmptyP2sh20")
});

/// The standard VMB `OP_RETURN` output (`vmbTestOutput`).
pub static vmbTestOutput: LazyLock<WalletTemplateScenarioTransactionOutput> = LazyLock::new(|| {
    transaction_output(
        WalletTemplateScenarioOutputLockingBytecode::Bytecode(definition("vmbTestNullData")),
        0.0,
    )
});

/// A source output placing the script under test in the first output position
/// (`slotOutput`).
pub static slotOutput: LazyLock<WalletTemplateScenarioSourceOutput> = LazyLock::new(|| {
    source_output(WalletTemplateScenarioOutputLockingBytecode::Slot, 10_000.0)
});

/// The `slot0` scenario (`slot0Scenario`).
pub static slot0Scenario: LazyLock<WalletTemplateScenario> = LazyLock::new(|| {
    scenario(
        vec![slotOutput.clone(), simpleP2pkhOutput.clone()],
        vec![slotInput.clone(), simpleP2pkhInput.clone()],
        vec![vmbTestOutput.clone()],
    )
});

/// The `slot1` scenario (`slot1Scenario`).
pub static slot1Scenario: LazyLock<WalletTemplateScenario> = LazyLock::new(|| {
    scenario(
        vec![simpleP2pkhOutput.clone(), slotOutput.clone()],
        vec![simpleP2pkhInput.clone(), slotInput.clone()],
        vec![vmbTestOutput.clone()],
    )
});

/// The `slot2` scenario (`slot2Scenario`).
pub static slot2Scenario: LazyLock<WalletTemplateScenario> = LazyLock::new(|| {
    scenario(
        vec![
            simpleP2pkhOutput.clone(),
            simpleP2pkhOutput.clone(),
            slotOutput.clone(),
        ],
        vec![
            simpleP2pkhInput.clone(),
            simpleP2pkhInput.clone(),
            slotInput.clone(),
        ],
        vec![vmbTestOutput.clone()],
    )
});

/// The `slot9` scenario (`slot9Scenario`).
pub static slot9Scenario: LazyLock<WalletTemplateScenario> = LazyLock::new(|| {
    let mut source_outputs = vec![simpleP2pkhOutput.clone(); 9];
    source_outputs.push(slotOutput.clone());
    let mut inputs = vec![simpleP2pkhInput.clone(); 9];
    inputs.push(slotInput.clone());
    scenario(source_outputs, inputs, vec![vmbTestOutput.clone()])
});

/// Repeat `cash_assembly` `count` times, separated by spaces
/// (`repeat` in libauth).
pub fn repeat(cash_assembly: &str, count: usize) -> String {
    std::iter::repeat(cash_assembly)
        .take(count)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Compile `cash_assembly` and return its hex-encoded bytecode
/// (`cashAssemblyToHex` in libauth).
///
/// libauth throws when the assembly is invalid; this port panics with the same
/// error message, matching the helper's use for known-valid fragments.
pub fn cash_assembly_to_hex(cash_assembly: &str) -> String {
    bin_to_hex(
        &cash_assembly_to_bin(cash_assembly)
            .unwrap_or_else(|error| panic!("invalid CashAssembly: {error}")),
    )
}

/// The minimal standard transaction scenario (`minimalScenarioStandard`).
pub static minimalScenarioStandard: LazyLock<WalletTemplateScenario> = LazyLock::new(|| {
    scenario(
        vec![slotOutput.clone()],
        vec![slotInput.clone()],
        vec![transaction_output(
            WalletTemplateScenarioOutputLockingBytecode::Bytecode(hex_bytecode(
                cash_assembly_to_hex("OP_RETURN"),
            )),
            0.0,
        )],
    )
});

/// The minimal standard transaction scenario padded with `bytes` additional
/// bytes in the `OP_RETURN` output (`minimalScenarioStandardPlusBytes`).
pub fn minimal_scenario_standard_plus_bytes(bytes: usize) -> WalletTemplateScenario {
    scenario(
        vec![slotOutput.clone()],
        vec![slotInput.clone()],
        vec![transaction_output(
            WalletTemplateScenarioOutputLockingBytecode::Bytecode(hex_bytecode(
                cash_assembly_to_hex(&format!(
                    "OP_RETURN <{}>",
                    repeat("\"a\"", bytes)
                )),
            )),
            0.0,
        )],
    )
}

const MIN_SATS: f64 = 10_000.0;

/// A scenario packing a transaction with the contract under test
/// (`packedTransactionScenario`).
///
/// `using` is either `"p2s"` or `"p2sh20"`; the last input is the input under
/// test.
pub fn packed_transaction_scenario(using: &str, repeat_count: usize) -> WalletTemplateScenario {
    let (locking_script, unlocking_script) = match using {
        "p2s" => ("lockStandard", "unlockStandard"),
        "p2sh20" => ("lockP2sh20", "unlockP2sh20"),
        other => panic!("unknown locking script type: {other}"),
    };
    let mut source_outputs: Vec<WalletTemplateScenarioSourceOutput> = (1..=repeat_count)
        .map(|index| {
            source_output(
                WalletTemplateScenarioOutputLockingBytecode::Bytecode(definition(locking_script)),
                index as f64 + MIN_SATS,
            )
        })
        .collect();
    source_outputs.push(slotOutput.clone());
    let mut inputs: Vec<WalletTemplateScenarioInput> = (0..repeat_count)
        .map(|_| script_input(unlocking_script))
        .collect();
    inputs.push(slotInput.clone());
    scenario(
        source_outputs,
        inputs,
        vec![transaction_output(
            WalletTemplateScenarioOutputLockingBytecode::Bytecode(hex_bytecode(
                cash_assembly_to_hex("OP_RETURN"),
            )),
            0.0,
        )],
    )
}

/// The minimal nonstandard transaction scenario (`minimalScenarioNonStandard`).
pub static minimalScenarioNonStandard: LazyLock<WalletTemplateScenario> = LazyLock::new(|| {
    scenario(
        vec![slotOutput.clone()],
        vec![slotInput.clone()],
        vec![transaction_output(
            WalletTemplateScenarioOutputLockingBytecode::Bytecode(hex_bytecode(String::new())),
            0.0,
        )],
    )
});
