//! Port of `mappings.spec.ts`.
//!
//! Libauth is designed to simultaneously support multiple chains/versions of
//! bitcoin without patches to the Libauth codebase. As such, Libauth can
//! potentially include support for multiple implementations of a particular
//! data structure. By convention, Libauth identifies chain-specific
//! implementations with an uppercase currency symbol suffix.
//!
//! For example, a "transaction" may include different properties depending on
//! the chain for which it is created. The type `TransactionBch` specifies a
//! transaction intended for the BCH network, while the type `TransactionBtc`
//! specifies a transaction intended for BTC.
//!
//! For convenience, unless another chain is specified, Libauth types refer to
//! their BCH implementation, e.g. `Transaction` is an alias for
//! `TransactionBch`.
//!
//! This file tests these default mappings.

use std::any::TypeId;

use libauth::{
    compiler_configuration_to_compiler, compiler_configuration_to_compiler_bch, create_compiler,
    create_compiler_bch, create_instruction_set_bch, create_instruction_set_bch_2023,
    create_virtual_machine_bch, create_virtual_machine_bch_2023, decode_transaction,
    decode_transaction_bch, decode_transaction_common, decode_transaction_unsafe,
    decode_transaction_unsafe_bch, decode_transaction_unsafe_common, encode_transaction,
    encode_transaction_bch, encode_transaction_common, AssertTypesEqual, AuthenticationErrorBch,
    AuthenticationErrorBchSpec, AuthenticationProgram, AuthenticationProgramBch,
    AuthenticationProgramCommon, AuthenticationProgramState, AuthenticationProgramStateBch,
    AuthenticationProgramStateCommon, ConsensusBch, ConsensusCommon, OpcodeDescriptions,
    OpcodeDescriptionsBch, OpcodeDescriptionsBchSpec, Opcodes, OpcodesBch, OpcodesBchSpec,
    ResolvedTransaction, ResolvedTransactionBch, ResolvedTransactionCommon,
    SigningSerializationType, SigningSerializationTypeBch, Transaction, TransactionBch,
    TransactionCommon,
};

/// libauth's `AssertTypesEqual<T1, T2>` as a compile-time check: this function
/// can only be instantiated when `T1` and `T2` are the same type.
fn assert_types_equal<T1: AssertTypesEqual<T1, T2>, T2>() -> bool {
    true
}

/// `t.deepEqual(fnA, fnB)`: AVA compares functions by identity. Two Rust paths
/// name the same function exactly when they resolve to the same function item,
/// i.e. the same (zero-sized) function item type.
fn same_function<A: 'static, B: 'static>(_a: A, _b: B) -> bool {
    TypeId::of::<A>() == TypeId::of::<B>()
}

/// `t.deepEqual(objectA, objectB)` for libauth's constant objects (enums such
/// as `OpcodesBch` and `ConsensusCommon`). In Rust these are unit structs with
/// associated constants, so the two names are equal when they name the same
/// type.
fn same_object<A: 'static, B: 'static>() -> bool {
    TypeId::of::<A>() == TypeId::of::<B>()
}

#[test]
fn libauth_exposes_all_expected_mappings() {
    // `type TypeTests = AssertTypesEqual<...> | ...;`
    let test_types: bool = assert_types_equal::<
        AuthenticationProgramStateBch,
        AuthenticationProgramStateCommon,
    >() && assert_types_equal::<OpcodeDescriptionsBchSpec, OpcodeDescriptions>()
        && assert_types_equal::<AuthenticationProgramBch, AuthenticationProgram>()
        && assert_types_equal::<AuthenticationProgramBch, AuthenticationProgramCommon>()
        && assert_types_equal::<AuthenticationProgramStateBch, AuthenticationProgramState>()
        && assert_types_equal::<ResolvedTransactionBch, ResolvedTransaction>()
        && assert_types_equal::<ResolvedTransactionBch, ResolvedTransactionCommon>()
        && assert_types_equal::<TransactionBch, Transaction>()
        && assert_types_equal::<TransactionBch, TransactionCommon>()
        && assert_types_equal::<ConsensusCommon, ConsensusBch>()
        && assert_types_equal::<OpcodesBchSpec, Opcodes>();
    assert!(test_types);
    assert!(same_object::<AuthenticationErrorBch, AuthenticationErrorBchSpec>());
    assert!(same_function(
        compiler_configuration_to_compiler_bch,
        compiler_configuration_to_compiler
    ));
    assert!(same_function(create_instruction_set_bch_2023, create_instruction_set_bch));
    assert!(same_function(create_virtual_machine_bch_2023, create_virtual_machine_bch));
    assert!(same_object::<ConsensusCommon, ConsensusBch>());
    assert!(same_function(create_compiler_bch, create_compiler));
    assert!(same_function(decode_transaction_common, decode_transaction_bch));
    assert!(same_function(decode_transaction, decode_transaction_bch));
    assert!(same_function(
        decode_transaction_unsafe_common,
        decode_transaction_unsafe_bch
    ));
    assert!(same_function(decode_transaction_unsafe, decode_transaction_unsafe_bch));
    assert!(same_function(encode_transaction_common, encode_transaction_bch));
    assert!(same_function(encode_transaction, encode_transaction_bch));
    assert!(same_object::<OpcodeDescriptionsBch, OpcodeDescriptionsBchSpec>());
    assert!(same_object::<OpcodeDescriptions, OpcodeDescriptionsBchSpec>());
    assert!(same_object::<OpcodesBch, OpcodesBchSpec>());
    assert!(same_object::<Opcodes, OpcodesBchSpec>());
    assert!(same_object::<SigningSerializationType, SigningSerializationTypeBch>());
}
