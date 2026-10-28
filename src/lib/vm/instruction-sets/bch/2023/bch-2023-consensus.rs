/// The type of the consensus settings objects of the BCH instruction sets
/// (libauth's `typeof ConsensusBch2023`, extended with the optional
/// settings introduced by later instruction sets).
///
/// Each consensus settings value (e.g. {@link ConsensusBch2023}) is a constant
/// of this type with the same name.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ConsensusBch2023 {
    pub base_instruction_cost: f64,
    /// The constant added to the unlocking bytecode length to determine a
    /// contract's density control length (for operation cost and hashing budgets).
    pub density_control_base_length: usize,
    pub hash_digest_iteration_cost_consensus: f64,
    pub hash_digest_iteration_cost_standard: f64,
    pub hash_digest_iterations_per_byte_nonstandard: f64,
    pub hash_digest_iterations_per_byte_standard: f64,
    /// A.K.A. `MAX_SCRIPT_SIZE`
    pub maximum_bytecode_length: usize,
    /// A.K.A. `MAX_CONSENSUS_VERSION`
    pub maximum_consensus_version: u32,
    pub maximum_control_stack_depth: usize,
    /// A.K.A. `MAX_OP_RETURN_RELAY`, `nMaxDatacarrierBytes`
    pub maximum_data_carrier_bytes: usize,
    pub maximum_fungible_token_amount: &'static str,
    /// The maximum length of a function identifier (`OP_DEFINE`/`OP_INVOKE`);
    /// introduced by `ConsensusBch2026` (`None` in earlier settings).
    pub maximum_function_identifier_length: Option<usize>,
    /// The maximum number of memory slots (stack items and function
    /// definitions); introduced by `ConsensusBch2026` (`None` in earlier
    /// settings).
    pub maximum_memory_slots: Option<usize>,
    /// A.K.A. `MAX_OPS_PER_SCRIPT`
    pub maximum_operation_count: usize,
    /// A.K.A. `MAX_STACK_SIZE`
    pub maximum_stack_depth: usize,
    /// A.K.A. `MAX_SCRIPT_ELEMENT_SIZE`
    pub maximum_stack_item_length: usize,
    /// When set to `-1`, only BCH_2023_05 standard patterns are accepted.
    pub maximum_standard_locking_bytecode_length: i64,
    /// A.K.A. `MAX_STANDARD_TX_SIZE`
    pub maximum_standard_transaction_size: usize,
    /// A.K.A. `MAX_TX_IN_SCRIPT_SIG_SIZE`
    pub maximum_standard_unlocking_bytecode_length: usize,
    pub maximum_token_commitment_length: usize,
    /// A.K.A. `MAX_TX_SIZE`
    pub maximum_transaction_length_bytes: usize,
    /// A.K.A. `MAX_TX_SIGCHECKS`
    pub maximum_transaction_signature_checks: usize,
    /// A.K.A. `nMaxNumSize`
    pub maximum_vm_number_byte_length: usize,
    /// A.K.A. `MIN_CONSENSUS_VERSION`
    pub minimum_consensus_version: u32,
    /// Transactions smaller than 65 bytes are forbidden to prevent exploits of the
    /// transaction Merkle tree design.
    ///
    /// A.K.A. `MIN_TX_SIZE`
    pub minimum_transaction_length_bytes: usize,
    pub operation_cost_budget_per_byte: f64,
    pub schnorr_signature_length: usize,
    pub signature_check_cost: f64,
}

/// Consensus settings for the `BCH_2023_05` instruction set.
pub const ConsensusBch2023: ConsensusBch2023 = ConsensusBch2023 {
    base_instruction_cost: 100.0,
    density_control_base_length: 41,
    hash_digest_iteration_cost_consensus: 64.0,
    hash_digest_iteration_cost_standard: 192.0,
    hash_digest_iterations_per_byte_nonstandard: 3.5,
    hash_digest_iterations_per_byte_standard: 0.5,
    maximum_bytecode_length: 10000,
    maximum_consensus_version: 2,
    maximum_control_stack_depth: 100,
    maximum_data_carrier_bytes: 223,
    maximum_fungible_token_amount: "9223372036854775807",
    maximum_function_identifier_length: None,
    maximum_memory_slots: None,
    maximum_operation_count: 201,
    maximum_stack_depth: 1000,
    maximum_stack_item_length: 520,
    maximum_standard_locking_bytecode_length: -1,
    maximum_standard_transaction_size: 100_000,
    maximum_standard_unlocking_bytecode_length: 1650,
    maximum_token_commitment_length: 40,
    maximum_transaction_length_bytes: 1_000_000,
    maximum_transaction_signature_checks: 3_000,
    maximum_vm_number_byte_length: 8,
    minimum_consensus_version: 1,
    minimum_transaction_length_bytes: 65,
    operation_cost_budget_per_byte: 800.0,
    schnorr_signature_length: 64,
    signature_check_cost: 26000.0,
};

/// Calculate the maximum signature check count (A.K.A. "SigChecks") as defined
/// by the `BCH_2020_05` upgrade.
pub fn maximum_signature_check_count(unlocking_bytecode_length: usize) -> usize {
    (unlocking_bytecode_length + 60) / 43
}
