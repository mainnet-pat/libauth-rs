use crate::vm::{create_instruction_set_bch_spec, create_virtual_machine, AuthenticationVirtualMachineBchSpec};

/// Initialize a virtual machine using the BCH `SPEC` instruction set, an
/// informal, speculative instruction set that implements a variety of future
/// Bitcoin Cash Improvement Proposals (CHIPs).
///
/// @param standard - If `true`, the additional `isStandard` validations will be
/// enabled. Transactions that fail these rules are often called "non-standard"
/// and can technically be included by miners in valid blocks, but most network
/// nodes will refuse to relay them. (Default: `true`)
pub fn create_virtual_machine_bch_spec(standard: Option<bool>) -> AuthenticationVirtualMachineBchSpec {
    create_virtual_machine(create_instruction_set_bch_spec(standard, None, None, None, None, None))
}
