use crate::vm::{create_instruction_set_bch_2025, create_virtual_machine, AuthenticationVirtualMachineBch2025};

/// Initialize a virtual machine using the `BCH_2025_05` instruction set.
///
/// @param standard - If `true`, the additional `isStandard` validations will be
/// enabled. Transactions that fail these rules are often called "non-standard"
/// and can technically be included by miners in valid blocks, but most network
/// nodes will refuse to relay them. (Default: `true`)
pub fn create_virtual_machine_bch_2025(standard: Option<bool>) -> AuthenticationVirtualMachineBch2025 {
    create_virtual_machine(create_instruction_set_bch_2025(standard, None, None, None, None, None))
}
