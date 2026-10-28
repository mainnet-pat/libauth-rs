use crate::vm::{create_instruction_set_xec, create_virtual_machine, AuthenticationVirtualMachineBch};

/// Initialize a virtual machine using the XEC instruction set.
///
/// @param standard - If `true`, the additional `isStandard` validations will be
/// enabled. Transactions that fail these rules are often called "non-standard"
/// and can technically be included by miners in valid blocks, but most network
/// nodes will refuse to relay them. (Default: `true`)
pub fn create_virtual_machine_xec(standard: Option<bool>) -> AuthenticationVirtualMachineBch {
    create_virtual_machine(create_instruction_set_xec(standard, None, None, None, None, None))
}
