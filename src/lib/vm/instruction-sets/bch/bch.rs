#[path = "2023/bch-2023.rs"]
pub mod bch_2023;
#[path = "2025/bch-2025.rs"]
pub mod bch_2025;
#[path = "2026/bch-2026.rs"]
pub mod bch_2026;
#[path = "spec/bch-spec.rs"]
pub mod bch_spec;

pub use bch_2023::*;
pub use bch_2025::*;
pub use bch_2026::*;
pub use bch_spec::*;

pub use self::bch_2023::bch_2023_vm::create_virtual_machine_bch_2023 as create_virtual_machine_bch;
pub use crate::vm::instruction_sets::common::consensus::ConsensusCommon as ConsensusBch;
pub use self::bch_spec::bch_spec_opcodes::OpcodesBchSpec as OpcodesBch;
pub use self::bch_spec::bch_spec_errors::AuthenticationErrorBchSpec as AuthenticationErrorBch;
pub use self::bch_spec::bch_spec_descriptions::OpcodeDescriptionsBchSpec as OpcodeDescriptionsBch;
/// @deprecated Alias of `ConsensusBch` for backwards-compatibility.
pub use crate::vm::instruction_sets::common::consensus::ConsensusCommon as ConsensusBCH;
/// @deprecated Alias of `AuthenticationErrorBch2023` for backwards-compatibility.
pub use self::bch_2023::bch_2023_errors::AuthenticationErrorBch2023 as AuthenticationErrorBCH2023;
/// @deprecated Alias of `AuthenticationErrorBch` for backwards-compatibility.
pub use self::bch_spec::bch_spec_errors::AuthenticationErrorBchSpec as AuthenticationErrorBCH;
/// @deprecated Alias of `OpcodeDescriptionsBch2023` for backwards-compatibility.
pub use self::bch_2023::bch_2023_descriptions::OpcodeDescriptionsBch2023 as OpcodeDescriptionsBCH2023;
/// @deprecated Alias of `OpcodeDescriptionsBch` for backwards-compatibility.
pub use self::bch_spec::bch_spec_descriptions::OpcodeDescriptionsBchSpec as OpcodeDescriptionsBCH;
/// @deprecated Alias of `OpcodesBch` for backwards-compatibility.
pub use self::bch_spec::bch_spec_opcodes::OpcodesBchSpec as OpcodesBCH;
/// @deprecated Alias of `OpcodesBch2023` for backwards-compatibility.
pub use self::bch_2023::bch_2023_opcodes::OpcodesBch2023 as OpcodesBCH2023;
/// @deprecated Alias of `createInstructionSetBch` for backwards-compatibility.
pub use self::bch_2023::bch_2023_instruction_set::create_instruction_set_bch as create_instruction_set_BCH;
/// @deprecated Alias of `createInstructionSetBch2023` for backwards-compatibility.
pub use self::bch_2023::bch_2023_instruction_set::create_instruction_set_bch_2023 as create_instruction_set_BCH2023;
/// @deprecated Alias of `createVirtualMachineBch` for backwards-compatibility.
pub use self::bch_2023::bch_2023_vm::create_virtual_machine_bch_2023 as create_virtual_machine_BCH;
/// @deprecated Alias of `createVirtualMachineBch2023` for backwards-compatibility.
pub use self::bch_2023::bch_2023_vm::create_virtual_machine_bch_2023 as create_virtual_machine_BCH2023;
