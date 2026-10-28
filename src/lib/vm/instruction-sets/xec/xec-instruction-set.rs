use std::rc::Rc;

use crate::crypto::{Ripemd160, Secp256k1, Sha1, Sha256};
use crate::vm::instruction_sets::xec::xec_2020_consensus::ConsensusXec;
use crate::vm::{
    create_instruction_set_bch_2023, undefined_operation, AuthenticationProgramBch,
    AuthenticationProgramStateBch, ConsensusBch2023, InstructionSet, Operation, OpcodesXec,
    ResolvedTransactionBch,
};

/// create an instance of the XEC virtual machine instruction set.
///
/// @param standard - If `true`, the additional `isStandard` validations will be
/// enabled. Transactions that fail these rules are often called "non-standard"
/// and can technically be included by miners in valid blocks, but most network
/// nodes will refuse to relay them. (Default: `true`)
///
/// The remaining parameters (libauth's second, object parameter) default to
/// `ConsensusXec` and the internal crypto instances.
pub fn create_instruction_set_xec(
    standard: Option<bool>,
    consensus: Option<ConsensusBch2023>,
    ripemd160: Option<Ripemd160>,
    secp256k1: Option<Secp256k1>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
) -> InstructionSet<ResolvedTransactionBch, AuthenticationProgramBch, AuthenticationProgramStateBch> {
    let consensus = consensus.unwrap_or(ConsensusXec);
    let instruction_set =
        create_instruction_set_bch_2023(standard, Some(consensus), ripemd160, secp256k1, sha1, sha256);
    let undefined: Operation = Rc::new(undefined_operation);
    let mut operations = instruction_set.operations.clone();
    operations.insert(OpcodesXec::OP_MUL, Rc::clone(&undefined));
    // OP_UNKNOWN192 through OP_UNKNOWN211
    for opcode in OpcodesXec::OP_UNKNOWN192..=OpcodesXec::OP_UNKNOWN211 {
        operations.insert(opcode, Rc::clone(&undefined));
    }
    InstructionSet {
        operations,
        ..instruction_set
    }
}
