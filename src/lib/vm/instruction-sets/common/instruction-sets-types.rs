/// A push instruction: an opcode and the data it pushes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthenticationInstructionPush {
    /// The data to be pushed to the stack.
    pub data: Vec<u8>,
    /// The opcode used to serialize this data.
    pub opcode: u8,
}

/// A non-push instruction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthenticationInstructionOperation {
    /// The opcode of this instruction's operation.
    pub opcode: u8,
}

/// A properly-formed instruction used by an {@link AuthenticationVirtualMachine}.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AuthenticationInstruction {
    Operation(AuthenticationInstructionOperation),
    Push(AuthenticationInstructionPush),
}

impl AuthenticationInstruction {
    /// The opcode of this instruction.
    pub fn opcode(&self) -> u8 {
        match self {
            AuthenticationInstruction::Operation(instruction) => instruction.opcode,
            AuthenticationInstruction::Push(instruction) => instruction.opcode,
        }
    }

    /// The pushed data, if this is a push instruction (libauth's
    /// `'data' in instruction`).
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            AuthenticationInstruction::Operation(_) => None,
            AuthenticationInstruction::Push(instruction) => Some(&instruction.data),
        }
    }
}

/// An array of authentication instructions.
pub type AuthenticationInstructions = Vec<AuthenticationInstruction>;

/// A push instruction with a malformed length: the bytecode ended before the
/// complete length of the push could be read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthenticationInstructionPushMalformedLength {
    /// The expected number of length bytes (`1`, `2`, or `4`).
    pub expected_length_bytes: u8,
    /// The length bytes which were available.
    pub length: Vec<u8>,
    pub opcode: u8,
}

/// A push instruction with malformed data: the bytecode ended before all of
/// the data indicated by the push length could be read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthenticationInstructionPushMalformedData {
    /// The data which was available.
    pub data: Vec<u8>,
    /// The number of data bytes indicated by the push.
    pub expected_data_bytes: usize,
    pub opcode: u8,
}

/// A malformed instruction (libauth marks these with `malformed: true`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AuthenticationInstructionMalformed {
    PushMalformedData(AuthenticationInstructionPushMalformedData),
    PushMalformedLength(AuthenticationInstructionPushMalformedLength),
}

impl AuthenticationInstructionMalformed {
    /// The opcode of this malformed instruction.
    pub fn opcode(&self) -> u8 {
        match self {
            AuthenticationInstructionMalformed::PushMalformedData(instruction) => {
                instruction.opcode
            }
            AuthenticationInstructionMalformed::PushMalformedLength(instruction) => {
                instruction.opcode
            }
        }
    }
}

/// An instruction which may be malformed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AuthenticationInstructionMaybeMalformed {
    Instruction(AuthenticationInstruction),
    Malformed(AuthenticationInstructionMalformed),
}

impl AuthenticationInstructionMaybeMalformed {
    /// The opcode of this instruction.
    pub fn opcode(&self) -> u8 {
        match self {
            AuthenticationInstructionMaybeMalformed::Instruction(instruction) => {
                instruction.opcode()
            }
            AuthenticationInstructionMaybeMalformed::Malformed(instruction) => {
                instruction.opcode()
            }
        }
    }
}

/// An array of authentication instructions in which the final instruction
/// is malformed.
pub type AuthenticationInstructionsMalformed = Vec<AuthenticationInstructionMaybeMalformed>;

/// An array of authentication instructions which may end with a malformed
/// instruction.
///
/// Implementation note: this type can be used only for instructions which
/// are pushes or operations, i.e. the result of decoding bytecode.
pub type AuthenticationInstructionsMaybeMalformed = Vec<AuthenticationInstructionMaybeMalformed>;
