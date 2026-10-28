use crate::vm::AuthenticationProgramStateCommon;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegWitState {
    pub witness_bytecode: Vec<u8>,
}

/// libauth's `AuthenticationProgramStateCommon & SegWitState`.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticationProgramStateBTC {
    pub state: AuthenticationProgramStateCommon,
    pub witness_bytecode: Vec<u8>,
}
