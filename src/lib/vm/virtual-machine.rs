use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crate::vm::{
    AuthenticationInstruction, AuthenticationProgramStateCommon, AuthenticationProgramStateMinimum,
};

/// Operations define the behavior of an opcode in an {@link InstructionSet}.
///
/// Operations should be written as efficiently as possible, and may safely
/// mutate the `ProgramState`. If needed, the {@link AuthenticationVirtualMachine}
/// will clone the `ProgramState` before providing it to an operation.
pub type Operation<ProgramState = AuthenticationProgramStateCommon> = Rc<dyn Fn(&mut ProgramState)>;

/// Test a program state, returning an error message or `Ok` (libauth's
/// `true`) if the test passes.
pub type TestState<ProgramState> = Rc<dyn Fn(&ProgramState) -> Result<(), String>>;

/// A mapping of opcodes to their {@link Operation}s.
pub type InstructionSetOperationMapping<ProgramState = AuthenticationProgramStateCommon> =
    BTreeMap<u8, Operation<ProgramState>>;

/// The virtual machine functions provided to an instruction set's `evaluate`
/// method.
pub struct InstructionSetEvaluation<'a, AuthenticationProgram, ProgramState> {
    /// Evaluate a program state to completion.
    pub state_evaluate: &'a dyn Fn(ProgramState) -> ProgramState,
    /// Create the initial program state for a program.
    pub state_initialize: &'a dyn Fn(&AuthenticationProgram) -> ProgramState,
    /// An optional modification applied to each initialized program state
    /// (libauth's `stateOverride`, a partial program state).
    pub state_override: Option<&'a dyn Fn(&mut ProgramState)>,
}

/// The virtual machine functions provided to an instruction set's `verify`
/// method.
pub struct InstructionSetVerification<'a, AuthenticationProgram, ProgramState> {
    /// Evaluate a program, returning the final program state.
    pub evaluate: &'a dyn Fn(&AuthenticationProgram) -> ProgramState,
    /// Create the initial program state for a program.
    pub initialize: &'a dyn Fn(&AuthenticationProgram) -> ProgramState,
    /// Verify that a program state has completed evaluation successfully.
    pub success: &'a dyn Fn(&ProgramState) -> Result<(), String>,
}

/// The `evaluate` method of an {@link InstructionSet}.
type InstructionSetEvaluate<AuthenticationProgram, ProgramState> = Rc<
    dyn Fn(
        &AuthenticationProgram,
        &InstructionSetEvaluation<'_, AuthenticationProgram, ProgramState>,
    ) -> ProgramState,
>;

/// The `verify` method of an {@link InstructionSet}.
type InstructionSetVerify<ResolvedTransaction, AuthenticationProgram, ProgramState> = Rc<
    dyn Fn(
        &ResolvedTransaction,
        &InstructionSetVerification<'_, AuthenticationProgram, ProgramState>,
    ) -> Result<(), String>,
>;

/// An `InstructionSet` is a mapping of methods that define the operation of an
/// {@link AuthenticationVirtualMachine}.
///
/// An instruction set is specific to a single consensus setting, e.g.
/// `BCH_2023_05`.
///
/// Instruction sets define how an authentication program is evaluated
/// (`evaluate`), how evaluation of an instruction should begin (`continue`),
/// the operation to perform for each defined opcode (`operations`) or for an
/// undefined opcode (`undefined`), how to determine the success or failure of
/// a completed program state (`success`), and how to verify a transaction
/// (`verify`).
pub struct InstructionSet<ResolvedTransaction, AuthenticationProgram, ProgramState> {
    /// Take a `ProgramState` and return a `boolean` indicating if the program
    /// should continue evaluation. (It may mutate the state, e.g. to return
    /// from a completed function frame.)
    pub r#continue: Rc<dyn Fn(&mut ProgramState) -> bool>,
    /// Evaluate a program to completion given the virtual machine's
    /// `stateEvaluate` and `stateInitialize` functions.
    pub evaluate: InstructionSetEvaluate<AuthenticationProgram, ProgramState>,
    /// An optional operation to be performed after every executed virtual
    /// machine operation.
    pub every: Option<Operation<ProgramState>>,
    /// Create the initial program state for an `AuthenticationProgram`.
    ///
    /// libauth's `initialize` is optional and returns a partial program state;
    /// a Rust program state must be fully constructed, so `initialize` is
    /// required and returns the complete initial state.
    pub initialize: Rc<dyn Fn(&AuthenticationProgram) -> ProgramState>,
    /// A mapping of `opcode` numbers (between 0 and 255) to `Operations`.
    pub operations: InstructionSetOperationMapping<ProgramState>,
    /// Test the state of a completed program to determine if it was successful.
    pub success: TestState<ProgramState>,
    /// The operation to perform for undefined opcodes.
    pub undefined: Operation<ProgramState>,
    /// Verify a transaction given the virtual machine's `evaluate`, `success`,
    /// and `initialize` functions.
    pub verify: InstructionSetVerify<ResolvedTransaction, AuthenticationProgram, ProgramState>,
}

impl<ResolvedTransaction, AuthenticationProgram, ProgramState> Clone
    for InstructionSet<ResolvedTransaction, AuthenticationProgram, ProgramState>
{
    fn clone(&self) -> Self {
        InstructionSet {
            r#continue: Rc::clone(&self.r#continue),
            evaluate: Rc::clone(&self.evaluate),
            every: self.every.clone(),
            initialize: Rc::clone(&self.initialize),
            operations: self.operations.clone(),
            success: Rc::clone(&self.success),
            undefined: Rc::clone(&self.undefined),
            verify: Rc::clone(&self.verify),
        }
    }
}

/// A program state with its static `instructions` and `program` masked and
/// the resolved `instruction` added.
///
/// libauth's `MaskedProgramState` omits `instructions` and `program`; Rust
/// cannot omit fields of a generic program state, so the (reference-counted)
/// static properties are retained in `state`.
#[derive(Clone, Debug, PartialEq)]
pub struct MaskedProgramState<ProgramState = AuthenticationProgramStateCommon> {
    /// The resolved instruction that was executed to arrive at this program
    /// state.
    ///
    /// Set to `None` for the last (duplicated) program state produced by each
    /// bytecode evaluation.
    pub instruction: Option<AuthenticationInstruction>,
    /// The (partially-cloned) program state.
    pub state: ProgramState,
}

/// A set of functions for evaluating authentication programs in a virtual
/// machine, created from an {@link InstructionSet} by
/// {@link createVirtualMachine}.
pub struct AuthenticationVirtualMachine<ResolvedTransaction, AuthenticationProgram, ProgramState> {
    instruction_set: InstructionSet<ResolvedTransaction, AuthenticationProgram, ProgramState>,
    operators: Vec<Operation<ProgramState>>,
}

impl<ResolvedTransaction, AuthenticationProgram, ProgramState> Clone
    for AuthenticationVirtualMachine<ResolvedTransaction, AuthenticationProgram, ProgramState>
{
    fn clone(&self) -> Self {
        AuthenticationVirtualMachine {
            instruction_set: self.instruction_set.clone(),
            operators: self.operators.clone(),
        }
    }
}

/// Create a partial clone of a program state: libauth shares the static
/// `instructions` and `program` by reference, shallow-clones the stacks and
/// `signedMessages`, and deep-clones everything else. (In Rust, the static
/// properties are reference-counted, so cloning shares them.)
pub fn partially_clone_program_state<ProgramState: Clone>(state: &ProgramState) -> ProgramState {
    state.clone()
}

/// Given a `ProgramState`, clone and return a {@link MaskedProgramState} from
/// it: the static `instructions` and `program` are masked and the current
/// `instruction` is added.
pub fn mask_static_program_state<ProgramState: AuthenticationProgramStateMinimum>(
    state: &ProgramState,
) -> MaskedProgramState<ProgramState> {
    let instruction = usize::try_from(state.ip())
        .ok()
        .and_then(|ip| state.instructions().get(ip).cloned());
    MaskedProgramState {
        instruction,
        state: partially_clone_program_state(state),
    }
}

impl<ResolvedTransaction, AuthenticationProgram, ProgramState>
    AuthenticationVirtualMachine<ResolvedTransaction, AuthenticationProgram, ProgramState>
where
    ProgramState: AuthenticationProgramStateMinimum,
{
    fn get_operation(&self, state: &ProgramState) -> Operation<ProgramState> {
        let opcode = state.instructions()[state.ip() as usize].opcode();
        Rc::clone(&self.operators[opcode as usize])
    }

    fn after_operation(state: &mut ProgramState) {
        *state.evaluated_instruction_count_mut() += 1.0;
    }

    fn after_instruction(state: &mut ProgramState) {
        *state.ip_mut() += 1;
    }

    fn state_every(&self, state: &mut ProgramState) {
        if let Some(every) = &self.instruction_set.every {
            every(state);
        }
    }

    fn until_complete(
        &self,
        mut state: ProgramState,
        mut step_function: impl FnMut(ProgramState) -> ProgramState,
    ) -> ProgramState {
        while (self.instruction_set.r#continue)(&mut state) {
            state = step_function(state);
        }
        state
    }

    fn state_debug_step(&self, state: &ProgramState) -> ProgramState {
        let operator = self.get_operation(state);
        let mut next = self.state_clone(state);
        operator(&mut next);
        Self::after_operation(&mut next);
        self.state_every(&mut next);
        Self::after_instruction(&mut next);
        next
    }

    /// Clone a program state.
    pub fn state_clone(&self, state: &ProgramState) -> ProgramState {
        partially_clone_program_state(state)
    }

    /// Test the program state to determine if evaluation should continue.
    pub fn state_continue(&self, state: &mut ProgramState) -> bool {
        (self.instruction_set.r#continue)(state)
    }

    /// Return an array of program states by fully evaluating `state`, cloning
    /// and adding each intermediate state to the array. The first state is
    /// the provided `state`.
    pub fn state_debug(&self, state: &ProgramState) -> Vec<ProgramState> {
        let mut trace = vec![state.clone()];
        // As in libauth, `continue` is applied to the most recent trace entry
        // itself (it may return from a completed function frame).
        while let Some(current_state) = trace.last_mut() {
            if !(self.instruction_set.r#continue)(current_state) {
                break;
            }
            let next_state = self.state_debug_step(current_state);
            trace.push(next_state);
        }
        trace
    }

    /// Return a new program state by cloning and fully evaluating `state`.
    pub fn state_evaluate(&self, state: &ProgramState) -> ProgramState {
        self.until_complete(self.state_clone(state), |mut state| {
            self.state_step_mutate(&mut state);
            state
        })
    }

    /// Create the initial program state for an `AuthenticationProgram`.
    pub fn state_initialize(&self, program: &AuthenticationProgram) -> ProgramState {
        (self.instruction_set.initialize)(program)
    }

    /// Clone the provided program state and advance it by one instruction.
    pub fn state_step(&self, state: &ProgramState) -> ProgramState {
        let mut next = self.state_clone(state);
        self.state_step_mutate(&mut next);
        next
    }

    /// A faster, less-safe version of `stateStep` that directly modifies the
    /// provided program state.
    pub fn state_step_mutate(&self, state: &mut ProgramState) {
        let operator = self.get_operation(state);
        operator(state);
        Self::after_operation(state);
        self.state_every(state);
        Self::after_instruction(state);
    }

    /// Verify a program state has completed evaluation successfully, returning
    /// an error message if it has not.
    pub fn state_success(&self, state: &ProgramState) -> Result<(), String> {
        (self.instruction_set.success)(state)
    }

    /// Evaluate an `AuthenticationProgram`, returning the resulting
    /// `ProgramState`.
    ///
    /// `state_override` (libauth's `stateOverride`) modifies each initialized
    /// program state.
    pub fn evaluate(
        &self,
        program: &AuthenticationProgram,
        state_override: Option<&dyn Fn(&mut ProgramState)>,
    ) -> ProgramState {
        let state_evaluate = |state: ProgramState| self.state_evaluate(&state);
        let initialize = |program: &AuthenticationProgram| self.state_initialize(program);
        (self.instruction_set.evaluate)(
            program,
            &InstructionSetEvaluation {
                state_evaluate: &state_evaluate,
                state_initialize: &initialize,
                state_override,
            },
        )
    }

    /// Debug an `AuthenticationProgram`, returning an array of every program
    /// state: the initial state of each evaluation, each intermediate state,
    /// and a duplicate of the final state.
    pub fn debug(
        &self,
        program: &AuthenticationProgram,
        state_override: Option<&dyn Fn(&mut ProgramState)>,
    ) -> Vec<ProgramState> {
        let results = RefCell::new(Vec::new());
        let proxy_debug = |state: ProgramState| {
            let debug_result = self.state_debug(&state);
            let last = debug_result.last().cloned().unwrap_or(state);
            results.borrow_mut().extend(debug_result);
            last
        };
        let initialize = |program: &AuthenticationProgram| self.state_initialize(program);
        let final_result = (self.instruction_set.evaluate)(
            program,
            &InstructionSetEvaluation {
                state_evaluate: &proxy_debug,
                state_initialize: &initialize,
                state_override,
            },
        );
        let mut trace = results.into_inner();
        trace.push(final_result);
        trace
    }

    /// Debug an `AuthenticationProgram` like {@link debug}, masking the
    /// static properties of each program state (libauth's
    /// `maskProgramState: true`).
    pub fn debug_masked(
        &self,
        program: &AuthenticationProgram,
        state_override: Option<&dyn Fn(&mut ProgramState)>,
    ) -> Vec<MaskedProgramState<ProgramState>> {
        self.debug(program, state_override)
            .iter()
            .map(mask_static_program_state)
            .collect()
    }

    /// Verify a resolved transaction, returning `Ok` if it is valid or an
    /// error message describing the first failure.
    pub fn verify(&self, resolved_transaction: &ResolvedTransaction) -> Result<(), String> {
        let evaluate = |program: &AuthenticationProgram| self.evaluate(program, None);
        let initialize = |program: &AuthenticationProgram| self.state_initialize(program);
        let success = |state: &ProgramState| self.state_success(state);
        (self.instruction_set.verify)(
            resolved_transaction,
            &InstructionSetVerification {
                evaluate: &evaluate,
                initialize: &initialize,
                success: &success,
            },
        )
    }
}

/// Create an {@link AuthenticationVirtualMachine} to evaluate authentication
/// programs constructed from operations in the `instructionSet`.
pub fn create_virtual_machine<ResolvedTransaction, AuthenticationProgram, ProgramState>(
    instruction_set: InstructionSet<ResolvedTransaction, AuthenticationProgram, ProgramState>,
) -> AuthenticationVirtualMachine<ResolvedTransaction, AuthenticationProgram, ProgramState> {
    const AVAILABLE_OPCODES: usize = 256;
    let operators = (0..AVAILABLE_OPCODES)
        .map(|codepoint| {
            instruction_set
                .operations
                .get(&(codepoint as u8))
                .cloned()
                .unwrap_or_else(|| Rc::clone(&instruction_set.undefined))
        })
        .collect();
    AuthenticationVirtualMachine {
        instruction_set,
        operators,
    }
}

/// @deprecated Alias of `createVirtualMachine` for backwards-compatibility.
pub fn create_authentication_virtual_machine<
    ResolvedTransaction,
    AuthenticationProgram,
    ProgramState,
>(
    instruction_set: InstructionSet<ResolvedTransaction, AuthenticationProgram, ProgramState>,
) -> AuthenticationVirtualMachine<ResolvedTransaction, AuthenticationProgram, ProgramState> {
    create_virtual_machine(instruction_set)
}

impl<ProgramState> std::borrow::Borrow<ProgramState> for MaskedProgramState<ProgramState> {
    fn borrow(&self) -> &ProgramState {
        &self.state
    }
}
