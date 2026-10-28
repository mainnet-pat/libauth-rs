//! Port of `vm/virtual-machine.spec.ts`.

use std::collections::BTreeMap;
use std::rc::Rc;

use libauth::{
    create_virtual_machine, format_error, AuthenticationInstruction,
    AuthenticationInstructionOperation, AuthenticationProgramStateMinimum,
    AuthenticationVirtualMachine, InstructionSet, MaskedProgramState, Operation,
};

/// libauth's (spec-local) `const enum SimpleOps`.
struct SimpleOps;

impl SimpleOps {
    const OP_0: u8 = 0;
    const OP_INCREMENT: u8 = 1;
    const OP_DECREMENT: u8 = 2;
    const OP_ADD: u8 = 3;
    const OP_REPEAT: u8 = 4;
}

/// libauth's (spec-local) `const enum SimpleError`.
struct SimpleError;

impl SimpleError {
    const UNDEFINED: &'static str = "The program called an undefined opcode.";
    const EMPTY_STACK: &'static str = "The program tried to pop from an empty stack.";
    const EXCESSIVE: &'static str = "Values may be no larger than 2.";
    const FAIL: &'static str = "The top stack item must be a 1.";
}

#[derive(Clone, Debug, PartialEq)]
struct SimpleTransaction {
    instructions: Vec<AuthenticationInstruction>,
}

#[derive(Clone, Debug, PartialEq)]
struct SimpleResolvedTransaction {
    transaction: SimpleTransaction,
}

#[derive(Clone, Debug, PartialEq)]
struct SimpleProgram {
    instructions: Vec<AuthenticationInstruction>,
}

#[derive(Clone, Debug, PartialEq)]
struct Metrics {
    evaluated_instruction_count: f64,
}

/// `AuthenticationProgramStateMinimum & { stack: number[]; repeated?: true;
/// error?: string }`
#[derive(Clone, Debug, PartialEq)]
struct SimpleProgramState {
    instructions: Vec<AuthenticationInstruction>,
    ip: isize,
    metrics: Metrics,
    stack: Vec<i64>,
    /// libauth's optional `repeated?: true`.
    repeated: Option<bool>,
    error: Option<String>,
}

impl AuthenticationProgramStateMinimum for SimpleProgramState {
    fn instructions(&self) -> &[AuthenticationInstruction] {
        &self.instructions
    }

    fn ip(&self) -> isize {
        self.ip
    }

    fn ip_mut(&mut self) -> &mut isize {
        &mut self.ip
    }

    fn evaluated_instruction_count_mut(&mut self) -> &mut f64 {
        &mut self.metrics.evaluated_instruction_count
    }
}

/// libauth's `applyError` (imported by the spec from `./vm.js`): set `error`
/// unless an error is already present.
///
/// libauth's `applyError` is generic over any program state with an optional
/// `error`; the Rust `apply_error` only accepts an
/// `AuthenticationProgramStateCommon`, so the same logic is applied to this
/// spec's `SimpleProgramState` here.
fn apply_error(state: &mut SimpleProgramState, error_type: &str) {
    if state.error.is_none() {
        state.error = Some(format_error(error_type, None));
    }
}

type SimpleVirtualMachine =
    AuthenticationVirtualMachine<SimpleResolvedTransaction, SimpleProgram, SimpleProgramState>;

fn operation(function: impl Fn(&mut SimpleProgramState) + 'static) -> Operation<SimpleProgramState> {
    Rc::new(function)
}

fn simple_instruction_set() -> InstructionSet<SimpleResolvedTransaction, SimpleProgram, SimpleProgramState> {
    let operations: BTreeMap<u8, Operation<SimpleProgramState>> = BTreeMap::from([
        (
            SimpleOps::OP_0,
            operation(|state| {
                state.stack.push(0);
            }),
        ),
        (
            SimpleOps::OP_INCREMENT,
            operation(|state| {
                let Some(top) = state.stack.pop() else {
                    state.error = Some(SimpleError::EMPTY_STACK.to_string());
                    return;
                };
                state.stack.push(top + 1);
            }),
        ),
        (
            SimpleOps::OP_DECREMENT,
            operation(|state| {
                let Some(top) = state.stack.pop() else {
                    state.error = Some(SimpleError::EMPTY_STACK.to_string());
                    return;
                };
                state.stack.push(top - 1);
            }),
        ),
        (
            SimpleOps::OP_ADD,
            operation(|state| {
                let a = state.stack.pop();
                let b = state.stack.pop();
                let (Some(a), Some(b)) = (a, b) else {
                    state.error = Some(SimpleError::EMPTY_STACK.to_string());
                    return;
                };
                state.stack.push(a + b);
            }),
        ),
        (
            SimpleOps::OP_REPEAT,
            operation(|state| {
                if state.repeated == Some(true) {
                    return;
                }
                state.repeated = Some(true);
                state.ip = -1;
            }),
        ),
    ]);
    InstructionSet {
        r#continue: Rc::new(|state: &mut SimpleProgramState| {
            state.error.is_none() && state.ip < state.instructions.len() as isize
        }),
        evaluate: Rc::new(|program: &SimpleProgram, evaluation| {
            // `stateEvaluate({ ...stateInitialize(program), ...program })`
            let mut state = (evaluation.state_initialize)(program);
            state.instructions = program.instructions.clone();
            (evaluation.state_evaluate)(state)
        }),
        every: Some(operation(|state| {
            if state.stack.last().copied().unwrap_or(0) > 2 {
                apply_error(state, SimpleError::EXCESSIVE);
            }
        })),
        // libauth's `initialize` returns `{ ip, metrics, stack }`, which
        // `evaluate` spreads together with the program's `instructions`; a
        // Rust program state is always complete, so `instructions` starts
        // empty here and is replaced by `evaluate`.
        initialize: Rc::new(|_program: &SimpleProgram| SimpleProgramState {
            instructions: vec![],
            ip: 0,
            metrics: Metrics {
                evaluated_instruction_count: 0.0,
            },
            stack: vec![],
            repeated: None,
            error: None,
        }),
        operations,
        success: Rc::new(|state: &SimpleProgramState| match &state.error {
            Some(error) => Err(error.clone()),
            None if state.stack.last() == Some(&1) => Ok(()),
            None => Err(SimpleError::FAIL.to_string()),
        }),
        undefined: operation(|state| {
            state.error = Some(SimpleError::UNDEFINED.to_string());
        }),
        verify: Rc::new(|resolved_transaction: &SimpleResolvedTransaction, verification| {
            // `typeof result === 'string' ? result : true`
            (verification.success)(&(verification.evaluate)(&SimpleProgram {
                instructions: resolved_transaction.transaction.instructions.clone(),
            }))
        }),
    }
}

fn vm() -> SimpleVirtualMachine {
    create_virtual_machine(simple_instruction_set())
}

fn op(opcode: u8) -> AuthenticationInstruction {
    AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode })
}

fn instructions() -> Vec<AuthenticationInstruction> {
    vec![
        op(SimpleOps::OP_0),
        op(SimpleOps::OP_INCREMENT),
        op(SimpleOps::OP_INCREMENT),
        op(SimpleOps::OP_0),
        op(SimpleOps::OP_DECREMENT),
        op(SimpleOps::OP_ADD),
    ]
}

fn instructions_fail_1() -> Vec<AuthenticationInstruction> {
    vec![op(SimpleOps::OP_0), op(SimpleOps::OP_DECREMENT)]
}

fn instructions_fail_2() -> Vec<AuthenticationInstruction> {
    vec![
        op(SimpleOps::OP_0),
        op(SimpleOps::OP_INCREMENT),
        op(SimpleOps::OP_INCREMENT),
        op(SimpleOps::OP_INCREMENT),
        op(SimpleOps::OP_DECREMENT),
        op(SimpleOps::OP_DECREMENT),
    ]
}

/// `{ instructions, ip, metrics: { evaluatedInstructionCount }, stack }`
fn state(
    instructions: &[AuthenticationInstruction],
    ip: isize,
    evaluated_instruction_count: u32,
    stack: Vec<i64>,
) -> SimpleProgramState {
    SimpleProgramState {
        instructions: instructions.to_vec(),
        ip,
        metrics: Metrics {
            evaluated_instruction_count: f64::from(evaluated_instruction_count),
        },
        stack,
        repeated: None,
        error: None,
    }
}

/// A [`state`] with `error` set.
fn state_with_error(
    error: &str,
    instructions: &[AuthenticationInstruction],
    ip: isize,
    evaluated_instruction_count: u32,
    stack: Vec<i64>,
) -> SimpleProgramState {
    SimpleProgramState {
        error: Some(error.to_string()),
        ..state(instructions, ip, evaluated_instruction_count, stack)
    }
}

/// A [`state`] with `repeated: true`.
fn state_repeated(
    instructions: &[AuthenticationInstruction],
    ip: isize,
    evaluated_instruction_count: u32,
    stack: Vec<i64>,
) -> SimpleProgramState {
    SimpleProgramState {
        repeated: Some(true),
        ..state(instructions, ip, evaluated_instruction_count, stack)
    }
}

/// A masked program state: `{ instruction, ip, metrics, stack }`.
///
/// libauth's `MaskedProgramState` omits the static `instructions`; the Rust
/// `MaskedProgramState` cannot omit fields of a generic program state, so it
/// retains them (the expected values include them for that reason).
fn masked(
    instruction: Option<AuthenticationInstruction>,
    instructions: &[AuthenticationInstruction],
    ip: isize,
    evaluated_instruction_count: u32,
    stack: Vec<i64>,
) -> MaskedProgramState<SimpleProgramState> {
    MaskedProgramState {
        instruction,
        state: state(instructions, ip, evaluated_instruction_count, stack),
    }
}

#[test]
fn vm_evaluate_with_a_simple_instruction_set() {
    let instructions = instructions();
    assert_eq!(
        vm().evaluate(
            &SimpleProgram {
                instructions: instructions.clone()
            },
            None
        ),
        state(&instructions, 6, 6, vec![1])
    );
}

#[test]
fn vm_debug_with_a_simple_instruction_set() {
    let instructions = instructions();
    assert_eq!(
        vm().debug(
            &SimpleProgram {
                instructions: instructions.clone()
            },
            None
        ),
        vec![
            state(&instructions, 0, 0, vec![]),
            state(&instructions, 1, 1, vec![0]),
            state(&instructions, 2, 2, vec![1]),
            state(&instructions, 3, 3, vec![2]),
            state(&instructions, 4, 4, vec![2, 0]),
            state(&instructions, 5, 5, vec![2, -1]),
            state(&instructions, 6, 6, vec![1]),
            state(&instructions, 6, 6, vec![1]),
        ]
    );
}

#[test]
fn vm_debug_with_a_simple_instruction_set_masked() {
    let instructions = instructions();
    // `vm.debug(program, { maskProgramState: true })`
    let results = vm().debug_masked(
        &SimpleProgram {
            instructions: instructions.clone(),
        },
        None,
    );
    assert_eq!(
        results,
        vec![
            masked(Some(op(0)), &instructions, 0, 0, vec![]),
            masked(Some(op(1)), &instructions, 1, 1, vec![0]),
            masked(Some(op(1)), &instructions, 2, 2, vec![1]),
            masked(Some(op(0)), &instructions, 3, 3, vec![2]),
            masked(Some(op(2)), &instructions, 4, 4, vec![2, 0]),
            masked(Some(op(3)), &instructions, 5, 5, vec![2, -1]),
            masked(None, &instructions, 6, 6, vec![1]),
            masked(None, &instructions, 6, 6, vec![1]),
        ]
    );
}

#[test]
fn vm_debug_with_a_simple_instruction_set_failure_1() {
    let instructions_fail_1 = instructions_fail_1();
    assert_eq!(
        vm().debug(
            &SimpleProgram {
                instructions: instructions_fail_1.clone()
            },
            None
        ),
        vec![
            state(&instructions_fail_1, 0, 0, vec![]),
            state(&instructions_fail_1, 1, 1, vec![0]),
            state(&instructions_fail_1, 2, 2, vec![-1]),
            state(&instructions_fail_1, 2, 2, vec![-1]),
        ]
    );
}

#[test]
fn vm_debug_with_a_simple_instruction_set_failure_2() {
    let instructions_fail_2 = instructions_fail_2();
    assert_eq!(
        vm().debug(
            &SimpleProgram {
                instructions: instructions_fail_2.clone()
            },
            None
        ),
        vec![
            state(&instructions_fail_2, 0, 0, vec![]),
            state(&instructions_fail_2, 1, 1, vec![0]),
            state(&instructions_fail_2, 2, 2, vec![1]),
            state(&instructions_fail_2, 3, 3, vec![2]),
            state_with_error(SimpleError::EXCESSIVE, &instructions_fail_2, 4, 4, vec![3]),
            state_with_error(SimpleError::EXCESSIVE, &instructions_fail_2, 4, 4, vec![3]),
        ]
    );
}

#[test]
fn vm_verify_with_a_simple_instruction_set_success() {
    assert_eq!(
        vm().verify(&SimpleResolvedTransaction {
            transaction: SimpleTransaction {
                instructions: instructions()
            }
        }),
        Ok(())
    );
}

#[test]
fn vm_verify_with_a_simple_instruction_set_failure_1() {
    assert_eq!(
        vm().verify(&SimpleResolvedTransaction {
            transaction: SimpleTransaction {
                instructions: instructions_fail_1()
            }
        }),
        Err(SimpleError::FAIL.to_string())
    );
}

#[test]
fn vm_verify_with_a_simple_instruction_set_failure_2() {
    assert_eq!(
        vm().verify(&SimpleResolvedTransaction {
            transaction: SimpleTransaction {
                instructions: instructions_fail_2()
            }
        }),
        Err(SimpleError::EXCESSIVE.to_string())
    );
}

#[test]
fn vm_state_debug_with_a_simple_instruction_set() {
    let instructions = instructions();
    assert_eq!(
        vm().state_debug(&state(&instructions, 0, 0, vec![])),
        vec![
            state(&instructions, 0, 0, vec![]),
            state(&instructions, 1, 1, vec![0]),
            state(&instructions, 2, 2, vec![1]),
            state(&instructions, 3, 3, vec![2]),
            state(&instructions, 4, 4, vec![2, 0]),
            state(&instructions, 5, 5, vec![2, -1]),
            state(&instructions, 6, 6, vec![1]),
        ]
    );
}

#[test]
fn vm_state_evaluate_does_not_mutate_the_original_state() {
    let instructions = instructions();
    let unchanged = state(&instructions, 0, 0, vec![]);
    assert_eq!(vm().state_evaluate(&unchanged), state(&instructions, 6, 6, vec![1]));
    assert_eq!(unchanged, state(&instructions, 0, 0, vec![]));
}

#[test]
fn vm_state_step_does_not_mutate_the_original_state() {
    let instructions = instructions();
    let unchanged = state(&instructions, 5, 5, vec![2, -1]);
    assert_eq!(vm().state_step(&unchanged), state(&instructions, 6, 6, vec![1]));
    assert_eq!(unchanged, state(&instructions, 5, 5, vec![2, -1]));
}

#[test]
fn vm_state_step_mutate_does_not_clone_mutating_the_original_state() {
    let instructions = instructions();
    let mut changed = state(&instructions, 5, 5, vec![2, -1]);
    // libauth's `stateStepMutate` returns the (mutated) state it was given; the
    // Rust method mutates it in place and returns nothing, so the "returned"
    // state is `changed` itself.
    let vm = vm();
    let returned = {
        vm.state_step_mutate(&mut changed);
        &changed
    };
    assert_eq!(returned, &state(&instructions, 6, 6, vec![1]));
    assert_eq!(changed, state(&instructions, 6, 6, vec![1]));
}

#[test]
fn vm_state_success_is_available() {
    assert_eq!(
        vm().state_success(&state(&instructions_fail_1(), 0, 0, vec![2])),
        Err(SimpleError::FAIL.to_string())
    );
}

#[test]
fn vm_state_clone_is_available() {
    let instructions = instructions();
    assert_eq!(
        vm().state_clone(&state(&instructions, 0, 0, vec![1, 2, 3])),
        state(&instructions, 0, 0, vec![1, 2, 3])
    );
}

#[test]
fn vm_can_control_the_instruction_pointer() {
    let repeated = vec![
        op(SimpleOps::OP_0),
        op(SimpleOps::OP_INCREMENT),
        op(SimpleOps::OP_REPEAT),
        op(SimpleOps::OP_ADD),
        op(SimpleOps::OP_0),
        op(SimpleOps::OP_DECREMENT),
        op(SimpleOps::OP_ADD),
    ];
    let result = vm().state_debug(&state(&repeated, 0, 0, vec![]));
    assert_eq!(
        result,
        vec![
            state(&repeated, 0, 0, vec![]),
            state(&repeated, 1, 1, vec![0]),
            state(&repeated, 2, 2, vec![1]),
            state_repeated(&repeated, 0, 3, vec![1]),
            state_repeated(&repeated, 1, 4, vec![1, 0]),
            state_repeated(&repeated, 2, 5, vec![1, 1]),
            state_repeated(&repeated, 3, 6, vec![1, 1]),
            state_repeated(&repeated, 4, 7, vec![2]),
            state_repeated(&repeated, 5, 8, vec![2, 0]),
            state_repeated(&repeated, 6, 9, vec![2, -1]),
            state_repeated(&repeated, 7, 10, vec![1]),
        ]
    );
}
