use crate::vm::{
    apply_error, is_vm_number_error, vm_number_to_big_int, AuthenticationErrorCommon,
    AuthenticationProgramStateCommon,
};

const SEQUENCE_LOCKTIME_DISABLE_FLAG_BIT: u32 = 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG_BIT: u32 = 22;

struct Constants;

impl Constants {
    const LOCKTIME_VM_NUMBER_BYTE_LENGTH: usize = 5;
    const LOCKTIME_THRESHOLD: i64 = 500_000_000;
    const LOCKTIME_DISABLING_SEQUENCE_NUMBER: u32 = 0xffff_ffff;
    const SEQUENCE_LOCKTIME_TRANSACTION_VERSION_MINIMUM: u32 = 2;
    const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << SEQUENCE_LOCKTIME_DISABLE_FLAG_BIT;
    const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << SEQUENCE_LOCKTIME_TYPE_FLAG_BIT;
    const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;
}

/// Read the top stack item (without removing it) as a locktime (a VM Number
/// of up to 5 bytes) and provide it to `operation`.
pub fn use_locktime(
    state: &mut AuthenticationProgramStateCommon,
    operation: impl FnOnce(&mut AuthenticationProgramStateCommon, i64),
) {
    let Some(item) = state.stack.last() else {
        apply_error(state, AuthenticationErrorCommon::emptyStack, None);
        return;
    };
    let decoded_locktime = vm_number_to_big_int(
        item,
        Some(Constants::LOCKTIME_VM_NUMBER_BYTE_LENGTH),
        Some(true),
    );
    if is_vm_number_error(&decoded_locktime) {
        let error = decoded_locktime.err().unwrap_or_default();
        apply_error(state, AuthenticationErrorCommon::invalidVmNumber, Some(&error));
        return;
    }
    let locktime = decoded_locktime
        .ok()
        .and_then(|locktime| locktime.to_i64())
        .expect("a 5-byte VM Number fits in an i64");
    if locktime < 0 {
        apply_error(
            state,
            AuthenticationErrorCommon::negativeLocktime,
            Some(&format!("Locktime: {locktime}.")),
        );
        return;
    }
    operation(state, locktime);
}

fn locktime_types_are_compatible(locktime: i64, required_locktime: i64) -> bool {
    (locktime < Constants::LOCKTIME_THRESHOLD && required_locktime < Constants::LOCKTIME_THRESHOLD)
        || (locktime >= Constants::LOCKTIME_THRESHOLD
            && required_locktime >= Constants::LOCKTIME_THRESHOLD)
}

pub fn op_check_lock_time_verify(state: &mut AuthenticationProgramStateCommon) {
    use_locktime(state, |next_state, required_locktime| {
        let locktime = next_state.program.transaction.locktime;
        if !locktime_types_are_compatible(locktime as i64, required_locktime) {
            let details =
                format!("Transaction locktime: {locktime}; required locktime: {required_locktime}.");
            apply_error(next_state, AuthenticationErrorCommon::incompatibleLocktimeType, Some(&details));
            return;
        }
        if required_locktime > locktime as i64 {
            let details =
                format!("Transaction locktime: {locktime}; required locktime: {required_locktime}.");
            apply_error(next_state, AuthenticationErrorCommon::unsatisfiedLocktime, Some(&details));
            return;
        }
        let sequence_number =
            next_state.program.transaction.inputs[next_state.program.input_index].sequence_number;
        if sequence_number == Constants::LOCKTIME_DISABLING_SEQUENCE_NUMBER {
            let details = format!("Sequence number: {sequence_number}.");
            apply_error(next_state, AuthenticationErrorCommon::locktimeDisabled, Some(&details));
        }
    });
}

/// `(value & flag) !== 0` (JavaScript bitwise operators truncate to 32 bits).
fn includes_flag(value: i64, flag: u32) -> bool {
    (value as u32 & flag) != 0
}

pub fn op_check_sequence_verify(state: &mut AuthenticationProgramStateCommon) {
    use_locktime(state, |next_state, required_sequence| {
        let sequence_number =
            next_state.program.transaction.inputs[next_state.program.input_index].sequence_number;
        let sequence_locktime_disabled =
            includes_flag(required_sequence, Constants::SEQUENCE_LOCKTIME_DISABLE_FLAG);
        if sequence_locktime_disabled {
            return;
        }
        let version = next_state.program.transaction.version;
        if version < Constants::SEQUENCE_LOCKTIME_TRANSACTION_VERSION_MINIMUM {
            let details = format!("Transaction version: {version}.");
            apply_error(next_state, AuthenticationErrorCommon::checkSequenceUnavailable, Some(&details));
            return;
        }
        if includes_flag(sequence_number as i64, Constants::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            let details = format!("Sequence number: {sequence_number}.");
            apply_error(next_state, AuthenticationErrorCommon::unmatchedSequenceDisable, Some(&details));
            return;
        }
        if includes_flag(required_sequence, Constants::SEQUENCE_LOCKTIME_TYPE_FLAG)
            != includes_flag(sequence_number as i64, Constants::SEQUENCE_LOCKTIME_TYPE_FLAG)
        {
            let details = format!(
                "Sequence number: {sequence_number}; required sequence number: {required_sequence}."
            );
            apply_error(next_state, AuthenticationErrorCommon::incompatibleSequenceType, Some(&details));
            return;
        }
        if (required_sequence as u32 & Constants::SEQUENCE_LOCKTIME_MASK)
            > (sequence_number & Constants::SEQUENCE_LOCKTIME_MASK)
        {
            let details = format!(
                "Sequence number: {sequence_number}; required sequence number: {required_sequence}."
            );
            apply_error(next_state, AuthenticationErrorCommon::unsatisfiedSequenceNumber, Some(&details));
        }
    });
}
