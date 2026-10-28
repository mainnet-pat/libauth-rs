//! Transaction estimation (`estimate-transaction.ts`).
//!
//! libauth v3.1.0-next.8 declares [`estimate_transaction`] but has not
//! implemented it: the reference returns an unsuccessful
//! `TransactionGenerationAttempt` (empty completions and errors, `inputs`
//! stage). This port reproduces that behavior exactly.

use crate::message::TransactionTemplateEstimated;
use crate::message::{TransactionGenerationAttempt, TransactionGenerationError, TransactionGenerationStage};

/// Generate an "estimated" transaction (libauth's `estimateTransaction`).
///
/// As in libauth v3.1.0-next.8, this is not yet implemented and always returns
/// an unsuccessful attempt.
pub fn estimate_transaction(
    _template: &TransactionTemplateEstimated,
) -> TransactionGenerationAttempt {
    TransactionGenerationAttempt::Error(TransactionGenerationError {
        completions: Vec::new(),
        errors: Vec::new(),
        stage: TransactionGenerationStage::Inputs,
    })
}
