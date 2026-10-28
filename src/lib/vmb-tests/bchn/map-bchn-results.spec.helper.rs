//! Port of `vmb-tests/bchn/map-bchn-results.spec.helper.ts`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use libauth::runtime::json::{parse_json, Json};
use libauth::vm::AuthenticationErrorBchSpec;

use crate::bchn_error_map_spec_helper::{
    libauthErrorPrefixToBchnErrorNonstandard, libauthErrorPrefixToBchnErrorStandard,
};
use crate::fail_reason_overrides_spec_helper::vmbTestBchnErrorMessageIdOverrides;

/// libauth resolves this directory from the working directory (the repository
/// root); the port resolves it from the crate root.
fn bchn_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib/vmb-tests/bchn")
}
const failReasonsFile: &str = "libauth_expected_test_fail_reasons.json";
const testMetricsFile: &str = "libauth_expected_test_metrics.json";
pub static failReasonsPath: LazyLock<PathBuf> = LazyLock::new(|| bchn_dir().join(failReasonsFile));
pub static testMetricsPath: LazyLock<PathBuf> = LazyLock::new(|| bchn_dir().join(testMetricsFile));

fn read_json(path: &Path) -> Json {
    let content = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    parse_json(&content).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// One entry of the BCHN fail reasons file: `[packName, testId,
/// testStandardness ('I' | 'N' | 'S'), evaluatedStandardness ('N' | 'S'),
/// bchnError]`.
pub type BchnFailReason = (String, String, String, String, String);

pub static bchnFailReasons: LazyLock<Vec<BchnFailReason>> = LazyLock::new(|| {
    let json = read_json(&failReasonsPath);
    json.as_array()
        .expect("the fail reasons file is an array")
        .iter()
        .map(|entry| {
            let field = |index: usize| entry.as_array().and_then(|fields| fields.get(index)).map(Json::as_string).expect("a fail reason field");
            (field(0), field(1), field(2), field(3), field(4))
        })
        .collect()
});

/// libauth searches the fail reasons with `Array.prototype.find` for every
/// lookup; the port indexes the first entry for each `(packName, testId,
/// evaluatedStandardness)` once, which returns the same entry.
static bchnFailReasonsIndex: LazyLock<HashMap<(String, String, String), usize>> = LazyLock::new(|| {
    let mut index = HashMap::new();
    for (position, entry) in bchnFailReasons.iter().enumerate() {
        index.entry((entry.0.clone(), entry.1.clone(), entry.3.clone())).or_insert(position);
    }
    index
});

/// Return the error message produced by BCHN's evaluation of the given test ID
/// with the given VM (year + standardness). Returns `None` if no matching
/// result is available in {@link failReasonsPath} (either because the test
/// passed or the file needs to be updated).
pub fn get_bchn_error_message(is_standard: bool, short_id: &str, vm_year: &str) -> Option<&'static str> {
    let evaluated = if is_standard { "S" } else { "N" };
    bchnFailReasonsIndex
        .get(&(vm_year.to_string(), short_id.to_string(), evaluated.to_string()))
        .map(|position| bchnFailReasons[*position].4.as_str())
}

/// libauth's `AuthenticationErrorBchSpec[prefix]`.
fn authentication_error_bch_spec(key: &str) -> Option<&'static str> {
    match key {
        "calledReserved" => Some(AuthenticationErrorBchSpec::calledReserved),
        "calledReturn" => Some(AuthenticationErrorBchSpec::calledReturn),
        "calledUpgradableNop" => Some(AuthenticationErrorBchSpec::calledUpgradableNop),
        "checkSequenceUnavailable" => Some(AuthenticationErrorBchSpec::checkSequenceUnavailable),
        "disabledOpcode" => Some(AuthenticationErrorBchSpec::disabledOpcode),
        "divisionByZero" => Some(AuthenticationErrorBchSpec::divisionByZero),
        "emptyAlternateStack" => Some(AuthenticationErrorBchSpec::emptyAlternateStack),
        "emptyStack" => Some(AuthenticationErrorBchSpec::emptyStack),
        "exceededMaximumBytecodeLengthLocking" => Some(AuthenticationErrorBchSpec::exceededMaximumBytecodeLengthLocking),
        "exceededMaximumBytecodeLengthUnlocking" => Some(AuthenticationErrorBchSpec::exceededMaximumBytecodeLengthUnlocking),
        "exceededMaximumControlStackDepth" => Some(AuthenticationErrorBchSpec::exceededMaximumControlStackDepth),
        "exceededMaximumMemorySlots" => Some(AuthenticationErrorBchSpec::exceededMaximumMemorySlots),
        "exceededMaximumOperationCount" => Some(AuthenticationErrorBchSpec::exceededMaximumOperationCount),
        "exceededMaximumSignatureCheckCount" => Some(AuthenticationErrorBchSpec::exceededMaximumSignatureCheckCount),
        "exceededMaximumStackDepth" => Some(AuthenticationErrorBchSpec::exceededMaximumStackDepth),
        "exceededMaximumStackItemLength" => Some(AuthenticationErrorBchSpec::exceededMaximumStackItemLength),
        "exceededMaximumVmNumberByteLength" => Some(AuthenticationErrorBchSpec::exceededMaximumVmNumberByteLength),
        "exceedsMaximumMultisigPublicKeyCount" => Some(AuthenticationErrorBchSpec::exceedsMaximumMultisigPublicKeyCount),
        "excessiveHashing" => Some(AuthenticationErrorBchSpec::excessiveHashing),
        "excessiveLooping" => Some(AuthenticationErrorBchSpec::excessiveLooping),
        "excessiveOperationCost" => Some(AuthenticationErrorBchSpec::excessiveOperationCost),
        "excessiveOperationCostOpPow" => Some(AuthenticationErrorBchSpec::excessiveOperationCostOpPow),
        "failedVerify" => Some(AuthenticationErrorBchSpec::failedVerify),
        "functionIdentifierExcessiveLength" => Some(AuthenticationErrorBchSpec::functionIdentifierExcessiveLength),
        "functionIdentifierPreviouslyDefined" => Some(AuthenticationErrorBchSpec::functionIdentifierPreviouslyDefined),
        "functionIdentifierUndefined" => Some(AuthenticationErrorBchSpec::functionIdentifierUndefined),
        "incompatibleLocktimeType" => Some(AuthenticationErrorBchSpec::incompatibleLocktimeType),
        "incompatibleSequenceType" => Some(AuthenticationErrorBchSpec::incompatibleSequenceType),
        "insufficientLength" => Some(AuthenticationErrorBchSpec::insufficientLength),
        "insufficientPublicKeys" => Some(AuthenticationErrorBchSpec::insufficientPublicKeys),
        "invalidCheckBitsSignatureCount" => Some(AuthenticationErrorBchSpec::invalidCheckBitsSignatureCount),
        "invalidCheckBitsValue" => Some(AuthenticationErrorBchSpec::invalidCheckBitsValue),
        "invalidNaturalNumber" => Some(AuthenticationErrorBchSpec::invalidNaturalNumber),
        "invalidPublicKeyEncoding" => Some(AuthenticationErrorBchSpec::invalidPublicKeyEncoding),
        "invalidShiftBitCount" => Some(AuthenticationErrorBchSpec::invalidShiftBitCount),
        "invalidSignatureEncoding" => Some(AuthenticationErrorBchSpec::invalidSignatureEncoding),
        "invalidSplitIndex" => Some(AuthenticationErrorBchSpec::invalidSplitIndex),
        "invalidStackIndex" => Some(AuthenticationErrorBchSpec::invalidStackIndex),
        "invalidTransactionInputIndex" => Some(AuthenticationErrorBchSpec::invalidTransactionInputIndex),
        "invalidTransactionOutputIndex" => Some(AuthenticationErrorBchSpec::invalidTransactionOutputIndex),
        "invalidTransactionUtxoIndex" => Some(AuthenticationErrorBchSpec::invalidTransactionUtxoIndex),
        "invalidVmNumber" => Some(AuthenticationErrorBchSpec::invalidVmNumber),
        "locktimeDisabled" => Some(AuthenticationErrorBchSpec::locktimeDisabled),
        "malformedEval" => Some(AuthenticationErrorBchSpec::malformedEval),
        "malformedFunction" => Some(AuthenticationErrorBchSpec::malformedFunction),
        "malformedLockingBytecode" => Some(AuthenticationErrorBchSpec::malformedLockingBytecode),
        "malformedP2shBytecode" => Some(AuthenticationErrorBchSpec::malformedP2shBytecode),
        "malformedPush" => Some(AuthenticationErrorBchSpec::malformedPush),
        "malformedUnlockingBytecode" => Some(AuthenticationErrorBchSpec::malformedUnlockingBytecode),
        "mismatchedBitwiseOperandLength" => Some(AuthenticationErrorBchSpec::mismatchedBitwiseOperandLength),
        "negativeLocktime" => Some(AuthenticationErrorBchSpec::negativeLocktime),
        "nonEmptyControlStackLockingBytecode" => Some(AuthenticationErrorBchSpec::nonEmptyControlStackLockingBytecode),
        "nonEmptyControlStackRedeemBytecode" => Some(AuthenticationErrorBchSpec::nonEmptyControlStackRedeemBytecode),
        "nonEmptyControlStackUnlockingBytecode" => Some(AuthenticationErrorBchSpec::nonEmptyControlStackUnlockingBytecode),
        "nonMinimalPush" => Some(AuthenticationErrorBchSpec::nonMinimalPush),
        "nonNullSignatureFailure" => Some(AuthenticationErrorBchSpec::nonNullSignatureFailure),
        "nonSchnorrSizedSignatureInSchnorrMultiSig" => Some(AuthenticationErrorBchSpec::nonSchnorrSizedSignatureInSchnorrMultiSig),
        "overflowsVmNumberRange" => Some(AuthenticationErrorBchSpec::overflowsVmNumberRange),
        "requiresCleanStackLockingBytecode" => Some(AuthenticationErrorBchSpec::requiresCleanStackLockingBytecode),
        "requiresCleanStackRedeemBytecode" => Some(AuthenticationErrorBchSpec::requiresCleanStackRedeemBytecode),
        "requiresPushOnly" => Some(AuthenticationErrorBchSpec::requiresPushOnly),
        "schnorrSizedSignatureInEcdsaMultiSig" => Some(AuthenticationErrorBchSpec::schnorrSizedSignatureInEcdsaMultiSig),
        "tokenValidationExcessiveAmount" => Some(AuthenticationErrorBchSpec::tokenValidationExcessiveAmount),
        "tokenValidationExcessiveCommitmentLength" => Some(AuthenticationErrorBchSpec::tokenValidationExcessiveCommitmentLength),
        "tokenValidationExcessiveImmutableTokens" => Some(AuthenticationErrorBchSpec::tokenValidationExcessiveImmutableTokens),
        "tokenValidationExcessiveMutableTokens" => Some(AuthenticationErrorBchSpec::tokenValidationExcessiveMutableTokens),
        "tokenValidationInvalidFungibleMint" => Some(AuthenticationErrorBchSpec::tokenValidationInvalidFungibleMint),
        "tokenValidationInvalidMintingToken" => Some(AuthenticationErrorBchSpec::tokenValidationInvalidMintingToken),
        "tokenValidationOutputsExceedInputs" => Some(AuthenticationErrorBchSpec::tokenValidationOutputsExceedInputs),
        "unexpectedElse" => Some(AuthenticationErrorBchSpec::unexpectedElse),
        "unexpectedEndIf" => Some(AuthenticationErrorBchSpec::unexpectedEndIf),
        "unexpectedUntil" => Some(AuthenticationErrorBchSpec::unexpectedUntil),
        "unexpectedUntilMissingEndIf" => Some(AuthenticationErrorBchSpec::unexpectedUntilMissingEndIf),
        "unknownOpcode" => Some(AuthenticationErrorBchSpec::unknownOpcode),
        "unmatchedP2shRedeemBytecode" => Some(AuthenticationErrorBchSpec::unmatchedP2shRedeemBytecode),
        "unmatchedSequenceDisable" => Some(AuthenticationErrorBchSpec::unmatchedSequenceDisable),
        "unsatisfiedLocktime" => Some(AuthenticationErrorBchSpec::unsatisfiedLocktime),
        "unsatisfiedSequenceNumber" => Some(AuthenticationErrorBchSpec::unsatisfiedSequenceNumber),
        "unsuccessfulEvaluation" => Some(AuthenticationErrorBchSpec::unsuccessfulEvaluation),
        "verifyFailedDuplicateSourceOutputs" => Some(AuthenticationErrorBchSpec::verifyFailedDuplicateSourceOutputs),
        "verifyFailedExcessiveLength" => Some(AuthenticationErrorBchSpec::verifyFailedExcessiveLength),
        "verifyFailedExcessiveSigChecks" => Some(AuthenticationErrorBchSpec::verifyFailedExcessiveSigChecks),
        "verifyFailedInputsExceedMaxMoney" => Some(AuthenticationErrorBchSpec::verifyFailedInputsExceedMaxMoney),
        "verifyFailedInsufficientLength" => Some(AuthenticationErrorBchSpec::verifyFailedInsufficientLength),
        "verifyFailedInvalidVersion" => Some(AuthenticationErrorBchSpec::verifyFailedInvalidVersion),
        "verifyFailedMismatchedSourceOutputs" => Some(AuthenticationErrorBchSpec::verifyFailedMismatchedSourceOutputs),
        "verifyFailedNoInputs" => Some(AuthenticationErrorBchSpec::verifyFailedNoInputs),
        "verifyFailedNoOutputs" => Some(AuthenticationErrorBchSpec::verifyFailedNoOutputs),
        "verifyFailedOutputsExceedInputs" => Some(AuthenticationErrorBchSpec::verifyFailedOutputsExceedInputs),
        "verifyFailedOutputsExceedMaxMoney" => Some(AuthenticationErrorBchSpec::verifyFailedOutputsExceedMaxMoney),
        "verifyStandardFailedDustOutput" => Some(AuthenticationErrorBchSpec::verifyStandardFailedDustOutput),
        "verifyStandardFailedExcessiveDataCarrierBytes" => Some(AuthenticationErrorBchSpec::verifyStandardFailedExcessiveDataCarrierBytes),
        "verifyStandardFailedExcessiveLength" => Some(AuthenticationErrorBchSpec::verifyStandardFailedExcessiveLength),
        "verifyStandardFailedExcessiveUnlockingBytecodeLength" => Some(AuthenticationErrorBchSpec::verifyStandardFailedExcessiveUnlockingBytecodeLength),
        "verifyStandardFailedNonPushUnlockingBytecode" => Some(AuthenticationErrorBchSpec::verifyStandardFailedNonPushUnlockingBytecode),
        "verifyStandardFailedNonstandardOutput" => Some(AuthenticationErrorBchSpec::verifyStandardFailedNonstandardOutput),
        "verifyStandardFailedNonstandardSourceOutput" => Some(AuthenticationErrorBchSpec::verifyStandardFailedNonstandardSourceOutput),
        _ => None,
    }
}

/// The keys of `libauthErrorPrefixToBchnErrorStandard`
/// (`libauthErrorPrefixes`).
fn libauth_error_prefixes() -> impl Iterator<Item = &'static str> {
    libauthErrorPrefixToBchnErrorStandard.iter().map(|(key, _)| *key)
}

/// A libauth error mapped to the corresponding BCHN error (`{ bchn, match }`).
pub struct BchnErrorMatch {
    pub bchn: &'static str,
    pub r#match: &'static str,
}

/// Map a libauth error to the expected BCHN error (`false` in libauth when no
/// known conversion exists: `None` here).
pub fn libauth_error_to_bchn_error(libauth_error: &str, is_standard: bool) -> Option<BchnErrorMatch> {
    let r#match = libauth_error_prefixes().find(|prefix| {
        libauth_error.contains(authentication_error_bch_spec(prefix).expect("a known AuthenticationErrorBchSpec member"))
    })?;
    let map = if is_standard {
        libauthErrorPrefixToBchnErrorStandard
    } else {
        libauthErrorPrefixToBchnErrorNonstandard
    };
    let bchn = map.iter().find(|(key, _)| *key == r#match).map(|(_, bchn)| *bchn)?;
    Some(BchnErrorMatch { bchn, r#match })
}

/// Returns `Ok(false)` if the BCHN {@link failReasonsFile} is missing the
/// expected error message (and needs to be updated).
///
/// Returns `Ok(true)` if the `libauth_result` matches the expected result
/// produced by BCHN's evaluation of the given test ID with the given VM
/// (year + standardness).
///
/// Unexpected results are returned as an error message (`Err`, a `string` in
/// libauth) describing the issue.
///
/// Note that this method first checks for overrides in
/// {@link vmbTestBchnErrorMessageIdOverrides} before mapping all other
/// `libauth_result`s to expected BCHN results using
/// {@link libauth_error_to_bchn_error}.
pub fn verify_expected_error_message(
    is_standard: bool,
    libauth_result: &Result<(), String>,
    short_id: &str,
    vm_year: &str,
) -> Result<bool, String> {
    let bchn_result = get_bchn_error_message(is_standard, short_id, vm_year);

    let libauth_error = match libauth_result {
        Ok(()) => {
            if let Some(bchn_result) = bchn_result {
                return Err(format!(
                    "The VMB test was accepted by Libauth, but BCHN rejected with the error: {bchn_result}"
                ));
            }
            return Ok(true);
        }
        Err(error) => error,
    };

    let Some(bchn_result) = bchn_result else {
        return Ok(false);
    };

    let Some(expected) = libauth_error_to_bchn_error(libauth_error, is_standard) else {
        return Err(format!(
            "BCHN rejected with the error: \"{bchn_result}\", but no known conversion was found in \"libauthErrorPrefixToBchnError{}\" for Libauth error: {libauth_error}",
            if is_standard { "Standard" } else { "Nonstandard" }
        ));
    };

    let r#override = vmbTestBchnErrorMessageIdOverrides
        .iter()
        .find(|(id, _)| *id == short_id)
        .map(|(_, bchn)| *bchn);

    if let Some(r#override) = r#override {
        if bchn_result != r#override {
            return Err(format!(
                "The Libauth error \"{}\" is expected to map to the BCHN error, \"{}\", but has been overridden in \"vmbTestBchnErrorMessageIdOverrides\" for test ID \"{short_id}\" with another expected error: \"{}\". BCHN rejected with the error: \"{bchn_result}\". Please review any relevant VM changes or correct \"vmbTestBchnErrorMessageIdOverrides\" to remove this unnecessary override. Full Libauth error: {libauth_error}",
                expected.r#match, expected.bchn, r#override
            ));
        }
        return Ok(true);
    }

    if bchn_result != expected.bchn {
        return Err(format!(
            "In {} validation, the Libauth error \"{}\" is expected to map to the BCHN error, \"{}\", but BCHN rejected with the error: \"{bchn_result}\". Please either correct \"libauthErrorPrefixToBchnError{}\" or include a new exception in \"vmbTestBchnErrorMessageIdOverrides\". Full Libauth error: {libauth_error}",
            if is_standard { "standard" } else { "nonstandard" },
            expected.r#match,
            expected.bchn,
            if is_standard { "Standard" } else { "Nonstandard" }
        ));
    }
    Ok(true)
}

/// One input of a BCHN test metrics entry: `[inputIndex, operationCost,
/// operationCostLimit, hashIterations, hashIterationsLimit, sigChecks,
/// sigChecksLimit]` (limits are `null` when BCHN does not report them).
pub type BchnInputMetricsEntry = (f64, f64, Option<f64>, f64, Option<f64>, f64, Option<f64>);

/// One entry of the BCHN test metrics file: `[packName, testId,
/// testStandardness, evaluatedStandardness, inputs]`.
pub type BchnTestMetricsEntry = (String, String, String, String, Vec<BchnInputMetricsEntry>);

pub static bchnTestMetrics: LazyLock<Vec<BchnTestMetricsEntry>> = LazyLock::new(|| {
    let json = read_json(&testMetricsPath);
    let number = |value: &Json| value.as_f64().expect("a metrics number");
    let nullable = |value: &Json| match value {
        Json::Null => None,
        value => Some(value.as_f64().expect("a metrics number or null")),
    };
    json.as_array()
        .expect("the test metrics file is an array")
        .iter()
        .map(|entry| {
            let fields = entry.as_array().expect("a test metrics entry");
            let inputs = fields[4]
                .as_array()
                .expect("a list of input metrics")
                .iter()
                .map(|input| {
                    let input = input.as_array().expect("input metrics");
                    (
                        number(&input[0]),
                        number(&input[1]),
                        nullable(&input[2]),
                        number(&input[3]),
                        nullable(&input[4]),
                        number(&input[5]),
                        nullable(&input[6]),
                    )
                })
                .collect();
            (fields[0].as_string(), fields[1].as_string(), fields[2].as_string(), fields[3].as_string(), inputs)
        })
        .collect()
});

/// As with {@link bchnFailReasonsIndex}: the first entry for each
/// `(packName, testId, evaluatedStandardness)`.
static bchnTestMetricsIndex: LazyLock<HashMap<(String, String, String), usize>> = LazyLock::new(|| {
    let mut index = HashMap::new();
    for (position, entry) in bchnTestMetrics.iter().enumerate() {
        index.entry((entry.0.clone(), entry.1.clone(), entry.3.clone())).or_insert(position);
    }
    index
});

/// The metrics BCHN reports for one input.
#[derive(Clone, Copy, Debug)]
pub struct BchnInputMetrics {
    pub hash_iterations: f64,
    pub hash_iterations_limit: Option<f64>,
    pub input_index: f64,
    pub operation_cost: f64,
    pub operation_cost_limit: Option<f64>,
    pub sig_checks: f64,
    pub sig_checks_limit: Option<f64>,
}

/// Return an array of metrics produced by BCHN's evaluation of the given test
/// ID with the given VM (year + standardness). Returns `None` if no matching
/// result is available in {@link testMetricsPath}.
pub fn get_bchn_metrics(is_standard: bool, short_id: &str, vm_year: &str) -> Option<Vec<BchnInputMetrics>> {
    let evaluated = if is_standard { "S" } else { "N" };
    let position = bchnTestMetricsIndex.get(&(vm_year.to_string(), short_id.to_string(), evaluated.to_string()))?;
    Some(
        bchnTestMetrics[*position]
            .4
            .iter()
            .map(
                |&(input_index, operation_cost, operation_cost_limit, hash_iterations, hash_iterations_limit, sig_checks, sig_checks_limit)| {
                    BchnInputMetrics {
                        hash_iterations,
                        hash_iterations_limit,
                        input_index,
                        operation_cost,
                        operation_cost_limit,
                        sig_checks,
                        sig_checks_limit,
                    }
                },
            )
            .collect(),
    )
}
