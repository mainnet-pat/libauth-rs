use crate::format::{bin_to_hex, flatten_bin_array, format_error};
use crate::message::{Input, NonFungibleTokenCapability, Output, TransactionCommon};
use crate::runtime::bigint::BigInt;
use crate::vm::{
    push_to_stack, push_to_stack_checked, push_to_stack_vm_number, use_transaction_output,
    use_transaction_utxo, AuthenticationErrorCommon, AuthenticationProgramStateCommon,
    ConsensusBch2023,
};

/// Given a list of transaction inputs, extract a hex-encoded list of all
/// {@link Input.outpointTransactionHash}es from inputs that spend output `0` of
/// that transaction (i.e. where {@link Input.outpointIndex} is `0`).
/// @param inputs - a list of transaction inputs
/// @returns a hex-encoded list of {@link Input.outpointTransactionHash}es
pub fn extract_genesis_categories<Bytecode>(inputs: &[Input<Bytecode>]) -> Vec<String> {
    inputs
        .iter()
        .filter(|input| input.outpoint_index == 0)
        .map(|input| bin_to_hex(&input.outpoint_transaction_hash))
        .collect()
}

/// An immutable token: its hex-encoded category and commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImmutableToken {
    pub category_hex: String,
    pub commitment_hex: String,
}

/// A JavaScript object keyed by hex-encoded token category (iterated in
/// insertion order).
type TokensByCategory<Value> = Vec<(String, Value)>;
type MutableTokensByCategory = TokensByCategory<i64>;

fn get_category<Value: Copy>(object: &TokensByCategory<Value>, category_hex: &str) -> Option<Value> {
    object
        .iter()
        .find(|(category, _)| category == category_hex)
        .map(|(_, value)| *value)
}

fn set_category<Value>(object: &mut TokensByCategory<Value>, category_hex: &str, value: Value) {
    match object.iter_mut().find(|(category, _)| category == category_hex) {
        Some((_, existing)) => *existing = value,
        None => object.push((category_hex.to_string(), value)),
    }
}

/// The token data of a transaction's source outputs (the result of
/// {@link extractSourceOutputTokenData}).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceOutputTokenData {
    pub available_immutable_tokens: Vec<ImmutableToken>,
    pub available_mutable_tokens_by_category: Vec<(String, i64)>,
    pub available_sums_by_category: Vec<(String, u128)>,
    pub input_minting_categories: Vec<String>,
}

/// Given the resolved list of a transaction's source outputs – the Unspent
/// Transaction Outputs (UTXOs) spent by the transaction, extract all token data
/// for token-aware validation. See CHIP-2022-02-CashTokens for details.
/// @param sourceOutputs - a list of resolved source outputs (UTXOs)
/// @returns an object containing `availableImmutableTokens`,
/// `availableMutableTokensByCategory`, `availableSumsByCategory`, and
/// `inputMintingCategories`. See CHIP-2022-02-CashTokens for details.
pub fn extract_source_output_token_data(source_outputs: &[Output]) -> SourceOutputTokenData {
    let mut agg = SourceOutputTokenData {
        available_immutable_tokens: Vec::new(),
        available_mutable_tokens_by_category: Vec::new(),
        available_sums_by_category: Vec::new(),
        input_minting_categories: Vec::new(),
    };
    for source_output in source_outputs {
        let Some(token) = &source_output.token else {
            continue;
        };
        let category_hex = bin_to_hex(&token.category);
        let capability = token.nft.as_ref().map(|nft| nft.capability);
        if let Some(nft) = token.nft.as_ref().filter(|nft| nft.capability == NonFungibleTokenCapability::None) {
            agg.available_immutable_tokens.push(ImmutableToken {
                category_hex: category_hex.clone(),
                commitment_hex: bin_to_hex(&nft.commitment),
            });
        }
        if capability == Some(NonFungibleTokenCapability::Mutable) {
            let count = get_category(&agg.available_mutable_tokens_by_category, &category_hex).unwrap_or(0);
            set_category(&mut agg.available_mutable_tokens_by_category, &category_hex, count + 1);
        }
        let sum = get_category(&agg.available_sums_by_category, &category_hex).unwrap_or(0);
        set_category(&mut agg.available_sums_by_category, &category_hex, sum + token.amount as u128);
        if capability == Some(NonFungibleTokenCapability::Minting) {
            agg.input_minting_categories.push(category_hex);
        }
    }
    agg
}

/// The token data of a transaction's outputs (the result of
/// {@link extractTransactionOutputTokenData}).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionOutputTokenData {
    pub output_immutable_tokens: Vec<ImmutableToken>,
    pub output_minting_categories: Vec<String>,
    pub output_mutable_tokens_by_category: Vec<(String, i64)>,
    pub output_sums_by_category: Vec<(String, u128)>,
}

/// Given a transaction's outputs, extract all token data for token-aware
/// validation. See CHIP-2022-02-CashTokens for details.
/// @param outputs - a list of transaction outputs
/// @returns an object containing `outputImmutableTokens`,
/// `outputMintingCategories`, `outputMutableTokensByCategory`, and
/// `outputSumsByCategory`. See CHIP-2022-02-CashTokens for details.
pub fn extract_transaction_output_token_data(outputs: &[Output]) -> TransactionOutputTokenData {
    let mut agg = TransactionOutputTokenData {
        output_immutable_tokens: Vec::new(),
        output_minting_categories: Vec::new(),
        output_mutable_tokens_by_category: Vec::new(),
        output_sums_by_category: Vec::new(),
    };
    for output in outputs {
        let Some(token) = &output.token else {
            continue;
        };
        let category_hex = bin_to_hex(&token.category);
        let capability = token.nft.as_ref().map(|nft| nft.capability);
        if let Some(nft) = token.nft.as_ref().filter(|nft| nft.capability == NonFungibleTokenCapability::None) {
            agg.output_immutable_tokens.push(ImmutableToken {
                category_hex: category_hex.clone(),
                commitment_hex: bin_to_hex(&nft.commitment),
            });
        }
        if capability == Some(NonFungibleTokenCapability::Minting) {
            agg.output_minting_categories.push(category_hex.clone());
        }
        if capability == Some(NonFungibleTokenCapability::Mutable) {
            let count = get_category(&agg.output_mutable_tokens_by_category, &category_hex).unwrap_or(0);
            set_category(&mut agg.output_mutable_tokens_by_category, &category_hex, count + 1);
        }
        let sum = get_category(&agg.output_sums_by_category, &category_hex).unwrap_or(0);
        set_category(&mut agg.output_sums_by_category, &category_hex, sum + token.amount as u128);
    }
    agg
}

/// Given a transaction and its resolved source outputs – the Unspent Transaction
/// Outputs (UTXOs) it spends – verify that the transaction passes token-aware
/// validation.
/// @param transaction - the transaction to verify
/// @param sourceOutputs - the resolved list of the transaction's source outputs
/// @returns `Ok` on success (libauth's `true`), or an error message on failure.
pub fn verify_transaction_tokens(
    transaction: &TransactionCommon,
    source_outputs: &[Output],
    maximum_token_commitment_length: usize,
) -> Result<(), String> {
    let excessive_commitment = source_outputs
        .iter()
        .chain(&transaction.outputs)
        .filter_map(|output| output.token.as_ref()?.nft.as_ref())
        .find(|nft| nft.commitment.len() > maximum_token_commitment_length);
    if let Some(nft) = excessive_commitment {
        return Err(format_error(
            AuthenticationErrorCommon::tokenValidationExcessiveCommitmentLength,
            Some(&format!(
                "A token commitment exceeds the consensus limit of {maximum_token_commitment_length} bytes. Excessive token commitment length: {}",
                nft.commitment.len()
            )),
        ));
    }
    let genesis_categories = extract_genesis_categories(&transaction.inputs);
    let SourceOutputTokenData {
        available_sums_by_category,
        available_mutable_tokens_by_category,
        input_minting_categories,
        available_immutable_tokens,
    } = extract_source_output_token_data(source_outputs);
    let TransactionOutputTokenData {
        output_sums_by_category,
        output_mutable_tokens_by_category,
        output_minting_categories,
        output_immutable_tokens,
    } = extract_transaction_output_token_data(&transaction.outputs);
    let available_minting_categories: Vec<String> = genesis_categories
        .iter()
        .chain(&input_minting_categories)
        .cloned()
        .collect();
    let missing_minting_category = output_minting_categories
        .iter()
        .find(|category| !available_minting_categories.contains(category));
    if let Some(missing_minting_category) = missing_minting_category {
        return Err(format_error(
            AuthenticationErrorCommon::tokenValidationInvalidMintingToken,
            Some(&format!("Invalid output minting token category: {missing_minting_category}")),
        ));
    }
    let maximum_fungible_token_amount: u128 = ConsensusBch2023
        .maximum_fungible_token_amount
        .parse()
        .expect("a decimal amount");
    for (category_hex, sum) in &output_sums_by_category {
        if *sum > maximum_fungible_token_amount {
            return Err(format_error(
                AuthenticationErrorCommon::tokenValidationExcessiveAmount,
                Some(&format!(
                    "Category: {category_hex}, total amount: {sum}. Consensus maximum amount: {}",
                    ConsensusBch2023.maximum_fungible_token_amount
                )),
            ));
        }
        let available_sum = get_category(&available_sums_by_category, category_hex);
        if available_sum.is_none() && *sum > 0 && !genesis_categories.contains(category_hex) {
            return Err(format_error(
                AuthenticationErrorCommon::tokenValidationInvalidFungibleMint,
                Some(&format!("Category: {category_hex}, tokens created: {sum}")),
            ));
        }
        if let Some(available_sum) = available_sum {
            if *sum > available_sum {
                return Err(format_error(
                    AuthenticationErrorCommon::tokenValidationOutputsExceedInputs,
                    Some(&format!(
                        "Category: {category_hex}, input amount: {available_sum}, output amount: {sum}"
                    )),
                ));
            }
        }
    }
    let mut remaining_mutable_tokens: MutableTokensByCategory = available_mutable_tokens_by_category;
    for (category_hex, sum) in &output_mutable_tokens_by_category {
        if available_minting_categories.contains(category_hex) {
            continue;
        }
        let remaining = get_category(&remaining_mutable_tokens, category_hex).unwrap_or(0) - sum;
        set_category(&mut remaining_mutable_tokens, category_hex, remaining);
    }
    for (category_hex, sum) in &remaining_mutable_tokens {
        if *sum < 0 {
            return Err(format_error(
                AuthenticationErrorCommon::tokenValidationExcessiveMutableTokens,
                Some(&format!("Category: {category_hex}, excess mutable tokens: {}", 0 - sum)),
            ));
        }
    }
    let mut available_immutable_tokens = available_immutable_tokens;
    let mut unmatched_immutable_tokens = Vec::new();
    for token in output_immutable_tokens {
        if available_minting_categories.contains(&token.category_hex) {
            continue;
        }
        let first_match = available_immutable_tokens.iter().position(|available| {
            available.category_hex == token.category_hex
                && available.commitment_hex == token.commitment_hex
        });
        match first_match {
            None => unmatched_immutable_tokens.push(token),
            Some(first_match) => {
                available_immutable_tokens.remove(first_match);
            }
        }
    }
    let mut required_mutable_tokens: MutableTokensByCategory = Vec::new();
    for token in &unmatched_immutable_tokens {
        let required = get_category(&required_mutable_tokens, &token.category_hex).unwrap_or(0) + 1;
        set_category(&mut required_mutable_tokens, &token.category_hex, required);
    }
    for (category_hex, required) in &required_mutable_tokens {
        let available = get_category(&remaining_mutable_tokens, category_hex).unwrap_or(0);
        if available < *required {
            return Err(format_error(
                AuthenticationErrorCommon::tokenValidationExcessiveImmutableTokens,
                Some(&format!(
                    "Category {category_hex}, available mutable tokens: {available}, new immutable tokens: {required}"
                )),
            ));
        }
    }
    Ok(())
}

const MUTABLE_CAPABILITY_BYTE: u8 = 0x01;
const MINTING_CAPABILITY_BYTE: u8 = 0x02;

/// Push the extended token category of the provided UTXO (the category in
/// script byte order, followed by the capability byte of a minting or mutable
/// token) to the stack, or `0` if the UTXO has no token.
pub fn push_token_extended_category(state: &mut AuthenticationProgramStateCommon, utxo: &Output) {
    let Some(token) = &utxo.token else {
        push_to_stack_vm_number(state, &BigInt::zero());
        return;
    };
    let capability_byte = match token.nft.as_ref().map(|nft| nft.capability) {
        Some(NonFungibleTokenCapability::Minting) => vec![MINTING_CAPABILITY_BYTE],
        Some(NonFungibleTokenCapability::Mutable) => vec![MUTABLE_CAPABILITY_BYTE],
        _ => Vec::new(),
    };
    let mut category = token.category.clone();
    category.reverse();
    let extended_category = flatten_bin_array(&[category, capability_byte]);
    push_to_stack(state, vec![extended_category], None);
}

/// Push the token commitment of the provided UTXO to the stack (or `0` if the
/// UTXO has no non-fungible token).
pub fn push_token_commitment(state: &mut AuthenticationProgramStateCommon, utxo: &Output) {
    match utxo.token.as_ref().and_then(|token| token.nft.as_ref()) {
        None => push_to_stack_vm_number(state, &BigInt::zero()),
        Some(nft) => push_to_stack_checked(state, nft.commitment.clone(), None),
    }
}

/// Push the fungible token amount of the provided UTXO to the stack (or `0`
/// if the UTXO has no token).
pub fn push_token_amount(state: &mut AuthenticationProgramStateCommon, utxo: &Output) {
    match &utxo.token {
        None => push_to_stack_vm_number(state, &BigInt::zero()),
        Some(token) => push_to_stack_vm_number(state, &BigInt::from_u64(token.amount)),
    }
}

pub fn op_utxo_token_category(state: &mut AuthenticationProgramStateCommon) {
    use_transaction_utxo(state, |next_state, [utxo]| push_token_extended_category(next_state, utxo));
}

pub fn op_utxo_token_commitment(state: &mut AuthenticationProgramStateCommon) {
    use_transaction_utxo(state, |next_state, [utxo]| push_token_commitment(next_state, utxo));
}

pub fn op_utxo_token_amount(state: &mut AuthenticationProgramStateCommon) {
    use_transaction_utxo(state, |next_state, [utxo]| push_token_amount(next_state, utxo));
}

pub fn op_output_token_category(state: &mut AuthenticationProgramStateCommon) {
    use_transaction_output(state, |next_state, [output]| {
        push_token_extended_category(next_state, output);
    });
}

pub fn op_output_token_commitment(state: &mut AuthenticationProgramStateCommon) {
    use_transaction_output(state, |next_state, [output]| push_token_commitment(next_state, output));
}

pub fn op_output_token_amount(state: &mut AuthenticationProgramStateCommon) {
    use_transaction_output(state, |next_state, [output]| push_token_amount(next_state, output));
}
