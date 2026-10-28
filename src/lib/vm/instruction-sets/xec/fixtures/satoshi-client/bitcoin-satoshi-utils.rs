use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::format::{flatten_bin_array, hex_to_bin, utf8_to_bin};
use crate::runtime::bigint::BigInt;
use crate::vm::{big_int_to_vm_number, encode_data_push, generate_bytecode_map, OpcodesXec};

/// The opcode identifiers of the Satoshi client's script test format (the
/// {@link OpcodesXec} names without the `OP_` prefix, plus `PUSHDATA1`,
/// `PUSHDATA2`, and `PUSHDATA4`).
pub static bitcoinSatoshiOpcodes: LazyLock<BTreeMap<String, Vec<u8>>> = LazyLock::new(|| {
    let mut opcodes = BTreeMap::from([
        ("PUSHDATA1".to_string(), vec![OpcodesXec::OP_PUSHDATA_1]),
        ("PUSHDATA2".to_string(), vec![OpcodesXec::OP_PUSHDATA_2]),
        ("PUSHDATA4".to_string(), vec![OpcodesXec::OP_PUSHDATA_4]),
    ]);
    for (name, bytecode) in generate_bytecode_map(OpcodesXec::MEMBERS) {
        opcodes.insert(name["OP_".len()..].to_string(), bytecode);
    }
    opcodes
});

/// Assemble a script in the Satoshi client's script test format.
///
/// Panics (like libauth's `BigInt` conversion throws) if a token is neither an
/// opcode, a hex literal, a string literal, nor a number.
pub fn assemble_bitcoin_satoshi_script(satoshi_script: &str) -> Vec<u8> {
    flatten_bin_array(
        &satoshi_script
            .split(' ')
            .filter(|token| !token.is_empty())
            .map(|token| {
                if let Some(hex) = token.strip_prefix("0x") {
                    return hex_to_bin(hex);
                }
                if token.starts_with('\'') {
                    return encode_data_push(&utf8_to_bin(&token[1..token.len() - 1]));
                }
                bitcoinSatoshiOpcodes.get(token).cloned().unwrap_or_else(|| {
                    let value = BigInt::parse(token).unwrap_or_else(|error| panic!("{error}"));
                    encode_data_push(&big_int_to_vm_number(&value))
                })
            })
            .collect::<Vec<_>>(),
    )
}
