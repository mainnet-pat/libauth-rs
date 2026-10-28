//! Port of `message/transaction-encoding.spec.ts`.

use libauth::runtime::json::{parse_json, Json};
use libauth::{
    decode_transaction_common, decode_transaction_outputs, encode_token_prefix,
    encode_transaction_common, hash_transaction, hash_transaction_p2p_order,
    hash_transaction_ui_order, hex_to_bin, read_locking_bytecode_with_prefix, read_token_amount,
    read_token_prefix, read_transaction, read_transaction_common, read_transaction_non_token_aware,
    read_transaction_output_non_token_aware, read_transaction_outputs_non_token_aware, sha256,
    Input, Nft, NonFungibleTokenCapability, Output, ReadPosition, Token, TransactionCommon,
    TransactionDecodingError,
};

const TOKEN_PREFIX_INVALID_JSON: &str = include_str!("fixtures/token-prefix-invalid.json");
const TOKEN_PREFIX_VALID_JSON: &str = include_str!("fixtures/token-prefix-valid.json");

/// The example transaction used by several tests.
const TX_HEX: &str = "3eb87070042d16f9469b0080a3c1fe8de0feae345200beef8b1e0d7c62501ae0df899dca1e03000000066a0065525365ffffffffd14a9a335e8babddd89b5d0b6a0f41dd6b18848050a0fc48ce32d892e11817fd030000000863acac00535200527ff62cf3ad30d9064e180eaed5e6303950121a8086b5266b55156e4f7612f2c7ebf223e0020000000100ffffffff6273ca3aceb55931160fa7a3064682b4790ee016b4a5c0c0d101fd449dff88ba01000000055351ac526aa3b8223d0421f25b0400000000026552f92db70500000000075253516a656a53c4a908010000000000b5192901000000000652525251516aa148ca38";

fn input(
    outpoint_index: u32,
    outpoint_transaction_hash: &str,
    sequence_number: u32,
    unlocking_bytecode: &str,
) -> Input {
    Input {
        outpoint_index,
        outpoint_transaction_hash: hex_to_bin(outpoint_transaction_hash),
        sequence_number,
        unlocking_bytecode: hex_to_bin(unlocking_bytecode),
    }
}

fn output(locking_bytecode: &str, value_satoshis: u64) -> Output {
    Output {
        locking_bytecode: hex_to_bin(locking_bytecode),
        token: None,
        value_satoshis,
    }
}

/// The decoded form of [`TX_HEX`].
fn example_transaction() -> TransactionCommon {
    TransactionCommon {
        inputs: vec![
            input(
                3,
                "1eca9d89dfe01a50627c0d1e8befbe005234aefee08dfec1a380009b46f9162d",
                4_294_967_295,
                "6a0065525365",
            ),
            input(
                3,
                "fd1718e192d832ce48fca0508084186bdd410f6a0b5d9bd8ddab8b5e339a4ad1",
                4_079_810_175,
                "63acac0053520052",
            ),
            input(
                2,
                "e023f2ebc7f212764f6e15556b26b586801a12503930e6d5ae0e184e06d930ad",
                4_294_967_295,
                "00",
            ),
            input(
                1,
                "ba88ff9d44fd01d1c0c0a5b416e00e79b4824606a3a70f163159b5ce3aca7362",
                1_025_685_667,
                "5351ac526a",
            ),
        ],
        locktime: 952_780_961,
        outputs: vec![
            output("6552", 73_134_625),
            output("5253516a656a53", 95_890_937),
            output("", 17_344_964),
            output("52525251516a", 19_470_773),
        ],
        version: 1_886_435_390,
    }
}

fn reversed(mut bin: Vec<u8>) -> Vec<u8> {
    bin.reverse();
    bin
}

/// AVA's `t.truthy(fn)` checks that an export exists; in Rust, naming the
/// function is the check (a missing export fails to compile).
fn truthy<T>(_value: T) -> bool {
    true
}

#[test]
fn decode_transaction() {
    /*
     * Example transaction:
     *
     * 3eb87070 ← version
     *
     * 04 ← number of inputs
     *
     * Input 1 outpointTransactionHash (reverse byte order):
     * 2d16f9469b0080a3c1fe8de0feae345200beef8b1e0d7c62501ae0df899dca1e
     * 03000000 ← outpointIndex (BinUint32LE)
     * 06 ← bytecodeLength (CompactUint)
     * 6a0065525365 ← bytecode
     * ffffffff ← sequence number (BinUint32LE)
     *
     * Input 2:
     * d14a9a335e8babddd89b5d0b6a0f41dd6b18848050a0fc48ce32d892e11817fd
     * 03000000
     * 08
     * 63acac0053520052
     * 7ff62cf3
     *
     * Input 3:
     * ad30d9064e180eaed5e6303950121a8086b5266b55156e4f7612f2c7ebf223e0
     * 02000000
     * 01
     * 00
     * ffffffff
     *
     * Input 4:
     * 6273ca3aceb55931160fa7a3064682b4790ee016b4a5c0c0d101fd449dff88ba
     * 01000000
     * 05
     * 5351ac526a
     * a3b8223d
     *
     * 04 ← number of outputs
     *
     * Output 1:
     * 21f25b0400000000 ← satoshis (BinUint64LE)
     * 02 ← bytecodeLength (CompactUint)
     * 6552 ← lockingBytecode
     *
     * Output 2:
     * f92db70500000000
     * 07
     * 5253516a656a53
     *
     * Output 3:
     * c4a9080100000000
     * 00
     *
     * Output 4:
     * b519290100000000
     * 06
     * 52525251516a
     *
     * a148ca38 ← locktime (BinUint32LE)
     */
    let tx = hex_to_bin(TX_HEX);
    assert_eq!(decode_transaction_common(&tx), Ok(example_transaction()));
}

#[test]
fn encode_transaction() {
    let tx = example_transaction();
    assert_eq!(encode_transaction_common(&tx), hex_to_bin(TX_HEX));
}

#[test]
fn decode_and_encode_transaction() {
    let tx = TX_HEX;
    assert_eq!(
        hex_to_bin(tx),
        encode_transaction_common(&decode_transaction_common(&hex_to_bin(tx)).unwrap())
    );
}

#[test]
fn decode_transaction_invalid() {
    assert_eq!(
        decode_transaction_common(&hex_to_bin("00")),
        Err("Error reading transaction. Error reading Uint32LE: requires 4 bytes. Remaining bytes: 1"
            .to_string())
    );
}

#[test]
fn hash_transaction_hash_transaction_ui_order_hash_transaction_p2p_order() {
    let tx = TX_HEX;
    let tx_id = "67adfe4f2b374e770584d2d0beb8eacc7b29287a47d2ffe511fa81f48e0ec4fb";
    let hal_tx = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
    let hal_tx_id = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";

    assert_eq!(hash_transaction(&hex_to_bin(tx)), tx_id);
    assert_eq!(hash_transaction_ui_order(&hex_to_bin(tx), None), hex_to_bin(tx_id));
    assert_eq!(
        hash_transaction_ui_order(&hex_to_bin(tx), Some(&sha256)),
        hex_to_bin(tx_id)
    );
    assert_eq!(
        hash_transaction_p2p_order(&hex_to_bin(tx), None),
        reversed(hex_to_bin(tx_id))
    );
    assert_eq!(
        hash_transaction_p2p_order(&hex_to_bin(tx), Some(&sha256)),
        reversed(hex_to_bin(tx_id))
    );

    assert_eq!(hash_transaction(&hex_to_bin(hal_tx)), hal_tx_id);
    assert_eq!(
        hash_transaction_ui_order(&hex_to_bin(hal_tx), None),
        hex_to_bin(hal_tx_id)
    );
    assert_eq!(
        hash_transaction_ui_order(&hex_to_bin(hal_tx), Some(&sha256)),
        hex_to_bin(hal_tx_id)
    );
    assert_eq!(
        hash_transaction_p2p_order(&hex_to_bin(hal_tx), None),
        reversed(hex_to_bin(hal_tx_id))
    );
    assert_eq!(
        hash_transaction_p2p_order(&hex_to_bin(hal_tx), Some(&sha256)),
        reversed(hex_to_bin(hal_tx_id))
    );
}

/// `Object.values(json).filter((item) => !Array.isArray(item))`
fn non_array_vectors(json: &str) -> Vec<Json> {
    parse_json(json)
        .expect("valid fixture JSON")
        .as_array()
        .expect("an array of test vectors")
        .iter()
        .filter(|item| item.as_array().is_none())
        .cloned()
        .collect()
}

fn string_property<'a>(object: &'a Json, key: &str) -> &'a str {
    object
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("missing string property {key:?}"))
}

#[test]
fn cash_tokens_token_prefix_valid_json() {
    for (index, vector) in non_array_vectors(TOKEN_PREFIX_VALID_JSON).iter().enumerate() {
        let prefix_hex = string_property(vector, "prefix");
        let data = vector.get("data").expect("data");
        let fail_message = format!("Failure on test vector #{index}: \"{prefix_hex}\"");
        let token = Token {
            amount: string_property(data, "amount")
                .parse()
                .expect("a valid token amount"),
            category: hex_to_bin(string_property(data, "category")),
            nft: data.get("nft").map(|nft| Nft {
                capability: match string_property(nft, "capability") {
                    "minting" => NonFungibleTokenCapability::Minting,
                    "mutable" => NonFungibleTokenCapability::Mutable,
                    "none" => NonFungibleTokenCapability::None,
                    other => panic!("unknown capability: {other}"),
                },
                commitment: hex_to_bin(string_property(nft, "commitment")),
            }),
        };
        let expected_prefix = hex_to_bin(prefix_hex);
        assert_eq!(expected_prefix, encode_token_prefix(Some(&token)), "{fail_message}");

        let decoded = match read_token_prefix(ReadPosition {
            bin: &expected_prefix,
            index: 0,
        }) {
            Err(decoded) => panic!("{decoded}"),
            Ok(decoded) => decoded,
        };
        if decoded.position.bin.len() != decoded.position.index {
            panic!(
                "{fail_message} Prefix \"{prefix_hex}\" includes unexpected bytes. Bytes remaining after read: {}, ",
                decoded.position.bin.len() - decoded.position.index
            );
        }
        assert_eq!(decoded.result, Some(token));
    }
}

#[test]
fn cash_tokens_token_prefix_invalid_json() {
    for (index, vector) in non_array_vectors(TOKEN_PREFIX_INVALID_JSON).iter().enumerate() {
        let prefix_hex = string_property(vector, "prefix");
        let error = string_property(vector, "error");
        let fail_message = format!("Failure on test vector #{index}: \"{prefix_hex}\"");
        let expected_prefix = hex_to_bin(prefix_hex);
        let decoded = read_token_prefix(ReadPosition {
            bin: &expected_prefix,
            index: 0,
        });
        assert_eq!(decoded, Err(error.to_string()), "{fail_message}");
    }
}

#[test]
fn read_token_amount_exists() {
    assert!(truthy(read_token_amount));
}

#[test]
fn read_locking_bytecode_with_prefix_exists() {
    assert!(truthy(read_locking_bytecode_with_prefix));
}

#[test]
fn read_transaction_output_non_token_aware_exists() {
    assert!(truthy(read_transaction_output_non_token_aware));
}

#[test]
fn read_transaction_outputs_non_token_aware_exists() {
    assert!(truthy(read_transaction_outputs_non_token_aware));
}

#[test]
fn decode_transaction_outputs_() {
    let decoded = decode_transaction_outputs(&hex_to_bin(
        "0210270000000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488ac102700000000000017a91498e86c508e780cfb822bba3d5ab9b3e30450196b87",
    ));
    // libauth's assertion message is `stringifyTestVector(decoded)`; the Rust
    // `stringify_test_vector` accepts only `Json`, so the debug
    // representation is used instead.
    assert_eq!(
        decoded,
        Ok(vec![
            output("76a91460011c6bf3f1dd98cff576437b9d85de780f497488ac", 10_000),
            output("a91498e86c508e780cfb822bba3d5ab9b3e30450196b87", 10_000),
        ]),
        "{decoded:#?}"
    );

    assert_eq!(
        decode_transaction_outputs(&hex_to_bin(
            "0210270000000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488ac102700000000000017a91498e86c508e780cfb822bba3d5ab9b3e30450196b8700",
        )),
        Err(format!(
            "{} Last encoded transaction output ends at index 66, leaving 1 remaining byte(s).",
            TransactionDecodingError::outputsEndWithUnexpectedBytes
        ))
    );
}

#[test]
fn read_transaction_non_token_aware_exists() {
    assert!(truthy(read_transaction_non_token_aware));
}

#[test]
fn read_transaction_and_read_transaction_common_are_exported_and_equivalent() {
    // libauth compares the functions' source text
    // (`readTransaction.toString()`), which has no Rust equivalent; the port
    // instead checks that both exported functions behave identically, on both
    // a valid and an invalid encoded transaction.
    let valid = hex_to_bin(TX_HEX);
    let invalid = hex_to_bin("00");
    for bin in [&valid, &invalid] {
        assert_eq!(
            read_transaction(ReadPosition { bin, index: 0 }),
            read_transaction_common(ReadPosition { bin, index: 0 })
        );
    }
}

#[test]
#[ignore = "test.todo: [fast-check] encodeTransactionInput <-> readTransactionInput"]
fn fast_check_encode_transaction_input_read_transaction_input() {}

#[test]
#[ignore = "test.todo: [fast-check] encodeTransactionInputs <-> readTransactionInputs"]
fn fast_check_encode_transaction_inputs_read_transaction_inputs() {}

#[test]
#[ignore = "test.todo: [fast-check] encodeTokenPrefix <-> readTokenPrefix"]
fn fast_check_encode_token_prefix_read_token_prefix() {}

#[test]
#[ignore = "test.todo: [fast-check] encodeTransactionOutput <-> readTransactionOutput"]
fn fast_check_encode_transaction_output_read_transaction_output() {}

#[test]
#[ignore = "test.todo: [fast-check] encodeTransactionOutputs <-> readTransactionOutputs"]
fn fast_check_encode_transaction_outputs_read_transaction_outputs() {}

#[test]
#[ignore = "test.todo: [fast-check] encodeTransaction <-> decodeTransaction/decodeTransactionUnsafe; encodeTransactionBch <-> decodeTransactionBch/decodeTransactionUnsafeBch, encodeTransactionCommon <-> decodeTransactionCommon/decodeTransactionUnsafeCommon"]
fn fast_check_encode_transaction_decode_transaction_decode_transaction_unsafe_encode_transaction_bch_decode_transaction_bch_decode_transaction_unsafe_bch_encode_transaction_common_decode_transaction_common_decode_transaction_unsafe_common(
) {
}

#[test]
#[ignore = "test.todo: hashTransactionP2pOrder"]
fn hash_transaction_p2p_order_() {}

#[test]
#[ignore = "test.todo: hashTransactionUiOrder"]
fn hash_transaction_ui_order_() {}

#[test]
#[ignore = "test.todo: hashTransaction"]
fn hash_transaction_() {}

#[test]
#[ignore = "test.todo: encodeTransactionOutpoints"]
fn encode_transaction_outpoints() {}

#[test]
#[ignore = "test.todo: encodeTransactionOutputsForSigning"]
fn encode_transaction_outputs_for_signing() {}

#[test]
#[ignore = "test.todo: encodeTransactionInputSequenceNumbersForSigning"]
fn encode_transaction_input_sequence_numbers_for_signing() {}
