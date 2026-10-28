//! Port of `vm/instruction-sets/common/push.spec.ts`.

use libauth::{encode_data_push, hex_to_bin, range};

/// libauth's (spec-local) `const enum PushOperationConstants`.
struct PushOperationConstants;

impl PushOperationConstants {
    const OP_PUSHDATA_1: u8 = 0x4c;
    const OP_PUSHDATA_2: u8 = 0x4d;
    const OP_PUSHDATA_4: u8 = 0x4e;
    /// 256 - 1
    const MAXIMUM_PUSH_DATA_1_SIZE: usize = 255;
    /// 256 ** 2 - 1
    const MAXIMUM_PUSH_DATA_2_SIZE: usize = 65535;
    /// 256 ** 4 - 1
    #[allow(dead_code)]
    const MAXIMUM_PUSH_DATA_4_SIZE: usize = 4_294_967_295;
}

const PREFIX_DATA_PUSH_VECTORS: &[(&str, &str)] = &[
    ("", "00"),
    ("81", "4f"),
    ("01", "51"),
    ("02", "52"),
    ("03", "53"),
    ("04", "54"),
    ("05", "55"),
    ("06", "56"),
    ("07", "57"),
    ("08", "58"),
    ("09", "59"),
    ("0a", "5a"),
    ("0b", "5b"),
    ("0c", "5c"),
    ("0d", "5d"),
    ("0e", "5e"),
    ("0f", "5f"),
    ("10", "60"),
    ("00", "0100"),
    ("0000", "020000"),
    ("80", "0180"),
    ("0081", "020081"),
    ("123456", "03123456"),
    ("123456789012345678901234567890", "0f123456789012345678901234567890"),
];

/// `Uint8Array.from(range(length))` (values wrap modulo 256).
fn uint8_array_from_range(length: usize) -> Vec<u8> {
    range(length, None).into_iter().map(|value| value as u8).collect()
}

#[test]
fn prefix_data_push() {
    for (input_hex, output_hex) in PREFIX_DATA_PUSH_VECTORS {
        assert_eq!(encode_data_push(&hex_to_bin(input_hex)), hex_to_bin(output_hex));
    }
    assert_eq!(
        encode_data_push(&uint8_array_from_range(
            PushOperationConstants::MAXIMUM_PUSH_DATA_1_SIZE
        )),
        [
            vec![PushOperationConstants::OP_PUSHDATA_1, 0xff],
            uint8_array_from_range(PushOperationConstants::MAXIMUM_PUSH_DATA_1_SIZE),
        ]
        .concat()
    );
    assert_eq!(
        encode_data_push(&uint8_array_from_range(
            PushOperationConstants::MAXIMUM_PUSH_DATA_1_SIZE + 1
        )),
        [
            vec![PushOperationConstants::OP_PUSHDATA_2, 0, 1],
            uint8_array_from_range(PushOperationConstants::MAXIMUM_PUSH_DATA_1_SIZE + 1),
        ]
        .concat()
    );
    assert_eq!(
        encode_data_push(&uint8_array_from_range(
            PushOperationConstants::MAXIMUM_PUSH_DATA_2_SIZE
        )),
        [
            vec![PushOperationConstants::OP_PUSHDATA_2, 0xff, 0xff],
            uint8_array_from_range(PushOperationConstants::MAXIMUM_PUSH_DATA_2_SIZE),
        ]
        .concat()
    );
    assert_eq!(
        encode_data_push(&uint8_array_from_range(
            PushOperationConstants::MAXIMUM_PUSH_DATA_2_SIZE + 1
        )),
        [
            vec![PushOperationConstants::OP_PUSHDATA_4, 0, 0, 1, 0],
            uint8_array_from_range(PushOperationConstants::MAXIMUM_PUSH_DATA_2_SIZE + 1),
        ]
        .concat()
    );
}
