//! Port of `vm/instruction-sets/common/instruction-sets-utils.spec.ts`.

#[path = "../../../../../tests/fast-check.rs"]
mod fc;

use std::collections::BTreeMap;

use libauth::{
    assemble_bytecode, assemble_bytecode_bch, assemble_bytecode_btc,
    authentication_instructions_are_malformed, cash_assembly_to_bin,
    decode_authentication_instructions, disassemble_authentication_instructions_maybe_malformed,
    disassemble_bytecode, disassemble_bytecode_bch, disassemble_bytecode_btc,
    encode_authentication_instruction, encode_authentication_instructions,
    encode_authentication_instructions_maybe_malformed, generate_bytecode_map, hex_to_bin,
    AuthenticationInstruction, AuthenticationInstructionMalformed,
    AuthenticationInstructionMaybeMalformed, AuthenticationInstructionOperation,
    AuthenticationInstructionPush, AuthenticationInstructionPushMalformedData,
    AuthenticationInstructionPushMalformedLength, AuthenticationInstructionsMaybeMalformed,
    BytecodeGenerationResult, OpcodesBch, OpcodesBtc,
};

/// One parsed instruction of a fixture (libauth's `parse` tuples):
/// - `[opcode]`
/// - `[opcode, data]`
/// - `[opcode, data, expectedDataBytes]` (malformed)
/// - `[opcode, undefined, undefined, length, expectedLengthBytes]` (malformed)
enum Parse {
    Operation(u8),
    Push(u8, &'static str),
    MalformedData(u8, &'static str, usize),
    MalformedLength(u8, &'static str, u8),
}

/// A `CommonScriptParseAndAsmTests` entry: the `0x`-prefixed script hex, the
/// expected ASM, and the parsed instructions.
type ScriptTest = (&'static str, &'static str, &'static [Parse]);

struct Fixture {
    asm: &'static str,
    #[allow(dead_code)]
    hex: &'static str,
    object: AuthenticationInstructionsMaybeMalformed,
    script: Vec<u8>,
}

/// libauth's `defToFixtures`.
fn def_to_fixtures(tests: &[ScriptTest]) -> Vec<Fixture> {
    tests
        .iter()
        .map(|(full_hex, asm, parse)| {
            let hex = full_hex.trim_start_matches("0x");
            let script = hex_to_bin(hex);
            let object = parse
                .iter()
                .map(|set| match *set {
                    Parse::Operation(opcode) => AuthenticationInstructionMaybeMalformed::Instruction(
                        AuthenticationInstruction::Operation(AuthenticationInstructionOperation {
                            opcode,
                        }),
                    ),
                    Parse::Push(opcode, data) => AuthenticationInstructionMaybeMalformed::Instruction(
                        AuthenticationInstruction::Push(AuthenticationInstructionPush {
                            data: hex_to_bin(data),
                            opcode,
                        }),
                    ),
                    Parse::MalformedData(opcode, data, expected_data_bytes) => {
                        AuthenticationInstructionMaybeMalformed::Malformed(
                            AuthenticationInstructionMalformed::PushMalformedData(
                                AuthenticationInstructionPushMalformedData {
                                    data: hex_to_bin(data),
                                    expected_data_bytes,
                                    opcode,
                                },
                            ),
                        )
                    }
                    Parse::MalformedLength(opcode, length, expected_length_bytes) => {
                        AuthenticationInstructionMaybeMalformed::Malformed(
                            AuthenticationInstructionMalformed::PushMalformedLength(
                                AuthenticationInstructionPushMalformedLength {
                                    expected_length_bytes,
                                    length: hex_to_bin(length),
                                    opcode,
                                },
                            ),
                        )
                    }
                })
                .collect();
            Fixture {
                asm,
                hex,
                object,
                script,
            }
        })
        .collect()
}

const WELL_FORMED_SCRIPTS: &[ScriptTest] = &[
    ("0x00", "OP_0", &[Parse::Push(0, "")]),
    (
        "0x0001010202020303030376",
        "OP_0 OP_PUSHBYTES_1 0x01 OP_PUSHBYTES_2 0x0202 OP_PUSHBYTES_3 0x030303 OP_DUP",
        &[
            Parse::Push(0, ""),
            Parse::Push(1, "01"),
            Parse::Push(2, "0202"),
            Parse::Push(3, "030303"),
            Parse::Operation(118),
        ],
    ),
    (
        "0x410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac",
        "OP_PUSHBYTES_65 0x0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3 OP_CHECKSIG",
        &[
            Parse::Push(
                0x41,
                "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
            ),
            Parse::Operation(0xac),
        ],
    ),
    ("0x4c020304", "OP_PUSHDATA_1 2 0x0304", &[Parse::Push(0x4c, "0304")]),
    (
        "0x76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac",
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 0x11b366edfc0a8b66feebae5c2e25a7b6a5d1cf31 OP_EQUALVERIFY OP_CHECKSIG",
        &[
            Parse::Operation(0x76),
            Parse::Operation(0xa9),
            Parse::Push(0x14, "11b366edfc0a8b66feebae5c2e25a7b6a5d1cf31"),
            Parse::Operation(0x88),
            Parse::Operation(0xac),
        ],
    ),
];

const MAL_FORMED_PUSHES: &[ScriptTest] = &[
    ("0x01", "OP_PUSHBYTES_1 [missing 1 byte]", &[Parse::MalformedData(0x01, "", 1)]),
    ("0x0201", "OP_PUSHBYTES_2 0x01[missing 1 byte]", &[Parse::MalformedData(0x02, "01", 2)]),
    ("0x4b", "OP_PUSHBYTES_75 [missing 75 bytes]", &[Parse::MalformedData(0x4b, "", 75)]),
    ("0x4c", "OP_PUSHDATA_1 [missing 1 byte]", &[Parse::MalformedLength(0x4c, "", 1)]),
    ("0x4c02", "OP_PUSHDATA_1 2 [missing 2 bytes]", &[Parse::MalformedData(0x4c, "", 2)]),
    ("0x4d", "OP_PUSHDATA_2 [missing 2 bytes]", &[Parse::MalformedLength(0x4d, "", 2)]),
    ("0x4d01", "OP_PUSHDATA_2 0x01[missing 1 byte]", &[Parse::MalformedLength(0x4d, "01", 2)]),
    ("0x4d0101", "OP_PUSHDATA_2 257 [missing 257 bytes]", &[Parse::MalformedData(0x4d, "", 257)]),
    (
        "0x4d010101",
        "OP_PUSHDATA_2 257 0x01[missing 256 bytes]",
        &[Parse::MalformedData(0x4d, "01", 257)],
    ),
    ("0x4e", "OP_PUSHDATA_4 [missing 4 bytes]", &[Parse::MalformedLength(0x4e, "", 4)]),
    ("0x4e01", "OP_PUSHDATA_4 0x01[missing 3 bytes]", &[Parse::MalformedLength(0x4e, "01", 4)]),
    (
        "0x4e01000001",
        "OP_PUSHDATA_4 16777217 [missing 16777217 bytes]",
        &[Parse::MalformedData(0x4e, "", 16_777_217)],
    ),
    (
        "0x4e0100000101",
        "OP_PUSHDATA_4 16777217 0x01[missing 16777216 bytes]",
        &[Parse::MalformedData(0x4e, "01", 16_777_217)],
    ),
];

fn well_formed(hex: &str) -> Fixture {
    find_fixture(WELL_FORMED_SCRIPTS, hex)
}

fn mal_formed(hex: &str) -> Fixture {
    find_fixture(MAL_FORMED_PUSHES, hex)
}

fn find_fixture(tests: &[ScriptTest], hex: &str) -> Fixture {
    let index = tests
        .iter()
        .position(|(full_hex, _, _)| *full_hex == hex)
        .unwrap_or_else(|| panic!("unknown fixture {hex}"));
    def_to_fixtures(tests).swap_remove(index)
}

/// The `object` of a well-formed fixture as `AuthenticationInstruction[]`.
fn well_formed_instructions(object: &[AuthenticationInstructionMaybeMalformed]) -> Vec<AuthenticationInstruction> {
    object
        .iter()
        .map(|instruction| match instruction {
            AuthenticationInstructionMaybeMalformed::Instruction(instruction) => instruction.clone(),
            AuthenticationInstructionMaybeMalformed::Malformed(malformed) => {
                panic!("unexpected malformed instruction: {malformed:?}")
            }
        })
        .collect()
}

/// libauth's `parse` macro (title: `parse script: ${title}`).
fn parse(input: &[u8], expected: &AuthenticationInstructionsMaybeMalformed) {
    assert_eq!(&decode_authentication_instructions(input), expected);
}

/// libauth's `disassemble` macro (title: `disassemble script: ${title}`).
fn disassemble(input: &[AuthenticationInstructionMaybeMalformed], expected: &str) {
    assert_eq!(
        disassemble_authentication_instructions_maybe_malformed(OpcodesBch::MEMBERS, input),
        expected
    );
}

/// libauth's `encode` macro (title: `encode script: ${title}`).
fn encode(input: &[AuthenticationInstruction], expected: &[u8]) {
    assert_eq!(encode_authentication_instructions(input), expected);
}

/// libauth's `reEncode` macro (title: `re-encode parsed script: ${title}`).
fn re_encode(input: &[AuthenticationInstructionMaybeMalformed], expected: &[u8]) {
    assert_eq!(encode_authentication_instructions_maybe_malformed(input), expected);
}

/// The four tests libauth registers for each well-formed script.
macro_rules! well_formed_tests {
    ($hex:literal => $parse:ident, $disassemble:ident, $encode:ident, $re_encode:ident) => {
        #[test]
        fn $parse() {
            let fixture = well_formed($hex);
            parse(&fixture.script, &fixture.object);
        }

        #[test]
        fn $disassemble() {
            let fixture = well_formed($hex);
            disassemble(&fixture.object, fixture.asm);
        }

        #[test]
        fn $encode() {
            let fixture = well_formed($hex);
            encode(&well_formed_instructions(&fixture.object), &fixture.script);
        }

        #[test]
        fn $re_encode() {
            let fixture = well_formed($hex);
            re_encode(&fixture.object, &fixture.script);
        }
    };
}

/// The three tests libauth registers for each malformed push.
macro_rules! mal_formed_tests {
    ($hex:literal => $parse:ident, $disassemble:ident, $re_encode:ident) => {
        #[test]
        fn $parse() {
            let fixture = mal_formed($hex);
            parse(&fixture.script, &fixture.object);
        }

        #[test]
        fn $disassemble() {
            let fixture = mal_formed($hex);
            disassemble(&fixture.object, fixture.asm);
        }

        #[test]
        fn $re_encode() {
            let fixture = mal_formed($hex);
            re_encode(&fixture.object, &fixture.script);
        }
    };
}

well_formed_tests!("0x00" =>
    parse_script_0x00,
    disassemble_script_0x00,
    encode_script_0x00,
    re_encode_parsed_script_0x00
);
well_formed_tests!("0x0001010202020303030376" =>
    parse_script_0x0001010202020303030376,
    disassemble_script_0x0001010202020303030376,
    encode_script_0x0001010202020303030376,
    re_encode_parsed_script_0x0001010202020303030376
);
well_formed_tests!("0x410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac" =>
    parse_script_0x410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac,
    disassemble_script_0x410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac,
    encode_script_0x410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac,
    re_encode_parsed_script_0x410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac
);
well_formed_tests!("0x4c020304" =>
    parse_script_0x4c020304,
    disassemble_script_0x4c020304,
    encode_script_0x4c020304,
    re_encode_parsed_script_0x4c020304
);
well_formed_tests!("0x76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac" =>
    parse_script_0x76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac,
    disassemble_script_0x76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac,
    encode_script_0x76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac,
    re_encode_parsed_script_0x76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac
);

mal_formed_tests!("0x01" => parse_script_0x01, disassemble_script_0x01, re_encode_parsed_script_0x01);
mal_formed_tests!("0x0201" => parse_script_0x0201, disassemble_script_0x0201, re_encode_parsed_script_0x0201);
mal_formed_tests!("0x4b" => parse_script_0x4b, disassemble_script_0x4b, re_encode_parsed_script_0x4b);
mal_formed_tests!("0x4c" => parse_script_0x4c, disassemble_script_0x4c, re_encode_parsed_script_0x4c);
mal_formed_tests!("0x4c02" => parse_script_0x4c02, disassemble_script_0x4c02, re_encode_parsed_script_0x4c02);
mal_formed_tests!("0x4d" => parse_script_0x4d, disassemble_script_0x4d, re_encode_parsed_script_0x4d);
mal_formed_tests!("0x4d01" => parse_script_0x4d01, disassemble_script_0x4d01, re_encode_parsed_script_0x4d01);
mal_formed_tests!("0x4d0101" => parse_script_0x4d0101, disassemble_script_0x4d0101, re_encode_parsed_script_0x4d0101);
mal_formed_tests!("0x4d010101" => parse_script_0x4d010101, disassemble_script_0x4d010101, re_encode_parsed_script_0x4d010101);
mal_formed_tests!("0x4e" => parse_script_0x4e, disassemble_script_0x4e, re_encode_parsed_script_0x4e);
mal_formed_tests!("0x4e01" => parse_script_0x4e01, disassemble_script_0x4e01, re_encode_parsed_script_0x4e01);
mal_formed_tests!("0x4e01000001" =>
    parse_script_0x4e01000001,
    disassemble_script_0x4e01000001,
    re_encode_parsed_script_0x4e01000001
);
mal_formed_tests!("0x4e0100000101" =>
    parse_script_0x4e0100000101,
    disassemble_script_0x4e0100000101,
    re_encode_parsed_script_0x4e0100000101
);

#[test]
fn generate_bytecode_map_() {
    /// The spec-local `enum TestOpcodes { OP_A = 1, OP_B = 2, OP_C = 3 }`.
    const TEST_OPCODES: &[(&str, u8)] = &[("OP_A", 1), ("OP_B", 2), ("OP_C", 3)];
    assert_eq!(
        generate_bytecode_map(TEST_OPCODES),
        BTreeMap::from([
            ("OP_A".to_string(), vec![1]),
            ("OP_B".to_string(), vec![2]),
            ("OP_C".to_string(), vec![3]),
        ])
    );
}

#[test]
fn encode_authentication_instruction_() {
    const OP_PUSHDATA_1: u8 = 0x4c;
    let mut push_data_1_expected = vec![0_u8; 102];
    push_data_1_expected[..2].copy_from_slice(&[OP_PUSHDATA_1, 100]);
    let push_data_1_encoded = encode_authentication_instruction(&AuthenticationInstruction::Push(
        AuthenticationInstructionPush {
            data: vec![0; 100],
            opcode: OP_PUSHDATA_1,
        },
    ));
    assert_eq!(push_data_1_encoded, push_data_1_expected);

    const OP_PUSHDATA_2: u8 = 0x4d;
    let mut push_data_2_expected = vec![0_u8; 259];
    push_data_2_expected[..3].copy_from_slice(&[OP_PUSHDATA_2, 0, 1]);
    let push_data_2_encoded = encode_authentication_instruction(&AuthenticationInstruction::Push(
        AuthenticationInstructionPush {
            data: vec![0; 256],
            opcode: OP_PUSHDATA_2,
        },
    ));
    assert_eq!(push_data_2_encoded, push_data_2_expected);

    const OP_PUSHDATA_4: u8 = 0x4e;
    let mut push_data_4_expected = vec![0_u8; 65541];
    push_data_4_expected[..5].copy_from_slice(&[OP_PUSHDATA_4, 0, 0, 1, 0]);
    let push_data_4_encoded = encode_authentication_instruction(&AuthenticationInstruction::Push(
        AuthenticationInstructionPush {
            data: vec![0; 65536],
            opcode: OP_PUSHDATA_4,
        },
    ));
    assert_eq!(push_data_4_encoded, push_data_4_expected);
}

/// The spec's module-level
/// `enum TestOpcodes { OP_PUSH_EMPTY = 0, OP_A = 81, OP_B = 82, OP_C = 83 }`.
const TEST_OPCODES: &[(&str, u8)] = &[
    ("OP_PUSH_EMPTY", 0),
    ("OP_A", 81),
    ("OP_B", 82),
    ("OP_C", 83),
];

#[test]
fn disassemble_bytecode_() {
    assert_eq!(
        disassemble_bytecode(TEST_OPCODES, &[0, 81, 82, 83, 81, 82, 83]),
        "OP_PUSH_EMPTY OP_A OP_B OP_C OP_A OP_B OP_C"
    );
}

/// `t.deepEqual(result, { bytecode, success: true })`
/// (`BytecodeGenerationResult` does not implement `PartialEq`).
fn assert_bytecode_success(result: BytecodeGenerationResult, expected: &[u8]) {
    match result {
        BytecodeGenerationResult::Success { bytecode } => assert_eq!(bytecode, expected),
        error => panic!("expected a successful assembly, got: {error:?}"),
    }
}

#[test]
fn assemble_bytecode_() {
    assert_bytecode_success(
        assemble_bytecode(
            &generate_bytecode_map(TEST_OPCODES),
            "OP_PUSH_EMPTY OP_A OP_B OP_C OP_A OP_B OP_C",
        ),
        &[0, 81, 82, 83, 81, 82, 83],
    );
}

const ZCF_HEX: &str = "76a9148b139a5274cc85e2d36d4f97922a15ae5d7f68af8763ac6776a914f127e6b53e2005930718681d245fe5a2b22f2b9f8763785479879169766bbb6cba676a6868";

#[test]
fn disassemble_bytecode_bch_assemble_bytecode_bch() {
    let zcf_asm = "OP_DUP OP_HASH160 OP_PUSHBYTES_20 0x8b139a5274cc85e2d36d4f97922a15ae5d7f68af OP_EQUAL OP_IF OP_CHECKSIG OP_ELSE OP_DUP OP_HASH160 OP_PUSHBYTES_20 0xf127e6b53e2005930718681d245fe5a2b22f2b9f OP_EQUAL OP_IF OP_OVER OP_4 OP_PICK OP_EQUAL OP_NOT OP_VERIFY OP_DUP OP_TOALTSTACK OP_CHECKDATASIGVERIFY OP_FROMALTSTACK OP_CHECKDATASIG OP_ELSE OP_RETURN OP_ENDIF OP_ENDIF";
    assert_eq!(disassemble_bytecode_bch(&hex_to_bin(ZCF_HEX)), zcf_asm);
    assert_bytecode_success(assemble_bytecode_bch(zcf_asm), &hex_to_bin(ZCF_HEX));
}

#[test]
fn cash_assembly_to_bin_() {
    assert_eq!(cash_assembly_to_bin("OP_1 OP_2 OP_ADD"), Ok(hex_to_bin("515293")));
    assert_eq!(
        cash_assembly_to_bin("OP_1 OP_2 OP_ADD OP_NOPE"),
        Err("CashAssembly compilation resolve error: Unknown identifier \"OP_NOPE\".".to_string())
    );
}

#[test]
fn disassemble_bytecode_btc_assemble_bytecode_btc() {
    let zcf_asm = "OP_DUP OP_HASH160 OP_PUSHBYTES_20 0x8b139a5274cc85e2d36d4f97922a15ae5d7f68af OP_EQUAL OP_IF OP_CHECKSIG OP_ELSE OP_DUP OP_HASH160 OP_PUSHBYTES_20 0xf127e6b53e2005930718681d245fe5a2b22f2b9f OP_EQUAL OP_IF OP_OVER OP_4 OP_PICK OP_EQUAL OP_NOT OP_VERIFY OP_DUP OP_TOALTSTACK OP_UNKNOWN187 OP_FROMALTSTACK OP_UNKNOWN186 OP_ELSE OP_RETURN OP_ENDIF OP_ENDIF";
    assert_eq!(disassemble_bytecode_btc(&hex_to_bin(ZCF_HEX)), zcf_asm);
    assert_bytecode_success(assemble_bytecode_btc(zcf_asm), &hex_to_bin(ZCF_HEX));
}

const MAX_BIN_LENGTH: usize = 100;

/// The shared body of the two `[fast-check]` round-trip properties
/// (`op_pushdata_*` and `op_1` are the respective instruction set's opcodes).
fn minimal_push_round_trip(
    random_bytecode: &[u8],
    op_1: u8,
    op_pushdata_1: u8,
    op_pushdata_2: u8,
    op_pushdata_4: u8,
    disassemble: fn(&[u8]) -> String,
    assemble: fn(&str) -> BytecodeGenerationResult,
) {
    let parsed = decode_authentication_instructions(random_bytecode);
    let instructions = well_formed_instructions(if authentication_instructions_are_malformed(&parsed) {
        &parsed[..parsed.len() - 1]
    } else {
        &parsed
    });
    let minimal_push: Vec<AuthenticationInstruction> = instructions
        .into_iter()
        .map(|instruction| {
            if [op_pushdata_2, op_pushdata_4].contains(&instruction.opcode()) {
                AuthenticationInstruction::Operation(AuthenticationInstructionOperation { opcode: op_1 })
            } else if instruction.opcode() == op_pushdata_1
                && instruction.data().expect("a push instruction").len() < 76
            {
                AuthenticationInstruction::Push(AuthenticationInstructionPush {
                    data: vec![0; 76],
                    opcode: op_pushdata_1,
                })
            } else {
                instruction
            }
        })
        .collect();
    let encoded = encode_authentication_instructions(&minimal_push);

    let disassembled = disassemble(&encoded);
    let reassembled = assemble(&disassembled);
    let BytecodeGenerationResult::Success { bytecode } = reassembled else {
        panic!("t.fail(): reassembly failed: {reassembled:?}");
    };
    assert_eq!(encoded, bytecode);
}

#[test]
fn fast_check_disassemble_bytecode_bch_assemble_bytecode_bch() {
    fc::test_prop(fc::uint8_array(Some(0), Some(MAX_BIN_LENGTH)), |random_bytecode| {
        minimal_push_round_trip(
            random_bytecode,
            OpcodesBch::OP_1,
            OpcodesBch::OP_PUSHDATA_1,
            OpcodesBch::OP_PUSHDATA_2,
            OpcodesBch::OP_PUSHDATA_4,
            disassemble_bytecode_bch,
            assemble_bytecode_bch,
        );
    });
}

#[test]
fn fast_check_disassemble_bytecode_btc_assemble_bytecode_btc() {
    fc::test_prop(fc::uint8_array(Some(0), Some(MAX_BIN_LENGTH)), |random_bytecode| {
        minimal_push_round_trip(
            random_bytecode,
            OpcodesBtc::OP_1,
            OpcodesBtc::OP_PUSHDATA_1,
            OpcodesBtc::OP_PUSHDATA_2,
            OpcodesBtc::OP_PUSHDATA_4,
            disassemble_bytecode_btc,
            assemble_bytecode_btc,
        );
    });
}
