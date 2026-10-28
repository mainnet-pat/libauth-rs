//! Port of `vm/instruction-sets/common/signing-serialization.spec.ts`.
//!
//! libauth registers one `test.skip` per (non-legacy) vector of the Satoshi
//! client's `sighash.json`; each is ported as an ignored `#[test]` (in the same
//! order, named by the snake case of libauth's title) running the same
//! assertion for its vector.

use std::sync::LazyLock;

use libauth::runtime::json::parse_json;
use libauth::{
    bin_to_hex, decode_transaction_unsafe_common, encode_signing_serialization_bch,
    encode_transaction_outputs_for_signing, generate_signing_serialization_components_bch,
    hash256, hex_to_bin, is_legacy_signing_serialization,
    number_to_bin_int32_twos_compliment, CompilationContext, Output,
};

const SIGHASH_TESTS: &str = include_str!("../xec/fixtures/satoshi-client/sighash.json");

#[derive(Clone, Debug)]
struct Expectation {
    input_index: usize,
    script_hex: String,
    signing_serialization_bch_digest_hex: String,
    signing_serialization_type: i64,
    #[allow(dead_code)]
    test_index: usize,
    transaction_hex: String,
}

static TESTS: LazyLock<Vec<Expectation>> = LazyLock::new(|| {
    parse_json(SIGHASH_TESTS)
        .expect("valid sighash.json")
        .as_array()
        .expect("an array of sighash tests")
        .iter()
        .map(|item| item.as_array().expect("a sighash test row").to_vec())
        .filter(|e| e.len() != 1 && e.len() < 8)
        .enumerate()
        .map(|(test_index, expectation)| Expectation {
            input_index: expectation[2].as_u64().expect("an input index") as usize,
            script_hex: expectation[1].as_str().expect("a script").to_string(),
            signing_serialization_bch_digest_hex: expectation[4]
                .as_str()
                .expect("a digest")
                .to_string(),
            signing_serialization_type: expectation[3].as_i64().expect("a signing serialization type"),
            test_index,
            transaction_hex: expectation[0].as_str().expect("a transaction").to_string(),
        })
        .filter(|expectation| {
            /*
             * Currently, this library only supports the new BCH signing
             * serialization algorithm. If the legacy algorithm is implemented,
             * we can re-enable the rest of these tests.
             */
            !is_legacy_signing_serialization(expectation.signing_serialization_type)
        })
        .collect()
});

/// The body of libauth's `test.skip(…)` for the vector at `current_test`.
fn run_sighash_test(current_test: usize) {
    /*
     * Isolate a single test for debugging
     */
    // const pendingTests = tests.filter(e => e.testIndex === 999);
    let pending_tests = &*TESTS;
    let expectation = &pending_tests[current_test];
    let tx = decode_transaction_unsafe_common(&hex_to_bin(&expectation.transaction_hex));
    let locking_bytecode = hex_to_bin(&expectation.script_hex);

    let signing_serialization_type =
        number_to_bin_int32_twos_compliment(expectation.signing_serialization_type);
    // libauth assigns `sourceOutputs[inputIndex]` of an empty array, leaving
    // holes before it. A Rust `Vec` cannot have holes, so they are filled with
    // the same empty output; see `transaction_utxos` below.
    let source_output = Output {
        locking_bytecode: vec![],
        token: None,
        value_satoshis: 0,
    };
    let source_outputs = vec![source_output.clone(); expectation.input_index + 1];

    let mut components = generate_signing_serialization_components_bch(&CompilationContext {
        input_index: expectation.input_index,
        source_outputs,
        transaction: tx,
    });
    // libauth's `encodeTransactionOutputsForSigning(sourceOutputs)` skips the
    // holes of the sparse array (`map`/`reduce` skip them), encoding only the
    // one assigned output.
    components.transaction_utxos = encode_transaction_outputs_for_signing(&[source_output]);
    let serialization = encode_signing_serialization_bch(
        components.corresponding_output.as_deref(),
        &locking_bytecode,
        Some(&signing_serialization_type[1..4]),
        components.locktime,
        components.outpoint_index,
        &components.outpoint_transaction_hash,
        &components.output_token_prefix,
        &components.output_value,
        components.sequence_number,
        &signing_serialization_type[0..1],
        &components.transaction_outpoints,
        &components.transaction_outputs,
        &components.transaction_sequence_numbers,
        &components.transaction_utxos,
        components.version,
        None,
    );
    let digest = hash256(&serialization, None);
    let mut expected = hex_to_bin(&expectation.signing_serialization_bch_digest_hex);
    expected.reverse();
    assert_eq!(
        digest,
        expected,
        "failed serialization: {}",
        bin_to_hex(&serialization)
    );
}

/// libauth's `test.skip(\`[signing-serialization tests] sighash.json …\`, …)`.
macro_rules! sighash_test {
    ($name:ident, $index:literal, $title:literal) => {
        #[test]
        #[ignore = $title]
        fn $name() {
            run_sighash_test($index);
        }
    };
}

sighash_test!(signing_serialization_tests_sighash_json_0_494_1, 0, "test.skip: [signing-serialization tests] sighash.json 0/494 (#1)");
sighash_test!(signing_serialization_tests_sighash_json_1_494_2, 1, "test.skip: [signing-serialization tests] sighash.json 1/494 (#2)");
sighash_test!(signing_serialization_tests_sighash_json_2_494_4, 2, "test.skip: [signing-serialization tests] sighash.json 2/494 (#4)");
sighash_test!(signing_serialization_tests_sighash_json_3_494_6, 3, "test.skip: [signing-serialization tests] sighash.json 3/494 (#6)");
sighash_test!(signing_serialization_tests_sighash_json_4_494_7, 4, "test.skip: [signing-serialization tests] sighash.json 4/494 (#7)");
sighash_test!(signing_serialization_tests_sighash_json_5_494_8, 5, "test.skip: [signing-serialization tests] sighash.json 5/494 (#8)");
sighash_test!(signing_serialization_tests_sighash_json_6_494_9, 6, "test.skip: [signing-serialization tests] sighash.json 6/494 (#9)");
sighash_test!(signing_serialization_tests_sighash_json_7_494_10, 7, "test.skip: [signing-serialization tests] sighash.json 7/494 (#10)");
sighash_test!(signing_serialization_tests_sighash_json_8_494_11, 8, "test.skip: [signing-serialization tests] sighash.json 8/494 (#11)");
sighash_test!(signing_serialization_tests_sighash_json_9_494_13, 9, "test.skip: [signing-serialization tests] sighash.json 9/494 (#13)");
sighash_test!(signing_serialization_tests_sighash_json_10_494_15, 10, "test.skip: [signing-serialization tests] sighash.json 10/494 (#15)");
sighash_test!(signing_serialization_tests_sighash_json_11_494_20, 11, "test.skip: [signing-serialization tests] sighash.json 11/494 (#20)");
sighash_test!(signing_serialization_tests_sighash_json_12_494_21, 12, "test.skip: [signing-serialization tests] sighash.json 12/494 (#21)");
sighash_test!(signing_serialization_tests_sighash_json_13_494_23, 13, "test.skip: [signing-serialization tests] sighash.json 13/494 (#23)");
sighash_test!(signing_serialization_tests_sighash_json_14_494_24, 14, "test.skip: [signing-serialization tests] sighash.json 14/494 (#24)");
sighash_test!(signing_serialization_tests_sighash_json_15_494_25, 15, "test.skip: [signing-serialization tests] sighash.json 15/494 (#25)");
sighash_test!(signing_serialization_tests_sighash_json_16_494_26, 16, "test.skip: [signing-serialization tests] sighash.json 16/494 (#26)");
sighash_test!(signing_serialization_tests_sighash_json_17_494_27, 17, "test.skip: [signing-serialization tests] sighash.json 17/494 (#27)");
sighash_test!(signing_serialization_tests_sighash_json_18_494_29, 18, "test.skip: [signing-serialization tests] sighash.json 18/494 (#29)");
sighash_test!(signing_serialization_tests_sighash_json_19_494_34, 19, "test.skip: [signing-serialization tests] sighash.json 19/494 (#34)");
sighash_test!(signing_serialization_tests_sighash_json_20_494_36, 20, "test.skip: [signing-serialization tests] sighash.json 20/494 (#36)");
sighash_test!(signing_serialization_tests_sighash_json_21_494_37, 21, "test.skip: [signing-serialization tests] sighash.json 21/494 (#37)");
sighash_test!(signing_serialization_tests_sighash_json_22_494_38, 22, "test.skip: [signing-serialization tests] sighash.json 22/494 (#38)");
sighash_test!(signing_serialization_tests_sighash_json_23_494_40, 23, "test.skip: [signing-serialization tests] sighash.json 23/494 (#40)");
sighash_test!(signing_serialization_tests_sighash_json_24_494_42, 24, "test.skip: [signing-serialization tests] sighash.json 24/494 (#42)");
sighash_test!(signing_serialization_tests_sighash_json_25_494_46, 25, "test.skip: [signing-serialization tests] sighash.json 25/494 (#46)");
sighash_test!(signing_serialization_tests_sighash_json_26_494_47, 26, "test.skip: [signing-serialization tests] sighash.json 26/494 (#47)");
sighash_test!(signing_serialization_tests_sighash_json_27_494_49, 27, "test.skip: [signing-serialization tests] sighash.json 27/494 (#49)");
sighash_test!(signing_serialization_tests_sighash_json_28_494_53, 28, "test.skip: [signing-serialization tests] sighash.json 28/494 (#53)");
sighash_test!(signing_serialization_tests_sighash_json_29_494_56, 29, "test.skip: [signing-serialization tests] sighash.json 29/494 (#56)");
sighash_test!(signing_serialization_tests_sighash_json_30_494_57, 30, "test.skip: [signing-serialization tests] sighash.json 30/494 (#57)");
sighash_test!(signing_serialization_tests_sighash_json_31_494_60, 31, "test.skip: [signing-serialization tests] sighash.json 31/494 (#60)");
sighash_test!(signing_serialization_tests_sighash_json_32_494_61, 32, "test.skip: [signing-serialization tests] sighash.json 32/494 (#61)");
sighash_test!(signing_serialization_tests_sighash_json_33_494_62, 33, "test.skip: [signing-serialization tests] sighash.json 33/494 (#62)");
sighash_test!(signing_serialization_tests_sighash_json_34_494_63, 34, "test.skip: [signing-serialization tests] sighash.json 34/494 (#63)");
sighash_test!(signing_serialization_tests_sighash_json_35_494_66, 35, "test.skip: [signing-serialization tests] sighash.json 35/494 (#66)");
sighash_test!(signing_serialization_tests_sighash_json_36_494_70, 36, "test.skip: [signing-serialization tests] sighash.json 36/494 (#70)");
sighash_test!(signing_serialization_tests_sighash_json_37_494_72, 37, "test.skip: [signing-serialization tests] sighash.json 37/494 (#72)");
sighash_test!(signing_serialization_tests_sighash_json_38_494_73, 38, "test.skip: [signing-serialization tests] sighash.json 38/494 (#73)");
sighash_test!(signing_serialization_tests_sighash_json_39_494_77, 39, "test.skip: [signing-serialization tests] sighash.json 39/494 (#77)");
sighash_test!(signing_serialization_tests_sighash_json_40_494_78, 40, "test.skip: [signing-serialization tests] sighash.json 40/494 (#78)");
sighash_test!(signing_serialization_tests_sighash_json_41_494_79, 41, "test.skip: [signing-serialization tests] sighash.json 41/494 (#79)");
sighash_test!(signing_serialization_tests_sighash_json_42_494_81, 42, "test.skip: [signing-serialization tests] sighash.json 42/494 (#81)");
sighash_test!(signing_serialization_tests_sighash_json_43_494_82, 43, "test.skip: [signing-serialization tests] sighash.json 43/494 (#82)");
sighash_test!(signing_serialization_tests_sighash_json_44_494_85, 44, "test.skip: [signing-serialization tests] sighash.json 44/494 (#85)");
sighash_test!(signing_serialization_tests_sighash_json_45_494_86, 45, "test.skip: [signing-serialization tests] sighash.json 45/494 (#86)");
sighash_test!(signing_serialization_tests_sighash_json_46_494_91, 46, "test.skip: [signing-serialization tests] sighash.json 46/494 (#91)");
sighash_test!(signing_serialization_tests_sighash_json_47_494_93, 47, "test.skip: [signing-serialization tests] sighash.json 47/494 (#93)");
sighash_test!(signing_serialization_tests_sighash_json_48_494_94, 48, "test.skip: [signing-serialization tests] sighash.json 48/494 (#94)");
sighash_test!(signing_serialization_tests_sighash_json_49_494_95, 49, "test.skip: [signing-serialization tests] sighash.json 49/494 (#95)");
sighash_test!(signing_serialization_tests_sighash_json_50_494_97, 50, "test.skip: [signing-serialization tests] sighash.json 50/494 (#97)");
sighash_test!(signing_serialization_tests_sighash_json_51_494_99, 51, "test.skip: [signing-serialization tests] sighash.json 51/494 (#99)");
sighash_test!(signing_serialization_tests_sighash_json_52_494_100, 52, "test.skip: [signing-serialization tests] sighash.json 52/494 (#100)");
sighash_test!(signing_serialization_tests_sighash_json_53_494_101, 53, "test.skip: [signing-serialization tests] sighash.json 53/494 (#101)");
sighash_test!(signing_serialization_tests_sighash_json_54_494_102, 54, "test.skip: [signing-serialization tests] sighash.json 54/494 (#102)");
sighash_test!(signing_serialization_tests_sighash_json_55_494_106, 55, "test.skip: [signing-serialization tests] sighash.json 55/494 (#106)");
sighash_test!(signing_serialization_tests_sighash_json_56_494_110, 56, "test.skip: [signing-serialization tests] sighash.json 56/494 (#110)");
sighash_test!(signing_serialization_tests_sighash_json_57_494_113, 57, "test.skip: [signing-serialization tests] sighash.json 57/494 (#113)");
sighash_test!(signing_serialization_tests_sighash_json_58_494_117, 58, "test.skip: [signing-serialization tests] sighash.json 58/494 (#117)");
sighash_test!(signing_serialization_tests_sighash_json_59_494_118, 59, "test.skip: [signing-serialization tests] sighash.json 59/494 (#118)");
sighash_test!(signing_serialization_tests_sighash_json_60_494_119, 60, "test.skip: [signing-serialization tests] sighash.json 60/494 (#119)");
sighash_test!(signing_serialization_tests_sighash_json_61_494_120, 61, "test.skip: [signing-serialization tests] sighash.json 61/494 (#120)");
sighash_test!(signing_serialization_tests_sighash_json_62_494_124, 62, "test.skip: [signing-serialization tests] sighash.json 62/494 (#124)");
sighash_test!(signing_serialization_tests_sighash_json_63_494_125, 63, "test.skip: [signing-serialization tests] sighash.json 63/494 (#125)");
sighash_test!(signing_serialization_tests_sighash_json_64_494_127, 64, "test.skip: [signing-serialization tests] sighash.json 64/494 (#127)");
sighash_test!(signing_serialization_tests_sighash_json_65_494_128, 65, "test.skip: [signing-serialization tests] sighash.json 65/494 (#128)");
sighash_test!(signing_serialization_tests_sighash_json_66_494_130, 66, "test.skip: [signing-serialization tests] sighash.json 66/494 (#130)");
sighash_test!(signing_serialization_tests_sighash_json_67_494_131, 67, "test.skip: [signing-serialization tests] sighash.json 67/494 (#131)");
sighash_test!(signing_serialization_tests_sighash_json_68_494_132, 68, "test.skip: [signing-serialization tests] sighash.json 68/494 (#132)");
sighash_test!(signing_serialization_tests_sighash_json_69_494_133, 69, "test.skip: [signing-serialization tests] sighash.json 69/494 (#133)");
sighash_test!(signing_serialization_tests_sighash_json_70_494_134, 70, "test.skip: [signing-serialization tests] sighash.json 70/494 (#134)");
sighash_test!(signing_serialization_tests_sighash_json_71_494_136, 71, "test.skip: [signing-serialization tests] sighash.json 71/494 (#136)");
sighash_test!(signing_serialization_tests_sighash_json_72_494_137, 72, "test.skip: [signing-serialization tests] sighash.json 72/494 (#137)");
sighash_test!(signing_serialization_tests_sighash_json_73_494_140, 73, "test.skip: [signing-serialization tests] sighash.json 73/494 (#140)");
sighash_test!(signing_serialization_tests_sighash_json_74_494_142, 74, "test.skip: [signing-serialization tests] sighash.json 74/494 (#142)");
sighash_test!(signing_serialization_tests_sighash_json_75_494_143, 75, "test.skip: [signing-serialization tests] sighash.json 75/494 (#143)");
sighash_test!(signing_serialization_tests_sighash_json_76_494_145, 76, "test.skip: [signing-serialization tests] sighash.json 76/494 (#145)");
sighash_test!(signing_serialization_tests_sighash_json_77_494_148, 77, "test.skip: [signing-serialization tests] sighash.json 77/494 (#148)");
sighash_test!(signing_serialization_tests_sighash_json_78_494_150, 78, "test.skip: [signing-serialization tests] sighash.json 78/494 (#150)");
sighash_test!(signing_serialization_tests_sighash_json_79_494_154, 79, "test.skip: [signing-serialization tests] sighash.json 79/494 (#154)");
sighash_test!(signing_serialization_tests_sighash_json_80_494_156, 80, "test.skip: [signing-serialization tests] sighash.json 80/494 (#156)");
sighash_test!(signing_serialization_tests_sighash_json_81_494_157, 81, "test.skip: [signing-serialization tests] sighash.json 81/494 (#157)");
sighash_test!(signing_serialization_tests_sighash_json_82_494_160, 82, "test.skip: [signing-serialization tests] sighash.json 82/494 (#160)");
sighash_test!(signing_serialization_tests_sighash_json_83_494_161, 83, "test.skip: [signing-serialization tests] sighash.json 83/494 (#161)");
sighash_test!(signing_serialization_tests_sighash_json_84_494_164, 84, "test.skip: [signing-serialization tests] sighash.json 84/494 (#164)");
sighash_test!(signing_serialization_tests_sighash_json_85_494_165, 85, "test.skip: [signing-serialization tests] sighash.json 85/494 (#165)");
sighash_test!(signing_serialization_tests_sighash_json_86_494_167, 86, "test.skip: [signing-serialization tests] sighash.json 86/494 (#167)");
sighash_test!(signing_serialization_tests_sighash_json_87_494_169, 87, "test.skip: [signing-serialization tests] sighash.json 87/494 (#169)");
sighash_test!(signing_serialization_tests_sighash_json_88_494_170, 88, "test.skip: [signing-serialization tests] sighash.json 88/494 (#170)");
sighash_test!(signing_serialization_tests_sighash_json_89_494_176, 89, "test.skip: [signing-serialization tests] sighash.json 89/494 (#176)");
sighash_test!(signing_serialization_tests_sighash_json_90_494_177, 90, "test.skip: [signing-serialization tests] sighash.json 90/494 (#177)");
sighash_test!(signing_serialization_tests_sighash_json_91_494_179, 91, "test.skip: [signing-serialization tests] sighash.json 91/494 (#179)");
sighash_test!(signing_serialization_tests_sighash_json_92_494_184, 92, "test.skip: [signing-serialization tests] sighash.json 92/494 (#184)");
sighash_test!(signing_serialization_tests_sighash_json_93_494_187, 93, "test.skip: [signing-serialization tests] sighash.json 93/494 (#187)");
sighash_test!(signing_serialization_tests_sighash_json_94_494_188, 94, "test.skip: [signing-serialization tests] sighash.json 94/494 (#188)");
sighash_test!(signing_serialization_tests_sighash_json_95_494_190, 95, "test.skip: [signing-serialization tests] sighash.json 95/494 (#190)");
sighash_test!(signing_serialization_tests_sighash_json_96_494_191, 96, "test.skip: [signing-serialization tests] sighash.json 96/494 (#191)");
sighash_test!(signing_serialization_tests_sighash_json_97_494_194, 97, "test.skip: [signing-serialization tests] sighash.json 97/494 (#194)");
sighash_test!(signing_serialization_tests_sighash_json_98_494_195, 98, "test.skip: [signing-serialization tests] sighash.json 98/494 (#195)");
sighash_test!(signing_serialization_tests_sighash_json_99_494_198, 99, "test.skip: [signing-serialization tests] sighash.json 99/494 (#198)");
sighash_test!(signing_serialization_tests_sighash_json_100_494_200, 100, "test.skip: [signing-serialization tests] sighash.json 100/494 (#200)");
sighash_test!(signing_serialization_tests_sighash_json_101_494_201, 101, "test.skip: [signing-serialization tests] sighash.json 101/494 (#201)");
sighash_test!(signing_serialization_tests_sighash_json_102_494_204, 102, "test.skip: [signing-serialization tests] sighash.json 102/494 (#204)");
sighash_test!(signing_serialization_tests_sighash_json_103_494_207, 103, "test.skip: [signing-serialization tests] sighash.json 103/494 (#207)");
sighash_test!(signing_serialization_tests_sighash_json_104_494_208, 104, "test.skip: [signing-serialization tests] sighash.json 104/494 (#208)");
sighash_test!(signing_serialization_tests_sighash_json_105_494_211, 105, "test.skip: [signing-serialization tests] sighash.json 105/494 (#211)");
sighash_test!(signing_serialization_tests_sighash_json_106_494_212, 106, "test.skip: [signing-serialization tests] sighash.json 106/494 (#212)");
sighash_test!(signing_serialization_tests_sighash_json_107_494_213, 107, "test.skip: [signing-serialization tests] sighash.json 107/494 (#213)");
sighash_test!(signing_serialization_tests_sighash_json_108_494_215, 108, "test.skip: [signing-serialization tests] sighash.json 108/494 (#215)");
sighash_test!(signing_serialization_tests_sighash_json_109_494_217, 109, "test.skip: [signing-serialization tests] sighash.json 109/494 (#217)");
sighash_test!(signing_serialization_tests_sighash_json_110_494_218, 110, "test.skip: [signing-serialization tests] sighash.json 110/494 (#218)");
sighash_test!(signing_serialization_tests_sighash_json_111_494_219, 111, "test.skip: [signing-serialization tests] sighash.json 111/494 (#219)");
sighash_test!(signing_serialization_tests_sighash_json_112_494_220, 112, "test.skip: [signing-serialization tests] sighash.json 112/494 (#220)");
sighash_test!(signing_serialization_tests_sighash_json_113_494_221, 113, "test.skip: [signing-serialization tests] sighash.json 113/494 (#221)");
sighash_test!(signing_serialization_tests_sighash_json_114_494_222, 114, "test.skip: [signing-serialization tests] sighash.json 114/494 (#222)");
sighash_test!(signing_serialization_tests_sighash_json_115_494_223, 115, "test.skip: [signing-serialization tests] sighash.json 115/494 (#223)");
sighash_test!(signing_serialization_tests_sighash_json_116_494_226, 116, "test.skip: [signing-serialization tests] sighash.json 116/494 (#226)");
sighash_test!(signing_serialization_tests_sighash_json_117_494_230, 117, "test.skip: [signing-serialization tests] sighash.json 117/494 (#230)");
sighash_test!(signing_serialization_tests_sighash_json_118_494_231, 118, "test.skip: [signing-serialization tests] sighash.json 118/494 (#231)");
sighash_test!(signing_serialization_tests_sighash_json_119_494_235, 119, "test.skip: [signing-serialization tests] sighash.json 119/494 (#235)");
sighash_test!(signing_serialization_tests_sighash_json_120_494_236, 120, "test.skip: [signing-serialization tests] sighash.json 120/494 (#236)");
sighash_test!(signing_serialization_tests_sighash_json_121_494_238, 121, "test.skip: [signing-serialization tests] sighash.json 121/494 (#238)");
sighash_test!(signing_serialization_tests_sighash_json_122_494_241, 122, "test.skip: [signing-serialization tests] sighash.json 122/494 (#241)");
sighash_test!(signing_serialization_tests_sighash_json_123_494_242, 123, "test.skip: [signing-serialization tests] sighash.json 123/494 (#242)");
sighash_test!(signing_serialization_tests_sighash_json_124_494_243, 124, "test.skip: [signing-serialization tests] sighash.json 124/494 (#243)");
sighash_test!(signing_serialization_tests_sighash_json_125_494_246, 125, "test.skip: [signing-serialization tests] sighash.json 125/494 (#246)");
sighash_test!(signing_serialization_tests_sighash_json_126_494_247, 126, "test.skip: [signing-serialization tests] sighash.json 126/494 (#247)");
sighash_test!(signing_serialization_tests_sighash_json_127_494_250, 127, "test.skip: [signing-serialization tests] sighash.json 127/494 (#250)");
sighash_test!(signing_serialization_tests_sighash_json_128_494_254, 128, "test.skip: [signing-serialization tests] sighash.json 128/494 (#254)");
sighash_test!(signing_serialization_tests_sighash_json_129_494_257, 129, "test.skip: [signing-serialization tests] sighash.json 129/494 (#257)");
sighash_test!(signing_serialization_tests_sighash_json_130_494_258, 130, "test.skip: [signing-serialization tests] sighash.json 130/494 (#258)");
sighash_test!(signing_serialization_tests_sighash_json_131_494_259, 131, "test.skip: [signing-serialization tests] sighash.json 131/494 (#259)");
sighash_test!(signing_serialization_tests_sighash_json_132_494_263, 132, "test.skip: [signing-serialization tests] sighash.json 132/494 (#263)");
sighash_test!(signing_serialization_tests_sighash_json_133_494_264, 133, "test.skip: [signing-serialization tests] sighash.json 133/494 (#264)");
sighash_test!(signing_serialization_tests_sighash_json_134_494_265, 134, "test.skip: [signing-serialization tests] sighash.json 134/494 (#265)");
sighash_test!(signing_serialization_tests_sighash_json_135_494_266, 135, "test.skip: [signing-serialization tests] sighash.json 135/494 (#266)");
sighash_test!(signing_serialization_tests_sighash_json_136_494_267, 136, "test.skip: [signing-serialization tests] sighash.json 136/494 (#267)");
sighash_test!(signing_serialization_tests_sighash_json_137_494_268, 137, "test.skip: [signing-serialization tests] sighash.json 137/494 (#268)");
sighash_test!(signing_serialization_tests_sighash_json_138_494_269, 138, "test.skip: [signing-serialization tests] sighash.json 138/494 (#269)");
sighash_test!(signing_serialization_tests_sighash_json_139_494_270, 139, "test.skip: [signing-serialization tests] sighash.json 139/494 (#270)");
sighash_test!(signing_serialization_tests_sighash_json_140_494_272, 140, "test.skip: [signing-serialization tests] sighash.json 140/494 (#272)");
sighash_test!(signing_serialization_tests_sighash_json_141_494_277, 141, "test.skip: [signing-serialization tests] sighash.json 141/494 (#277)");
sighash_test!(signing_serialization_tests_sighash_json_142_494_279, 142, "test.skip: [signing-serialization tests] sighash.json 142/494 (#279)");
sighash_test!(signing_serialization_tests_sighash_json_143_494_280, 143, "test.skip: [signing-serialization tests] sighash.json 143/494 (#280)");
sighash_test!(signing_serialization_tests_sighash_json_144_494_281, 144, "test.skip: [signing-serialization tests] sighash.json 144/494 (#281)");
sighash_test!(signing_serialization_tests_sighash_json_145_494_282, 145, "test.skip: [signing-serialization tests] sighash.json 145/494 (#282)");
sighash_test!(signing_serialization_tests_sighash_json_146_494_284, 146, "test.skip: [signing-serialization tests] sighash.json 146/494 (#284)");
sighash_test!(signing_serialization_tests_sighash_json_147_494_287, 147, "test.skip: [signing-serialization tests] sighash.json 147/494 (#287)");
sighash_test!(signing_serialization_tests_sighash_json_148_494_290, 148, "test.skip: [signing-serialization tests] sighash.json 148/494 (#290)");
sighash_test!(signing_serialization_tests_sighash_json_149_494_292, 149, "test.skip: [signing-serialization tests] sighash.json 149/494 (#292)");
sighash_test!(signing_serialization_tests_sighash_json_150_494_298, 150, "test.skip: [signing-serialization tests] sighash.json 150/494 (#298)");
sighash_test!(signing_serialization_tests_sighash_json_151_494_299, 151, "test.skip: [signing-serialization tests] sighash.json 151/494 (#299)");
sighash_test!(signing_serialization_tests_sighash_json_152_494_300, 152, "test.skip: [signing-serialization tests] sighash.json 152/494 (#300)");
sighash_test!(signing_serialization_tests_sighash_json_153_494_302, 153, "test.skip: [signing-serialization tests] sighash.json 153/494 (#302)");
sighash_test!(signing_serialization_tests_sighash_json_154_494_305, 154, "test.skip: [signing-serialization tests] sighash.json 154/494 (#305)");
sighash_test!(signing_serialization_tests_sighash_json_155_494_310, 155, "test.skip: [signing-serialization tests] sighash.json 155/494 (#310)");
sighash_test!(signing_serialization_tests_sighash_json_156_494_311, 156, "test.skip: [signing-serialization tests] sighash.json 156/494 (#311)");
sighash_test!(signing_serialization_tests_sighash_json_157_494_312, 157, "test.skip: [signing-serialization tests] sighash.json 157/494 (#312)");
sighash_test!(signing_serialization_tests_sighash_json_158_494_313, 158, "test.skip: [signing-serialization tests] sighash.json 158/494 (#313)");
sighash_test!(signing_serialization_tests_sighash_json_159_494_314, 159, "test.skip: [signing-serialization tests] sighash.json 159/494 (#314)");
sighash_test!(signing_serialization_tests_sighash_json_160_494_315, 160, "test.skip: [signing-serialization tests] sighash.json 160/494 (#315)");
sighash_test!(signing_serialization_tests_sighash_json_161_494_318, 161, "test.skip: [signing-serialization tests] sighash.json 161/494 (#318)");
sighash_test!(signing_serialization_tests_sighash_json_162_494_321, 162, "test.skip: [signing-serialization tests] sighash.json 162/494 (#321)");
sighash_test!(signing_serialization_tests_sighash_json_163_494_330, 163, "test.skip: [signing-serialization tests] sighash.json 163/494 (#330)");
sighash_test!(signing_serialization_tests_sighash_json_164_494_332, 164, "test.skip: [signing-serialization tests] sighash.json 164/494 (#332)");
sighash_test!(signing_serialization_tests_sighash_json_165_494_333, 165, "test.skip: [signing-serialization tests] sighash.json 165/494 (#333)");
sighash_test!(signing_serialization_tests_sighash_json_166_494_335, 166, "test.skip: [signing-serialization tests] sighash.json 166/494 (#335)");
sighash_test!(signing_serialization_tests_sighash_json_167_494_338, 167, "test.skip: [signing-serialization tests] sighash.json 167/494 (#338)");
sighash_test!(signing_serialization_tests_sighash_json_168_494_339, 168, "test.skip: [signing-serialization tests] sighash.json 168/494 (#339)");
sighash_test!(signing_serialization_tests_sighash_json_169_494_340, 169, "test.skip: [signing-serialization tests] sighash.json 169/494 (#340)");
sighash_test!(signing_serialization_tests_sighash_json_170_494_341, 170, "test.skip: [signing-serialization tests] sighash.json 170/494 (#341)");
sighash_test!(signing_serialization_tests_sighash_json_171_494_342, 171, "test.skip: [signing-serialization tests] sighash.json 171/494 (#342)");
sighash_test!(signing_serialization_tests_sighash_json_172_494_343, 172, "test.skip: [signing-serialization tests] sighash.json 172/494 (#343)");
sighash_test!(signing_serialization_tests_sighash_json_173_494_345, 173, "test.skip: [signing-serialization tests] sighash.json 173/494 (#345)");
sighash_test!(signing_serialization_tests_sighash_json_174_494_348, 174, "test.skip: [signing-serialization tests] sighash.json 174/494 (#348)");
sighash_test!(signing_serialization_tests_sighash_json_175_494_349, 175, "test.skip: [signing-serialization tests] sighash.json 175/494 (#349)");
sighash_test!(signing_serialization_tests_sighash_json_176_494_351, 176, "test.skip: [signing-serialization tests] sighash.json 176/494 (#351)");
sighash_test!(signing_serialization_tests_sighash_json_177_494_352, 177, "test.skip: [signing-serialization tests] sighash.json 177/494 (#352)");
sighash_test!(signing_serialization_tests_sighash_json_178_494_353, 178, "test.skip: [signing-serialization tests] sighash.json 178/494 (#353)");
sighash_test!(signing_serialization_tests_sighash_json_179_494_354, 179, "test.skip: [signing-serialization tests] sighash.json 179/494 (#354)");
sighash_test!(signing_serialization_tests_sighash_json_180_494_355, 180, "test.skip: [signing-serialization tests] sighash.json 180/494 (#355)");
sighash_test!(signing_serialization_tests_sighash_json_181_494_356, 181, "test.skip: [signing-serialization tests] sighash.json 181/494 (#356)");
sighash_test!(signing_serialization_tests_sighash_json_182_494_357, 182, "test.skip: [signing-serialization tests] sighash.json 182/494 (#357)");
sighash_test!(signing_serialization_tests_sighash_json_183_494_360, 183, "test.skip: [signing-serialization tests] sighash.json 183/494 (#360)");
sighash_test!(signing_serialization_tests_sighash_json_184_494_362, 184, "test.skip: [signing-serialization tests] sighash.json 184/494 (#362)");
sighash_test!(signing_serialization_tests_sighash_json_185_494_363, 185, "test.skip: [signing-serialization tests] sighash.json 185/494 (#363)");
sighash_test!(signing_serialization_tests_sighash_json_186_494_364, 186, "test.skip: [signing-serialization tests] sighash.json 186/494 (#364)");
sighash_test!(signing_serialization_tests_sighash_json_187_494_365, 187, "test.skip: [signing-serialization tests] sighash.json 187/494 (#365)");
sighash_test!(signing_serialization_tests_sighash_json_188_494_366, 188, "test.skip: [signing-serialization tests] sighash.json 188/494 (#366)");
sighash_test!(signing_serialization_tests_sighash_json_189_494_370, 189, "test.skip: [signing-serialization tests] sighash.json 189/494 (#370)");
sighash_test!(signing_serialization_tests_sighash_json_190_494_374, 190, "test.skip: [signing-serialization tests] sighash.json 190/494 (#374)");
sighash_test!(signing_serialization_tests_sighash_json_191_494_377, 191, "test.skip: [signing-serialization tests] sighash.json 191/494 (#377)");
sighash_test!(signing_serialization_tests_sighash_json_192_494_378, 192, "test.skip: [signing-serialization tests] sighash.json 192/494 (#378)");
sighash_test!(signing_serialization_tests_sighash_json_193_494_379, 193, "test.skip: [signing-serialization tests] sighash.json 193/494 (#379)");
sighash_test!(signing_serialization_tests_sighash_json_194_494_380, 194, "test.skip: [signing-serialization tests] sighash.json 194/494 (#380)");
sighash_test!(signing_serialization_tests_sighash_json_195_494_381, 195, "test.skip: [signing-serialization tests] sighash.json 195/494 (#381)");
sighash_test!(signing_serialization_tests_sighash_json_196_494_382, 196, "test.skip: [signing-serialization tests] sighash.json 196/494 (#382)");
sighash_test!(signing_serialization_tests_sighash_json_197_494_383, 197, "test.skip: [signing-serialization tests] sighash.json 197/494 (#383)");
sighash_test!(signing_serialization_tests_sighash_json_198_494_385, 198, "test.skip: [signing-serialization tests] sighash.json 198/494 (#385)");
sighash_test!(signing_serialization_tests_sighash_json_199_494_394, 199, "test.skip: [signing-serialization tests] sighash.json 199/494 (#394)");
sighash_test!(signing_serialization_tests_sighash_json_200_494_397, 200, "test.skip: [signing-serialization tests] sighash.json 200/494 (#397)");
sighash_test!(signing_serialization_tests_sighash_json_201_494_398, 201, "test.skip: [signing-serialization tests] sighash.json 201/494 (#398)");
sighash_test!(signing_serialization_tests_sighash_json_202_494_399, 202, "test.skip: [signing-serialization tests] sighash.json 202/494 (#399)");
sighash_test!(signing_serialization_tests_sighash_json_203_494_403, 203, "test.skip: [signing-serialization tests] sighash.json 203/494 (#403)");
sighash_test!(signing_serialization_tests_sighash_json_204_494_404, 204, "test.skip: [signing-serialization tests] sighash.json 204/494 (#404)");
sighash_test!(signing_serialization_tests_sighash_json_205_494_405, 205, "test.skip: [signing-serialization tests] sighash.json 205/494 (#405)");
sighash_test!(signing_serialization_tests_sighash_json_206_494_407, 206, "test.skip: [signing-serialization tests] sighash.json 206/494 (#407)");
sighash_test!(signing_serialization_tests_sighash_json_207_494_408, 207, "test.skip: [signing-serialization tests] sighash.json 207/494 (#408)");
sighash_test!(signing_serialization_tests_sighash_json_208_494_410, 208, "test.skip: [signing-serialization tests] sighash.json 208/494 (#410)");
sighash_test!(signing_serialization_tests_sighash_json_209_494_412, 209, "test.skip: [signing-serialization tests] sighash.json 209/494 (#412)");
sighash_test!(signing_serialization_tests_sighash_json_210_494_413, 210, "test.skip: [signing-serialization tests] sighash.json 210/494 (#413)");
sighash_test!(signing_serialization_tests_sighash_json_211_494_414, 211, "test.skip: [signing-serialization tests] sighash.json 211/494 (#414)");
sighash_test!(signing_serialization_tests_sighash_json_212_494_415, 212, "test.skip: [signing-serialization tests] sighash.json 212/494 (#415)");
sighash_test!(signing_serialization_tests_sighash_json_213_494_416, 213, "test.skip: [signing-serialization tests] sighash.json 213/494 (#416)");
sighash_test!(signing_serialization_tests_sighash_json_214_494_417, 214, "test.skip: [signing-serialization tests] sighash.json 214/494 (#417)");
sighash_test!(signing_serialization_tests_sighash_json_215_494_418, 215, "test.skip: [signing-serialization tests] sighash.json 215/494 (#418)");
sighash_test!(signing_serialization_tests_sighash_json_216_494_419, 216, "test.skip: [signing-serialization tests] sighash.json 216/494 (#419)");
sighash_test!(signing_serialization_tests_sighash_json_217_494_422, 217, "test.skip: [signing-serialization tests] sighash.json 217/494 (#422)");
sighash_test!(signing_serialization_tests_sighash_json_218_494_423, 218, "test.skip: [signing-serialization tests] sighash.json 218/494 (#423)");
sighash_test!(signing_serialization_tests_sighash_json_219_494_424, 219, "test.skip: [signing-serialization tests] sighash.json 219/494 (#424)");
sighash_test!(signing_serialization_tests_sighash_json_220_494_427, 220, "test.skip: [signing-serialization tests] sighash.json 220/494 (#427)");
sighash_test!(signing_serialization_tests_sighash_json_221_494_430, 221, "test.skip: [signing-serialization tests] sighash.json 221/494 (#430)");
sighash_test!(signing_serialization_tests_sighash_json_222_494_431, 222, "test.skip: [signing-serialization tests] sighash.json 222/494 (#431)");
sighash_test!(signing_serialization_tests_sighash_json_223_494_434, 223, "test.skip: [signing-serialization tests] sighash.json 223/494 (#434)");
sighash_test!(signing_serialization_tests_sighash_json_224_494_437, 224, "test.skip: [signing-serialization tests] sighash.json 224/494 (#437)");
sighash_test!(signing_serialization_tests_sighash_json_225_494_442, 225, "test.skip: [signing-serialization tests] sighash.json 225/494 (#442)");
sighash_test!(signing_serialization_tests_sighash_json_226_494_443, 226, "test.skip: [signing-serialization tests] sighash.json 226/494 (#443)");
sighash_test!(signing_serialization_tests_sighash_json_227_494_451, 227, "test.skip: [signing-serialization tests] sighash.json 227/494 (#451)");
sighash_test!(signing_serialization_tests_sighash_json_228_494_454, 228, "test.skip: [signing-serialization tests] sighash.json 228/494 (#454)");
sighash_test!(signing_serialization_tests_sighash_json_229_494_456, 229, "test.skip: [signing-serialization tests] sighash.json 229/494 (#456)");
sighash_test!(signing_serialization_tests_sighash_json_230_494_460, 230, "test.skip: [signing-serialization tests] sighash.json 230/494 (#460)");
sighash_test!(signing_serialization_tests_sighash_json_231_494_463, 231, "test.skip: [signing-serialization tests] sighash.json 231/494 (#463)");
sighash_test!(signing_serialization_tests_sighash_json_232_494_466, 232, "test.skip: [signing-serialization tests] sighash.json 232/494 (#466)");
sighash_test!(signing_serialization_tests_sighash_json_233_494_469, 233, "test.skip: [signing-serialization tests] sighash.json 233/494 (#469)");
sighash_test!(signing_serialization_tests_sighash_json_234_494_471, 234, "test.skip: [signing-serialization tests] sighash.json 234/494 (#471)");
sighash_test!(signing_serialization_tests_sighash_json_235_494_474, 235, "test.skip: [signing-serialization tests] sighash.json 235/494 (#474)");
sighash_test!(signing_serialization_tests_sighash_json_236_494_475, 236, "test.skip: [signing-serialization tests] sighash.json 236/494 (#475)");
sighash_test!(signing_serialization_tests_sighash_json_237_494_476, 237, "test.skip: [signing-serialization tests] sighash.json 237/494 (#476)");
sighash_test!(signing_serialization_tests_sighash_json_238_494_478, 238, "test.skip: [signing-serialization tests] sighash.json 238/494 (#478)");
sighash_test!(signing_serialization_tests_sighash_json_239_494_479, 239, "test.skip: [signing-serialization tests] sighash.json 239/494 (#479)");
sighash_test!(signing_serialization_tests_sighash_json_240_494_481, 240, "test.skip: [signing-serialization tests] sighash.json 240/494 (#481)");
sighash_test!(signing_serialization_tests_sighash_json_241_494_484, 241, "test.skip: [signing-serialization tests] sighash.json 241/494 (#484)");
sighash_test!(signing_serialization_tests_sighash_json_242_494_487, 242, "test.skip: [signing-serialization tests] sighash.json 242/494 (#487)");
sighash_test!(signing_serialization_tests_sighash_json_243_494_490, 243, "test.skip: [signing-serialization tests] sighash.json 243/494 (#490)");
sighash_test!(signing_serialization_tests_sighash_json_244_494_491, 244, "test.skip: [signing-serialization tests] sighash.json 244/494 (#491)");
sighash_test!(signing_serialization_tests_sighash_json_245_494_492, 245, "test.skip: [signing-serialization tests] sighash.json 245/494 (#492)");
sighash_test!(signing_serialization_tests_sighash_json_246_494_497, 246, "test.skip: [signing-serialization tests] sighash.json 246/494 (#497)");
sighash_test!(signing_serialization_tests_sighash_json_247_494_498, 247, "test.skip: [signing-serialization tests] sighash.json 247/494 (#498)");
sighash_test!(signing_serialization_tests_sighash_json_248_494_499, 248, "test.skip: [signing-serialization tests] sighash.json 248/494 (#499)");
sighash_test!(signing_serialization_tests_sighash_json_249_494_502, 249, "test.skip: [signing-serialization tests] sighash.json 249/494 (#502)");
sighash_test!(signing_serialization_tests_sighash_json_250_494_503, 250, "test.skip: [signing-serialization tests] sighash.json 250/494 (#503)");
sighash_test!(signing_serialization_tests_sighash_json_251_494_505, 251, "test.skip: [signing-serialization tests] sighash.json 251/494 (#505)");
sighash_test!(signing_serialization_tests_sighash_json_252_494_506, 252, "test.skip: [signing-serialization tests] sighash.json 252/494 (#506)");
sighash_test!(signing_serialization_tests_sighash_json_253_494_507, 253, "test.skip: [signing-serialization tests] sighash.json 253/494 (#507)");
sighash_test!(signing_serialization_tests_sighash_json_254_494_508, 254, "test.skip: [signing-serialization tests] sighash.json 254/494 (#508)");
sighash_test!(signing_serialization_tests_sighash_json_255_494_509, 255, "test.skip: [signing-serialization tests] sighash.json 255/494 (#509)");
sighash_test!(signing_serialization_tests_sighash_json_256_494_512, 256, "test.skip: [signing-serialization tests] sighash.json 256/494 (#512)");
sighash_test!(signing_serialization_tests_sighash_json_257_494_513, 257, "test.skip: [signing-serialization tests] sighash.json 257/494 (#513)");
sighash_test!(signing_serialization_tests_sighash_json_258_494_514, 258, "test.skip: [signing-serialization tests] sighash.json 258/494 (#514)");
sighash_test!(signing_serialization_tests_sighash_json_259_494_515, 259, "test.skip: [signing-serialization tests] sighash.json 259/494 (#515)");
sighash_test!(signing_serialization_tests_sighash_json_260_494_516, 260, "test.skip: [signing-serialization tests] sighash.json 260/494 (#516)");
sighash_test!(signing_serialization_tests_sighash_json_261_494_518, 261, "test.skip: [signing-serialization tests] sighash.json 261/494 (#518)");
sighash_test!(signing_serialization_tests_sighash_json_262_494_519, 262, "test.skip: [signing-serialization tests] sighash.json 262/494 (#519)");
sighash_test!(signing_serialization_tests_sighash_json_263_494_520, 263, "test.skip: [signing-serialization tests] sighash.json 263/494 (#520)");
sighash_test!(signing_serialization_tests_sighash_json_264_494_522, 264, "test.skip: [signing-serialization tests] sighash.json 264/494 (#522)");
sighash_test!(signing_serialization_tests_sighash_json_265_494_524, 265, "test.skip: [signing-serialization tests] sighash.json 265/494 (#524)");
sighash_test!(signing_serialization_tests_sighash_json_266_494_525, 266, "test.skip: [signing-serialization tests] sighash.json 266/494 (#525)");
sighash_test!(signing_serialization_tests_sighash_json_267_494_526, 267, "test.skip: [signing-serialization tests] sighash.json 267/494 (#526)");
sighash_test!(signing_serialization_tests_sighash_json_268_494_531, 268, "test.skip: [signing-serialization tests] sighash.json 268/494 (#531)");
sighash_test!(signing_serialization_tests_sighash_json_269_494_532, 269, "test.skip: [signing-serialization tests] sighash.json 269/494 (#532)");
sighash_test!(signing_serialization_tests_sighash_json_270_494_533, 270, "test.skip: [signing-serialization tests] sighash.json 270/494 (#533)");
sighash_test!(signing_serialization_tests_sighash_json_271_494_534, 271, "test.skip: [signing-serialization tests] sighash.json 271/494 (#534)");
sighash_test!(signing_serialization_tests_sighash_json_272_494_540, 272, "test.skip: [signing-serialization tests] sighash.json 272/494 (#540)");
sighash_test!(signing_serialization_tests_sighash_json_273_494_541, 273, "test.skip: [signing-serialization tests] sighash.json 273/494 (#541)");
sighash_test!(signing_serialization_tests_sighash_json_274_494_543, 274, "test.skip: [signing-serialization tests] sighash.json 274/494 (#543)");
sighash_test!(signing_serialization_tests_sighash_json_275_494_544, 275, "test.skip: [signing-serialization tests] sighash.json 275/494 (#544)");
sighash_test!(signing_serialization_tests_sighash_json_276_494_545, 276, "test.skip: [signing-serialization tests] sighash.json 276/494 (#545)");
sighash_test!(signing_serialization_tests_sighash_json_277_494_548, 277, "test.skip: [signing-serialization tests] sighash.json 277/494 (#548)");
sighash_test!(signing_serialization_tests_sighash_json_278_494_549, 278, "test.skip: [signing-serialization tests] sighash.json 278/494 (#549)");
sighash_test!(signing_serialization_tests_sighash_json_279_494_550, 279, "test.skip: [signing-serialization tests] sighash.json 279/494 (#550)");
sighash_test!(signing_serialization_tests_sighash_json_280_494_553, 280, "test.skip: [signing-serialization tests] sighash.json 280/494 (#553)");
sighash_test!(signing_serialization_tests_sighash_json_281_494_554, 281, "test.skip: [signing-serialization tests] sighash.json 281/494 (#554)");
sighash_test!(signing_serialization_tests_sighash_json_282_494_557, 282, "test.skip: [signing-serialization tests] sighash.json 282/494 (#557)");
sighash_test!(signing_serialization_tests_sighash_json_283_494_560, 283, "test.skip: [signing-serialization tests] sighash.json 283/494 (#560)");
sighash_test!(signing_serialization_tests_sighash_json_284_494_561, 284, "test.skip: [signing-serialization tests] sighash.json 284/494 (#561)");
sighash_test!(signing_serialization_tests_sighash_json_285_494_562, 285, "test.skip: [signing-serialization tests] sighash.json 285/494 (#562)");
sighash_test!(signing_serialization_tests_sighash_json_286_494_563, 286, "test.skip: [signing-serialization tests] sighash.json 286/494 (#563)");
sighash_test!(signing_serialization_tests_sighash_json_287_494_564, 287, "test.skip: [signing-serialization tests] sighash.json 287/494 (#564)");
sighash_test!(signing_serialization_tests_sighash_json_288_494_566, 288, "test.skip: [signing-serialization tests] sighash.json 288/494 (#566)");
sighash_test!(signing_serialization_tests_sighash_json_289_494_568, 289, "test.skip: [signing-serialization tests] sighash.json 289/494 (#568)");
sighash_test!(signing_serialization_tests_sighash_json_290_494_570, 290, "test.skip: [signing-serialization tests] sighash.json 290/494 (#570)");
sighash_test!(signing_serialization_tests_sighash_json_291_494_572, 291, "test.skip: [signing-serialization tests] sighash.json 291/494 (#572)");
sighash_test!(signing_serialization_tests_sighash_json_292_494_574, 292, "test.skip: [signing-serialization tests] sighash.json 292/494 (#574)");
sighash_test!(signing_serialization_tests_sighash_json_293_494_575, 293, "test.skip: [signing-serialization tests] sighash.json 293/494 (#575)");
sighash_test!(signing_serialization_tests_sighash_json_294_494_579, 294, "test.skip: [signing-serialization tests] sighash.json 294/494 (#579)");
sighash_test!(signing_serialization_tests_sighash_json_295_494_581, 295, "test.skip: [signing-serialization tests] sighash.json 295/494 (#581)");
sighash_test!(signing_serialization_tests_sighash_json_296_494_584, 296, "test.skip: [signing-serialization tests] sighash.json 296/494 (#584)");
sighash_test!(signing_serialization_tests_sighash_json_297_494_586, 297, "test.skip: [signing-serialization tests] sighash.json 297/494 (#586)");
sighash_test!(signing_serialization_tests_sighash_json_298_494_587, 298, "test.skip: [signing-serialization tests] sighash.json 298/494 (#587)");
sighash_test!(signing_serialization_tests_sighash_json_299_494_589, 299, "test.skip: [signing-serialization tests] sighash.json 299/494 (#589)");
sighash_test!(signing_serialization_tests_sighash_json_300_494_590, 300, "test.skip: [signing-serialization tests] sighash.json 300/494 (#590)");
sighash_test!(signing_serialization_tests_sighash_json_301_494_591, 301, "test.skip: [signing-serialization tests] sighash.json 301/494 (#591)");
sighash_test!(signing_serialization_tests_sighash_json_302_494_592, 302, "test.skip: [signing-serialization tests] sighash.json 302/494 (#592)");
sighash_test!(signing_serialization_tests_sighash_json_303_494_595, 303, "test.skip: [signing-serialization tests] sighash.json 303/494 (#595)");
sighash_test!(signing_serialization_tests_sighash_json_304_494_599, 304, "test.skip: [signing-serialization tests] sighash.json 304/494 (#599)");
sighash_test!(signing_serialization_tests_sighash_json_305_494_601, 305, "test.skip: [signing-serialization tests] sighash.json 305/494 (#601)");
sighash_test!(signing_serialization_tests_sighash_json_306_494_602, 306, "test.skip: [signing-serialization tests] sighash.json 306/494 (#602)");
sighash_test!(signing_serialization_tests_sighash_json_307_494_606, 307, "test.skip: [signing-serialization tests] sighash.json 307/494 (#606)");
sighash_test!(signing_serialization_tests_sighash_json_308_494_608, 308, "test.skip: [signing-serialization tests] sighash.json 308/494 (#608)");
sighash_test!(signing_serialization_tests_sighash_json_309_494_609, 309, "test.skip: [signing-serialization tests] sighash.json 309/494 (#609)");
sighash_test!(signing_serialization_tests_sighash_json_310_494_610, 310, "test.skip: [signing-serialization tests] sighash.json 310/494 (#610)");
sighash_test!(signing_serialization_tests_sighash_json_311_494_613, 311, "test.skip: [signing-serialization tests] sighash.json 311/494 (#613)");
sighash_test!(signing_serialization_tests_sighash_json_312_494_616, 312, "test.skip: [signing-serialization tests] sighash.json 312/494 (#616)");
sighash_test!(signing_serialization_tests_sighash_json_313_494_619, 313, "test.skip: [signing-serialization tests] sighash.json 313/494 (#619)");
sighash_test!(signing_serialization_tests_sighash_json_314_494_621, 314, "test.skip: [signing-serialization tests] sighash.json 314/494 (#621)");
sighash_test!(signing_serialization_tests_sighash_json_315_494_622, 315, "test.skip: [signing-serialization tests] sighash.json 315/494 (#622)");
sighash_test!(signing_serialization_tests_sighash_json_316_494_626, 316, "test.skip: [signing-serialization tests] sighash.json 316/494 (#626)");
sighash_test!(signing_serialization_tests_sighash_json_317_494_631, 317, "test.skip: [signing-serialization tests] sighash.json 317/494 (#631)");
sighash_test!(signing_serialization_tests_sighash_json_318_494_632, 318, "test.skip: [signing-serialization tests] sighash.json 318/494 (#632)");
sighash_test!(signing_serialization_tests_sighash_json_319_494_637, 319, "test.skip: [signing-serialization tests] sighash.json 319/494 (#637)");
sighash_test!(signing_serialization_tests_sighash_json_320_494_640, 320, "test.skip: [signing-serialization tests] sighash.json 320/494 (#640)");
sighash_test!(signing_serialization_tests_sighash_json_321_494_641, 321, "test.skip: [signing-serialization tests] sighash.json 321/494 (#641)");
sighash_test!(signing_serialization_tests_sighash_json_322_494_644, 322, "test.skip: [signing-serialization tests] sighash.json 322/494 (#644)");
sighash_test!(signing_serialization_tests_sighash_json_323_494_645, 323, "test.skip: [signing-serialization tests] sighash.json 323/494 (#645)");
sighash_test!(signing_serialization_tests_sighash_json_324_494_646, 324, "test.skip: [signing-serialization tests] sighash.json 324/494 (#646)");
sighash_test!(signing_serialization_tests_sighash_json_325_494_648, 325, "test.skip: [signing-serialization tests] sighash.json 325/494 (#648)");
sighash_test!(signing_serialization_tests_sighash_json_326_494_649, 326, "test.skip: [signing-serialization tests] sighash.json 326/494 (#649)");
sighash_test!(signing_serialization_tests_sighash_json_327_494_650, 327, "test.skip: [signing-serialization tests] sighash.json 327/494 (#650)");
sighash_test!(signing_serialization_tests_sighash_json_328_494_651, 328, "test.skip: [signing-serialization tests] sighash.json 328/494 (#651)");
sighash_test!(signing_serialization_tests_sighash_json_329_494_654, 329, "test.skip: [signing-serialization tests] sighash.json 329/494 (#654)");
sighash_test!(signing_serialization_tests_sighash_json_330_494_655, 330, "test.skip: [signing-serialization tests] sighash.json 330/494 (#655)");
sighash_test!(signing_serialization_tests_sighash_json_331_494_656, 331, "test.skip: [signing-serialization tests] sighash.json 331/494 (#656)");
sighash_test!(signing_serialization_tests_sighash_json_332_494_657, 332, "test.skip: [signing-serialization tests] sighash.json 332/494 (#657)");
sighash_test!(signing_serialization_tests_sighash_json_333_494_660, 333, "test.skip: [signing-serialization tests] sighash.json 333/494 (#660)");
sighash_test!(signing_serialization_tests_sighash_json_334_494_664, 334, "test.skip: [signing-serialization tests] sighash.json 334/494 (#664)");
sighash_test!(signing_serialization_tests_sighash_json_335_494_665, 335, "test.skip: [signing-serialization tests] sighash.json 335/494 (#665)");
sighash_test!(signing_serialization_tests_sighash_json_336_494_668, 336, "test.skip: [signing-serialization tests] sighash.json 336/494 (#668)");
sighash_test!(signing_serialization_tests_sighash_json_337_494_671, 337, "test.skip: [signing-serialization tests] sighash.json 337/494 (#671)");
sighash_test!(signing_serialization_tests_sighash_json_338_494_672, 338, "test.skip: [signing-serialization tests] sighash.json 338/494 (#672)");
sighash_test!(signing_serialization_tests_sighash_json_339_494_675, 339, "test.skip: [signing-serialization tests] sighash.json 339/494 (#675)");
sighash_test!(signing_serialization_tests_sighash_json_340_494_677, 340, "test.skip: [signing-serialization tests] sighash.json 340/494 (#677)");
sighash_test!(signing_serialization_tests_sighash_json_341_494_678, 341, "test.skip: [signing-serialization tests] sighash.json 341/494 (#678)");
sighash_test!(signing_serialization_tests_sighash_json_342_494_679, 342, "test.skip: [signing-serialization tests] sighash.json 342/494 (#679)");
sighash_test!(signing_serialization_tests_sighash_json_343_494_680, 343, "test.skip: [signing-serialization tests] sighash.json 343/494 (#680)");
sighash_test!(signing_serialization_tests_sighash_json_344_494_681, 344, "test.skip: [signing-serialization tests] sighash.json 344/494 (#681)");
sighash_test!(signing_serialization_tests_sighash_json_345_494_683, 345, "test.skip: [signing-serialization tests] sighash.json 345/494 (#683)");
sighash_test!(signing_serialization_tests_sighash_json_346_494_684, 346, "test.skip: [signing-serialization tests] sighash.json 346/494 (#684)");
sighash_test!(signing_serialization_tests_sighash_json_347_494_686, 347, "test.skip: [signing-serialization tests] sighash.json 347/494 (#686)");
sighash_test!(signing_serialization_tests_sighash_json_348_494_690, 348, "test.skip: [signing-serialization tests] sighash.json 348/494 (#690)");
sighash_test!(signing_serialization_tests_sighash_json_349_494_691, 349, "test.skip: [signing-serialization tests] sighash.json 349/494 (#691)");
sighash_test!(signing_serialization_tests_sighash_json_350_494_692, 350, "test.skip: [signing-serialization tests] sighash.json 350/494 (#692)");
sighash_test!(signing_serialization_tests_sighash_json_351_494_695, 351, "test.skip: [signing-serialization tests] sighash.json 351/494 (#695)");
sighash_test!(signing_serialization_tests_sighash_json_352_494_696, 352, "test.skip: [signing-serialization tests] sighash.json 352/494 (#696)");
sighash_test!(signing_serialization_tests_sighash_json_353_494_699, 353, "test.skip: [signing-serialization tests] sighash.json 353/494 (#699)");
sighash_test!(signing_serialization_tests_sighash_json_354_494_701, 354, "test.skip: [signing-serialization tests] sighash.json 354/494 (#701)");
sighash_test!(signing_serialization_tests_sighash_json_355_494_703, 355, "test.skip: [signing-serialization tests] sighash.json 355/494 (#703)");
sighash_test!(signing_serialization_tests_sighash_json_356_494_704, 356, "test.skip: [signing-serialization tests] sighash.json 356/494 (#704)");
sighash_test!(signing_serialization_tests_sighash_json_357_494_705, 357, "test.skip: [signing-serialization tests] sighash.json 357/494 (#705)");
sighash_test!(signing_serialization_tests_sighash_json_358_494_707, 358, "test.skip: [signing-serialization tests] sighash.json 358/494 (#707)");
sighash_test!(signing_serialization_tests_sighash_json_359_494_710, 359, "test.skip: [signing-serialization tests] sighash.json 359/494 (#710)");
sighash_test!(signing_serialization_tests_sighash_json_360_494_711, 360, "test.skip: [signing-serialization tests] sighash.json 360/494 (#711)");
sighash_test!(signing_serialization_tests_sighash_json_361_494_712, 361, "test.skip: [signing-serialization tests] sighash.json 361/494 (#712)");
sighash_test!(signing_serialization_tests_sighash_json_362_494_716, 362, "test.skip: [signing-serialization tests] sighash.json 362/494 (#716)");
sighash_test!(signing_serialization_tests_sighash_json_363_494_718, 363, "test.skip: [signing-serialization tests] sighash.json 363/494 (#718)");
sighash_test!(signing_serialization_tests_sighash_json_364_494_719, 364, "test.skip: [signing-serialization tests] sighash.json 364/494 (#719)");
sighash_test!(signing_serialization_tests_sighash_json_365_494_720, 365, "test.skip: [signing-serialization tests] sighash.json 365/494 (#720)");
sighash_test!(signing_serialization_tests_sighash_json_366_494_721, 366, "test.skip: [signing-serialization tests] sighash.json 366/494 (#721)");
sighash_test!(signing_serialization_tests_sighash_json_367_494_725, 367, "test.skip: [signing-serialization tests] sighash.json 367/494 (#725)");
sighash_test!(signing_serialization_tests_sighash_json_368_494_726, 368, "test.skip: [signing-serialization tests] sighash.json 368/494 (#726)");
sighash_test!(signing_serialization_tests_sighash_json_369_494_728, 369, "test.skip: [signing-serialization tests] sighash.json 369/494 (#728)");
sighash_test!(signing_serialization_tests_sighash_json_370_494_735, 370, "test.skip: [signing-serialization tests] sighash.json 370/494 (#735)");
sighash_test!(signing_serialization_tests_sighash_json_371_494_736, 371, "test.skip: [signing-serialization tests] sighash.json 371/494 (#736)");
sighash_test!(signing_serialization_tests_sighash_json_372_494_738, 372, "test.skip: [signing-serialization tests] sighash.json 372/494 (#738)");
sighash_test!(signing_serialization_tests_sighash_json_373_494_740, 373, "test.skip: [signing-serialization tests] sighash.json 373/494 (#740)");
sighash_test!(signing_serialization_tests_sighash_json_374_494_744, 374, "test.skip: [signing-serialization tests] sighash.json 374/494 (#744)");
sighash_test!(signing_serialization_tests_sighash_json_375_494_746, 375, "test.skip: [signing-serialization tests] sighash.json 375/494 (#746)");
sighash_test!(signing_serialization_tests_sighash_json_376_494_748, 376, "test.skip: [signing-serialization tests] sighash.json 376/494 (#748)");
sighash_test!(signing_serialization_tests_sighash_json_377_494_749, 377, "test.skip: [signing-serialization tests] sighash.json 377/494 (#749)");
sighash_test!(signing_serialization_tests_sighash_json_378_494_752, 378, "test.skip: [signing-serialization tests] sighash.json 378/494 (#752)");
sighash_test!(signing_serialization_tests_sighash_json_379_494_753, 379, "test.skip: [signing-serialization tests] sighash.json 379/494 (#753)");
sighash_test!(signing_serialization_tests_sighash_json_380_494_754, 380, "test.skip: [signing-serialization tests] sighash.json 380/494 (#754)");
sighash_test!(signing_serialization_tests_sighash_json_381_494_759, 381, "test.skip: [signing-serialization tests] sighash.json 381/494 (#759)");
sighash_test!(signing_serialization_tests_sighash_json_382_494_761, 382, "test.skip: [signing-serialization tests] sighash.json 382/494 (#761)");
sighash_test!(signing_serialization_tests_sighash_json_383_494_762, 383, "test.skip: [signing-serialization tests] sighash.json 383/494 (#762)");
sighash_test!(signing_serialization_tests_sighash_json_384_494_765, 384, "test.skip: [signing-serialization tests] sighash.json 384/494 (#765)");
sighash_test!(signing_serialization_tests_sighash_json_385_494_767, 385, "test.skip: [signing-serialization tests] sighash.json 385/494 (#767)");
sighash_test!(signing_serialization_tests_sighash_json_386_494_768, 386, "test.skip: [signing-serialization tests] sighash.json 386/494 (#768)");
sighash_test!(signing_serialization_tests_sighash_json_387_494_773, 387, "test.skip: [signing-serialization tests] sighash.json 387/494 (#773)");
sighash_test!(signing_serialization_tests_sighash_json_388_494_774, 388, "test.skip: [signing-serialization tests] sighash.json 388/494 (#774)");
sighash_test!(signing_serialization_tests_sighash_json_389_494_775, 389, "test.skip: [signing-serialization tests] sighash.json 389/494 (#775)");
sighash_test!(signing_serialization_tests_sighash_json_390_494_779, 390, "test.skip: [signing-serialization tests] sighash.json 390/494 (#779)");
sighash_test!(signing_serialization_tests_sighash_json_391_494_783, 391, "test.skip: [signing-serialization tests] sighash.json 391/494 (#783)");
sighash_test!(signing_serialization_tests_sighash_json_392_494_786, 392, "test.skip: [signing-serialization tests] sighash.json 392/494 (#786)");
sighash_test!(signing_serialization_tests_sighash_json_393_494_787, 393, "test.skip: [signing-serialization tests] sighash.json 393/494 (#787)");
sighash_test!(signing_serialization_tests_sighash_json_394_494_788, 394, "test.skip: [signing-serialization tests] sighash.json 394/494 (#788)");
sighash_test!(signing_serialization_tests_sighash_json_395_494_790, 395, "test.skip: [signing-serialization tests] sighash.json 395/494 (#790)");
sighash_test!(signing_serialization_tests_sighash_json_396_494_793, 396, "test.skip: [signing-serialization tests] sighash.json 396/494 (#793)");
sighash_test!(signing_serialization_tests_sighash_json_397_494_794, 397, "test.skip: [signing-serialization tests] sighash.json 397/494 (#794)");
sighash_test!(signing_serialization_tests_sighash_json_398_494_795, 398, "test.skip: [signing-serialization tests] sighash.json 398/494 (#795)");
sighash_test!(signing_serialization_tests_sighash_json_399_494_797, 399, "test.skip: [signing-serialization tests] sighash.json 399/494 (#797)");
sighash_test!(signing_serialization_tests_sighash_json_400_494_800, 400, "test.skip: [signing-serialization tests] sighash.json 400/494 (#800)");
sighash_test!(signing_serialization_tests_sighash_json_401_494_804, 401, "test.skip: [signing-serialization tests] sighash.json 401/494 (#804)");
sighash_test!(signing_serialization_tests_sighash_json_402_494_805, 402, "test.skip: [signing-serialization tests] sighash.json 402/494 (#805)");
sighash_test!(signing_serialization_tests_sighash_json_403_494_809, 403, "test.skip: [signing-serialization tests] sighash.json 403/494 (#809)");
sighash_test!(signing_serialization_tests_sighash_json_404_494_811, 404, "test.skip: [signing-serialization tests] sighash.json 404/494 (#811)");
sighash_test!(signing_serialization_tests_sighash_json_405_494_812, 405, "test.skip: [signing-serialization tests] sighash.json 405/494 (#812)");
sighash_test!(signing_serialization_tests_sighash_json_406_494_815, 406, "test.skip: [signing-serialization tests] sighash.json 406/494 (#815)");
sighash_test!(signing_serialization_tests_sighash_json_407_494_816, 407, "test.skip: [signing-serialization tests] sighash.json 407/494 (#816)");
sighash_test!(signing_serialization_tests_sighash_json_408_494_818, 408, "test.skip: [signing-serialization tests] sighash.json 408/494 (#818)");
sighash_test!(signing_serialization_tests_sighash_json_409_494_819, 409, "test.skip: [signing-serialization tests] sighash.json 409/494 (#819)");
sighash_test!(signing_serialization_tests_sighash_json_410_494_821, 410, "test.skip: [signing-serialization tests] sighash.json 410/494 (#821)");
sighash_test!(signing_serialization_tests_sighash_json_411_494_822, 411, "test.skip: [signing-serialization tests] sighash.json 411/494 (#822)");
sighash_test!(signing_serialization_tests_sighash_json_412_494_825, 412, "test.skip: [signing-serialization tests] sighash.json 412/494 (#825)");
sighash_test!(signing_serialization_tests_sighash_json_413_494_833, 413, "test.skip: [signing-serialization tests] sighash.json 413/494 (#833)");
sighash_test!(signing_serialization_tests_sighash_json_414_494_834, 414, "test.skip: [signing-serialization tests] sighash.json 414/494 (#834)");
sighash_test!(signing_serialization_tests_sighash_json_415_494_835, 415, "test.skip: [signing-serialization tests] sighash.json 415/494 (#835)");
sighash_test!(signing_serialization_tests_sighash_json_416_494_836, 416, "test.skip: [signing-serialization tests] sighash.json 416/494 (#836)");
sighash_test!(signing_serialization_tests_sighash_json_417_494_838, 417, "test.skip: [signing-serialization tests] sighash.json 417/494 (#838)");
sighash_test!(signing_serialization_tests_sighash_json_418_494_842, 418, "test.skip: [signing-serialization tests] sighash.json 418/494 (#842)");
sighash_test!(signing_serialization_tests_sighash_json_419_494_844, 419, "test.skip: [signing-serialization tests] sighash.json 419/494 (#844)");
sighash_test!(signing_serialization_tests_sighash_json_420_494_846, 420, "test.skip: [signing-serialization tests] sighash.json 420/494 (#846)");
sighash_test!(signing_serialization_tests_sighash_json_421_494_849, 421, "test.skip: [signing-serialization tests] sighash.json 421/494 (#849)");
sighash_test!(signing_serialization_tests_sighash_json_422_494_851, 422, "test.skip: [signing-serialization tests] sighash.json 422/494 (#851)");
sighash_test!(signing_serialization_tests_sighash_json_423_494_853, 423, "test.skip: [signing-serialization tests] sighash.json 423/494 (#853)");
sighash_test!(signing_serialization_tests_sighash_json_424_494_855, 424, "test.skip: [signing-serialization tests] sighash.json 424/494 (#855)");
sighash_test!(signing_serialization_tests_sighash_json_425_494_857, 425, "test.skip: [signing-serialization tests] sighash.json 425/494 (#857)");
sighash_test!(signing_serialization_tests_sighash_json_426_494_861, 426, "test.skip: [signing-serialization tests] sighash.json 426/494 (#861)");
sighash_test!(signing_serialization_tests_sighash_json_427_494_862, 427, "test.skip: [signing-serialization tests] sighash.json 427/494 (#862)");
sighash_test!(signing_serialization_tests_sighash_json_428_494_863, 428, "test.skip: [signing-serialization tests] sighash.json 428/494 (#863)");
sighash_test!(signing_serialization_tests_sighash_json_429_494_868, 429, "test.skip: [signing-serialization tests] sighash.json 429/494 (#868)");
sighash_test!(signing_serialization_tests_sighash_json_430_494_869, 430, "test.skip: [signing-serialization tests] sighash.json 430/494 (#869)");
sighash_test!(signing_serialization_tests_sighash_json_431_494_871, 431, "test.skip: [signing-serialization tests] sighash.json 431/494 (#871)");
sighash_test!(signing_serialization_tests_sighash_json_432_494_872, 432, "test.skip: [signing-serialization tests] sighash.json 432/494 (#872)");
sighash_test!(signing_serialization_tests_sighash_json_433_494_873, 433, "test.skip: [signing-serialization tests] sighash.json 433/494 (#873)");
sighash_test!(signing_serialization_tests_sighash_json_434_494_877, 434, "test.skip: [signing-serialization tests] sighash.json 434/494 (#877)");
sighash_test!(signing_serialization_tests_sighash_json_435_494_879, 435, "test.skip: [signing-serialization tests] sighash.json 435/494 (#879)");
sighash_test!(signing_serialization_tests_sighash_json_436_494_880, 436, "test.skip: [signing-serialization tests] sighash.json 436/494 (#880)");
sighash_test!(signing_serialization_tests_sighash_json_437_494_881, 437, "test.skip: [signing-serialization tests] sighash.json 437/494 (#881)");
sighash_test!(signing_serialization_tests_sighash_json_438_494_883, 438, "test.skip: [signing-serialization tests] sighash.json 438/494 (#883)");
sighash_test!(signing_serialization_tests_sighash_json_439_494_886, 439, "test.skip: [signing-serialization tests] sighash.json 439/494 (#886)");
sighash_test!(signing_serialization_tests_sighash_json_440_494_888, 440, "test.skip: [signing-serialization tests] sighash.json 440/494 (#888)");
sighash_test!(signing_serialization_tests_sighash_json_441_494_891, 441, "test.skip: [signing-serialization tests] sighash.json 441/494 (#891)");
sighash_test!(signing_serialization_tests_sighash_json_442_494_893, 442, "test.skip: [signing-serialization tests] sighash.json 442/494 (#893)");
sighash_test!(signing_serialization_tests_sighash_json_443_494_894, 443, "test.skip: [signing-serialization tests] sighash.json 443/494 (#894)");
sighash_test!(signing_serialization_tests_sighash_json_444_494_895, 444, "test.skip: [signing-serialization tests] sighash.json 444/494 (#895)");
sighash_test!(signing_serialization_tests_sighash_json_445_494_896, 445, "test.skip: [signing-serialization tests] sighash.json 445/494 (#896)");
sighash_test!(signing_serialization_tests_sighash_json_446_494_897, 446, "test.skip: [signing-serialization tests] sighash.json 446/494 (#897)");
sighash_test!(signing_serialization_tests_sighash_json_447_494_900, 447, "test.skip: [signing-serialization tests] sighash.json 447/494 (#900)");
sighash_test!(signing_serialization_tests_sighash_json_448_494_901, 448, "test.skip: [signing-serialization tests] sighash.json 448/494 (#901)");
sighash_test!(signing_serialization_tests_sighash_json_449_494_905, 449, "test.skip: [signing-serialization tests] sighash.json 449/494 (#905)");
sighash_test!(signing_serialization_tests_sighash_json_450_494_907, 450, "test.skip: [signing-serialization tests] sighash.json 450/494 (#907)");
sighash_test!(signing_serialization_tests_sighash_json_451_494_911, 451, "test.skip: [signing-serialization tests] sighash.json 451/494 (#911)");
sighash_test!(signing_serialization_tests_sighash_json_452_494_913, 452, "test.skip: [signing-serialization tests] sighash.json 452/494 (#913)");
sighash_test!(signing_serialization_tests_sighash_json_453_494_914, 453, "test.skip: [signing-serialization tests] sighash.json 453/494 (#914)");
sighash_test!(signing_serialization_tests_sighash_json_454_494_918, 454, "test.skip: [signing-serialization tests] sighash.json 454/494 (#918)");
sighash_test!(signing_serialization_tests_sighash_json_455_494_919, 455, "test.skip: [signing-serialization tests] sighash.json 455/494 (#919)");
sighash_test!(signing_serialization_tests_sighash_json_456_494_926, 456, "test.skip: [signing-serialization tests] sighash.json 456/494 (#926)");
sighash_test!(signing_serialization_tests_sighash_json_457_494_928, 457, "test.skip: [signing-serialization tests] sighash.json 457/494 (#928)");
sighash_test!(signing_serialization_tests_sighash_json_458_494_929, 458, "test.skip: [signing-serialization tests] sighash.json 458/494 (#929)");
sighash_test!(signing_serialization_tests_sighash_json_459_494_930, 459, "test.skip: [signing-serialization tests] sighash.json 459/494 (#930)");
sighash_test!(signing_serialization_tests_sighash_json_460_494_932, 460, "test.skip: [signing-serialization tests] sighash.json 460/494 (#932)");
sighash_test!(signing_serialization_tests_sighash_json_461_494_937, 461, "test.skip: [signing-serialization tests] sighash.json 461/494 (#937)");
sighash_test!(signing_serialization_tests_sighash_json_462_494_940, 462, "test.skip: [signing-serialization tests] sighash.json 462/494 (#940)");
sighash_test!(signing_serialization_tests_sighash_json_463_494_943, 463, "test.skip: [signing-serialization tests] sighash.json 463/494 (#943)");
sighash_test!(signing_serialization_tests_sighash_json_464_494_945, 464, "test.skip: [signing-serialization tests] sighash.json 464/494 (#945)");
sighash_test!(signing_serialization_tests_sighash_json_465_494_947, 465, "test.skip: [signing-serialization tests] sighash.json 465/494 (#947)");
sighash_test!(signing_serialization_tests_sighash_json_466_494_949, 466, "test.skip: [signing-serialization tests] sighash.json 466/494 (#949)");
sighash_test!(signing_serialization_tests_sighash_json_467_494_955, 467, "test.skip: [signing-serialization tests] sighash.json 467/494 (#955)");
sighash_test!(signing_serialization_tests_sighash_json_468_494_960, 468, "test.skip: [signing-serialization tests] sighash.json 468/494 (#960)");
sighash_test!(signing_serialization_tests_sighash_json_469_494_962, 469, "test.skip: [signing-serialization tests] sighash.json 469/494 (#962)");
sighash_test!(signing_serialization_tests_sighash_json_470_494_963, 470, "test.skip: [signing-serialization tests] sighash.json 470/494 (#963)");
sighash_test!(signing_serialization_tests_sighash_json_471_494_965, 471, "test.skip: [signing-serialization tests] sighash.json 471/494 (#965)");
sighash_test!(signing_serialization_tests_sighash_json_472_494_967, 472, "test.skip: [signing-serialization tests] sighash.json 472/494 (#967)");
sighash_test!(signing_serialization_tests_sighash_json_473_494_968, 473, "test.skip: [signing-serialization tests] sighash.json 473/494 (#968)");
sighash_test!(signing_serialization_tests_sighash_json_474_494_969, 474, "test.skip: [signing-serialization tests] sighash.json 474/494 (#969)");
sighash_test!(signing_serialization_tests_sighash_json_475_494_970, 475, "test.skip: [signing-serialization tests] sighash.json 475/494 (#970)");
sighash_test!(signing_serialization_tests_sighash_json_476_494_971, 476, "test.skip: [signing-serialization tests] sighash.json 476/494 (#971)");
sighash_test!(signing_serialization_tests_sighash_json_477_494_973, 477, "test.skip: [signing-serialization tests] sighash.json 477/494 (#973)");
sighash_test!(signing_serialization_tests_sighash_json_478_494_974, 478, "test.skip: [signing-serialization tests] sighash.json 478/494 (#974)");
sighash_test!(signing_serialization_tests_sighash_json_479_494_975, 479, "test.skip: [signing-serialization tests] sighash.json 479/494 (#975)");
sighash_test!(signing_serialization_tests_sighash_json_480_494_976, 480, "test.skip: [signing-serialization tests] sighash.json 480/494 (#976)");
sighash_test!(signing_serialization_tests_sighash_json_481_494_977, 481, "test.skip: [signing-serialization tests] sighash.json 481/494 (#977)");
sighash_test!(signing_serialization_tests_sighash_json_482_494_979, 482, "test.skip: [signing-serialization tests] sighash.json 482/494 (#979)");
sighash_test!(signing_serialization_tests_sighash_json_483_494_981, 483, "test.skip: [signing-serialization tests] sighash.json 483/494 (#981)");
sighash_test!(signing_serialization_tests_sighash_json_484_494_982, 484, "test.skip: [signing-serialization tests] sighash.json 484/494 (#982)");
sighash_test!(signing_serialization_tests_sighash_json_485_494_986, 485, "test.skip: [signing-serialization tests] sighash.json 485/494 (#986)");
sighash_test!(signing_serialization_tests_sighash_json_486_494_988, 486, "test.skip: [signing-serialization tests] sighash.json 486/494 (#988)");
sighash_test!(signing_serialization_tests_sighash_json_487_494_991, 487, "test.skip: [signing-serialization tests] sighash.json 487/494 (#991)");
sighash_test!(signing_serialization_tests_sighash_json_488_494_992, 488, "test.skip: [signing-serialization tests] sighash.json 488/494 (#992)");
sighash_test!(signing_serialization_tests_sighash_json_489_494_994, 489, "test.skip: [signing-serialization tests] sighash.json 489/494 (#994)");
sighash_test!(signing_serialization_tests_sighash_json_490_494_996, 490, "test.skip: [signing-serialization tests] sighash.json 490/494 (#996)");
sighash_test!(signing_serialization_tests_sighash_json_491_494_997, 491, "test.skip: [signing-serialization tests] sighash.json 491/494 (#997)");
sighash_test!(signing_serialization_tests_sighash_json_492_494_998, 492, "test.skip: [signing-serialization tests] sighash.json 492/494 (#998)");
sighash_test!(signing_serialization_tests_sighash_json_493_494_999, 493, "test.skip: [signing-serialization tests] sighash.json 493/494 (#999)");
