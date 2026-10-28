//! VM evaluation benchmark generator and runner.
//!
//! Builds a near-limit BCH_2026 authentication program that exercises most of
//! the instruction set, writes it as a shared fixture for the TypeScript
//! reference benchmark (`tools/bench-vm.mjs`), and measures repeated
//! evaluation of the shipped Rust VM. This is a port-only tool; libauth has no
//! counterpart.

use std::time::Instant;

use libauth::runtime::json::parse_json;
// Like libauth's `bch-2026-opcodes.ts`, this module is not re-exported by its
// barrel.
use libauth::vm::instruction_sets::bch::bch_2026::bch_2026_opcodes::OpcodesBch2026 as Op;
use libauth::{
    bin_to_hex, create_virtual_machine_bch_2026, decode_transaction, decode_transaction_outputs,
    disassemble_bytecode_bch, encode_data_push, encode_transaction, encode_transaction_outputs, hex_to_bin,
    AuthenticationProgramCommon, AuthenticationProgramStateBch2026, AuthenticationVirtualMachineBch2026, Input,
    Output, TransactionCommon,
};

const FIXTURE: &str = "tests/fixtures/vm_benchmark_program.json";

fn push(script: &mut Vec<u8>, data: &[u8]) {
    script.extend_from_slice(&encode_data_push(data));
}

fn op(script: &mut Vec<u8>, opcode: u8) {
    script.push(opcode);
}

fn snippet(script: &mut Vec<u8>, bytes: &[u8]) {
    script.extend_from_slice(bytes);
}

fn balanced_snippets() -> Vec<Vec<u8>> {
    let mut s = Vec::new();
    let mut add = |bytes: &[u8]| s.push(bytes.to_vec());

    add(&[Op::OP_0, Op::OP_DROP]);
    add(&[Op::OP_1NEGATE, Op::OP_DROP]);
    add(&[Op::OP_16, Op::OP_DROP]);
    add(&[Op::OP_NOP]);
    add(&[
        Op::OP_1, Op::OP_IF, Op::OP_1, Op::OP_ELSE, Op::OP_0, Op::OP_ENDIF, Op::OP_DROP,
    ]);
    add(&[Op::OP_0, Op::OP_NOTIF, Op::OP_1, Op::OP_ENDIF, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_VERIFY]);
    add(&[
        Op::OP_1, Op::OP_TOALTSTACK, Op::OP_FROMALTSTACK, Op::OP_DROP,
    ]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_2DROP]);
    add(&[
        Op::OP_1, Op::OP_2, Op::OP_2DUP, Op::OP_2DROP, Op::OP_2DROP,
    ]);
    add(&[
        Op::OP_1, Op::OP_2, Op::OP_3, Op::OP_3DUP, Op::OP_2DROP, Op::OP_2DROP, Op::OP_2DROP,
    ]);
    add(&[
        Op::OP_1, Op::OP_2, Op::OP_3, Op::OP_4, Op::OP_2OVER, Op::OP_2DROP, Op::OP_2DROP,
        Op::OP_2DROP,
    ]);
    add(&[
        Op::OP_1, Op::OP_2, Op::OP_3, Op::OP_4, Op::OP_5, Op::OP_6, Op::OP_2ROT,
        Op::OP_2DROP, Op::OP_2DROP, Op::OP_2DROP,
    ]);
    add(&[
        Op::OP_1, Op::OP_2, Op::OP_3, Op::OP_4, Op::OP_2SWAP, Op::OP_2DROP, Op::OP_2DROP,
    ]);
    add(&[Op::OP_0, Op::OP_IFDUP, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_IFDUP, Op::OP_DROP, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_DUP, Op::OP_DROP, Op::OP_DROP]);
    add(&[Op::OP_DEPTH, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_NIP, Op::OP_DROP]);
    add(&[
        Op::OP_1, Op::OP_2, Op::OP_OVER, Op::OP_DROP, Op::OP_DROP, Op::OP_DROP,
    ]);
    add(&[
        Op::OP_1, Op::OP_2, Op::OP_3, Op::OP_2, Op::OP_PICK, Op::OP_DROP, Op::OP_DROP,
        Op::OP_DROP, Op::OP_DROP,
    ]);
    add(&[
        Op::OP_1, Op::OP_2, Op::OP_3, Op::OP_2, Op::OP_ROLL, Op::OP_DROP, Op::OP_DROP,
        Op::OP_DROP,
    ]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_3, Op::OP_ROT, Op::OP_DROP, Op::OP_DROP, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_SWAP, Op::OP_DROP, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_TUCK, Op::OP_DROP, Op::OP_DROP, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_SIZE, Op::OP_DROP, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_1, Op::OP_EQUAL, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_1, Op::OP_EQUALVERIFY]);
    add(&[Op::OP_1, Op::OP_1ADD, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_1SUB, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_NEGATE, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_ABS, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_NOT, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_0NOTEQUAL, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_ADD, Op::OP_DROP]);
    add(&[Op::OP_3, Op::OP_2, Op::OP_SUB, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_BOOLAND, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_0, Op::OP_BOOLOR, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_1, Op::OP_NUMEQUAL, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_1, Op::OP_NUMEQUALVERIFY]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_NUMNOTEQUAL, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_LESSTHAN, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_LESSTHANOREQUAL, Op::OP_DROP]);
    add(&[Op::OP_2, Op::OP_1, Op::OP_GREATERTHAN, Op::OP_DROP]);
    add(&[Op::OP_2, Op::OP_1, Op::OP_GREATERTHANOREQUAL, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_MIN, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_MAX, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_1, Op::OP_2, Op::OP_WITHIN, Op::OP_DROP]);
    add(&[0x01, 0x00, Op::OP_BIN2NUM, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_NUM2BIN, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_1, Op::OP_LSHIFTNUM, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_1, Op::OP_RSHIFTNUM, Op::OP_DROP]);
    add(&[0x01, Op::OP_INVERT, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_1, Op::OP_1, Op::OP_LSHIFTBIN, Op::OP_DROP, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_1, Op::OP_1, Op::OP_RSHIFTBIN, Op::OP_DROP, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_3, Op::OP_AND, Op::OP_DROP, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_3, Op::OP_OR, Op::OP_DROP, Op::OP_DROP]);
    add(&[Op::OP_1, Op::OP_2, Op::OP_3, Op::OP_XOR, Op::OP_DROP, Op::OP_DROP]);
    add(&[0x01, Op::OP_SHA1, Op::OP_DROP]);
    add(&[0x01, Op::OP_SHA256, Op::OP_DROP]);
    add(&[0x01, Op::OP_RIPEMD160, Op::OP_DROP]);
    add(&[0x01, Op::OP_HASH160, Op::OP_DROP]);
    add(&[0x01, Op::OP_HASH256, Op::OP_DROP]);
    add(&[Op::OP_CODESEPARATOR]);
    add(&[Op::OP_0, Op::OP_0, Op::OP_0, Op::OP_CHECKMULTISIG, Op::OP_DROP]);
    add(&[Op::OP_0, Op::OP_0, Op::OP_0, Op::OP_CHECKMULTISIGVERIFY]);
    // CHECKSIG with an empty signature and a valid public key pushes false.
    add(&[
        Op::OP_0,
        0x21,
        0x02,
        0x79,
        0xbe,
        0x66,
        0x7e,
        0xf9,
        0xdc,
        0xbb,
        0xac,
        0x55,
        0xa0,
        0x62,
        0x95,
        0xce,
        0x87,
        0x0b,
        0x07,
        0x02,
        0x9b,
        0xfc,
        0xdb,
        0x2d,
        0xce,
        0x28,
        0xd9,
        0x59,
        0xf2,
        0x81,
        0x5b,
        0x16,
        0xf8,
        0x17,
        0x98,
        Op::OP_CHECKSIG,
        Op::OP_DROP,
    ]);
    // Introspection.
    add(&[Op::OP_INPUTINDEX, Op::OP_DROP]);
    add(&[Op::OP_ACTIVEBYTECODE, Op::OP_DROP]);
    add(&[Op::OP_TXVERSION, Op::OP_DROP]);
    add(&[Op::OP_TXINPUTCOUNT, Op::OP_DROP]);
    add(&[Op::OP_TXOUTPUTCOUNT, Op::OP_DROP]);
    add(&[Op::OP_TXLOCKTIME, Op::OP_DROP]);
    for introspection in [
        Op::OP_UTXOVALUE,
        Op::OP_UTXOBYTECODE,
        Op::OP_OUTPOINTTXHASH,
        Op::OP_OUTPOINTINDEX,
        Op::OP_INPUTBYTECODE,
        Op::OP_INPUTSEQUENCENUMBER,
        Op::OP_OUTPUTVALUE,
        Op::OP_OUTPUTBYTECODE,
        Op::OP_UTXOTOKENCATEGORY,
        Op::OP_UTXOTOKENCOMMITMENT,
        Op::OP_UTXOTOKENAMOUNT,
        Op::OP_OUTPUTTOKENCATEGORY,
        Op::OP_OUTPUTTOKENCOMMITMENT,
        Op::OP_OUTPUTTOKENAMOUNT,
    ] {
        add(&[Op::OP_0, introspection, Op::OP_DROP]);
    }
    // 2026 loops and functions.
    add(&[
        Op::OP_0,
        Op::OP_BEGIN,
        Op::OP_1ADD,
        Op::OP_DUP,
        Op::OP_5,
        Op::OP_NUMEQUAL,
        Op::OP_UNTIL,
        Op::OP_DROP,
    ]);
    add(&[
        0x01, Op::OP_1, // body: data push of the byte 0x51 (OP_1)
        Op::OP_1,
        Op::OP_DEFINE,
        Op::OP_1,
        Op::OP_INVOKE,
        Op::OP_DROP,
    ]);
    // Time locks (transaction version 2, sequence 0, locktime 0).
    add(&[Op::OP_0, Op::OP_CHECKLOCKTIMEVERIFY, Op::OP_DROP]);
    add(&[Op::OP_0, Op::OP_CHECKSEQUENCEVERIFY, Op::OP_DROP]);
    s
}

fn build_program(variant: &str) -> (TransactionCommon, Vec<Output>) {
    // Near the 10 KB unlocking bytecode limit: one 9,900-byte push raises the
    // density-control budget for the locking script.
    let mut unlocking = Vec::new();
    push(&mut unlocking, &vec![0x00; 9_900]);

    let mut locking = Vec::new();
    op(&mut locking, Op::OP_DROP);
    if variant != "hash" && variant != "mul" {
        for bytes in balanced_snippets() {
            snippet(&mut locking, &bytes);
        }
    }

    if variant != "hash" && variant != "ops" {
        // Arithmetic cost: a multiplication of two large VM numbers.
        let big_number = vec![0x01_u8; 2_400];
        push(&mut locking, &big_number);
        push(&mut locking, &big_number);
        op(&mut locking, Op::OP_MUL);
        op(&mut locking, Op::OP_DROP);
    }

    if variant != "mul" && variant != "ops" {
        // Hashing density: hash a 520-byte item repeatedly.
        push(&mut locking, &vec![0xab_u8; 520]);
        for _ in 0..1_380 {
            op(&mut locking, Op::OP_DUP);
            op(&mut locking, Op::OP_SHA256);
            op(&mut locking, Op::OP_DROP);
        }
        op(&mut locking, Op::OP_DROP);
    }

    // Pad to just under the 10 KB locking bytecode limit.
    if std::env::var_os("VM_BENCH_VERBOSE").is_some() {
        eprintln!("pre-padding locking length: {}", locking.len());
    }
    if variant == "full" {
        while locking.len() + 1 < 9_990 {
            op(&mut locking, Op::OP_NOP);
        }
    }
    op(&mut locking, Op::OP_1);

    let transaction = TransactionCommon {
        version: 2,
        inputs: vec![Input {
            outpoint_transaction_hash: vec![0x11; 32],
            outpoint_index: 0,
            unlocking_bytecode: unlocking,
            sequence_number: 0,
        }],
        outputs: vec![Output {
            locking_bytecode: vec![Op::OP_1],
            token: None,
            value_satoshis: 0,
        }],
        locktime: 0,
    };
    let source_outputs = vec![Output {
        locking_bytecode: locking,
        token: None,
        value_satoshis: 10_000,
    }];
    (transaction, source_outputs)
}

/// The authentication program evaluating input 0 of `transaction`.
fn program(transaction: &TransactionCommon, source_outputs: &[Output]) -> AuthenticationProgramCommon {
    AuthenticationProgramCommon {
        input_index: 0,
        source_outputs: source_outputs.to_vec(),
        transaction: transaction.clone(),
    }
}

fn metrics_report(vm: &AuthenticationVirtualMachineBch2026, state: &AuthenticationProgramStateBch2026) -> String {
    let m = &state.metrics;
    let input_index = state.program.input_index;
    format!(
        "success={} error={:?} stack_len={}\n  locking_len={} unlocking_len={} density={}\n  operation_cost={} / {} ({:.1}%)\n  hash_iters={} / {} ({:.1}%)\n  sigchecks={} / {} evaluated_instructions={}\n  stack_pushed_bytes={} arithmetic_cost={}",
        state.error.is_none() && vm.state_success(state).is_ok(),
        state.error,
        state.stack.len(),
        state.program.source_outputs[input_index].locking_bytecode.len(),
        state.program.transaction.inputs[input_index].unlocking_bytecode.len(),
        m.density_control_length,
        m.operation_cost,
        m.maximum_operation_cost,
        100.0 * m.operation_cost / m.maximum_operation_cost.max(1.0),
        m.hash_digest_iterations,
        m.maximum_hash_digest_iterations,
        100.0 * m.hash_digest_iterations / m.maximum_hash_digest_iterations.max(1.0),
        m.signature_check_count,
        m.maximum_signature_check_count,
        m.evaluated_instruction_count,
        m.stack_pushed_bytes,
        m.arithmetic_cost,
    )
}

fn write_fixture(transaction: &TransactionCommon, source_outputs: &[Output]) -> String {
    format!(
        "{{\n  \"transaction\": \"{}\",\n  \"sourceOutputs\": \"{}\",\n  \"inputIndex\": 0\n}}\n",
        bin_to_hex(&encode_transaction(transaction)),
        bin_to_hex(&encode_transaction_outputs(source_outputs)),
    )
}

fn load_fixture(text: &str) -> (TransactionCommon, Vec<Output>) {
    let json = parse_json(text).expect("fixture parses");
    let transaction = decode_transaction(&hex_to_bin(
        json.get("transaction").and_then(|value| value.as_str()).expect("transaction"),
    ))
    .expect("transaction decodes");
    let source_outputs = decode_transaction_outputs(&hex_to_bin(
        json.get("sourceOutputs").and_then(|value| value.as_str()).expect("source outputs"),
    ))
    .expect("source outputs decode");
    (transaction, source_outputs)
}

/// The CPU time consumed by the calling thread. (`/proc/self/schedstat` is
/// only updated on scheduler ticks, too coarse for single evaluations.)
#[cfg(target_os = "linux")]
fn thread_cpu_nanos() -> u128 {
    use std::os::raw::{c_int, c_long};
    #[repr(C)]
    struct Timespec {
        tv_sec: c_long,
        tv_nsec: c_long,
    }
    extern "C" {
        fn clock_gettime(clock_id: c_int, time: *mut Timespec) -> c_int;
    }
    const CLOCK_THREAD_CPUTIME_ID: c_int = 3;
    let mut time = Timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `clock_gettime` only writes the `timespec` it is given.
    if unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut time) } != 0 {
        return 0;
    }
    time.tv_sec as u128 * 1_000_000_000 + time.tv_nsec as u128
}

#[cfg(not(target_os = "linux"))]
fn thread_cpu_nanos() -> u128 {
    0
}

fn stats(samples: &[u128]) -> (f64, f64, f64, f64, u128, u128) {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let n = sorted.len() as f64;
    let mean = sorted.iter().map(|value| *value as f64).sum::<f64>() / n;
    let variance = sorted
        .iter()
        .map(|value| {
            let delta = *value as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / (n - 1.0);
    let stddev = variance.sqrt();
    let median = if sorted.len() % 2 == 0 {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) as f64 / 2.0
    } else {
        sorted[sorted.len() / 2] as f64
    };
    let ci95 = 1.96 * stddev / n.sqrt();
    (
        mean / 1000.0,
        median / 1000.0,
        stddev / 1000.0,
        ci95 / 1000.0,
        sorted[0],
        *sorted.last().unwrap(),
    )
}

fn check_snippets(vm: &AuthenticationVirtualMachineBch2026) {
    let (mut transaction, _) = build_program("full");
    transaction.inputs[0].unlocking_bytecode = Vec::new();
    let snippets = balanced_snippets();
    for (index, bytes) in snippets.iter().enumerate() {
        let mut locking = bytes.clone();
        locking.push(Op::OP_1);
        let source_outputs = vec![Output {
            locking_bytecode: locking,
            token: None,
            value_satoshis: 10_000,
        }];
        let state = vm.evaluate(&program(&transaction, &source_outputs), None);
        if let Some(error) = state.error {
            println!("snippet {index:02} {bytes:02x?}: {error}");
        }
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let vm = create_virtual_machine_bch_2026(Some(false));
    if arguments.iter().any(|argument| argument == "--check-snippets") {
        check_snippets(&vm);
        return;
    }
    let write = arguments.iter().position(|argument| argument == "--write");
    let variant = arguments
        .iter()
        .position(|argument| argument == "--variant")
        .and_then(|index| arguments.get(index + 1))
        .cloned()
        .unwrap_or_else(|| "full".to_string());
    let iterations: usize = arguments
        .iter()
        .position(|argument| argument == "--iterations")
        .and_then(|index| arguments.get(index + 1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(200);
    let warmup: usize = arguments
        .iter()
        .position(|argument| argument == "--warmup")
        .and_then(|index| arguments.get(index + 1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(20);

    let (transaction, source_outputs) = if write.is_some() || variant != "full" {
        build_program(&variant)
    } else {
        load_fixture(&std::fs::read_to_string(FIXTURE).expect("fixture file"))
    };

    if let Some(index) = write {
        let path = arguments.get(index + 1).map(String::as_str).unwrap_or(FIXTURE);
        std::fs::write(path, write_fixture(&transaction, &source_outputs)).expect("write fixture");
    }

    let program = program(&transaction, &source_outputs);
    let initial = vm.evaluate(&program, None);
    println!("{}", metrics_report(&vm, &initial));
    if arguments.iter().any(|argument| argument == "--coverage") {
        let mut used = std::collections::BTreeSet::new();
        for script in [
            source_outputs[0].locking_bytecode.clone(),
            transaction.inputs[0].unlocking_bytecode.clone(),
        ] {
            for token in disassemble_bytecode_bch(&script).split(' ') {
                if token.starts_with("OP_") {
                    used.insert(token.to_string());
                }
            }
        }
        println!("coverage distinct_opcodes={} {:?}", used.len(), used);
    }
    if initial.error.is_some() {
        std::process::exit(1);
    }

    for _ in 0..warmup {
        let state = vm.evaluate(&program, None);
        assert!(state.error.is_none());
    }
    let cpu_mode = arguments.iter().any(|argument| argument == "--cpu");
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let (start, cpu_start) = (Instant::now(), thread_cpu_nanos());
        let state = vm.evaluate(&program, None);
        let elapsed = if cpu_mode {
            thread_cpu_nanos().saturating_sub(cpu_start)
        } else {
            start.elapsed().as_nanos()
        };
        samples.push(elapsed);
        assert!(state.error.is_none());
        assert!(vm.state_success(&state).is_ok());
    }
    if let Some(index) = arguments.iter().position(|argument| argument == "--samples") {
        if let Some(path) = arguments.get(index + 1) {
            let mut text = String::new();
            for sample in &samples {
                text.push_str(&format!("{sample}\n"));
            }
            std::fs::write(path, text).expect("write samples");
        }
    }
    let (mean, median, stddev, ci95, min, max) = stats(&samples);
    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let percentile = |fraction: f64| {
        let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
        sorted[index] as f64 / 1000.0
    };
    println!(
        "rust iterations={iterations} mean_us={mean:.1} median_us={median:.1} stddev_us={stddev:.1} ci95_us={ci95:.1} p90_us={:.1} p99_us={:.1} min_us={:.1} max_us={:.1}",
        percentile(0.9),
        percentile(0.99),
        min as f64 / 1000.0,
        max as f64 / 1000.0
    );
}
