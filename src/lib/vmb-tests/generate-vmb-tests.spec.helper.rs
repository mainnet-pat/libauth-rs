//! Port of `vmb-tests/generate-vmb-tests.spec.helper.ts`: the utilities
//! required for VMB test generation.
//!
//! Differences from libauth, which are inherent to Rust:
//! - libauth imports each compiled `sources/*.js` file by name; here the
//!   sources are compiled into the binary (see [`compiled_sources`]), and the
//!   build manifest hashes the `sources/*.rs` files.
//! - Workers are threads (see `generate-vmb-tests-worker.spec.helper.rs`).
//! - tinybench is replaced by a minimal stand-in ([`Bench`]) implementing the
//!   same sampling loop and statistics.
//! - The result directory can be overridden (see [`result_dir`]).
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Instant;

use libauth::format::{assert_non_null, assert_success, bin_to_hex, hex_to_bin, ReadPosition};
use libauth::message::{read_transaction_common, read_transaction_outputs};
use libauth::runtime::json::{encode_json, parse_json, Json};
use libauth::sha256;
use libauth::vm::{AuthenticationProgramCommon, ResolvedTransactionCommon};
use libauth::vmb_tests::sources;
use libauth::vmb_tests::{
    vmb_test_group_to_vmb_tests, vmb_test_partition_master_test_list, VmbTest, VmbTestDefinitionGroup,
    VmbTestMasterBch,
};

use crate::generate_vmb_tests_worker_spec_helper::{worker_main, WorkerData};
use crate::map_bchn_results_spec_helper::{
    failReasonsPath, get_bchn_metrics, testMetricsPath, verify_expected_error_message,
};
use crate::vmb_tests_spec_helper::{baselineBenchmarkId, vms, TestedVM};

/// A list of directories for which annotation and benchmarking should be
/// skipped (e.g. test sets that aren't ready to publish and excluded
/// by `.gitignore`).
const skipDirectoryPrefixes: &[&str] = &[];
// const skipDirectoryPrefixes: &[&str] = &["bch_chip", "bch_2026"];
static warnedOnce: Mutex<bool> = Mutex::new(false);

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The VMB test sources compiled into this binary, by file name (libauth
/// dynamically imports `${compiledDir}/${filename}`).
pub fn compiled_sources() -> Vec<(&'static str, &'static LazyLock<Vec<VmbTestDefinitionGroup>>)> {
    vec![
        ("chip.benchmarks.bitwise.rs", &sources::chip_benchmarks_bitwise::default),
        ("chip.bitwise.rs", &sources::chip_bitwise::default),
        ("chip.eval.rs", &sources::chip_eval::default),
        ("chip.flow-control.rs", &sources::chip_flow_control::default),
        ("chip.functions.rs", &sources::chip_functions::default),
        ("chip.loops.rs", &sources::chip_loops::default),
        ("chip.p2s.rs", &sources::chip_p2s::default),
        ("chip.pow.rs", &sources::chip_pow::default),
        ("core.benchmarks.arithmetic.add-sub.rs", &sources::core_benchmarks_arithmetic_add_sub::default),
        ("core.benchmarks.arithmetic.div-mod.rs", &sources::core_benchmarks_arithmetic_div_mod::default),
        ("core.benchmarks.arithmetic.mul.rs", &sources::core_benchmarks_arithmetic_mul::default),
        ("core.benchmarks.baseline.rs", &sources::core_benchmarks_baseline::default),
        ("core.benchmarks.bitwise.rs", &sources::core_benchmarks_bitwise::default),
        ("core.benchmarks.hashing-bytes.packed.rs", &sources::core_benchmarks_hashing_bytes_packed::default),
        ("core.benchmarks.hashing-iters.packed.rs", &sources::core_benchmarks_hashing_iters_packed::default),
        ("core.benchmarks.hashing.rs", &sources::core_benchmarks_hashing::default),
        ("core.benchmarks.roll.rs", &sources::core_benchmarks_roll::default),
        ("core.benchmarks.signature-checking.bms-ecdsa.rs", &sources::core_benchmarks_signature_checking_bms_ecdsa::default),
        ("core.benchmarks.signature-checking.bms-schnorr.rs", &sources::core_benchmarks_signature_checking_bms_schnorr::default),
        ("core.benchmarks.signature-checking.p2pk.rs", &sources::core_benchmarks_signature_checking_p2pk::default),
        ("core.benchmarks.signature-checking.p2pkh.rs", &sources::core_benchmarks_signature_checking_p2pkh::default),
        ("core.benchmarks.stack.rs", &sources::core_benchmarks_stack::default),
        ("core.bigint-basics.rs", &sources::core_bigint_basics::default),
        ("core.bigint-limits.binary.rs", &sources::core_bigint_limits_binary::default),
        ("core.bigint-limits.ternary.rs", &sources::core_bigint_limits_ternary::default),
        ("core.bigint-limits.unary.rs", &sources::core_bigint_limits_unary::default),
        ("core.bigint.0notequal.rs", &sources::core_bigint_0notequal::default),
        ("core.bigint.1add.rs", &sources::core_bigint_1add::default),
        ("core.bigint.1sub.rs", &sources::core_bigint_1sub::default),
        ("core.bigint.abs.rs", &sources::core_bigint_abs::default),
        ("core.bigint.add.rs", &sources::core_bigint_add::default),
        ("core.bigint.bin2num.rs", &sources::core_bigint_bin2num::default),
        ("core.bigint.booland.rs", &sources::core_bigint_booland::default),
        ("core.bigint.boolor.rs", &sources::core_bigint_boolor::default),
        ("core.bigint.div.rs", &sources::core_bigint_div::default),
        ("core.bigint.greaterthan.rs", &sources::core_bigint_greaterthan::default),
        ("core.bigint.greaterthanorequal.rs", &sources::core_bigint_greaterthanorequal::default),
        ("core.bigint.lessthan.rs", &sources::core_bigint_lessthan::default),
        ("core.bigint.lessthanorequal.rs", &sources::core_bigint_lessthanorequal::default),
        ("core.bigint.max.rs", &sources::core_bigint_max::default),
        ("core.bigint.min.rs", &sources::core_bigint_min::default),
        ("core.bigint.mod.rs", &sources::core_bigint_mod::default),
        ("core.bigint.mul.rs", &sources::core_bigint_mul::default),
        ("core.bigint.negate.rs", &sources::core_bigint_negate::default),
        ("core.bigint.not.rs", &sources::core_bigint_not::default),
        ("core.bigint.num2bin.rs", &sources::core_bigint_num2bin::default),
        ("core.bigint.numequal.rs", &sources::core_bigint_numequal::default),
        ("core.bigint.numequalverify.rs", &sources::core_bigint_numequalverify::default),
        ("core.bigint.numnotequal.rs", &sources::core_bigint_numnotequal::default),
        ("core.bigint.sub.rs", &sources::core_bigint_sub::default),
        ("core.bigint.within.rs", &sources::core_bigint_within::default),
        ("core.cashtokens.rs", &sources::core_cashtokens::default),
        ("core.conditionals.rs", &sources::core_conditionals::default),
        ("core.copy.rs", &sources::core_copy::default),
        ("core.data-signatures.rs", &sources::core_data_signatures::default),
        ("core.disabled.rs", &sources::core_disabled::default),
        ("core.formatting.rs", &sources::core_formatting::default),
        ("core.hashing.rs", &sources::core_hashing::default),
        ("core.inspection.rs", &sources::core_inspection::default),
        ("core.limits.rs", &sources::core_limits::default),
        ("core.nop.rs", &sources::core_nop::default),
        ("core.push-only.rs", &sources::core_push_only::default),
        ("core.push.bytes.rs", &sources::core_push_bytes::default),
        ("core.push.data.limits.rs", &sources::core_push_data_limits::default),
        ("core.push.data.rs", &sources::core_push_data::default),
        ("core.push.minimal.rs", &sources::core_push_minimal::default),
        ("core.push.numbers.rs", &sources::core_push_numbers::default),
        ("core.push.ops.rs", &sources::core_push_ops::default),
        ("core.signature-checking.multisig.m-of-15.rs", &sources::core_signature_checking_multisig_m_of_15::default),
        ("core.signature-checking.multisig.m-of-20.rs", &sources::core_signature_checking_multisig_m_of_20::default),
        ("core.signature-checking.multisig.m-of-3.rs", &sources::core_signature_checking_multisig_m_of_3::default),
        ("core.signature-checking.multisig.pubkey-validation.rs", &sources::core_signature_checking_multisig_pubkey_validation::default),
        ("core.signature-checking.multisig.signing-serialization.rs", &sources::core_signature_checking_multisig_signing_serialization::default),
        ("core.signing-serialization.rs", &sources::core_signing_serialization::default),
    ]
}

fn compiled_source(filename: &str) -> Option<&'static LazyLock<Vec<VmbTestDefinitionGroup>>> {
    compiled_sources()
        .into_iter()
        .find(|(name, _)| *name == filename)
        .map(|(_, source)| source)
}

/// libauth reads the compiled JS from `build/lib/vmb-tests/sources`; the Rust
/// sources are compiled into this binary, so the manifest hashes the source
/// files themselves.
pub fn compiled_dir() -> PathBuf {
    manifest_dir().join("src/lib/vmb-tests/sources")
}
/// We compare against the source files to exclude any registered sources whose
/// files have since been deleted. (In libauth, this excludes outdated JS files
/// compiled from now-deleted TS source files.)
fn sources_dir() -> PathBuf {
    manifest_dir().join("src/lib/vmb-tests/sources")
}

/// The environment variable overriding [`result_dir`].
pub const resultDirEnvironmentVariable: &str = "VMB_TESTS_RESULT_DIR";
static resultDirOverride: OnceLock<PathBuf> = OnceLock::new();

/// Override the result directory for this process (e.g. from a
/// `--result-dir=<path>` argument). Must be called before the first use of
/// [`result_dir`].
pub fn set_result_dir(path: PathBuf) {
    resultDirOverride
        .set(path)
        .expect("the result directory is set at most once, before it is used");
}

/// The directory of the generated VMB tests: `src/lib/vmb-tests/generated`,
/// unless overridden with [`set_result_dir`] or the `VMB_TESTS_RESULT_DIR`
/// environment variable.
pub fn result_dir() -> PathBuf {
    resultDirOverride
        .get_or_init(|| match std::env::var_os(resultDirEnvironmentVariable) {
            Some(path) if !path.is_empty() => {
                let path = PathBuf::from(path);
                if path.is_absolute() {
                    path
                } else {
                    std::env::current_dir().expect("a working directory").join(path)
                }
            }
            _ => manifest_dir().join("src/lib/vmb-tests/generated"),
        })
        .clone()
}

/// Take a `--result-dir=<path>` (or `--result-dir <path>`) argument out of
/// `arguments`, applying it with [`set_result_dir`].
pub fn take_result_dir_argument(arguments: &mut Vec<String>) {
    let Some(position) = arguments.iter().position(|argument| argument.starts_with("--result-dir")) else {
        return;
    };
    let argument = arguments.remove(position);
    let value = match argument.strip_prefix("--result-dir=") {
        Some(value) => value.to_string(),
        None if position < arguments.len() => arguments.remove(position),
        None => panic!("--result-dir requires a path"),
    };
    let path = PathBuf::from(value);
    set_result_dir(if path.is_absolute() {
        path
    } else {
        std::env::current_dir().expect("a working directory").join(path)
    });
}

const buildInfoFile: &str = ".vmb-build-info.json";
const benchInfoFile: &str = ".vmb-bench-info.json";
fn build_info_path() -> PathBuf {
    result_dir().join(buildInfoFile)
}
fn bench_info_path() -> PathBuf {
    result_dir().join(benchInfoFile)
}

pub const benchHeader: &str =
    "Test ID,Relative Time Per Transaction Byte,Relative Time,Hz,Average Time (ns),Margin (+/- %),Samples,Accepted/Rejected";

/* ------------------------------------------------------------------------- */

/// A JavaScript object used as a dictionary. As in JavaScript, keys that are
/// array indexes (canonical numeric strings below 2^32 - 1, e.g. the test ID
/// `"805675"`) are enumerated first in ascending order, followed by all other
/// keys in insertion order; assigning an existing key keeps its position.
#[derive(Clone, Debug)]
pub struct JsObject<V> {
    entries: Vec<(String, V)>,
    positions: HashMap<String, usize>,
}

impl<V> Default for JsObject<V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            positions: HashMap::new(),
        }
    }
}

fn array_index(key: &str) -> Option<u32> {
    let value: u32 = key.parse().ok()?;
    (value != u32::MAX && value.to_string() == key).then_some(value)
}

impl<V> JsObject<V> {
    pub fn set(&mut self, key: &str, value: V) {
        match self.positions.get(key) {
            Some(position) => self.entries[*position].1 = value,
            None => {
                self.positions.insert(key.to_string(), self.entries.len());
                self.entries.push((key.to_string(), value));
            }
        }
    }
    pub fn get(&self, key: &str) -> Option<&V> {
        self.positions.get(key).map(|position| &self.entries[*position].1)
    }
    pub fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        self.positions.get(key).map(|position| &mut self.entries[*position].1)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// `Object.entries(object)`, in JavaScript property order.
    pub fn entries(&self) -> Vec<(&str, &V)> {
        let mut indexes: Vec<(u32, &str, &V)> = Vec::new();
        let mut others: Vec<(&str, &V)> = Vec::new();
        for (key, value) in &self.entries {
            match array_index(key) {
                Some(index) => indexes.push((index, key, value)),
                None => others.push((key, value)),
            }
        }
        indexes.sort_by_key(|(index, _, _)| *index);
        indexes
            .into_iter()
            .map(|(_, key, value)| (key, value))
            .chain(others)
            .collect()
    }
}

/// A build manifest: source file name → SHA-256 of its contents.
type Manifest = JsObject<String>;

fn get_previous_manifest(path: &Path) -> Manifest {
    let parsed = std::fs::read_to_string(path)
        .map_err(|error| error.to_string())
        .and_then(|data| parse_json(&data));
    match parsed.as_ref().ok().and_then(Json::as_object) {
        Some(entries) => {
            let mut manifest = Manifest::default();
            for (file, hash) in entries {
                manifest.set(file, hash.as_string());
            }
            manifest
        }
        None => {
            println!("No manifest for this build type. Creating: {}", path.display());
            Manifest::default()
        }
    }
}

fn save_manifest(path: &Path, build_info: &Manifest) {
    let json = Json::Object(
        build_info
            .entries()
            .into_iter()
            .map(|(file, hash)| (file.to_string(), Json::String(hash.clone())))
            .collect(),
    );
    std::fs::write(path, encode_json(&json)).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

fn hash_file(file_path: &Path) -> String {
    let file_buffer = std::fs::read(file_path).unwrap_or_else(|error| panic!("{}: {error}", file_path.display()));
    bin_to_hex(&sha256.hash(&file_buffer))
}

fn get_sources() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(sources_dir())
        .unwrap_or_else(|error| panic!("{}: {error}", sources_dir().display()))
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".rs") && !name.contains(".skip."))
        .collect();
    names.sort();
    names
}

fn get_latest_manifest() -> Result<Manifest, String> {
    let files: Vec<&str> = compiled_sources().into_iter().map(|(name, _)| name).collect();
    let matches = get_sources();
    for r#match in &matches {
        if !files.contains(&r#match.as_str()) {
            return Err(format!(
                "Could not find compiled file \"{match}\" in: {}. Please mount it in `vmb_tests::sources`, register it in `compiled_sources`, rebuild, and try again.",
                compiled_dir().display(),
                r#match = r#match
            ));
        }
    }
    let mut manifest = Manifest::default();
    for filename in &matches {
        manifest.set(filename, hash_file(&compiled_dir().join(filename)));
    }
    Ok(manifest)
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

/// From `core.benchmarks.baseline.vmb_tests.json`
#[rustfmt::skip]
const baselineVmbTest: (&str, &str, &str, &str, &str, &str, usize) = ("trxhzt","Transaction validation benchmarks: [baseline] 2 P2PKH inputs, 2 P2PKH outputs (one Schnorr signature, one ECDSA signature) (P2S)","<key1.schnorr_signature.all_outputs> <key1.public_key>","OP_DUP OP_HASH160 <$(<key1.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG","02000000020100000000000000000000000000000000000000000000000000000000000000000000006a47304402204a86326ea6e2abb2ba73d490cd3293bdb7ff35886f9571064fb61e3dc64cb28b0220239338de5a5b1d54f7ff07196e16d10456da74b11ef1a79fc1bb02a084a977fd412103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e785000000000100000000000000000000000000000000000000000000000000000000000000010000006441de6174892e09d0b5d48c69d76cd4510d0254fd4a35edb6283454b0be48aa8db13c7d5b4cc84019cdf82a87c5bef2fc7768a7f249b681be49480e61a0b093b2a6412103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7850000000002a0860100000000001976a9144af864646d46ee5a12f4695695ae78f993cad77588ac32850100000000001976a9144af864646d46ee5a12f4695695ae78f993cad77588ac00000000","02a0860100000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488aca0860100000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488ac",1);
const baselineId: &str = baselineVmbTest.0;
const baselineTxHex: &str = baselineVmbTest.4;
const baselineSourceOutputsHex: &str = baselineVmbTest.5;
/// libauth's `AssertTypesEqual<typeof baselineId, typeof baselineBenchmarkId>`.
const _: () = {
    const fn str_eq(a: &str, b: &str) -> bool {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        let mut index = 0;
        while index < a.len() {
            if a[index] != b[index] {
                return false;
            }
            index += 1;
        }
        true
    }
    assert!(str_eq(baselineId, baselineBenchmarkId));
};
static baselineSourceOutputsBin: LazyLock<Vec<u8>> = LazyLock::new(|| hex_to_bin(baselineSourceOutputsHex));
static baselineTxBin: LazyLock<Vec<u8>> = LazyLock::new(|| hex_to_bin(baselineTxHex));
static baseline: LazyLock<ResolvedTransactionCommon> = LazyLock::new(|| ResolvedTransactionCommon {
    source_outputs: assert_success(
        read_transaction_outputs(ReadPosition { bin: &baselineSourceOutputsBin, index: 0 }),
        None,
    )
    .result,
    transaction: assert_success(read_transaction_common(ReadPosition { bin: &baselineTxBin, index: 0 }), None).result,
});

/// `JSON.stringify(vmbTest)`
fn vmb_test_to_json(vmb_test: &VmbTest) -> Json {
    let mut fields = vec![
        Json::String(vmb_test.short_id.clone()),
        Json::String(vmb_test.test_description.clone()),
        Json::String(vmb_test.unlocking_script_asm.clone()),
        Json::String(vmb_test.redeem_or_locking_script_asm.clone()),
        Json::String(vmb_test.test_transaction_hex.clone()),
        Json::String(vmb_test.source_outputs_hex.clone()),
    ];
    if let Some(input_index) = vmb_test.input_index {
        fields.push(Json::Number(input_index.to_string()));
    }
    Json::Array(fields)
}

/// A custom formatter to quickly and correctly format VMB test JSON files. Line
/// numbers intentionally align with test count: line one begins with `[[...` and
/// the last line ends with `]]`. (Placing the final closing `]` on the following
/// line does not reduce diffs, as a trailing comma must be added to the final
/// test if a new test is appended to the list (standard JSON does not support
/// trailing commas). To reduce file size, no additional spaces are added between
/// VMB test definition array elements.
fn format_vmb_test_set(test_set: &[VmbTest]) -> String {
    format!(
        "[{}]",
        test_set
            .iter()
            .map(|vmb_test| encode_json(&vmb_test_to_json(vmb_test)))
            .collect::<Vec<_>>()
            .join(",\n")
    )
}

/// A custom formatter to quickly and correctly format the auxiliary VMB
/// dictionary JSON files. To minimize diffs, the initial `{` and trailing `}`
/// are placed on their own lines; each dictionary item is then printed on a
/// single line (with no indentation or additional spaces between terms).
fn format_vmb_dictionary(dictionary: &JsObject<Json>) -> String {
    format!(
        "{{\n{}\n}}",
        dictionary
            .entries()
            .into_iter()
            .map(|(key, value)| format!("\"{key}\":{}", encode_json(value)))
            .collect::<Vec<_>>()
            .join(",\n")
    )
}

/// JavaScript's `Number.prototype.toString` for the (integer) VM metrics.
fn js_number(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    if value == value.trunc() && value.abs() < 1e21 {
        return format!("{value:.0}");
    }
    // Shortest round-trip representation (as in JavaScript for 1e-6 <= |x| < 1e21).
    format!("{value}")
}

/// JavaScript's `Number.prototype.toPrecision(precision)`.
fn to_precision(value: f64, precision: usize) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    if value == 0.0 {
        return if precision > 1 { format!("0.{}", "0".repeat(precision - 1)) } else { "0".to_string() };
    }
    let sign = if value < 0.0 { "-" } else { "" };
    let scientific = format!("{:.*e}", precision - 1, value.abs());
    let (mantissa, exponent) = scientific.split_once('e').expect("scientific notation");
    let exponent: i32 = exponent.parse().expect("an exponent");
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    if exponent < -6 || exponent >= precision as i32 {
        let fraction = &digits[1..];
        return format!(
            "{sign}{}{}{}e{}{}",
            &digits[..1],
            if fraction.is_empty() { "" } else { "." },
            fraction,
            if exponent >= 0 { "+" } else { "-" },
            exponent.abs()
        );
    }
    if exponent >= 0 {
        let integer_digits = exponent as usize + 1;
        let (integer, fraction) = digits.split_at(integer_digits.min(digits.len()));
        return format!("{sign}{integer}{}{fraction}", if fraction.is_empty() { "" } else { "." });
    }
    format!("{sign}0.{}{digits}", "0".repeat((-exponent - 1) as usize))
}

/* ------------------------------------------------------------------------- */

/// A minimal stand-in for tinybench's `Bench` (v2.8.0 defaults: 100ms/5
/// iterations of warmup, then at least 500ms and 10 iterations per task),
/// computing the same statistics.
pub struct Bench {
    tasks: Vec<BenchTask>,
}

pub struct BenchTask {
    pub name: String,
    function: Box<dyn Fn()>,
    pub result: Option<BenchResult>,
}

#[derive(Clone, Debug)]
pub struct BenchResult {
    pub hz: f64,
    pub mean: f64,
    pub rme: f64,
    pub samples: Vec<f64>,
}

const tinybenchWarmupTime: f64 = 100.0;
const tinybenchWarmupIterations: usize = 5;
const tinybenchTime: f64 = 500.0;
const tinybenchIterations: usize = 10;
/// tinybench's table of critical t-values (two-tailed, 95%), by degrees of
/// freedom.
const tinybenchTTable: [f64; 120] = [
    12.71, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179, 2.16, 2.145, 2.131, 2.12,
    2.11, 2.101, 2.093, 2.086, 2.08, 2.074, 2.069, 2.064, 2.06, 2.056, 2.052, 2.048, 2.045, 2.042, 2.0399, 2.0378,
    2.0357, 2.0336, 2.0315, 2.0294, 2.0273, 2.0252, 2.0231, 2.021, 2.0198, 2.0186, 2.0174, 2.0162, 2.015, 2.0138,
    2.0126, 2.0114, 2.0102, 2.009, 2.0081, 2.0072, 2.0063, 2.0054, 2.0045, 2.0036, 2.0027, 2.0018, 2.0009, 2.0,
    1.9995, 1.999, 1.9985, 1.998, 1.9975, 1.997, 1.9965, 1.996, 1.9955, 1.995, 1.9945, 1.994, 1.9935, 1.993, 1.9925,
    1.992, 1.9915, 1.991, 1.9905, 1.99, 1.9897, 1.9894, 1.9891, 1.9888, 1.9885, 1.9882, 1.9879, 1.9876, 1.9873,
    1.987, 1.9867, 1.9864, 1.9861, 1.9858, 1.9855, 1.9852, 1.9849, 1.9846, 1.9843, 1.984, 1.9838, 1.9836, 1.9834,
    1.9832, 1.983, 1.9828, 1.9826, 1.9824, 1.9822, 1.982, 1.9818, 1.9816, 1.9814, 1.9812, 1.9819, 1.9808, 1.9806,
    1.9804, 1.9802, 1.98,
];

impl Bench {
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }
    /// Add a task (replacing any task of the same name in place).
    pub fn add(&mut self, name: &str, function: impl Fn() + 'static) {
        let task = BenchTask {
            name: name.to_string(),
            function: Box::new(function),
            result: None,
        };
        match self.tasks.iter_mut().find(|existing| existing.name == name) {
            Some(existing) => *existing = task,
            None => self.tasks.push(task),
        }
    }
    fn sample(task: &BenchTask, time: f64, iterations: usize) -> Vec<f64> {
        let mut samples = Vec::new();
        let mut total = 0.0;
        while total < time || samples.len() < iterations {
            let start = Instant::now();
            (task.function)();
            let duration = elapsed_ms(start);
            samples.push(duration);
            total += duration;
        }
        samples
    }
    pub fn warmup(&mut self) {
        for task in &self.tasks {
            Self::sample(task, tinybenchWarmupTime, tinybenchWarmupIterations);
        }
    }
    pub fn run(&mut self) {
        for task in &mut self.tasks {
            let mut samples = Self::sample(task, tinybenchTime, tinybenchIterations);
            let total: f64 = samples.iter().sum();
            let runs = samples.len() as f64;
            samples.sort_by(|a, b| a.partial_cmp(b).expect("comparable samples"));
            let period = total / runs;
            let hz = 1000.0 / period;
            let degrees_of_freedom = samples.len() - 1;
            let mean = total / runs;
            let variance = if samples.len() > 1 {
                samples.iter().map(|sample| (sample - mean).powi(2)).sum::<f64>() / degrees_of_freedom as f64
            } else {
                0.0
            };
            let sd = variance.sqrt();
            let sem = sd / runs.sqrt();
            let critical = tinybenchTTable
                .get(degrees_of_freedom.max(1) - 1)
                .copied()
                .unwrap_or(1.96);
            let moe = sem * critical;
            let rme = (moe / mean) * 100.0;
            task.result = Some(BenchResult { hz, mean, rme, samples });
        }
    }
    pub fn get_task(&self, name: &str) -> Option<&BenchTask> {
        self.tasks.iter().find(|task| task.name == name)
    }
    pub fn tasks(&self) -> &[BenchTask] {
        &self.tasks
    }
}

/* ------------------------------------------------------------------------- */

/// The console used to report progress (libauth's `{ error, log, warn }`).
pub struct Console<'a> {
    pub error: &'a dyn Fn(String),
    pub log: &'a dyn Fn(String),
    pub warn: &'a dyn Fn(String),
}

fn console_error(message: String) {
    eprintln!("{message}");
}
fn console_log(message: String) {
    println!("{message}");
}

pub const defaultConsole: Console<'static> = Console {
    error: &console_error,
    log: &console_log,
    warn: &console_error,
};

/// The severity of the issues found while generating a source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warn,
}

impl Severity {
    /// The severity label used by libauth (`'error' | 'warn'`).
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warn => "warn",
        }
    }
}

/// The result of [`generate_vmb_tests_from_source_file`]: `{ issues, severity }`.
#[derive(Clone, Debug)]
pub struct SourceFileIssues {
    pub issues: Vec<String>,
    pub severity: Severity,
}

fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    match panic.downcast::<String>() {
        Ok(message) => *message,
        Err(panic) => match panic.downcast::<&str>() {
            Ok(message) => message.to_string(),
            Err(_) => "unknown panic".to_string(),
        },
    }
}

/// (Re)generate and run a VMB tests defined in `filename`, formatting and
/// writing all output files to the generated results directory.
/// @param filename - the filename of the source `.rs` file
/// @returns a `string[]` describing any errors or an empty array if
/// (re)generation and all testing was successful.
///
/// Options (positional): `benchmark` (default: `false`), `console` (default:
/// {@link defaultConsole}), `log_prefix` (default: `''`), `ignore_warnings`
/// (default: `false`).
pub fn generate_vmb_tests_from_source_file(
    filename: &str,
    cache_hash: &str,
    benchmark: Option<bool>,
    console: Option<&Console>,
    log_prefix: Option<&str>,
    ignore_warnings: Option<bool>,
) -> SourceFileIssues {
    let benchmark = benchmark.unwrap_or(false);
    let console = console.unwrap_or(&defaultConsole);
    let log_prefix = log_prefix.unwrap_or("");
    let ignore_warnings = ignore_warnings.unwrap_or(false);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        generate_vmb_tests_from_source_file_inner(filename, cache_hash, benchmark, console, log_prefix, ignore_warnings)
    }));
    let error = match outcome {
        Ok(Ok(result)) => return result,
        Ok(Err(error)) => error,
        Err(panic) => panic_message(panic),
    };
    let message = format!("Error generating {filename}: Error: {error}");
    (console.error)(message.clone());
    SourceFileIssues {
        issues: vec![message],
        severity: Severity::Error,
    }
}

/// A value for each VM mode (libauth's `{ standard, nonstandard }` objects).
#[derive(Default)]
struct ByMode<T> {
    standard: T,
    nonstandard: T,
}

impl<T> ByMode<T> {
    fn get_mut(&mut self, mode: &str) -> &mut T {
        if mode == "standard" {
            &mut self.standard
        } else {
            &mut self.nonstandard
        }
    }
    fn get(&self, mode: &str) -> &T {
        if mode == "standard" {
            &self.standard
        } else {
            &self.nonstandard
        }
    }
}

/// `[using, testSet, severity]`
type IssueOccurrence = (String, String, Severity);

#[allow(clippy::too_many_lines)]
fn generate_vmb_tests_from_source_file_inner(
    filename: &str,
    cache_hash: &str,
    benchmark: bool,
    console: &Console,
    log_prefix: &str,
    ignore_warnings: bool,
) -> Result<SourceFileIssues, String> {
    (console.log)(format!("{log_prefix}Generating VMB tests from {filename}..."));
    let import_start = Instant::now();
    // libauth appends `?h=${cacheHash}` to the import specifier to bypass the
    // module cache; compiled-in sources are always current.
    let _ = cache_hash;
    let imported = compiled_source(filename).ok_or_else(|| {
        format!("Error: the default export of {filename} must an array of test definition groups.")
    })?;
    let test_groups: &Vec<VmbTestDefinitionGroup> = imported;
    let import_end = Instant::now();
    let import_time = format!("{:.0}", (import_end - import_start).as_secs_f64() * 1000.0);
    (console.log)(format!("{log_prefix}{filename}: imported in {import_time}ms..."));
    let generation_start = Instant::now();
    let tests = test_groups
        .iter()
        .map(vmb_test_group_to_vmb_tests)
        .collect::<Result<Vec<_>, String>>()?;
    let all_test_cases: Vec<VmbTestMasterBch> = tests.into_iter().flatten().flatten().collect();
    let partitioned_test_cases = vmb_test_partition_master_test_list(&all_test_cases);
    // libauth iterates the partitioned test sets in insertion order.
    let mut test_set_names: Vec<&str> = Vec::new();
    for test_case in &all_test_cases {
        for test_set in &test_case.test_sets {
            if !test_set_names.contains(&test_set.as_str()) {
                test_set_names.push(test_set);
            }
        }
    }
    let filename_without_js = filename.replacen(".rs", "", 1);
    let generation_time = format!("{:.0}", elapsed_ms(generation_start));
    (console.log)(format!(
        "{log_prefix}{filename}: test generation complete in {generation_time}ms..."
    ));

    // A mapping of unexpected VMB test results (i.e. tests that pass but are
    // expected to fail, or vice versa.) to the test set(s) in which the
    // issues occur.
    let mut issues: Vec<(String, Vec<IssueOccurrence>)> = Vec::new();
    // Queue up benchmarks to run after any issues have been logged (for faster
    // results).
    let mut benchmark_functions: Vec<Box<dyn FnOnce() -> Result<(), String> + '_>> = Vec::new();

    let vms = vms();
    let find_vm = |name: &str| vms.iter().find(|(vm_name, _)| *vm_name == name).map(|(_, vm)| vm.clone());

    let annotation_start = Instant::now();

    for test_set_name in test_set_names {
        let test_set = &partitioned_test_cases[test_set_name];
        let full_test_set_name = format!("bch_{test_set_name}");
        if skipDirectoryPrefixes
            .iter()
            .any(|prefix| full_test_set_name.starts_with(prefix))
        {
            let mut warned_once = warnedOnce.lock().expect("unpoisoned");
            if !*warned_once {
                *warned_once = true;
                (console.log)(format!(
                    "{log_prefix}Note that annotation and benchmarking are currently being skipped for test sets with prefixes: {}.",
                    skipDirectoryPrefixes.join(", ")
                ));
            }
            continue;
        }
        let test_set_dir = result_dir().join(&full_test_set_name);
        let file_base = test_set_dir.join(&filename_without_js).to_string_lossy().into_owned();
        let test_contents = format_vmb_test_set(test_set);
        let test_file = format!("{file_base}.vmb_tests.json");
        std::fs::create_dir_all(&test_set_dir).map_err(|error| format!("{}: {error}", test_set_dir.display()))?;
        std::fs::write(&test_file, test_contents).map_err(|error| format!("{test_file}: {error}"))?;
        let test_set_base = &full_test_set_name[..full_test_set_name.rfind('_').expect("a test set type")];
        let non_std_vm_id = format!("{test_set_base}_nonstandard");
        let standard_vm_id = format!("{test_set_base}_standard");
        let nonstandard_vm: TestedVM = find_vm(&non_std_vm_id)
            .ok_or_else(|| format!("Could not find a nonstandard VM for {non_std_vm_id}."))?;
        let standard_vm: TestedVM = find_vm(&standard_vm_id)
            .ok_or_else(|| format!("Could not find a standard VM for {standard_vm_id}."))?;

        // A mapping of test IDs to the result of vm.verify for that VMB test.
        let mut results: ByMode<JsObject<Json>> = ByMode::default();
        // A mapping of test IDs to the summarized limit information for the
        // input under test. Note that VMB tests with no indicated input index
        // are test input 0 by default.
        //
        // Limit information is an array of 3 integers (and the description):
        // 1. The Density Control Length of the input under test.
        // 2. The maximum allowed operation cost given the input length.
        // 3. The measured cumulative operation cost following evaluation.
        let mut limits: ByMode<JsObject<Json>> = ByMode::default();
        let mut header = String::new();
        // CSV breakdown of all measured stats
        let mut stats: ByMode<Vec<Vec<String>>> = ByMode::default();
        let mut bench = ByMode {
            nonstandard: Bench::new(),
            standard: Bench::new(),
        };
        // `{ [shortId]: { txLength } }`
        let baseline_stats = baselineTxBin.len();
        let mut bench_map: ByMode<JsObject<usize>> = ByMode::default();

        if benchmark {
            let vm = standard_vm.clone();
            bench.standard.add(baselineId, move || {
                let _ = vm.verify(&baseline);
            });
            let vm = nonstandard_vm.clone();
            bench.nonstandard.add(baselineId, move || {
                let _ = vm.verify(&baseline);
            });
        }
        for test_case in test_set {
            let short_id = test_case.short_id.as_str();
            let description = test_case.test_description.as_str();
            let input_index = test_case.input_index.unwrap_or(0);
            let source_outputs_bin = hex_to_bin(&test_case.source_outputs_hex);
            let tx_bin = hex_to_bin(&test_case.test_transaction_hex);

            let source_outputs_read = read_transaction_outputs(ReadPosition {
                bin: &source_outputs_bin,
                index: 0,
            });
            let transaction_read = read_transaction_common(ReadPosition { bin: &tx_bin, index: 0 });
            let source_outputs = match source_outputs_read {
                Err(error) => {
                    results.nonstandard.set(short_id, Json::String(error.clone()));
                    results.standard.set(short_id, Json::String(error));
                    // Since this test is designed to fail UTXO parsing, it will
                    // be excluded from the `*.limits.json` and `*.stats.csv`
                    // files.
                    continue;
                }
                Ok(read) => read.result,
            };
            let transaction = match transaction_read {
                Err(error) => {
                    results.nonstandard.set(short_id, Json::String(error.clone()));
                    results.standard.set(short_id, Json::String(error));
                    // Since this test is designed to fail transaction parsing, it
                    // will be excluded from the `*.limits.json` and `*.stats.csv`
                    // files.
                    continue;
                }
                Ok(read) => read.result,
            };

            for (mode, vm) in [("standard", &standard_vm), ("nonstandard", &nonstandard_vm)] {
                let resolved_tx = ResolvedTransactionCommon {
                    source_outputs: source_outputs.clone(),
                    transaction: transaction.clone(),
                };
                if benchmark {
                    let (bench_vm, bench_tx) = (vm.clone(), resolved_tx.clone());
                    bench.get_mut(mode).add(short_id, move || {
                        let _ = bench_vm.verify(&bench_tx);
                    });
                }
                let result = vm.verify(&resolved_tx);
                results.get_mut(mode).set(
                    short_id,
                    match &result {
                        Ok(()) => Json::Bool(true),
                        Err(error) => Json::String(error.clone()),
                    },
                );
                let final_state = vm.evaluate(
                    &AuthenticationProgramCommon {
                        input_index,
                        source_outputs: source_outputs.clone(),
                        transaction: transaction.clone(),
                    },
                    None,
                );
                let metrics = &final_state.metrics;
                let density_control_length = metrics.density_control_length;
                let arithmetic_cost = metrics.arithmetic_cost;
                let evaluated_instruction_count = metrics.evaluated_instruction_count;
                let hash_digest_iterations = metrics.hash_digest_iterations;
                let maximum_hash_digest_iterations = metrics.maximum_hash_digest_iterations;
                let maximum_operation_cost = metrics.maximum_operation_cost;
                let maximum_signature_check_count = metrics.maximum_signature_check_count;
                let operation_cost = metrics.operation_cost;
                let signature_check_count = metrics.signature_check_count;
                let stack_pushed_bytes = metrics.stack_pushed_bytes;
                limits.get_mut(mode).set(
                    short_id,
                    Json::Array(vec![
                        Json::Number(js_number(density_control_length)),
                        Json::Number(js_number(maximum_operation_cost)),
                        Json::Number(js_number(operation_cost)),
                        Json::String(description.to_string()),
                    ]),
                );
                let stats_config: [(&str, String); 16] = [
                    ("Test ID", short_id.to_string()),
                    ("Description", format!("\"{description}\"")),
                    ("Transaction Length", tx_bin.len().to_string()),
                    ("UTXOs Length", source_outputs_bin.len().to_string()),
                    ("UTXO Count", source_outputs.len().to_string()),
                    ("Tested Input Index", input_index.to_string()),
                    ("Density Control Length", js_number(density_control_length)),
                    ("Maximum Operation Cost", js_number(maximum_operation_cost)),
                    ("Operation Cost", js_number(operation_cost)),
                    ("Maximum SigChecks", js_number(maximum_signature_check_count)),
                    ("SigChecks", js_number(signature_check_count)),
                    ("Maximum Hash Digest Iterations", js_number(maximum_hash_digest_iterations)),
                    ("Hash Digest Iterations", js_number(hash_digest_iterations)),
                    ("Evaluated Instructions", js_number(evaluated_instruction_count)),
                    ("Stack Pushed Bytes", js_number(stack_pushed_bytes)),
                    ("Arithmetic Cost", js_number(arithmetic_cost)),
                ];
                if header.is_empty() {
                    header = stats_config.iter().map(|(label, _)| *label).collect::<Vec<_>>().join(",");
                }
                let stats_entry: Vec<String> = stats_config.into_iter().map(|(_key, value)| value).collect();
                stats.get_mut(mode).push(stats_entry);
                bench_map.get_mut(mode).set(short_id, tx_bin.len());
                let is_standard = mode == "standard";
                // In standard mode:
                // - `standard` tests are expected to succeed,
                // - `nonstandard` and `invalid` tests are expected to reject.
                //
                // In nonstandard mode:
                // - `standard` and `nonstandard` tests are expected to succeed,
                // - `invalid` tests are expected to reject.
                let from_standard_set = full_test_set_name.contains("_standard");
                let from_nonstandard_set = full_test_set_name.contains("_nonstandard");
                let from_invalid_set = full_test_set_name.contains("invalid");
                let expected_to_succeed = if is_standard { from_standard_set } else { !from_invalid_set };
                let using = if mode == "standard" { &standard_vm_id } else { &non_std_vm_id };
                let mut mark_issue = |error: String, severity: Severity| {
                    let occurrence = (using.clone(), full_test_set_name.clone(), severity);
                    match issues.iter_mut().find(|(issue, _)| *issue == error) {
                        Some((_, occurrences)) => occurrences.push(occurrence),
                        None => issues.push((error, vec![occurrence])),
                    }
                };
                if input_index as isize > source_outputs.len() as isize - 1 {
                    mark_issue(
                        format!(
                            "Malformed VMB test in {filename}: test ID \"{short_id}\" (\"{description}\") is configured to test input index {input_index}, but the highest input index is {}. Please correct this test to specify a valid tested index.",
                            source_outputs.len() as isize - 1
                        ),
                        Severity::Error,
                    );
                    continue;
                }
                let message = match (&result, expected_to_succeed) {
                    (Err(error), true) => Some(format!(
                        "VMB test failure in {filename}: test ID \"{short_id}\" (\"{description}\") was expected to succeed but rejected with error: {error}"
                    )),
                    (Ok(()), false) => Some(format!(
                        "VMB test failure in {filename}: test ID \"{short_id}\" (\"{description}\") was expected to fail but succeeded."
                    )),
                    _ => None,
                };
                if let Some(message) = message {
                    mark_issue(message, Severity::Error);
                    continue;
                }
                // Note, the below checks only execute if no issues have occurred
                // (we avoid cluttering development with the additional errors if
                // the above validation already failed).
                let prefix = 4;
                let vm_year = &test_set_base[prefix..];

                let bchn_tested_years = ["2023", "2025"];
                if !bchn_tested_years.contains(&vm_year) {
                    continue;
                }
                let matched_bchn_result = verify_expected_error_message(is_standard, &result, short_id, vm_year);
                if matched_bchn_result == Ok(false) {
                    mark_issue(
                        format!(
                            "[warning] New VMB test in {filename}: test ID \"{short_id}\" (\"{description}\") was not found in the BCHN fail reasons. Please evaluate new tests in BCHN and update the reasons file ({}) by running: \"yarn bchn:update-vmb-tests\"",
                            failReasonsPath.display()
                        ),
                        Severity::Warn,
                    );
                    continue;
                }
                // TODO: review remaining reasons
                let skip_reasons = true;
                if let (false, Err(matched_bchn_result)) = (skip_reasons, &matched_bchn_result) {
                    mark_issue(
                        format!(
                            "[warning] VMB test failure in {filename}: test ID \"{short_id}\" (\"{description}\") evaluated result is inconsistent with BCHN's expected result. {matched_bchn_result}"
                        ),
                        Severity::Warn,
                    );
                    continue;
                }
                // Any "metrics" from 2023 are not consensus standardized, so they
                // are not expected to match between Libauth and BCHN.
                let excluded = "2023";
                if vm_year == excluded
                    // BCHN does not export metrics from mismatched evaluations,
                    // so all possible checks for this evaluation are now complete.
                    || (is_standard && !from_standard_set)
                    || (!is_standard && !from_nonstandard_set)
                {
                    continue;
                }
                let Some(bchn_metrics) = get_bchn_metrics(is_standard, short_id, vm_year) else {
                    mark_issue(
                        format!(
                            "[warning] New VMB test in {filename}: test ID \"{short_id}\" (\"{description}\") was not found in the BCHN test metrics. Please evaluate new tests in BCHN and update the metrics file ({}) by running: \"yarn bchn:update-vmb-tests\"",
                            testMetricsPath.display()
                        ),
                        Severity::Warn,
                    );
                    continue;
                };
                let input = bchn_metrics
                    .get(input_index)
                    .copied()
                    // "scriptonly" tests only provide metrics for the tested index
                    .or_else(|| {
                        bchn_metrics
                            .iter()
                            .find(|metrics| metrics.input_index == input_index as f64)
                            .copied()
                    });
                let Some(input) = input else {
                    return Err(format!(
                        "Issue in BCHN metrics file at {}: metrics are not provided for input index {input_index} in entry – vmYear: {vm_year}, isStandard: {is_standard}, shortId: {short_id}; this happens for \"scriptonly\" cases. If this is expected, add \"{short_id}\" to \"reviewedScriptOnlyIds\".",
                        testMetricsPath.display()
                    ));
                };
                if input.hash_iterations != hash_digest_iterations
                    || (input.hash_iterations_limit != Some(maximum_hash_digest_iterations)
                        && input.hash_iterations_limit.is_some())
                    || input.operation_cost != operation_cost
                    || (input.operation_cost_limit != Some(maximum_operation_cost)
                        && input.operation_cost_limit.is_some())
                    || input.sig_checks != signature_check_count
                    || (input.sig_checks_limit != Some(maximum_signature_check_count) && input.sig_checks_limit.is_some())
                {
                    let limit = |limit: Option<f64>| limit.map_or("null".to_string(), js_number);
                    mark_issue(
                        format!(
                            "[metrics] VMB test failure in {filename}: test ID \"{short_id}\" (\"{description}\") evaluated metrics are inconsistent with BCHN's metrics.
Libauth metrics: {} hash iterations ({} max), {} operation cost ({} max), {} sigChecks ({} max)
BCHN metrics: {} hash iterations ({} max), {} operation cost ({} max), {} sigChecks ({} max)
This is a vulnerability in one of the implementations, please confidentially report this issue: https://github.com/bitauth/libauth/security",
                            js_number(hash_digest_iterations),
                            js_number(maximum_hash_digest_iterations),
                            js_number(operation_cost),
                            js_number(maximum_operation_cost),
                            js_number(signature_check_count),
                            js_number(maximum_signature_check_count),
                            js_number(input.hash_iterations),
                            limit(input.hash_iterations_limit),
                            js_number(input.operation_cost),
                            limit(input.operation_cost_limit),
                            js_number(input.sig_checks),
                            limit(input.sig_checks_limit),
                        ),
                        Severity::Error,
                    );
                }
            }
        }

        for mode in ["standard", "nonstandard"] {
            let results_file = format!("{file_base}.{mode}_results.json");
            let results_contents = format_vmb_dictionary(results.get(mode));
            std::fs::write(&results_file, results_contents).map_err(|error| format!("{results_file}: {error}"))?;
            let limits_file = format!("{file_base}.{mode}_limits.json");
            let limits_contents = format_vmb_dictionary(limits.get(mode));
            std::fs::write(&limits_file, limits_contents).map_err(|error| format!("{limits_file}: {error}"))?;
            let stats_file = format!("{file_base}.{mode}_stats.csv");
            let csv = format!(
                "{header}\n{}",
                stats
                    .get(mode)
                    .iter()
                    .map(|row| row.join(","))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            std::fs::write(&stats_file, csv).map_err(|error| format!("{stats_file}: {error}"))?;
        }

        if benchmark {
            let log_prefix = log_prefix.to_string();
            let filename = filename.to_string();
            let results_by_mode: ByMode<HashMap<String, bool>> = ByMode {
                standard: results
                    .standard
                    .entries()
                    .into_iter()
                    .map(|(id, result)| (id.to_string(), *result == Json::Bool(true)))
                    .collect(),
                nonstandard: results
                    .nonstandard
                    .entries()
                    .into_iter()
                    .map(|(id, result)| (id.to_string(), *result == Json::Bool(true)))
                    .collect(),
            };
            let (standard_vm_id, non_std_vm_id) = (standard_vm_id.clone(), non_std_vm_id.clone());
            let full_test_set_name = full_test_set_name.clone();
            let file_base = file_base.clone();
            let mut bench = bench;
            benchmark_functions.push(Box::new(move || {
                for mode in ["standard", "nonstandard"] {
                    let using = if mode == "standard" { &standard_vm_id } else { &non_std_vm_id };
                    (console.log)(format!("{log_prefix}{filename}: benchmarking {full_test_set_name} using {using}..."));
                    let start = Instant::now();
                    bench.get_mut(mode).warmup();
                    bench.get_mut(mode).run();
                    let bench_mode = bench.get(mode);
                    let baseline_mean = assert_non_null(
                        bench_mode.get_task(baselineId).and_then(|task| task.result.as_ref()).map(|result| result.mean),
                        None,
                    );
                    let bench_results: Vec<(f64, String, f64, bool, f64, f64, usize)> = bench_mode
                        .tasks()
                        .iter()
                        .map(|task| {
                            let result = assert_non_null(task.result.as_ref(), None);
                            let relative_time = result.mean / baseline_mean;
                            let id = task.name.clone();
                            let passes = id == baselineId
                                || results_by_mode.get(mode).get(&id).copied().unwrap_or(false);
                            (result.hz, id, result.mean, passes, relative_time, result.rme, result.samples.len())
                        })
                        .collect();
                    let bench_file = format!("{file_base}.{mode}_bench.csv");
                    let digits = 6;
                    let lines = bench_results
                        .iter()
                        .map(|(hz, id, mean, passes, relative_time, rme, samples)| {
                            let test_stats = if id == baselineId {
                                Some(baseline_stats)
                            } else {
                                bench_map.get(mode).get(id).copied()
                            };
                            let Some(tx_length) = test_stats else {
                                return Err(format!("Missing bench stats for mode: {mode} id: {id}"));
                            };
                            let relative_time_per_tx_byte = relative_time * (baselineTxBin.len() as f64 / tx_length as f64);
                            Ok([
                                id.clone(),
                                to_precision(relative_time_per_tx_byte, digits),
                                to_precision(*relative_time, digits),
                                to_precision(*hz, digits),
                                to_precision(*mean, digits),
                                to_precision(*rme, digits),
                                samples.to_string(),
                                if *passes { "A" } else { "R" }.to_string(),
                            ]
                            .join(","))
                        })
                        .collect::<Result<Vec<_>, String>>()?;
                    let csv = format!("{benchHeader}\n{}", lines.join("\n"));
                    std::fs::write(&bench_file, csv).map_err(|error| format!("{bench_file}: {error}"))?;
                    let ms = format!("{:.0}", elapsed_ms(start));
                    (console.log)(format!("{log_prefix}{filename}: benchmarked {full_test_set_name} using {using} in {ms}ms."));
                }
                Ok(())
            }));
        }
    }

    let hide_warnings = issues
        .iter()
        .any(|(_, runs)| runs.iter().any(|occurrence| occurrence.2 == Severity::Error));
    if hide_warnings {
        (console.error)("\nErrors found, hiding warnings...\n".to_string());
    }

    let issue_messages: Vec<String> = issues
        .iter()
        .filter(|(_, occurrences)| {
            if hide_warnings || ignore_warnings {
                occurrences.iter().any(|occurrence| occurrence.2 == Severity::Error)
            } else {
                true
            }
        })
        .enumerate()
        .map(|(index, (issue, occurrences))| {
            let mut by_set: Vec<(&str, Vec<&str>)> = Vec::new();
            for (vm, set, _) in occurrences {
                match by_set.iter_mut().find(|(existing, _)| *existing == set.as_str()) {
                    Some((_, vms)) => vms.push(vm),
                    None => by_set.push((set, vec![vm])),
                }
            }
            let runs = by_set
                .iter()
                .map(|(set, vm)| {
                    format!(
                        "{}{}",
                        vm.join(", "),
                        if set.is_empty() { String::new() } else { format!(" (set: {set})") }
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            let message = format!("{index}. {issue} Occurred in: {runs}");
            let first_vm = occurrences.first().map_or("undefined", |occurrence| occurrence.0.as_str());
            let id = message
                .find("test ID \"")
                .map(|start| &message[start + "test ID \"".len()..])
                .map(|rest| {
                    rest.chars()
                        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                        .collect::<String>()
                })
                .filter(|id| message.contains(&format!("test ID \"{id}\"")) && !id.is_empty())
                .unwrap_or_else(|| "undefined".to_string());
            let output = if hide_warnings { console.error } else { console.warn };
            output(format!(
                "{message}\nFor more detailed debugging information, try e.g.: \"cargo run --release --example run-bch-vmb-test -- {first_vm} {id} [-v]\"\n"
            ));
            message
        })
        .collect();

    let annotation_end = Instant::now();
    let annotation_time = format!("{:.0}", (annotation_end - annotation_start).as_secs_f64() * 1000.0);
    let build_ms = (annotation_end - import_start).as_secs_f64() * 1000.0;
    let build_time = format!("{build_ms:.0}");
    (console.log)(format!(
        "{log_prefix}{filename}: finished in {build_time}ms: imported in {import_time}ms, generated in {generation_time}ms, annotated in {annotation_time}ms."
    ));

    if benchmark {
        let bench_start = Instant::now();
        (console.log)(format!("{log_prefix}{filename}: Benchmarking..."));
        for benchmark_fn in benchmark_functions {
            benchmark_fn()?;
        }
        let bench_ms = elapsed_ms(bench_start);
        let bench_time = format!("{bench_ms:.0}");
        let total_time = format!("{:.0}", build_ms + bench_ms);
        (console.log)(format!(
            "{log_prefix}{filename}: finished and benchmarked in {total_time}ms: imported in {import_time}ms, generated in {generation_time}ms, annotated in {annotation_time}ms, benchmarked in {bench_time}ms."
        ));
    }
    Ok(SourceFileIssues {
        issues: issue_messages,
        severity: if hide_warnings { Severity::Error } else { Severity::Warn },
    })
}

/* ------------------------------------------------------------------------- */

fn parse_vmb_test(json: &Json) -> Result<VmbTest, String> {
    let fields = json.as_array().ok_or("a VMB test must be an array")?;
    let string_field = |index: usize| -> Result<String, String> {
        fields
            .get(index)
            .and_then(Json::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("VMB test field {index} must be a string"))
    };
    Ok(VmbTest {
        short_id: string_field(0)?,
        test_description: string_field(1)?,
        unlocking_script_asm: string_field(2)?,
        redeem_or_locking_script_asm: string_field(3)?,
        test_transaction_hex: string_field(4)?,
        source_outputs_hex: string_field(5)?,
        input_index: fields.get(6).and_then(Json::as_u64).map(|index| index as usize),
    })
}

/// The VMB tests of one `.vmb_tests.json` file (`{ file, tests }`).
pub type VmbTestFile = (String, Vec<VmbTest>);

/// Read, parse, and return the full contents of all `.vmb_tests.json` files.
/// @param filterDirectories - if provided, only the VMB tests within directories
/// matching this filter will be returned.
///
/// Returns each directory with its files (`{ directory, files }[]`).
pub fn import_vmb_tests(filter_directories: Option<&str>) -> Result<Vec<(String, Vec<VmbTestFile>)>, String> {
    let result_dir = result_dir();
    let mut vm_directories: Vec<String> = std::fs::read_dir(&result_dir)
        .map_err(|error| format!("{}: {error}", result_dir.display()))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    vm_directories.sort();
    let filtered_directories = vm_directories
        .into_iter()
        .filter(|name| filter_directories.is_none_or(|filter| name.contains(filter)));
    filtered_directories
        .map(|vm_directory| {
            let dir_path = result_dir.join(&vm_directory);
            let mut file_names: Vec<String> = std::fs::read_dir(&dir_path)
                .map_err(|error| format!("{}: {error}", dir_path.display()))?
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|file| file.ends_with(".vmb_tests.json"))
                .collect();
            file_names.sort();
            let files = file_names
                .into_iter()
                .map(|file| {
                    let file_path = dir_path.join(&file);
                    let content = std::fs::read_to_string(&file_path)
                        .map_err(|error| format!("{}: {error}", file_path.display()))?;
                    let parsed = parse_json(&content).map_err(|error| {
                        format!("Failed to parse contents of {}: {error}", file_path.display())
                    })?;
                    let tests = parsed
                        .as_array()
                        .ok_or_else(|| format!("{} must contain an array", file_path.display()))?
                        .iter()
                        .map(parse_vmb_test)
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok((file, tests))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok((vm_directory, files))
        })
        .collect()
}

/// Check for duplicate VMB test IDs or descriptions among all `.vmb_tests.json`
/// files in each VM test set.
/// @returns a `string[]` describing all conflicts found or an empty array if no
/// conflicts are found.
pub fn check_vmb_tests_for_conflicts() -> Vec<String> {
    let directories = match import_vmb_tests(None) {
        Ok(directories) => directories,
        Err(error) => {
            let message = format!("Error checking for duplicate test IDs and descriptions: Error: {error}");
            eprintln!("{message}");
            return vec![message];
        }
    };
    let mut conflicts: Vec<(String, Vec<String>)> = Vec::new();
    let mut mark_conflict = |directory: &str, message: String| {
        match conflicts.iter_mut().find(|(conflict, _)| *conflict == message) {
            Some((_, sets)) => sets.push(directory.to_string()),
            None => conflicts.push((message, vec![directory.to_string()])),
        }
    };
    for (directory, files) in &directories {
        let mut id_map: BTreeMap<&str, (&str, &str)> = BTreeMap::new();
        let mut desc_map: BTreeMap<&str, (&str, &str)> = BTreeMap::new();
        for (file, tests) in files {
            for test in tests {
                let (id, description) = (test.short_id.as_str(), test.test_description.as_str());
                match id_map.get(id) {
                    None => {
                        id_map.insert(id, (file, description));
                    }
                    Some((first_file, first_description)) => mark_conflict(
                        directory,
                        format!(
                            "Duplicate VMB test ID: \"{id}\" is first found in \n{first_file}, description: \"{first_description}\" but later found in \n{file}, description: \"{description}\""
                        ),
                    ),
                }
                match desc_map.get(description) {
                    None => {
                        desc_map.insert(description, (file, id));
                    }
                    Some((first_file, first_id)) => mark_conflict(
                        directory,
                        format!(
                            "Duplicate VMB test description: \"{description}\" is first found in \n{first_file}, test ID: \"{first_id}\" but later found in \n{file}, test ID: \"{id}\""
                        ),
                    ),
                }
            }
        }
        let is_standard_annual_set = directory.split('_').nth(2) == Some("standard");
        let missing_baseline = !id_map.contains_key(baselineId);
        if is_standard_annual_set && missing_baseline {
            mark_conflict(
                directory,
                format!(
                    "The baseline VMB test ID, \"{baselineId}\" was not found. If it's been modified, please be sure to update it throughout the codebase."
                ),
            );
        }
    }
    conflicts
        .into_iter()
        .enumerate()
        .map(|(index, (issue, sets))| {
            let message = format!("{index}. {issue}\nTest sets: {}\n", sets.join(", "));
            eprintln!("{message}");
            message
        })
        .collect()
}

/* ------------------------------------------------------------------------- */

/// A message from the main thread to a worker (`{ type: 'generate', data }` or
/// `{ type: 'shutdown' }`).
pub enum WorkerMessage {
    Generate(WorkerTask),
    Shutdown,
}

/// A message from a worker to the main thread (`{ type: 'error' | 'log' |
/// 'warn', args }` or `{ type: 'result', data }`).
pub enum ParentMessage {
    Error(String),
    Log(String),
    Warn(String),
    Result(WorkerResult),
}

/// A worker thread (libauth's `worker_threads` `Worker`).
pub struct Worker {
    pub index: usize,
    sender: Sender<WorkerMessage>,
    handle: Mutex<Option<JoinHandle<()>>>,
    /// The messages of all workers, tagged with the sending worker's index.
    messages: Arc<Mutex<Receiver<(usize, ParentMessage)>>>,
}

impl Worker {
    pub fn post_message(&self, message: WorkerMessage) {
        if self.sender.send(message).is_err() {
            eprintln!("Worker {} is not running.", self.index);
        }
    }
    /// Wait for the worker thread to exit (after a `Shutdown` message).
    pub fn join(&self) {
        if let Some(handle) = self.handle.lock().expect("unpoisoned").take() {
            if handle.join().is_err() {
                eprintln!("Worker {} stopped with an error.", self.index);
            }
        }
    }
}

pub struct WorkerWrapper {
    pub worker: Worker,
}
#[derive(Clone, Debug)]
pub struct WorkerTask {
    pub file: String,
    pub hash: String,
}
#[derive(Clone, Debug)]
pub struct WorkerResult {
    pub file: String,
    pub hash: String,
    pub file_issues: Vec<String>,
    pub severity: Severity,
}

/// The stack size of worker threads (deeply-nested CashAssembly is compiled
/// recursively).
const workerStackSize: usize = 256 * 1024 * 1024;

pub fn create_workers(count: usize, benchmark: bool, ignore_warnings: bool) -> Vec<WorkerWrapper> {
    let (parent_port, messages) = channel::<(usize, ParentMessage)>();
    let messages = Arc::new(Mutex::new(messages));
    (0..count)
        .map(|index| {
            let (sender, receiver) = channel::<WorkerMessage>();
            let parent_port = parent_port.clone();
            let handle = std::thread::Builder::new()
                .name(format!("vmb-worker-{index}"))
                .stack_size(workerStackSize)
                .spawn(move || {
                    worker_main(
                        WorkerData {
                            benchmark,
                            ignore_warnings,
                            index,
                        },
                        receiver,
                        parent_port,
                    );
                })
                .unwrap_or_else(|error| panic!("Error from worker {index}: {error}"));
            WorkerWrapper {
                worker: Worker {
                    index,
                    sender,
                    handle: Mutex::new(Some(handle)),
                    messages: Arc::clone(&messages),
                },
            }
        })
        .collect()
}

/// (Re)generate all VMB tests, verifying all expected results and checking for
/// duplicate IDs/descriptions.
/// @param workers - if provided, these workers will be used during
/// generation rather than the current thread.
/// @param options - options for generation (positional: `benchmark`,
/// `delete_unexpected`, `ignore_warnings`; all default to `false`)
/// @param changedFile - if provided, only regenerate this specific file
/// @returns a list of any regeneration or validation errors or – if no issues
/// are found – an empty array (or a message if unexpected files are found).
/// Errors libauth throws are returned as `Err`.
pub fn generate_vmb_tests(
    workers: Option<&[WorkerWrapper]>,
    benchmark: Option<bool>,
    delete_unexpected: Option<bool>,
    ignore_warnings: Option<bool>,
    changed_file: Option<&str>,
) -> Result<GenerateVmbTestsResult, String> {
    let benchmark = benchmark.unwrap_or(false);
    let delete_unexpected = delete_unexpected.unwrap_or(false);
    let ignore_warnings = ignore_warnings.unwrap_or(false);
    let bases: Vec<String> = get_sources().iter().map(|name| name.replacen(".rs", "", 1)).collect();
    let suffixes = [
        ".nonstandard_bench.csv",
        ".nonstandard_limits.json",
        ".nonstandard_results.json",
        ".nonstandard_stats.csv",
        ".standard_bench.csv",
        ".standard_limits.json",
        ".standard_results.json",
        ".standard_stats.csv",
        ".vmb_tests.json",
    ];
    let result_dir = result_dir();
    let mut result_sub_dirs: Vec<String> = std::fs::read_dir(&result_dir)
        .map_err(|error| format!("{}: {error}", result_dir.display()))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    result_sub_dirs.sort();
    let mut unexpected_files: Vec<PathBuf> = Vec::new();
    for sub_dir in &result_sub_dirs {
        let sub_dir_path = result_dir.join(sub_dir);
        let mut files: Vec<String> = std::fs::read_dir(&sub_dir_path)
            .map_err(|error| format!("{}: {error}", sub_dir_path.display()))?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        files.sort();
        for file in files {
            let expected = file.ends_with(".scriptonly.json")
                || bases.iter().any(|base| {
                    file.starts_with(base.as_str()) && suffixes.iter().any(|suffix| file == format!("{base}{suffix}"))
                });
            if !expected {
                unexpected_files.push(sub_dir_path.join(file));
            }
        }
    }

    if !unexpected_files.is_empty() {
        if delete_unexpected {
            for file in &unexpected_files {
                std::fs::remove_file(file).map_err(|error| format!("{}: {error}", file.display()))?;
                println!("Deleted unexpected file: {}", file.display());
            }
        } else {
            let message = format!(
                "Found unexpected files in the result directory that do not correspond to any source files:\n{}\n\nTo automatically delete these unexpected files, re-run generation with the '-d' flag.",
                unexpected_files
                    .iter()
                    .map(|file| file.display().to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            eprintln!("{message}");
            return Ok(GenerateVmbTestsResult::Message(message));
        }
    }

    println!("Generating vmb_tests...");
    let manifest_path = if benchmark { bench_info_path() } else { build_info_path() };
    println!("Using manifest: {}", manifest_path.display());

    let mut current_manifest = get_previous_manifest(&manifest_path);
    let new_manifest = get_latest_manifest()?;

    let choose_files_to_regenerate = |specific_file: Option<&str>| -> Vec<(String, String)> {
        if let Some(specific_file) = specific_file {
            if let Some(hash) = new_manifest.get(specific_file) {
                println!("Processing only changed file: {specific_file}");
                return vec![(specific_file.to_string(), hash.clone())];
            }
            println!("Changed file ({specific_file}) not found in manifest, processing all modified files.");
        }
        new_manifest
            .entries()
            .into_iter()
            .filter(|(file, hash)| current_manifest.get(file) != Some(*hash))
            .map(|(file, hash)| (file.to_string(), hash.clone()))
            .collect()
    };
    let modified_files = choose_files_to_regenerate(changed_file);
    let generation_start = Instant::now();
    println!(
        "{} modified files: {}",
        modified_files.len(),
        modified_files.iter().map(|(file, _)| file.as_str()).collect::<Vec<_>>().join(", ")
    );
    let mut issues: Vec<String> = Vec::new();
    let mut save_on_success = |file_name: &str, new_hash: &str, file_issues: Vec<String>| {
        if file_issues.is_empty() {
            current_manifest.set(file_name, new_hash.to_string());
            save_manifest(&manifest_path, &current_manifest);
            return;
        }
        issues.extend(file_issues);
    };

    match workers {
        None => {
            println!("(Not using workers.)");
            for (file, hash) in &modified_files {
                let file_issues = generate_vmb_tests_from_source_file(
                    file,
                    hash,
                    Some(benchmark),
                    None,
                    None,
                    Some(ignore_warnings),
                )
                .issues;
                save_on_success(file, hash, file_issues);
            }
        }
        Some(workers) => {
            let mut waiting: Vec<WorkerTask> = modified_files
                .iter()
                .map(|(file, hash)| WorkerTask {
                    file: file.clone(),
                    hash: hash.clone(),
                })
                .collect();
            let mut assigned: Vec<WorkerTask> = Vec::new();
            let mut complete: Vec<WorkerTask> = Vec::new();
            let assign_next_item =
                |wrapper: &WorkerWrapper, waiting: &mut Vec<WorkerTask>, assigned: &mut Vec<WorkerTask>| {
                    let Some(work_item) = waiting.pop() else {
                        return;
                    };
                    assigned.push(work_item.clone());
                    wrapper.worker.post_message(WorkerMessage::Generate(work_item));
                };
            for wrapper in workers {
                assign_next_item(wrapper, &mut waiting, &mut assigned);
            }
            if let Some(first) = workers.first() {
                let messages = first.worker.messages.lock().expect("unpoisoned");
                while !(waiting.is_empty() && assigned.is_empty()) {
                    let Ok((index, message)) = messages.recv() else {
                        return Err("All workers stopped before the work was complete.".to_string());
                    };
                    match message {
                        ParentMessage::Error(message) => eprintln!("{message}"),
                        ParentMessage::Warn(message) => eprintln!("{message}"),
                        ParentMessage::Log(message) => println!("{message}"),
                        ParentMessage::Result(data) => {
                            let WorkerResult { file, hash, file_issues, .. } = data;
                            save_on_success(&file, &hash, file_issues);
                            let time = format!("{:.0}", elapsed_ms(generation_start));
                            let position = assigned
                                .iter()
                                .position(|item| item.file == file)
                                .expect("an assigned work item");
                            let item = assigned.remove(position);
                            complete.push(item);
                            println!(
                                "After {time}ms: {} files waiting for a worker; {} currently being processed ({}); {} files complete.",
                                waiting.len(),
                                assigned.len(),
                                assigned.iter().map(|task| task.file.as_str()).collect::<Vec<_>>().join(", "),
                                complete.len()
                            );
                            let wrapper = workers
                                .iter()
                                .find(|wrapper| wrapper.worker.index == index)
                                .expect("a known worker");
                            assign_next_item(wrapper, &mut waiting, &mut assigned);
                        }
                    }
                }
            }
        }
    }

    let generation_time = format!("{:.0}", elapsed_ms(generation_start));
    println!("Regenerated all vmb_tests in {generation_time}ms.");

    if !issues.is_empty() {
        return Ok(GenerateVmbTestsResult::Issues(issues));
    }

    let dup_check_start = Instant::now();
    let conflicts = check_vmb_tests_for_conflicts();
    let dup_check_time = format!("{:.0}", elapsed_ms(dup_check_start));
    println!("Checked for duplicated IDs and duplicated descriptions in {dup_check_time}ms.");
    Ok(GenerateVmbTestsResult::Issues(conflicts))
}

/// The result of [`generate_vmb_tests`] (`string | string[]` in libauth).
#[derive(Clone, Debug)]
pub enum GenerateVmbTestsResult {
    /// Unexpected files were found in the result directory (and not deleted).
    Message(String),
    /// Any regeneration or validation errors (empty if no issues are found).
    Issues(Vec<String>),
}
