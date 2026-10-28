//! Run a single VMB test on the requested VM, logging the results and debugging
//! information (`cargo run --example run-bch-vmb-test -- <vm> <test_id> [-v|-b]`).
//!
//! Port addition: `--all [test_set_filter]` evaluates every generated VMB test
//! with the standard and nonstandard VM of its test set and compares each
//! verdict (and libauth's exact error message) with the recorded
//! `*.standard_results.json` and `*.nonstandard_results.json` files. This is
//! the VMB suite which this port is required to pass. The generated VMB tests
//! are not tracked by this repository; see the README.

// libauth names its helpers in camelCase; keep those names.
#![allow(non_upper_case_globals)]

#[path = "bchn/bchn-error-map.spec.helper.rs"]
mod bchn_error_map_spec_helper;
#[path = "bchn/fail-reason-overrides.spec.helper.rs"]
mod fail_reason_overrides_spec_helper;
#[path = "generate-vmb-tests-worker.spec.helper.rs"]
mod generate_vmb_tests_worker_spec_helper;
#[path = "generate-vmb-tests.spec.helper.rs"]
mod generate_vmb_tests_spec_helper;
#[path = "bchn/map-bchn-results.spec.helper.rs"]
mod map_bchn_results_spec_helper;
#[path = "vmb-tests.spec.helper.rs"]
mod vmb_tests_spec_helper;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use generate_vmb_tests_spec_helper::{import_vmb_tests, result_dir};
use libauth::address::is_pay_to_script_hash20;
use libauth::format::{assert_success, elide_words_and_hex_at_length, hex_to_bin, ReadPosition};
use libauth::language::{stringify_debug_trace_summary, summarize_debug_trace};
use libauth::message::{decode_transaction, decode_transaction_outputs, read_transaction_common, read_transaction_outputs};
use libauth::runtime::json::{parse_json, Json};
use libauth::vm::{AuthenticationProgramCommon, ResolvedTransactionCommon};
use libauth::vmb_tests::VmbTest;
use vmb_tests_spec_helper::{baselineBenchmarkId, is_vm, vms, TestedVM};

fn usage_info() -> String {
    format!(
        "
This script runs a single VMB test on the requested VM, logging the results and debugging information. Use the \"--verbose\" (-v) flag to output the full debug trace, or use the \"--bench\" (-b) flag to benchmark the VM's validation performance for the specified test.

Available VMs: {}

Usage: cargo run --release --example run-bch-vmb-test -- <vm> <test_id> [-v OR -b]
E.g.: cargo run --release --example run-bch-vmb-test -- bch_2023_standard trxhzt
      cargo run --release --example run-bch-vmb-test -- bch_2025_standard trxhzt --verbose  # or -v
      cargo run --release --example run-bch-vmb-test -- bch_spec_standard trxhzt --bench    # or -b

Verify every generated VMB test (optionally filtering test sets):
      cargo run --release --example run-bch-vmb-test -- --all [bch_2023]
",
        vms().iter().map(|(name, _)| *name).collect::<Vec<_>>().join(", ")
    )
}

fn vm_named(vm_id: &str) -> TestedVM {
    vms()
        .into_iter()
        .find(|(name, _)| *name == vm_id)
        .map(|(_, vm)| vm)
        .expect("a known VM")
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.first().map(String::as_str) == Some("--all") {
        let passed = verify_all(arguments.get(1).map(String::as_str));
        std::process::exit(if passed { 0 } else { 1 });
    }
    let (Some(vm_id), Some(test_id)) = (arguments.first(), arguments.get(1)) else {
        println!("{}", usage_info());
        std::process::exit(1);
    };
    let flag = arguments.get(2).cloned().unwrap_or_default();
    let use_verbose = flag.contains('v');
    let run_benchmark = flag.contains('b') || flag.contains('p');
    if !is_vm(vm_id) {
        println!("Error: the VM \"{vm_id}\" is unknown.\n{}", usage_info());
        std::process::exit(1);
    }
    let base_vm = &vm_id[..vm_id.rfind('_').expect("VM names include a mode")];
    let all_tests: Vec<VmbTest> = assert_success(import_vmb_tests(Some(base_vm)), None)
        .into_iter()
        .flat_map(|(_, files)| files.into_iter().flat_map(|(_, tests)| tests))
        .collect();
    let vm = vm_named(vm_id);
    let Some(test_definition) = all_tests.iter().find(|test| &test.short_id == test_id) else {
        println!("Error: the test ID \"{test_id}\" is unknown.\n{}", usage_info());
        std::process::exit(1);
    };
    let tested_index = test_definition.input_index.unwrap_or(0);
    let transaction_bin = hex_to_bin(&test_definition.test_transaction_hex);
    let source_outputs_bin = hex_to_bin(&test_definition.source_outputs_hex);
    let transaction = assert_success(decode_transaction(&transaction_bin), None);
    let source_outputs = assert_success(decode_transaction_outputs(&source_outputs_bin), None);
    let result = vm.verify(&ResolvedTransactionCommon {
        source_outputs: source_outputs.clone(),
        transaction: transaction.clone(),
    });
    let program = AuthenticationProgramCommon {
        input_index: tested_index,
        source_outputs: source_outputs.clone(),
        transaction: transaction.clone(),
    };
    let high_memory = test_definition.test_description.contains("[high-memory]");
    let debug_result = if high_memory {
        Vec::new()
    } else {
        vm.debug_masked(&program, None)
    };
    let failing_index = result.as_ref().err().and_then(|result| {
        let start = result.find("evaluating input index ")? + "evaluating input index ".len();
        result[start..]
            .split(|character: char| !character.is_ascii_digit())
            .next()?
            .parse::<usize>()
            .ok()
    });
    let unexpected_failing_index_debug_trace = failing_index
        .filter(|index| *index != tested_index)
        .map(|index| {
            if high_memory {
                Vec::new()
            } else {
                vm.debug(
                    &AuthenticationProgramCommon {
                        input_index: index,
                        source_outputs: source_outputs.clone(),
                        transaction: transaction.clone(),
                    },
                    None,
                )
            }
        });
    let is_p2sh20 = is_pay_to_script_hash20(&source_outputs[tested_index].locking_bytecode);
    let metrics = debug_result
        .last()
        .map(|state| state.state.metrics.clone())
        .unwrap_or_default();
    let mut print = String::new();
    if use_verbose {
        print.push_str(&format!(
            "\nVerbose information (-v):\n=========================\n{}\nFull debug trace at index {tested_index}:\n{:#?}\n----------\nSource outputs (hex): {}\nDecoded:\n{source_outputs:#?}\n----------\nTransaction (hex): {}\nDecoded:\n{transaction:#?}\n\nStandard information:\n=====================\n",
            unexpected_failing_index_debug_trace
                .as_ref()
                .map(|trace| format!(
                    "\nFull debug trace at failing index {}:\n{trace:#?}\n----------\n",
                    failing_index.unwrap_or_default()
                ))
                .unwrap_or_default(),
            debug_result,
            test_definition.source_outputs_hex,
            test_definition.test_transaction_hex,
        ));
    }
    print.push_str(&format!(
        "\nVMB test ID: {}\nDescription: {}\nTransaction byte length: {} | UTXOs byte length: {} ({} UTXOs) | Tested index: {tested_index} | Locking bytecode length: {} | Unlocking bytecode length: {} | Density control length: {}\nOp. Cost: {} (Max: {}) | SigChecks: {} (Max: {}) | Hash iters. {} (Max: {}) | Evaluated Ops: {} | Pushed Bytes: {} | Math Cost: {}\nResult (VM: {vm_id}): {}{}\nUnlocking ASM: {}\n{} ASM: {}\n\nEvaluation at index {tested_index}:\n{}\n",
        test_definition.short_id,
        test_definition.test_description,
        transaction_bin.len(),
        source_outputs_bin.len(),
        source_outputs.len(),
        source_outputs
            .get(tested_index)
            .map_or("???".to_string(), |output| output.locking_bytecode.len().to_string()),
        transaction
            .inputs
            .get(tested_index)
            .map_or("???".to_string(), |input| input.unlocking_bytecode.len().to_string()),
        metrics.density_control_length,
        metrics.operation_cost,
        metrics.maximum_operation_cost,
        metrics.signature_check_count,
        metrics.maximum_signature_check_count,
        metrics.hash_digest_iterations,
        metrics.maximum_hash_digest_iterations,
        metrics.evaluated_instruction_count,
        metrics.stack_pushed_bytes,
        metrics.arithmetic_cost,
        match &result {
            Ok(()) => "Transaction accepted".to_string(),
            Err(result) => format!("Transaction rejected: {result}"),
        },
        unexpected_failing_index_debug_trace
            .as_ref()
            .map(|trace| format!(
                "\nNote: an unexpected index is failing; the input index under test is {tested_index}, but input index {} failed.\nEvaluation at failing index ({}):\n{}\n",
                failing_index.unwrap_or_default(),
                failing_index.unwrap_or_default(),
                stringify_debug_trace_summary(&summarize_debug_trace(trace), None, None, None)
            ))
            .unwrap_or_default(),
        test_definition.unlocking_script_asm,
        if is_p2sh20 { "Redeem (P2SH20)" } else { "Locking" },
        test_definition.redeem_or_locking_script_asm,
        stringify_debug_trace_summary(&summarize_debug_trace(&debug_result), None, None, None),
    ));
    println!(
        "{}",
        if use_verbose {
            print
        } else {
            elide_words_and_hex_at_length(&print, Some(200))
        }
    );
    if !run_benchmark {
        return;
    }
    println!("Benchmarking...");
    let Some(baseline_definition) = all_tests.iter().find(|test| test.short_id == baselineBenchmarkId) else {
        panic!(
            "Error: the benchmark baseline ID \"{baselineBenchmarkId}\" could not be found. Was the baseline modified?"
        );
    };
    let baseline = ResolvedTransactionCommon {
        source_outputs: assert_success(
            decode_transaction_outputs(&hex_to_bin(&baseline_definition.source_outputs_hex)),
            None,
        ),
        transaction: assert_success(
            decode_transaction(&hex_to_bin(&baseline_definition.test_transaction_hex)),
            None,
        ),
    };
    let tested = ResolvedTransactionCommon {
        source_outputs,
        transaction,
    };
    let time = |resolved: &ResolvedTransactionCommon| {
        let iterations = 100;
        let _ = vm.verify(resolved);
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = vm.verify(resolved);
        }
        start.elapsed().as_secs_f64() / iterations as f64
    };
    let baseline_mean = time(&baseline);
    let test_mean = time(&tested);
    println!(
        "Baseline ID: {baselineBenchmarkId} ({vm_id}): {:.3}ms | VMB Test ID: {} ({vm_id}): {:.3}ms",
        baseline_mean * 1000.0,
        test_definition.short_id,
        test_mean * 1000.0
    );
    println!(
        "Test ID {} verifies in {} baseline validations ({baselineBenchmarkId}).",
        test_definition.short_id,
        test_mean / baseline_mean
    );
}

/// The verdicts and libauth error messages recorded for a test file
/// (`{ [shortId]: true | string }`).
fn read_results(path: &std::path::Path) -> Result<BTreeMap<String, Result<(), String>>, String> {
    let content = std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let json = parse_json(&content).map_err(|error| format!("{}: {error}", path.display()))?;
    json.as_object()
        .ok_or_else(|| format!("{} must contain an object", path.display()))?
        .iter()
        .map(|(short_id, result)| match result {
            Json::Bool(true) => Ok((short_id.clone(), Ok(()))),
            Json::String(error) => Ok((short_id.clone(), Err(error.clone()))),
            _ => Err(format!("{}: unexpected result for {short_id}", path.display())),
        })
        .collect()
}

#[derive(Default)]
struct SuiteResult {
    verdicts: usize,
    verdict_mismatches: usize,
    message_mismatches: usize,
    skipped: usize,
    examples: Vec<String>,
}

fn evaluate(vm: &TestedVM, test: &VmbTest) -> Result<(), String> {
    let source_outputs_bin = hex_to_bin(&test.source_outputs_hex);
    let transaction_bin = hex_to_bin(&test.test_transaction_hex);
    let source_outputs = read_transaction_outputs(ReadPosition {
        bin: &source_outputs_bin,
        index: 0,
    })?;
    let transaction = read_transaction_common(ReadPosition {
        bin: &transaction_bin,
        index: 0,
    })?;
    vm.verify(&ResolvedTransactionCommon {
        source_outputs: source_outputs.result,
        transaction: transaction.result,
    })
}

/// Verify every generated VMB test (see the module documentation).
fn verify_all(filter: Option<&str>) -> bool {
    let started = Instant::now();
    // The generated VMB tests are not tracked, so their directory may be missing.
    let directories = if result_dir().exists() {
        assert_success(import_vmb_tests(filter), None)
    } else {
        Default::default()
    };
    let tasks: Vec<(String, String, Vec<VmbTest>)> = directories
        .into_iter()
        .flat_map(|(directory, files)| {
            files
                .into_iter()
                .map(move |(file, tests)| (directory.clone(), file, tests))
        })
        .collect();
    let suites: Mutex<BTreeMap<String, SuiteResult>> = Mutex::new(BTreeMap::new());
    let next_task = AtomicUsize::new(0);
    let worker_count = std::thread::available_parallelism().map_or(1, |count| count.get()).clamp(1, 8);
    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| {
                let thread_vms = vms();
                loop {
                    let Some((directory, file, tests)) = tasks.get(next_task.fetch_add(1, Ordering::SeqCst)) else {
                        break;
                    };
                    let test_set_base = &directory[..directory.rfind('_').expect("test sets include a type")];
                    let vm_for = |mode: &str| {
                        let name = format!("{test_set_base}_{mode}");
                        thread_vms
                            .iter()
                            .find(|(vm_name, _)| *vm_name == name)
                            .map(|(_, vm)| vm)
                            .unwrap_or_else(|| panic!("Could not find a {mode} VM for {name}."))
                    };
                    let base = result_dir().join(directory).join(file.trim_end_matches(".vmb_tests.json"));
                    let mut local = SuiteResult::default();
                    for mode in ["standard", "nonstandard"] {
                        let results_path = base.with_file_name(format!(
                            "{}.{mode}_results.json",
                            file.trim_end_matches(".vmb_tests.json")
                        ));
                        let expected = assert_success(read_results(&results_path), None);
                        let vm = vm_for(mode);
                        for test in tests {
                            let Some(expected) = expected.get(&test.short_id) else {
                                local.skipped += 1;
                                continue;
                            };
                            local.verdicts += 1;
                            let actual = evaluate(vm, test);
                            if actual.is_ok() != expected.is_ok() {
                                local.verdict_mismatches += 1;
                                if local.examples.len() < 20 {
                                    local.examples.push(format!(
                                        "VERDICT {directory}/{} ({mode}): expected {expected:?}, got {actual:?}",
                                        test.short_id
                                    ));
                                }
                            } else if actual != *expected {
                                local.message_mismatches += 1;
                                if local.examples.len() < 20 {
                                    local.examples.push(format!(
                                        "MESSAGE {directory}/{} ({mode}): expected {expected:?}, got {actual:?}",
                                        test.short_id
                                    ));
                                }
                            }
                        }
                    }
                    let mut suites = suites.lock().expect("unpoisoned");
                    let suite = suites.entry(directory.clone()).or_default();
                    suite.verdicts += local.verdicts;
                    suite.verdict_mismatches += local.verdict_mismatches;
                    suite.message_mismatches += local.message_mismatches;
                    suite.skipped += local.skipped;
                    suite.examples.extend(local.examples);
                }
            });
        }
    });
    let suites = suites.into_inner().expect("unpoisoned");
    let mut totals = SuiteResult::default();
    for (directory, suite) in &suites {
        for example in suite.examples.iter().take(5) {
            eprintln!("{example}");
        }
        println!(
            "{directory}: {} verdicts, {} verdict mismatches, {} message mismatches, {} skipped",
            suite.verdicts, suite.verdict_mismatches, suite.message_mismatches, suite.skipped
        );
        totals.verdicts += suite.verdicts;
        totals.verdict_mismatches += suite.verdict_mismatches;
        totals.message_mismatches += suite.message_mismatches;
        totals.skipped += suite.skipped;
    }
    println!(
        "TOTAL: {} verdicts, {} verdict mismatches, {} message mismatches, {} skipped ({:.1}s)",
        totals.verdicts,
        totals.verdict_mismatches,
        totals.message_mismatches,
        totals.skipped,
        started.elapsed().as_secs_f64()
    );
    if totals.verdicts == 0 {
        println!(
            "Error: no VMB tests found in {}{}. Copy libauth's (src/lib/vmb-tests/generated) or regenerate them with the dev-vmb-tests example.",
            result_dir().display(),
            filter.map_or(String::new(), |filter| format!(" matching \"{filter}\""))
        );
        return false;
    }
    totals.verdict_mismatches == 0 && totals.skipped == 0
}
