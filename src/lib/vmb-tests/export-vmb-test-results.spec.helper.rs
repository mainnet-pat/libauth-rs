//! Port of `vmb-tests/export-vmb-test-results.spec.helper.ts`
//! (`cargo run --release --example export-vmb-test-results [-- --result-dir=<path>]`).
//!
//! This script compiles all VMB benchmarking results into single-file CSVs in
//! the `export` directory, e.g.:
//!  - `export/bench/bch_2025.libauth.standard_bench.csv`,
//!  - `export/stats/bch_2025.standard_stats.csv`, and
//!
//! Then, separately, all `bench/VM_NAME.*.[non]standard_bench.csv` files in the
//! export directory are extended using the matching
//! `stats/VM_NAME.*.[non]standard_stats.csv` file to
//! produce `extended/VM_NAME.*.[non]standard.csv`.
//!
//! This approach allows for extending benchmark results produced by other
//! implementations: save any externally-produced benchmark results using a
//! matching pattern, and the results will be extended with matching stats data,
//! e.g. `bench/bch_2025.bchn.standard_bench.csv` will be extended with data
//! from `stats/bch_2025.standard_stats.csv` to
//! produce `extended/bch_2025.bchn.standard.csv`.

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

use std::path::{Path, PathBuf};

use generate_vmb_tests_spec_helper::{benchHeader, result_dir, take_result_dir_argument};

/// `resolve(resultDir, '../export')`
fn export_dir() -> PathBuf {
    let result_dir = result_dir();
    result_dir.parent().map_or_else(|| result_dir.join(".."), Path::to_path_buf).join("export")
}

const statsHeader: &str = "Test ID,Description,Transaction Length,UTXOs Length,UTXO Count,Tested Input Index,Density Control Length,Maximum Operation Cost,Operation Cost,Maximum SigChecks,SigChecks,Maximum Hash Digest Iterations,Hash Digest Iterations,Evaluated Instructions,Stack Pushed Bytes,Arithmetic Cost";

const modes: [&str; 2] = ["nonstandard", "standard"];

/// `readdirSync` (Node lists directory entries sorted by byte order).
fn read_dir_sorted(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn read_file(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn write_file(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
}

/// The aggregated CSVs of a VM (`{ bench: { nonstandard, standard }, stats:
/// { nonstandard, standard } }`).
struct Aggregated {
    bench: [String; 2],
    stats: [String; 2],
}

fn mode_index(mode: &str) -> usize {
    modes.iter().position(|item| *item == mode).expect("a known mode")
}

fn main() {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    take_result_dir_argument(&mut arguments);
    let result_dir = result_dir();
    let export_dir = export_dir();
    let bench_dir = export_dir.join("bench");
    let stats_dir = export_dir.join("stats");
    let extended_dir = export_dir.join("extended");

    println!("Reading all results from: {}", result_dir.display());
    let vm_directories: Vec<String> = read_dir_sorted(&result_dir)
        .into_iter()
        .filter(|name| result_dir.join(name).is_dir())
        .collect();

    let mut aggregated: Vec<(String, Aggregated)> = Vec::new();
    for vm_directory in &vm_directories {
        let dir_path = result_dir.join(vm_directory);
        let file_list = read_dir_sorted(&dir_path);
        let vm_base_name = vm_directory[..vm_directory.rfind('_').unwrap_or(vm_directory.len())].to_string();
        if !aggregated.iter().any(|(name, _)| *name == vm_base_name) {
            aggregated.push((
                vm_base_name.clone(),
                Aggregated {
                    bench: [benchHeader.to_string(), benchHeader.to_string()],
                    stats: [statsHeader.to_string(), statsHeader.to_string()],
                },
            ));
        }
        let entry = &mut aggregated
            .iter_mut()
            .find(|(name, _)| *name == vm_base_name)
            .expect("an aggregated VM")
            .1;
        for mode in modes {
            for file in file_list.iter().filter(|file| file.ends_with(&format!(".{mode}_bench.csv"))) {
                let file_path = dir_path.join(file);
                let content = read_file(&file_path);
                let lines: Vec<&str> = content.split('\n').collect();
                let header = lines[0];
                if header != benchHeader {
                    panic!(
                        "Unexpected header in {}:\n\"{header}\"\nExpected:\n\"{benchHeader}\"",
                        file_path.display()
                    );
                }
                let header_and_baseline_lines = 2;
                let trimmed = lines.get(header_and_baseline_lines..).unwrap_or_default().join("\n");
                let new_line_if_content = if trimmed.is_empty() { trimmed } else { format!("\n{trimmed}") };
                entry.bench[mode_index(mode)].push_str(&new_line_if_content);
            }
            for file in file_list.iter().filter(|file| file.ends_with(&format!(".{mode}_stats.csv"))) {
                let file_path = dir_path.join(file);
                let content = read_file(&file_path);
                let lines: Vec<&str> = content.split('\n').collect();
                let header = lines[0];
                if header != statsHeader {
                    panic!(
                        "Unexpected header in {}:\n\"{header}\"\nExpected:\n\"{statsHeader}\"",
                        file_path.display()
                    );
                }
                let header_line = 1;
                let trimmed = lines[header_line..].join("\n");
                let new_line_if_content = if trimmed.is_empty() { trimmed } else { format!("\n{trimmed}") };
                entry.stats[mode_index(mode)].push_str(&new_line_if_content);
            }
        }
    }
    for dir in [&bench_dir, &stats_dir, &extended_dir] {
        std::fs::create_dir_all(dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
    }
    for (vm_base_name, entry) in &aggregated {
        for mode in modes {
            let bench_file = bench_dir.join(format!("{vm_base_name}.libauth.{mode}_bench.csv"));
            write_file(&bench_file, &entry.bench[mode_index(mode)]);
            println!("Wrote: {}", bench_file.display());
        }
        for mode in modes {
            let stats_file = stats_dir.join(format!("{vm_base_name}.{mode}_stats.csv"));
            write_file(&stats_file, &entry.stats[mode_index(mode)]);
            println!("Wrote: {}", stats_file.display());
        }
    }
    // `{ [vmName]: { [mode]: { [testId]: statsLine } } }`
    let mut stats: Vec<(String, [Vec<(String, String)>; 2])> = Vec::new();
    for (vm_base_name, entry) in &aggregated {
        let mut by_mode: [Vec<(String, String)>; 2] = [Vec::new(), Vec::new()];
        for mode in modes {
            let lines: Vec<&str> = entry.stats[mode_index(mode)].split('\n').collect();
            let without_header = &lines[1..];
            let test_stats = &mut by_mode[mode_index(mode)];
            for line in without_header {
                let mut parts = line.split(',');
                let test_id = parts.next().unwrap_or_default().to_string();
                let rest_of_line = parts.collect::<Vec<_>>().join(",");
                if let Some((_, old)) = test_stats.iter().find(|(id, _)| *id == test_id) {
                    panic!(
                        "Stats were previously ingested for VM \"{vm_base_name}\", mode \"{mode}\", test ID \"{test_id}\". Please review for duplicates: {}/{vm_base_name}.{mode}_stats.csv\nOld stats: {old}\nNew stats: {rest_of_line}",
                        stats_dir.display()
                    );
                }
                test_stats.push((test_id, rest_of_line));
            }
        }
        stats.push((vm_base_name.clone(), by_mode));
    }
    // Note, we re-read benchmarking results from disk here to pull in any
    // results produced externally. See the explanation at the top of this file.
    for file in read_dir_sorted(&bench_dir).into_iter().filter(|file| file.ends_with("_bench.csv")) {
        let parts: Vec<&str> = file.split('.').collect();
        let (requested_vm_name, implementation_id, result_type, ext) =
            (parts.first().copied(), parts.get(1).copied(), parts.get(2).copied(), parts.get(3).copied());
        let mode = if result_type == Some("nonstandard_bench") { "nonstandard" } else { "standard" };
        let (Some(requested_vm_name), Some(implementation_id)) = (requested_vm_name, implementation_id) else {
            panic!("Unexpected filename, \"{file}\". Unified benchmark filenames should follow the pattern: VM_NAME.IMPLEMENTATION.[non]standard_bench.csv");
        };
        if (mode == "standard" && result_type != Some("standard_bench")) || ext != Some("csv") {
            panic!("Unexpected filename, \"{file}\". Unified benchmark filenames should follow the pattern: VM_NAME.IMPLEMENTATION.[non]standard_bench.csv");
        }
        let Some((_, relevant_stats)) = stats.iter().find(|(name, _)| name == requested_vm_name) else {
            panic!(
                "Requested results for an unknown VM, \"{requested_vm_name}\". Please rename \"{file}\" to extend it with stats from a known VM: {}",
                stats.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>().join(", ")
            );
        };
        let file_path = bench_dir.join(&file);
        let content = read_file(&file_path).trim().to_string();
        let mut lines = content.split('\n');
        let header = lines.next().unwrap_or_default();
        let remaining_lines: Vec<&str> = lines.collect();
        if header != benchHeader {
            panic!(
                "Unexpected header in {}:\n\"{header}\"\nExpected:\n\"{benchHeader}\"",
                file_path.display()
            );
        }
        let extended_lines: Vec<String> = remaining_lines
            .iter()
            .enumerate()
            .map(|(index, line)| {
                let test_id = line.split(',').next().unwrap_or_default();
                let Some((_, line_stats)) = relevant_stats[mode_index(mode)].iter().find(|(id, _)| id == test_id) else {
                    panic!(
                        "Line {index} of {} references an unknown test ID, \"{test_id}\".",
                        file_path.display()
                    );
                };
                format!("{line},{line_stats}")
            })
            .collect();
        let extended_file = extended_dir.join(format!("{requested_vm_name}.{mode}.{implementation_id}.csv"));
        let extended_contents = format!(
            "{header},{}\n{}",
            statsHeader.replacen("Test ID,", "", 1),
            extended_lines.join("\n")
        );
        write_file(&extended_file, &extended_contents);
        println!("Extended {file}, wrote: {}", extended_file.display());
    }
}
