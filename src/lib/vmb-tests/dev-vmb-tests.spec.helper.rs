//! Port of `vmb-tests/dev-vmb-tests.spec.helper.ts`: (re)generate the VMB
//! tests (`cargo run --release --offline --example dev-vmb-tests -- [flags]`).
//!
//! The result directory defaults to `src/lib/vmb-tests/generated`; override it
//! with `--result-dir=<path>` or the `VMB_TESTS_RESULT_DIR` environment
//! variable.
//!
//! Simplified: libauth's watch mode (`-w`) re-imports the recompiled JS
//! sources whenever `yarn watch` rebuilds them. The Rust sources are compiled
//! into this binary, so the flag is accepted but only reported: generation
//! runs once (re-run this command after editing the sources).

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

use generate_vmb_tests_spec_helper::{
    compiled_dir, create_workers, generate_vmb_tests, result_dir, take_result_dir_argument, GenerateVmbTestsResult,
    WorkerMessage,
};

fn main() {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    take_result_dir_argument(&mut arguments);
    let flags = arguments.first();
    let show_help = flags.is_some_and(|flags| flags.contains("help"));
    let benchmark = flags.is_some_and(|flags| flags.contains('b'));
    let watch_files = flags.is_some_and(|flags| flags.contains('w'));
    let delete_unexpected = flags.is_some_and(|flags| flags.contains('d'));
    let ignore_warnings = flags.is_some_and(|flags| flags.contains('i'));

    if show_help {
        println!(
            "Usage examples:
       cargo run --release --example dev-vmb-tests             # re-generate outdated VMB tests
       cargo run --release --example dev-vmb-tests -- -b       # enable benchmarks
       cargo run --release --example dev-vmb-tests -- -w       # watch mode (not supported: generates once)
       cargo run --release --example dev-vmb-tests -- -d       # perform any deletions (dry-run happens automatically)
       cargo run --release --example dev-vmb-tests -- -i       # ignore generation warnings
       cargo run --release --example dev-vmb-tests -- -bi      # benchmark + ignore warnings
       cargo run --release --example dev-vmb-tests -- --help   # show this message

       Add --result-dir=<path> (or set VMB_TESTS_RESULT_DIR) to write the generated
       files somewhere other than src/lib/vmb-tests/generated.
"
        );
        std::process::exit(0);
    }

    println!(
        "Benchmarking {}. {}",
        if benchmark { "enabled" } else { "disabled" },
        if ignore_warnings { "\nWarnings are disabled." } else { "" }
    );

    let result_dir = result_dir();
    if !result_dir.exists() {
        std::fs::create_dir_all(&result_dir).unwrap_or_else(|error| panic!("{}: {error}", result_dir.display()));
        println!("Created result directory: {}", result_dir.display());
    }
    println!("Writing results to: {}", result_dir.display());

    let available_cpus = std::thread::available_parallelism().map_or(1, |count| count.get());
    let most = 0.5;
    let worker_count = (most * available_cpus as f64).floor() as usize;
    println!("Spawning {worker_count} workers...");
    let workers = create_workers(worker_count, benchmark, ignore_warnings);
    let outcome = generate_vmb_tests(
        Some(&workers),
        Some(benchmark),
        Some(delete_unexpected),
        Some(ignore_warnings),
        None,
    );
    if watch_files {
        println!(
            "Watch mode is not supported by the Rust port: the sources in {} are compiled into this binary. Re-run this command after editing them.",
            compiled_dir().display()
        );
    }
    for wrapper in &workers {
        wrapper.worker.post_message(WorkerMessage::Shutdown);
    }
    for wrapper in &workers {
        wrapper.worker.join();
    }
    // libauth always exits with 0; the port exits with 1 if generation failed
    // or found issues (for use in scripts).
    match outcome {
        Err(error) => {
            eprintln!("{error}");
            println!("\n\nPlease run \"cargo build --release --example dev-vmb-tests\" to recompile the latest changes.");
            std::process::exit(1);
        }
        Ok(GenerateVmbTestsResult::Message(_)) => std::process::exit(1),
        Ok(GenerateVmbTestsResult::Issues(issues)) if !issues.is_empty() => std::process::exit(1),
        Ok(GenerateVmbTestsResult::Issues(_)) => {}
    }
}
