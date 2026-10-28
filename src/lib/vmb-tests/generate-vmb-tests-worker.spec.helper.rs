//! Port of `vmb-tests/generate-vmb-tests-worker.spec.helper.ts`.
//!
//! libauth runs this script in a `worker_threads` Worker; the port runs
//! [`worker_main`] on a thread started by `create_workers`, exchanging the same
//! messages over channels.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{Receiver, Sender};

use crate::generate_vmb_tests_spec_helper::{
    generate_vmb_tests_from_source_file, Console, ParentMessage, WorkerMessage, WorkerResult,
};

/// libauth's `workerData`.
pub struct WorkerData {
    pub benchmark: bool,
    pub ignore_warnings: bool,
    pub index: usize,
}

/// Handle `generate` and `shutdown` messages from the main thread until shut
/// down.
pub fn worker_main(worker_data: WorkerData, messages: Receiver<WorkerMessage>, parent_port: Sender<(usize, ParentMessage)>) {
    let WorkerData {
        benchmark,
        ignore_warnings,
        index,
    } = worker_data;
    let log_prefix = format!("Worker {index}: ");

    // By sending errors to the main thread, we can log them using the main
    // thread's console.
    let post = |message: ParentMessage| {
        let _ = parent_port.send((index, message));
    };
    let error = |message: String| post(ParentMessage::Error(message));
    let log = |message: String| post(ParentMessage::Log(message));
    let warn = |message: String| post(ParentMessage::Warn(message));
    let console = Console {
        error: &error,
        log: &log,
        warn: &warn,
    };

    let generate_file = |file: &str, hash: &str| {
        let file_issues = generate_vmb_tests_from_source_file(
            file,
            hash,
            Some(benchmark),
            Some(&console),
            Some(&log_prefix),
            Some(ignore_warnings),
        );
        WorkerResult {
            file: file.to_string(),
            hash: hash.to_string(),
            file_issues: file_issues.issues,
            severity: file_issues.severity,
        }
    };

    for message in messages {
        match message {
            WorkerMessage::Generate(data) => {
                let (file, hash) = (data.file, data.hash);
                match catch_unwind(AssertUnwindSafe(|| generate_file(&file, &hash))) {
                    Ok(result) => post(ParentMessage::Result(result)),
                    Err(panic) => {
                        let panic = panic
                            .downcast_ref::<String>()
                            .cloned()
                            .or_else(|| panic.downcast_ref::<&str>().map(|message| message.to_string()))
                            .unwrap_or_default();
                        (console.error)(format!("{log_prefix}error: {panic:?}"));
                    }
                }
            }
            WorkerMessage::Shutdown => return,
        }
    }
}
