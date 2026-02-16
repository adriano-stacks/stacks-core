// Copyright (C) 2025-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Instrumentation module for tracking `at-block` opcode usage.
//!
//! Gated behind the `at-block-tracker` Cargo feature. When active, reads the
//! `STACKS_AT_BLOCK_CSV` env var to determine the output file path. If the env
//! var is not set, all logging calls are no-ops.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};

thread_local! {
    static WRITER: RefCell<Option<BufWriter<File>>> = const { RefCell::new(None) };
}

/// Initialize the tracker by reading `STACKS_AT_BLOCK_CSV`.
/// If the env var is unset or empty, the tracker remains inactive.
pub fn init() {
    let path = match std::env::var("STACKS_AT_BLOCK_CSV") {
        Ok(p) if !p.is_empty() => p,
        _ => return,
    };

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("at-block-tracker: failed to open {path}: {e}"));

    let is_empty = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
    let mut writer = BufWriter::new(file);

    if is_empty {
        writeln!(
            writer,
            "current_block_height,target_block_hash,contract_id,sender,caller,call_stack_depth,call_stack_top,epoch,success,error_msg"
        )
        .expect("at-block-tracker: failed to write CSV header");
    }

    WRITER.with(|w| {
        *w.borrow_mut() = Some(writer);
    });
}

/// Log a single `at-block` invocation. No-op if the tracker was not initialized.
#[allow(clippy::too_many_arguments)]
pub fn log_at_block(
    current_block_height: u32,
    target_block_hash: &str,
    contract_id: &str,
    sender: &str,
    caller: &str,
    call_stack_depth: u64,
    call_stack_top: &str,
    epoch: &str,
    success: bool,
    error_msg: &str,
) {
    WRITER.with(|w| {
        let mut borrow = w.borrow_mut();
        let Some(writer) = borrow.as_mut() else {
            return;
        };
        // Escape fields that might contain commas or quotes
        let _ = writeln!(
            writer,
            "{current_block_height},{target_block_hash},\"{contract_id}\",\"{sender}\",\"{caller}\",{call_stack_depth},\"{call_stack_top}\",{epoch},{success},\"{error_msg}\""
        );
    });
}

/// Flush buffered output. No-op if the tracker was not initialized.
pub fn flush() {
    WRITER.with(|w| {
        let mut borrow = w.borrow_mut();
        if let Some(writer) = borrow.as_mut() {
            let _ = writer.flush();
        }
    });
}

/// Drop the writer for test isolation.
#[cfg(any(test, feature = "testing"))]
pub fn reset() {
    WRITER.with(|w| {
        *w.borrow_mut() = None;
    });
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn test_log_without_init() {
        // Calling log_at_block without init should not panic
        reset();
        log_at_block(100, "0xaabb", "contract-id", "sender", "caller", 2, "top", "2.1", true, "");
        // No assertion needed — we just verify no panic
    }

    #[test]
    fn test_init_and_log() {
        reset();

        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "at_block_tracker_test_{}.csv",
            std::process::id()
        ));
        let path_str = path.to_str().unwrap().to_string();

        // Clean up any prior run
        let _ = std::fs::remove_file(&path);

        // SAFETY: test is single-threaded; no concurrent env var access
        unsafe { std::env::set_var("STACKS_AT_BLOCK_CSV", &path_str) };
        init();

        log_at_block(
            42,
            "aabbccdd",
            "SP123.my-contract",
            "SP123",
            "SP456",
            3,
            "my-function",
            "2.1",
            true,
            "",
        );
        log_at_block(
            43,
            "11223344",
            "SP789.other",
            "SP789",
            "SP789",
            1,
            "",
            "2.05",
            false,
            "UnknownBlockHeaderHash",
        );
        flush();
        reset();

        // SAFETY: test is single-threaded; no concurrent env var access
        unsafe { std::env::remove_var("STACKS_AT_BLOCK_CSV") };

        let mut contents = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();

        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 3, "Expected header + 2 data rows");

        assert!(lines[0].starts_with("current_block_height,"));
        assert!(lines[1].starts_with("42,aabbccdd,"));
        assert!(lines[1].contains("SP123.my-contract"));
        assert!(lines[1].ends_with(",true,\"\""));
        assert!(lines[2].starts_with("43,11223344,"));
        assert!(lines[2].contains("UnknownBlockHeaderHash"));

        let _ = std::fs::remove_file(&path);
    }
}
