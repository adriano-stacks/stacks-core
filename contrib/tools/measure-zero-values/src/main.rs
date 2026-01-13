// Copyright (C) 2025 Stacks Open Internet Foundation
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

//! Tool to measure wasted space from TriePtr back_block fields in MARF storage.
//!
//! # Background
//!
//! The MARF (Merklized Adaptive Radix Forest) uses TriePtr structures (10 bytes each)
//! to reference nodes. The TriePtr format is:
//!   - byte 0: id (node type, with 0x80 flag indicating backptr)
//!   - byte 1: chr (character/branch selector)
//!   - bytes 2-5: ptr (u32 storage pointer)
//!   - bytes 6-9: back_block (u32 block reference)
//!
//! When a TriePtr is NOT a back-pointer (id & 0x80 == 0), the back_block field
//! is always 0 but is still stored, wasting 4 bytes per such pointer.
//!
//! This tool scans the MARF trie storage to count how many TriePtrs have this
//! wasted space and calculates the total recoverable bytes.

use std::fs::{self, File};
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::PathBuf;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::{Connection, OpenFlags};

use stackslib::chainstate::stacks::index::bits::read_nodetype_at_head_nohash;
use stackslib::chainstate::stacks::index::node::{is_backptr, TrieNode, TrieNodeID, TrieNodeType};
use stacks_common::types::chainstate::TRIEHASH_ENCODED_SIZE;

/// Measure wasted space from TriePtr back_block fields in MARF storage
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the chainstate directory (contains vm/ subdirectory with MARF)
    #[arg(short, long)]
    chainstate_path: PathBuf,

    /// Sample mode: only scan N random blocks (faster but approximate)
    #[arg(short, long)]
    sample_size: Option<usize>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

/// Statistics about TriePtr space usage in MARF storage
#[derive(Debug, Default)]
struct TriePtrStats {
    /// Total number of blocks scanned
    blocks_scanned: u64,
    /// Total bytes of trie data scanned
    bytes_scanned: u64,
    /// Total nodes deserialized
    total_nodes: u64,
    /// Total TriePtrs found in nodes
    total_trie_ptrs: u64,
    /// TriePtrs without backptr flag (back_block is 0, wasting 4 bytes each)
    non_backptr_trie_ptrs: u64,
    /// TriePtrs with backptr flag (back_block is used, no waste)
    backptr_trie_ptrs: u64,
}

/// Scan a single trie blob using proper MARF deserialization
///
/// Blob format (from storage.rs):
/// - First 32 bytes: parent block hash
/// - Next 4 bytes: local block identifier
/// - Then serialized nodes: [32-byte hash][node data]...
fn scan_trie_blob(data: &[u8], stats: &mut TriePtrStats, verbose: bool, first_blob: bool) {
    // Minimum blob size: 32 (parent hash) + 4 (block id) + some node data
    if data.len() < 36 {
        eprintln!(
            "WARNING: Blob too small ({} bytes), expected at least 36 bytes. Skipping.",
            data.len()
        );
        return;
    }

    // Debug: print first blob header
    if verbose && first_blob {
        eprintln!(
            "  First blob header (first 64 bytes): 0x{}",
            hex::encode(&data[..std::cmp::min(64, data.len())])
        );
        eprintln!("  Blob size: {} bytes", data.len());
    }

    let mut cursor = Cursor::new(data);

    // Skip header: 32-byte parent hash + 4-byte block id
    if let Err(e) = cursor.seek(SeekFrom::Start(36)) {
        eprintln!("WARNING: Failed to seek past blob header: {:?}", e);
        return;
    }

    // Read nodes until we run out of data
    while (cursor.position() as usize) + TRIEHASH_ENCODED_SIZE + 1 < data.len() {
        // Skip the 32-byte node hash
        if let Err(e) = cursor.seek(SeekFrom::Current(TRIEHASH_ENCODED_SIZE as i64)) {
            eprintln!(
                "WARNING: Failed to seek past node hash at position {}: {:?}",
                cursor.position(),
                e
            );
            break;
        }

        // Peek at the node type ID
        let node_id_pos = cursor.position();
        let mut id_byte = [0u8];
        if let Err(e) = cursor.read_exact(&mut id_byte) {
            eprintln!(
                "WARNING: Failed to read node ID at position {}: {:?}",
                node_id_pos, e
            );
            break;
        }

        // Seek back to read the full node
        if let Err(e) = cursor.seek(SeekFrom::Start(node_id_pos)) {
            eprintln!(
                "WARNING: Failed to seek back to node position {}: {:?}",
                node_id_pos, e
            );
            break;
        }

        let node_id = id_byte[0] & 0x7F; // Clear backptr flag for type check

        // Check if this is a valid node type
        let Some(trie_node_id) = TrieNodeID::from_u8(node_id) else {
            eprintln!(
                "WARNING: Invalid node ID 0x{:02x} at position {}, stopping blob scan",
                id_byte[0], node_id_pos
            );
            break;
        };

        // Skip empty nodes
        if trie_node_id == TrieNodeID::Empty {
            if let Err(e) = cursor.seek(SeekFrom::Current(1)) {
                eprintln!(
                    "WARNING: Failed to skip empty node at position {}: {:?}",
                    node_id_pos, e
                );
                break;
            }
            continue;
        }

        // Deserialize the node using stackslib's proper deserialization
        let node = match read_nodetype_at_head_nohash(&mut cursor, id_byte[0]) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "WARNING: Failed to deserialize node at position {}: {:?}",
                    node_id_pos, e
                );
                break;
            }
        };

        stats.total_nodes += 1;

        // Get the TriePtrs from this node and analyze them
        let ptrs = match &node {
            TrieNodeType::Leaf(_) => {
                // Leaves have no child pointers
                continue;
            }
            TrieNodeType::Node4(n) => n.ptrs(),
            TrieNodeType::Node16(n) => n.ptrs(),
            TrieNodeType::Node48(n) => n.ptrs(),
            TrieNodeType::Node256(n) => n.ptrs(),
        };

        // Analyze each TriePtr
        for ptr in ptrs {
            // Skip empty pointers
            if ptr.id() == TrieNodeID::Empty as u8 {
                continue;
            }

            stats.total_trie_ptrs += 1;

            if is_backptr(ptr.id()) {
                stats.backptr_trie_ptrs += 1;
            } else {
                stats.non_backptr_trie_ptrs += 1;
            }
        }
    }

    if verbose && first_blob {
        eprintln!("  Deserialized {} nodes from first blob", stats.total_nodes);
    }
}

/// Scan the external blobs file
fn scan_external_blobs(
    blobs_path: &PathBuf,
    db_conn: &Connection,
    sample_size: Option<usize>,
    verbose: bool,
) -> Result<TriePtrStats, Box<dyn std::error::Error>> {
    let mut stats = TriePtrStats::default();

    // Get all block entries with external blob info, sorted by offset for sequential reading
    let mut stmt = db_conn.prepare(
        "SELECT block_id, external_offset, external_length FROM marf_data
         WHERE external_length > 0 AND unconfirmed = 0
         ORDER BY external_offset",
    )?;

    let blocks: Vec<(u32, u64, u64)> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let total_blocks = blocks.len();
    let (blocks_to_scan, is_sampling): (Vec<_>, bool) = if let Some(n) = sample_size {
        // Sample N blocks evenly distributed
        if n >= total_blocks {
            (blocks, false)
        } else {
            let step = total_blocks / n;
            (blocks.into_iter().step_by(step).take(n).collect(), true)
        }
    } else {
        (blocks, false)
    };

    let file = File::open(blobs_path)?;
    let file_size = file.metadata()?.len();
    let mut reader = BufReader::new(file);

    let pb = ProgressBar::new(blocks_to_scan.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} blocks ({eta})")?
            .progress_chars("=>-"),
    );

    // Track current position for sequential reading
    let mut current_pos: u64 = 0;

    for (block_id, offset, length) in blocks_to_scan {
        pb.inc(1);

        if offset + length > file_size {
            eprintln!(
                "WARNING: Block {} has invalid offset/length ({}/{}), skipping",
                block_id, offset, length
            );
            continue;
        }

        // Only seek if we're not at the expected position
        // (sampling mode will need seeks, full scan should be sequential)
        if current_pos != offset {
            if is_sampling {
                // Expected when sampling - seek silently
                reader.seek(SeekFrom::Start(offset))?;
            } else {
                // Unexpected gap in full scan mode - warn about it
                eprintln!(
                    "WARNING: Unexpected gap in blob file at offset {}. Expected {}, seeking.",
                    offset, current_pos
                );
                reader.seek(SeekFrom::Start(offset))?;
            }
        }

        // Read the trie blob
        let mut blob_data = vec![0u8; length as usize];
        reader.read_exact(&mut blob_data)?;
        current_pos = offset + length;

        let first_blob = stats.blocks_scanned == 0;
        stats.blocks_scanned += 1;
        stats.bytes_scanned += length;

        scan_trie_blob(&blob_data, &mut stats, verbose, first_blob);
    }

    pb.finish_with_message("Scan complete");

    // If we sampled, extrapolate the results
    if is_sampling && stats.blocks_scanned > 0 {
        let scale = total_blocks as f64 / stats.blocks_scanned as f64;
        eprintln!(
            "\nNote: Results extrapolated from {} sampled blocks (scale factor: {:.2}x)",
            stats.blocks_scanned, scale
        );
        stats.total_nodes = (stats.total_nodes as f64 * scale) as u64;
        stats.total_trie_ptrs = (stats.total_trie_ptrs as f64 * scale) as u64;
        stats.non_backptr_trie_ptrs = (stats.non_backptr_trie_ptrs as f64 * scale) as u64;
        stats.backptr_trie_ptrs = (stats.backptr_trie_ptrs as f64 * scale) as u64;
    }

    Ok(stats)
}

/// Scan inline SQLite blobs (for databases without external blobs)
fn scan_sqlite_blobs(
    db_conn: &Connection,
    sample_size: Option<usize>,
    verbose: bool,
) -> Result<TriePtrStats, Box<dyn std::error::Error>> {
    let mut stats = TriePtrStats::default();

    // Count total blocks
    let total_blocks: u32 = db_conn.query_row(
        "SELECT COUNT(*) FROM marf_data WHERE unconfirmed = 0 AND LENGTH(data) > 0",
        [],
        |row| row.get(0),
    )?;

    let limit_clause = if let Some(n) = sample_size {
        format!("LIMIT {}", n)
    } else {
        String::new()
    };

    let mut stmt = db_conn.prepare(&format!(
        "SELECT block_id, data FROM marf_data
         WHERE unconfirmed = 0 AND LENGTH(data) > 0
         ORDER BY block_id {}",
        limit_clause
    ))?;

    let pb = ProgressBar::new(sample_size.unwrap_or(total_blocks as usize) as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} blocks ({eta})")?
            .progress_chars("=>-"),
    );

    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        pb.inc(1);
        let _block_id: u32 = row.get(0)?;
        let blob_data: Vec<u8> = row.get(1)?;

        let first_blob = stats.blocks_scanned == 0;
        stats.blocks_scanned += 1;
        stats.bytes_scanned += blob_data.len() as u64;

        scan_trie_blob(&blob_data, &mut stats, verbose, first_blob);
    }

    pb.finish_with_message("Scan complete");

    // If we sampled, extrapolate
    if sample_size.is_some() && stats.blocks_scanned > 0 {
        let scale = total_blocks as f64 / stats.blocks_scanned as f64;
        eprintln!(
            "\nNote: Results extrapolated from {} sampled blocks (scale factor: {:.2}x)",
            stats.blocks_scanned, scale
        );
        stats.total_nodes = (stats.total_nodes as f64 * scale) as u64;
        stats.total_trie_ptrs = (stats.total_trie_ptrs as f64 * scale) as u64;
        stats.non_backptr_trie_ptrs = (stats.non_backptr_trie_ptrs as f64 * scale) as u64;
        stats.backptr_trie_ptrs = (stats.backptr_trie_ptrs as f64 * scale) as u64;
    }

    Ok(stats)
}

/// Represents a MARF database location
struct MarfLocation {
    name: &'static str,
    db_path: PathBuf,
    blobs_path: PathBuf,
}

/// Scan a single MARF database and return stats
fn scan_marf(
    location: &MarfLocation,
    sample_size: Option<usize>,
    verbose: bool,
) -> Result<Option<TriePtrStats>, Box<dyn std::error::Error>> {
    if !location.db_path.exists() {
        return Ok(None);
    }

    println!("\n--- {} ---", location.name);
    println!("Database: {:?}", location.db_path);

    let db_conn = Connection::open_with_flags(&location.db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let use_external_blobs = location.blobs_path.exists();
    if use_external_blobs {
        let blobs_size = fs::metadata(&location.blobs_path)?.len();
        println!(
            "External blobs: {:?} ({:.2} GB)",
            location.blobs_path,
            blobs_size as f64 / 1_073_741_824.0
        );
    } else {
        println!("External blobs: Not found (using inline SQLite blobs)");
        eprintln!(
            "WARNING: Production nodes always use external blobs. \
             Inline blobs suggest a test database or misconfigured path. \
             Expected blobs file at: {:?}",
            location.blobs_path
        );
    }

    println!("Scanning...");

    let stats = if use_external_blobs {
        scan_external_blobs(&location.blobs_path, &db_conn, sample_size, verbose)?
    } else {
        scan_sqlite_blobs(&db_conn, sample_size, verbose)?
    };

    Ok(Some(stats))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("MARF TriePtr back_block Inefficiency Analysis");
    println!("=============================================\n");
    println!("Chainstate path: {:?}", args.chainstate_path);

    // Define all MARF locations to scan
    let marf_locations = [
        // Clarity VM MARF - stores Clarity values
        MarfLocation {
            name: "Clarity VM MARF",
            db_path: args.chainstate_path.join("vm/index.sqlite"),
            blobs_path: args.chainstate_path.join("vm/index.sqlite.blobs"),
        },
        // Chainstate MARF - stores block header data
        MarfLocation {
            name: "Chainstate MARF",
            db_path: args.chainstate_path.join("vm/clarity/marf.sqlite"),
            blobs_path: args.chainstate_path.join("vm/clarity/marf.sqlite.blobs"),
        },
    ];

    let mut total_stats = TriePtrStats::default();
    let mut found_any = false;

    for location in &marf_locations {
        match scan_marf(location, args.sample_size, args.verbose)? {
            Some(stats) => {
                found_any = true;

                // Print per-MARF stats
                println!("  Blocks scanned: {}", stats.blocks_scanned);
                println!(
                    "  Bytes scanned: {:.2} GB",
                    stats.bytes_scanned as f64 / 1_073_741_824.0
                );
                println!("  Nodes deserialized: {}", stats.total_nodes);
                println!("  Total TriePtrs found: {}", stats.total_trie_ptrs);
                println!(
                    "  Non-backptr TriePtrs: {} (wasting 4 bytes each)",
                    stats.non_backptr_trie_ptrs
                );
                println!("  Backptr TriePtrs: {}", stats.backptr_trie_ptrs);

                // Accumulate totals
                total_stats.blocks_scanned += stats.blocks_scanned;
                total_stats.bytes_scanned += stats.bytes_scanned;
                total_stats.total_nodes += stats.total_nodes;
                total_stats.total_trie_ptrs += stats.total_trie_ptrs;
                total_stats.non_backptr_trie_ptrs += stats.non_backptr_trie_ptrs;
                total_stats.backptr_trie_ptrs += stats.backptr_trie_ptrs;
            }
            None => {
                println!("\n--- {} ---", location.name);
                println!("Not found at {:?}", location.db_path);
            }
        }
    }

    if !found_any {
        return Err("No MARF databases found in the specified chainstate path".into());
    }

    let stats = total_stats;

    // Print results
    println!("\n\nResults");
    println!("=======");
    println!("Blocks scanned: {}", stats.blocks_scanned);
    println!(
        "Bytes scanned: {:.2} GB",
        stats.bytes_scanned as f64 / 1_073_741_824.0
    );
    println!("Nodes deserialized: {}", stats.total_nodes);
    println!("\nTriePtr Statistics:");
    println!("  Total TriePtrs found: {}", stats.total_trie_ptrs);
    println!(
        "  Non-backptr TriePtrs (back_block=0): {}",
        stats.non_backptr_trie_ptrs
    );
    println!(
        "  Backptr TriePtrs (back_block used): {}",
        stats.backptr_trie_ptrs
    );

    if stats.total_trie_ptrs > 0 {
        let backptr_percentage =
            (stats.backptr_trie_ptrs as f64 / stats.total_trie_ptrs as f64) * 100.0;
        let non_backptr_percentage =
            (stats.non_backptr_trie_ptrs as f64 / stats.total_trie_ptrs as f64) * 100.0;
        println!("  Non-backptr percentage: {:.2}%", non_backptr_percentage);
        println!("  Backptr percentage: {:.2}%", backptr_percentage);
    }

    println!("\n\nPotential Space Recovery");
    println!("========================");

    if stats.total_trie_ptrs > 0 {
        // Each non-backptr TriePtr wastes 4 bytes (the back_block field)
        let wasted_bytes = stats.non_backptr_trie_ptrs * 4;
        println!(
            "Wasted bytes (4 bytes per non-backptr TriePtr): {} bytes ({:.2} MB, {:.2} GB)",
            wasted_bytes,
            wasted_bytes as f64 / 1_048_576.0,
            wasted_bytes as f64 / 1_073_741_824.0
        );

        if stats.bytes_scanned > 0 {
            let waste_percentage = (wasted_bytes as f64 / stats.bytes_scanned as f64) * 100.0;
            println!(
                "Percentage of scanned data that is wasted: {:.2}%",
                waste_percentage
            );
        }
    } else {
        println!("No TriePtr patterns found.");
    }

    Ok(())
}
