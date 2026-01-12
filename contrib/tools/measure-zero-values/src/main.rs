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

//! Tool to measure space used by zero-values (Clarity `none`) in MARF storage.
//!
//! # Background
//!
//! The MARF (Merklized Adaptive Radix Forest) stores Clarity `none` values explicitly
//! rather than treating them as absent entries. When a data-map entry is "deleted",
//! Stacks writes `Value::none()` to mark it as removed.
//!
//! This tool scans the MARF trie storage to count how many leaf nodes contain the
//! none-value MARFValue (SHA512_256 hash of "09"), and calculates the recoverable space.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::{Connection, OpenFlags};

use stacks_common::types::chainstate::TRIEHASH_ENCODED_SIZE;
use stackslib::chainstate::stacks::index::node::TrieNodeID;
use stackslib::chainstate::stacks::index::{MARFValue, MARF_VALUE_ENCODED_SIZE};

const MARF_VALUE_SIZE: usize = MARF_VALUE_ENCODED_SIZE as usize;
const TRIE_HASH_SIZE: usize = TRIEHASH_ENCODED_SIZE;
const TRIE_NODE_ID_LEAF: u8 = TrieNodeID::Leaf as u8;

/// Measure space used by zero-values (none) in MARF storage
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

/// Compute the MARFValue hash for Clarity `none` (serialized as "09")
fn compute_none_marf_value() -> [u8; MARF_VALUE_SIZE] {
    // Use the actual MARFValue implementation to ensure correctness
    // Clarity none serializes to 0x09 (TypePrefix::OptionalNone)
    // As hex string: "09"
    let marf_value = MARFValue::from_value("09");
    let mut result = [0u8; MARF_VALUE_SIZE];
    result.copy_from_slice(marf_value.as_bytes());
    result
}

/// Statistics about zero-values in MARF storage
#[derive(Debug, Default)]
struct ZeroValueStats {
    /// Total number of blocks scanned
    blocks_scanned: u64,
    /// Total bytes of trie data scanned
    bytes_scanned: u64,
    /// Number of leaf nodes found
    total_leaves: u64,
    /// Number of leaf nodes with none-value
    none_leaves: u64,
    /// Bytes used by none-leaf nodes (including node hash overhead)
    none_bytes: u64,
    /// Distribution of path lengths in none-leaves
    none_path_lengths: HashMap<usize, u64>,
}

impl ZeroValueStats {
    fn none_percentage(&self) -> f64 {
        if self.total_leaves == 0 {
            0.0
        } else {
            (self.none_leaves as f64 / self.total_leaves as f64) * 100.0
        }
    }

    fn bytes_percentage(&self) -> f64 {
        if self.bytes_scanned == 0 {
            0.0
        } else {
            (self.none_bytes as f64 / self.bytes_scanned as f64) * 100.0
        }
    }
}

/// Scan a single trie blob for none-MARFValues
///
/// Blob format (from storage.rs and bits.rs):
/// - First 32 bytes: parent block hash
/// - Next 4 bytes: local block identifier
/// - Then nodes, each stored as: [32-byte hash][node data]
///
/// For leaf nodes, node data is: [1-byte ID][1-byte path_len][path bytes][40-byte MARFValue]
///
/// Rather than parsing the trie structure, we search for the none-MARFValue pattern directly.
/// This is reliable because the 40-byte pattern is unique enough to not have false positives.
fn scan_trie_blob(
    data: &[u8],
    none_marf_value: &[u8; MARF_VALUE_SIZE],
    stats: &mut ZeroValueStats,
    verbose: bool,
    first_blob: bool,
    sample_marf_values: &mut Vec<[u8; MARF_VALUE_SIZE]>,
) {
    // Minimum blob size: 32 (parent hash) + 4 (block id) + some node data
    if data.len() < 36 {
        return;
    }

    // Debug: print first blob header
    if verbose && first_blob {
        eprintln!("  First blob header (first 64 bytes): 0x{}", hex::encode(&data[..std::cmp::min(64, data.len())]));
        eprintln!("  Blob size: {} bytes", data.len());
    }

    // Count total leaves by scanning for leaf node IDs and extract MARFValues
    // Node format: [32-byte hash][1-byte ID][1-byte path_len][path bytes][40-byte MARFValue for leaves]
    let mut pos = 36; // Skip header (32 + 4)
    while pos + TRIE_HASH_SIZE + 1 < data.len() {
        let node_id = data[pos + TRIE_HASH_SIZE] & 0x7F; // Clear backptr flag
        if node_id == TRIE_NODE_ID_LEAF {
            stats.total_leaves += 1;
            // Extract the MARFValue from this leaf
            if pos + TRIE_HASH_SIZE + 2 < data.len() {
                let path_len = data[pos + TRIE_HASH_SIZE + 1] as usize;
                let marf_value_start = pos + TRIE_HASH_SIZE + 2 + path_len;
                let marf_value_end = marf_value_start + MARF_VALUE_SIZE;

                if marf_value_end <= data.len() {
                    // Check if this MARFValue matches the none pattern
                    if &data[marf_value_start..marf_value_end] == none_marf_value.as_slice() {
                        stats.none_leaves += 1;
                        let estimated_leaf_bytes = TRIE_HASH_SIZE + 2 + path_len + MARF_VALUE_SIZE;
                        stats.none_bytes += estimated_leaf_bytes as u64;
                        *stats.none_path_lengths.entry(path_len).or_insert(0) += 1;

                        if verbose {
                            eprintln!("  Found none-MARFValue at offset {} (path_len={})", marf_value_start, path_len);
                        }
                    }

                    // Collect sample MARFValues for debugging
                    if sample_marf_values.len() < 10 {
                        let mut value = [0u8; MARF_VALUE_SIZE];
                        value.copy_from_slice(&data[marf_value_start..marf_value_end]);
                        sample_marf_values.push(value);
                    }
                }

                pos = marf_value_end;
            } else {
                pos += 1;
            }
        } else if node_id >= 2 && node_id <= 5 {
            // Internal node (Node4, Node16, Node48, Node256) - skip by estimating size
            // This is approximate; we mainly care about finding leaves
            pos += TRIE_HASH_SIZE + 1;
        } else {
            pos += 1;
        }
    }
}

/// Result of scanning a MARF, including sample values for debugging
struct ScanResult {
    stats: ZeroValueStats,
    sample_marf_values: Vec<[u8; MARF_VALUE_SIZE]>,
}

/// Scan the external blobs file
fn scan_external_blobs(
    blobs_path: &PathBuf,
    db_conn: &Connection,
    none_marf_value: &[u8; MARF_VALUE_SIZE],
    sample_size: Option<usize>,
    verbose: bool,
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let mut stats = ZeroValueStats::default();
    let mut sample_marf_values = Vec::new();

    // Get all block entries with external blob info
    let mut stmt = db_conn.prepare(
        "SELECT block_id, external_offset, external_length FROM marf_data
         WHERE external_length > 0 AND unconfirmed = 0
         ORDER BY block_id",
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
    let blocks_to_scan: Vec<_> = if let Some(n) = sample_size {
        // Sample N blocks evenly distributed
        if n >= total_blocks {
            blocks
        } else {
            let step = total_blocks / n;
            blocks.into_iter().step_by(step).take(n).collect()
        }
    } else {
        blocks
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

    for (block_id, offset, length) in blocks_to_scan {
        pb.inc(1);

        if offset + length > file_size {
            if verbose {
                eprintln!(
                    "Warning: Block {} has invalid offset/length ({}/{}), skipping",
                    block_id, offset, length
                );
            }
            continue;
        }

        // Read the trie blob
        reader.seek(SeekFrom::Start(offset))?;
        let mut blob_data = vec![0u8; length as usize];
        reader.read_exact(&mut blob_data)?;

        let first_blob = stats.blocks_scanned == 0;
        stats.blocks_scanned += 1;
        stats.bytes_scanned += length;

        scan_trie_blob(&blob_data, none_marf_value, &mut stats, verbose, first_blob, &mut sample_marf_values);
    }

    pb.finish_with_message("Scan complete");

    // If we sampled, extrapolate the results
    if let Some(_) = sample_size {
        let scale = total_blocks as f64 / stats.blocks_scanned as f64;
        eprintln!(
            "\nNote: Results extrapolated from {} sampled blocks (scale factor: {:.2}x)",
            stats.blocks_scanned, scale
        );
        stats.none_leaves = (stats.none_leaves as f64 * scale) as u64;
        stats.none_bytes = (stats.none_bytes as f64 * scale) as u64;
        stats.total_leaves = (stats.total_leaves as f64 * scale) as u64;
    }

    Ok(ScanResult { stats, sample_marf_values })
}

/// Scan inline SQLite blobs (for databases without external blobs)
fn scan_sqlite_blobs(
    db_conn: &Connection,
    none_marf_value: &[u8; MARF_VALUE_SIZE],
    sample_size: Option<usize>,
    verbose: bool,
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let mut stats = ZeroValueStats::default();
    let mut sample_marf_values = Vec::new();

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

        scan_trie_blob(&blob_data, none_marf_value, &mut stats, verbose, first_blob, &mut sample_marf_values);
    }

    pb.finish_with_message("Scan complete");

    // If we sampled, extrapolate
    if sample_size.is_some() && stats.blocks_scanned > 0 {
        let scale = total_blocks as f64 / stats.blocks_scanned as f64;
        eprintln!(
            "\nNote: Results extrapolated from {} sampled blocks (scale factor: {:.2}x)",
            stats.blocks_scanned, scale
        );
        stats.none_leaves = (stats.none_leaves as f64 * scale) as u64;
        stats.none_bytes = (stats.none_bytes as f64 * scale) as u64;
        stats.total_leaves = (stats.total_leaves as f64 * scale) as u64;
    }

    Ok(ScanResult { stats, sample_marf_values })
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
    none_marf_value: &[u8; MARF_VALUE_SIZE],
    sample_size: Option<usize>,
    verbose: bool,
) -> Result<Option<ScanResult>, Box<dyn std::error::Error>> {
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
    }

    println!("Scanning...");

    let result = if use_external_blobs {
        scan_external_blobs(
            &location.blobs_path,
            &db_conn,
            none_marf_value,
            sample_size,
            verbose,
        )?
    } else {
        scan_sqlite_blobs(&db_conn, none_marf_value, sample_size, verbose)?
    };

    Ok(Some(result))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Compute the none-value MARFValue hash
    let none_marf_value = compute_none_marf_value();
    println!("MARF Zero-Value Analysis");
    println!("========================\n");
    println!(
        "None-value MARFValue (40 bytes): 0x{}",
        hex::encode(&none_marf_value)
    );
    println!(
        "  Hash (first 32 bytes): 0x{}",
        hex::encode(&none_marf_value[..32])
    );
    println!(
        "  Reserved (last 8 bytes): 0x{}",
        hex::encode(&none_marf_value[32..])
    );
    println!("\nChainstate path: {:?}", args.chainstate_path);

    // Define all MARF locations to scan
    let marf_locations = [
        // Clarity VM MARF - stores Clarity values (this is where none values live)
        MarfLocation {
            name: "Clarity VM MARF",
            db_path: args.chainstate_path.join("vm/index.sqlite"),
            blobs_path: args.chainstate_path.join("vm/index.sqlite.blobs"),
        },
        // Chainstate MARF - stores block header data
        MarfLocation {
            name: "Chainstate MARF",
            db_path: args.chainstate_path.join("marf.sqlite"),
            blobs_path: args.chainstate_path.join("marf.sqlite.blobs"),
        },
    ];

    let mut total_stats = ZeroValueStats::default();
    let mut all_sample_values: Vec<[u8; MARF_VALUE_SIZE]> = Vec::new();
    let mut found_any = false;

    for location in &marf_locations {
        match scan_marf(location, &none_marf_value, args.sample_size, args.verbose)? {
            Some(result) => {
                found_any = true;
                let stats = result.stats;

                // Print per-MARF stats
                println!("  Blocks scanned: {}", stats.blocks_scanned);
                println!(
                    "  Bytes scanned: {:.2} GB",
                    stats.bytes_scanned as f64 / 1_073_741_824.0
                );
                println!("  Leaf nodes: {}", stats.total_leaves);
                println!("  None-value leaves: {}", stats.none_leaves);
                println!(
                    "  None-value bytes: {:.2} MB",
                    stats.none_bytes as f64 / 1_048_576.0
                );

                // Print sample MARFValues for debugging
                if !result.sample_marf_values.is_empty() {
                    println!("  Sample MARFValues from leaves:");
                    for (i, value) in result.sample_marf_values.iter().enumerate() {
                        println!("    [{}] 0x{}", i, hex::encode(value));
                    }
                    // Collect for later comparison
                    all_sample_values.extend(result.sample_marf_values);
                }

                // Accumulate totals
                total_stats.blocks_scanned += stats.blocks_scanned;
                total_stats.bytes_scanned += stats.bytes_scanned;
                total_stats.total_leaves += stats.total_leaves;
                total_stats.none_leaves += stats.none_leaves;
                total_stats.none_bytes += stats.none_bytes;
                for (len, count) in stats.none_path_lengths {
                    *total_stats.none_path_lengths.entry(len).or_insert(0) += count;
                }
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
    println!("Total leaf nodes found: {}", stats.total_leaves);
    println!("None-value leaf nodes: {}", stats.none_leaves);
    println!(
        "None-value percentage: {:.2}% of leaves",
        stats.none_percentage()
    );
    println!(
        "\nBytes used by none-leaves: {:.2} MB ({:.2} GB)",
        stats.none_bytes as f64 / 1_048_576.0,
        stats.none_bytes as f64 / 1_073_741_824.0
    );
    println!(
        "Percentage of scanned data: {:.2}%",
        stats.bytes_percentage()
    );

    if !stats.none_path_lengths.is_empty() {
        println!("\nNone-leaf path length distribution:");
        let mut lengths: Vec<_> = stats.none_path_lengths.iter().collect();
        lengths.sort_by_key(|(len, _)| *len);
        for (len, count) in lengths {
            println!("  Path length {}: {} leaves", len, count);
        }
    }

    let avg_none_leaf_size = if stats.none_leaves > 0 {
        stats.none_bytes as f64 / stats.none_leaves as f64
    } else {
        0.0
    };
    println!("\nAverage bytes per none-leaf: {:.1}", avg_none_leaf_size);

    println!("\n\nPotential Space Recovery");
    println!("========================");
    println!(
        "If none-values were not stored: {:.2} MB ({:.2} GB) recoverable",
        stats.none_bytes as f64 / 1_048_576.0,
        stats.none_bytes as f64 / 1_073_741_824.0
    );

    Ok(())
}
