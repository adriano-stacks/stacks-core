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
use sha2::{Digest, Sha512_256};

/// Size of MARFValue in bytes
const MARF_VALUE_SIZE: usize = 40;
/// Size of TrieHash (node hash) in bytes
const TRIE_HASH_SIZE: usize = 32;
/// TrieNodeID for Leaf nodes
const TRIE_NODE_ID_LEAF: u8 = 1;

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
    // Clarity none serializes to 0x09 (TypePrefix::OptionalNone)
    // As hex string: "09"
    // MARFValue::from_value("09") computes SHA512_256("09".as_bytes())
    let mut hasher = Sha512_256::new();
    hasher.update(b"09");
    let hash: [u8; 32] = hasher.finalize().into();

    // MARFValue is 40 bytes: 32-byte hash + 8 reserved bytes (zeros)
    let mut marf_value = [0u8; MARF_VALUE_SIZE];
    marf_value[..TRIE_HASH_SIZE].copy_from_slice(&hash);
    marf_value
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

/// Scan a single trie blob for leaf nodes and count none-values
fn scan_trie_blob(
    data: &[u8],
    none_marf_value: &[u8; MARF_VALUE_SIZE],
    stats: &mut ZeroValueStats,
    verbose: bool,
) {
    // Trie blob format:
    // - First 32 bytes: root hash
    // - Remaining: serialized nodes
    //
    // We scan for leaf nodes by looking for the leaf ID byte pattern
    // Each leaf is: [ID:1][path_len:1][path:N][MARFValue:40]

    if data.len() < TRIE_HASH_SIZE {
        return;
    }

    let mut pos = TRIE_HASH_SIZE; // Skip root hash

    while pos < data.len() {
        let node_id = data[pos] & 0x7F; // Clear backptr flag

        if node_id == TRIE_NODE_ID_LEAF {
            // This looks like a leaf node - try to parse it
            if pos + 2 > data.len() {
                break;
            }

            let path_len = data[pos + 1] as usize;

            // Calculate expected leaf size
            let leaf_data_start = pos + 2 + path_len;
            let leaf_end = leaf_data_start + MARF_VALUE_SIZE;

            if leaf_end > data.len() {
                // Not enough data - this isn't a valid leaf or we're at a boundary
                pos += 1;
                continue;
            }

            // Extract the MARFValue from the leaf
            let marf_value = &data[leaf_data_start..leaf_end];

            stats.total_leaves += 1;

            // Check if this is a none-value
            if marf_value == none_marf_value.as_slice() {
                stats.none_leaves += 1;

                // Calculate bytes used by this none-leaf:
                // - 32 bytes for node hash (stored before node in blob)
                // - 1 byte for node ID
                // - 1 byte for path length
                // - N bytes for path
                // - 40 bytes for MARFValue
                let leaf_bytes = TRIE_HASH_SIZE + 2 + path_len + MARF_VALUE_SIZE;
                stats.none_bytes += leaf_bytes as u64;

                *stats.none_path_lengths.entry(path_len).or_insert(0) += 1;

                if verbose {
                    eprintln!(
                        "  Found none-leaf at offset {}, path_len={}, size={}",
                        pos, path_len, leaf_bytes
                    );
                }
            }

            // Move past this leaf
            pos = leaf_end;
        } else {
            // Not a leaf - move forward byte by byte looking for next node
            // (This is a simplification; proper parsing would decode each node type)
            pos += 1;
        }
    }
}

/// Scan the external blobs file
fn scan_external_blobs(
    blobs_path: &PathBuf,
    db_conn: &Connection,
    none_marf_value: &[u8; MARF_VALUE_SIZE],
    sample_size: Option<usize>,
    verbose: bool,
) -> Result<ZeroValueStats, Box<dyn std::error::Error>> {
    let mut stats = ZeroValueStats::default();

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

        stats.blocks_scanned += 1;
        stats.bytes_scanned += length;

        scan_trie_blob(&blob_data, none_marf_value, &mut stats, verbose);
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

    Ok(stats)
}

/// Scan inline SQLite blobs (for databases without external blobs)
fn scan_sqlite_blobs(
    db_conn: &Connection,
    none_marf_value: &[u8; MARF_VALUE_SIZE],
    sample_size: Option<usize>,
    verbose: bool,
) -> Result<ZeroValueStats, Box<dyn std::error::Error>> {
    let mut stats = ZeroValueStats::default();

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

        stats.blocks_scanned += 1;
        stats.bytes_scanned += blob_data.len() as u64;

        scan_trie_blob(&blob_data, none_marf_value, &mut stats, verbose);
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

    Ok(stats)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Compute the none-value MARFValue hash
    let none_marf_value = compute_none_marf_value();
    println!("MARF Zero-Value Analysis");
    println!("========================\n");
    println!(
        "None-value MARFValue (SHA512_256 of \"09\"): 0x{}",
        hex::encode(&none_marf_value[..32])
    );

    // Locate MARF database
    let marf_db_path = args.chainstate_path.join("vm/index.sqlite");
    let marf_blobs_path = args.chainstate_path.join("vm/index.sqlite.blobs");

    if !marf_db_path.exists() {
        // Try alternative paths
        let alt_path = args.chainstate_path.join("index.sqlite");
        if !alt_path.exists() {
            return Err(format!(
                "MARF database not found at {:?} or {:?}",
                marf_db_path, alt_path
            )
            .into());
        }
    }

    println!("\nChainstate path: {:?}", args.chainstate_path);
    println!("MARF database: {:?}", marf_db_path);

    // Open database
    let db_conn = Connection::open_with_flags(&marf_db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    // Check if external blobs exist
    let use_external_blobs = marf_blobs_path.exists();
    if use_external_blobs {
        let blobs_size = fs::metadata(&marf_blobs_path)?.len();
        println!(
            "External blobs file: {:?} ({:.2} GB)",
            marf_blobs_path,
            blobs_size as f64 / 1_073_741_824.0
        );
    } else {
        println!("External blobs file: Not found (using inline SQLite blobs)");
    }

    println!("\nScanning...\n");

    let stats = if use_external_blobs {
        scan_external_blobs(
            &marf_blobs_path,
            &db_conn,
            &none_marf_value,
            args.sample_size,
            args.verbose,
        )?
    } else {
        scan_sqlite_blobs(&db_conn, &none_marf_value, args.sample_size, args.verbose)?
    };

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
