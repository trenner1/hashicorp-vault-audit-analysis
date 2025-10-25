//! Parallel file processing utilities.
//!
//! This module provides high-performance parallel processing of multiple audit log files
//! using Rayon for CPU-bound workloads. Files are processed concurrently with proper
//! progress tracking and error handling.

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Result of processing a single file
#[derive(Debug)]
#[allow(dead_code)]
pub struct FileProcessResult<T> {
    pub file_path: String,
    pub lines_processed: usize,
    pub data: T,
}

/// Process multiple files in parallel with a custom handler function
///
/// This function processes files concurrently, maximizing CPU utilization
/// for I/O and CPU intensive audit log analysis.
///
/// # Arguments
/// * `files` - List of file paths to process
/// * `processor` - Function that processes entries from a single file
/// * `combiner` - Function that combines results from all files
///
/// # Returns
/// Combined result from all files plus total lines processed
pub fn process_files_parallel<T, F, C, R>(
    files: &[String],
    processor: F,
    combiner: C,
) -> Result<(R, usize)>
where
    T: Send + 'static,
    R: Send + 'static,
    F: Fn(&str, Vec<AuditEntry>) -> T + Send + Sync,
    C: Fn(Vec<FileProcessResult<T>>) -> R + Send + Sync,
{
    if files.is_empty() {
        return Err(anyhow::anyhow!("No files provided for processing"));
    }

    eprintln!("Processing {} files in parallel...", files.len());

    let total_lines = Arc::new(AtomicUsize::new(0));
    let progress = Arc::new(Mutex::new(ProgressBar::new_spinner("Processing files")));

    // Process files in parallel
    let results: Result<Vec<_>> = files
        .par_iter()
        .enumerate()
        .map(|(idx, file_path)| -> Result<FileProcessResult<T>> {
            eprintln!("[{}/{}] Starting: {}", idx + 1, files.len(), file_path);

            // Read and parse the entire file
            let entries = read_file_entries(file_path)?;
            let lines_count = entries.len();

            // Update progress
            total_lines.fetch_add(lines_count, Ordering::Relaxed);
            if let Ok(mut progress) = progress.lock() {
                progress.update(total_lines.load(Ordering::Relaxed));
            }

            // Process entries with the provided function
            let data = processor(file_path, entries);

            eprintln!(
                "[{}/{}] Completed: {} ({} lines)",
                idx + 1,
                files.len(),
                file_path,
                lines_count
            );

            Ok(FileProcessResult {
                file_path: file_path.clone(),
                lines_processed: lines_count,
                data,
            })
        })
        .collect();

    let results = results?;
    let total_lines_processed = total_lines.load(Ordering::Relaxed);

    if let Ok(mut progress) = progress.lock() {
        progress.finish_with_message(&format!("Processed {} total lines", total_lines_processed));
    }

    // Combine results
    let result = combiner(results);

    Ok((result, total_lines_processed))
}

/// Read all entries from a single file
fn read_file_entries(file_path: &str) -> Result<Vec<AuditEntry>> {
    let file =
        open_file(file_path).with_context(|| format!("Failed to open file: {}", file_path))?;
    let reader = BufReader::new(file);

    let mut entries = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line
            .with_context(|| format!("Failed to read line {} from {}", line_num + 1, file_path))?;

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        // Parse JSON entry
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Process multiple files with simple aggregation (sum, count, etc.)
///
/// This is a simpler version for cases where you just need to aggregate
/// simple metrics across files.
#[allow(dead_code)]
pub fn process_files_aggregate<T, F, A>(
    files: &[String],
    processor: F,
    aggregator: A,
    initial: T,
) -> Result<(T, usize)>
where
    T: Send + Clone + Sync + 'static,
    F: Fn(&str, Vec<AuditEntry>) -> T + Send + Sync,
    A: Fn(T, T) -> T + Send + Sync,
{
    process_files_parallel(files, processor, |results| {
        results
            .into_iter()
            .fold(initial.clone(), |acc, result| aggregator(acc, result.data))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parallel_processing() {
        // Create test files
        let mut files = Vec::new();
        let _temp_files: Vec<NamedTempFile> = (0..3).map(|i| {
            let mut temp_file = NamedTempFile::new().unwrap();
            writeln!(temp_file, r#"{{"type":"response","time":"2025-10-07T10:00:0{}Z","auth":{{"entity_id":"entity-{}"}}}}"#, i, i).unwrap();
            writeln!(temp_file, r#"{{"type":"response","time":"2025-10-07T10:00:0{}Z","auth":{{"entity_id":"entity-{}"}}}}"#, i+1, i).unwrap();

            files.push(temp_file.path().to_str().unwrap().to_string());
            temp_file
        }).collect();

        // Process files to count entries per file
        let (results, total_lines) = process_files_parallel(
            &files,
            |_file_path, entries| entries.len(),
            |results| results.into_iter().map(|r| r.data).sum::<usize>(),
        )
        .unwrap();

        assert_eq!(results, 6); // 2 entries per file * 3 files
        assert_eq!(total_lines, 6);
    }
}
