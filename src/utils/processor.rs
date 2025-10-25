//! Log file processing utilities.
//!
//! This module provides a common abstraction for processing multiple audit log files
//! with progress tracking, error handling, and consistent patterns across commands.

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};

/// Statistics collected during log processing
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct ProcessStats {
    /// Total number of lines processed across all files
    pub total_lines: usize,
    /// Number of successfully parsed audit entries
    pub parsed_entries: usize,
    /// Number of lines skipped due to parse errors
    pub skipped_lines: usize,
    /// Number of files processed
    pub files_processed: usize,
}

impl ProcessStats {
    /// Print a summary of processing statistics
    #[allow(dead_code)]
    pub fn report(&self) {
        eprintln!("\nProcessing Summary:");
        eprintln!("  Files processed: {}", self.files_processed);
        eprintln!("  Total lines: {}", self.total_lines);
        eprintln!("  Parsed entries: {}", self.parsed_entries);
        if self.skipped_lines > 0 {
            let skip_percentage = (self.skipped_lines as f64 / self.total_lines as f64) * 100.0;
            eprintln!(
                "  Skipped lines: {} ({:.2}%)",
                self.skipped_lines, skip_percentage
            );
        }
    }
}

/// Context provided to the entry handler function
#[allow(dead_code)]
pub struct ProcessContext {
    /// Current file being processed (0-indexed)
    pub file_index: usize,
    /// Total number of files to process
    pub total_files: usize,
    /// Current line number within the current file
    pub line_number: usize,
    /// Current file path
    pub file_path: String,
    /// Processing statistics
    pub stats: ProcessStats,
}

/// A log processor that handles the common pattern of processing audit log files
#[allow(dead_code)]
pub struct LogProcessor<'a> {
    files: &'a [String],
    progress_label: String,
    strict_parsing: bool,
}

impl<'a> LogProcessor<'a> {
    /// Create a new log processor for the given files
    #[allow(dead_code)]
    pub fn new(files: &'a [String], progress_label: &str) -> Self {
        Self {
            files,
            progress_label: progress_label.to_string(),
            strict_parsing: false,
        }
    }

    /// Enable strict parsing mode (fail on any parse error)
    #[must_use]
    #[allow(dead_code)]
    pub const fn strict_parsing(mut self, strict: bool) -> Self {
        self.strict_parsing = strict;
        self
    }

    /// Process all files with the given entry handler
    ///
    /// The handler function receives each parsed audit entry and a context object.
    /// It should return Ok(()) to continue processing or Err(e) to stop.
    #[allow(dead_code)]
    pub fn process<F, E>(self, mut handler: F) -> Result<ProcessStats>
    where
        F: FnMut(&AuditEntry, &mut ProcessContext) -> Result<(), E>,
        E: Into<anyhow::Error>,
    {
        let mut stats = ProcessStats::default();

        for (file_idx, log_file) in self.files.iter().enumerate() {
            eprintln!(
                "[{}/{}] Processing: {}",
                file_idx + 1,
                self.files.len(),
                log_file
            );

            // Get file size for progress tracking
            let file_size = std::fs::metadata(log_file).ok().map(|m| m.len() as usize);
            let mut progress = if let Some(size) = file_size {
                ProgressBar::new(size, &self.progress_label)
            } else {
                ProgressBar::new_spinner(&self.progress_label)
            };

            let file = open_file(log_file)
                .with_context(|| format!("Failed to open file: {}", log_file))?;
            let reader = BufReader::new(file);

            let mut file_lines = 0;
            let mut bytes_read = 0;
            let mut context = ProcessContext {
                file_index: file_idx,
                total_files: self.files.len(),
                line_number: 0,
                file_path: log_file.clone(),
                stats,
            };

            for line in reader.lines() {
                file_lines += 1;
                context.line_number = file_lines;
                context.stats.total_lines += 1;

                let line = line.with_context(|| {
                    format!("Failed to read line {} from {}", file_lines, log_file)
                })?;
                bytes_read += line.len() + 1; // +1 for newline

                // Update progress every 10k lines for smooth animation
                if file_lines % 10_000 == 0 {
                    if let Some(size) = file_size {
                        progress.update(bytes_read.min(size)); // Cap at file size
                    } else {
                        progress.update(file_lines);
                    }
                }

                // Parse the audit entry
                let entry: AuditEntry = match serde_json::from_str(&line) {
                    Ok(e) => {
                        context.stats.parsed_entries += 1;
                        e
                    }
                    Err(e) => {
                        context.stats.skipped_lines += 1;
                        if self.strict_parsing {
                            return Err(e).with_context(|| {
                                format!(
                                    "Failed to parse JSON at line {} in {}",
                                    file_lines, log_file
                                )
                            });
                        }
                        // Skip invalid lines and continue
                        continue;
                    }
                };

                // Call the handler
                if let Err(e) = handler(&entry, &mut context) {
                    return Err(e.into()).with_context(|| {
                        format!("Handler failed at line {} in {}", file_lines, log_file)
                    });
                }
            }

            progress.finish();
            stats = context.stats;
            stats.files_processed += 1;
        }

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_process_empty_file() {
        let temp = NamedTempFile::new().unwrap();
        let files = vec![temp.path().to_string_lossy().to_string()];

        let processor = LogProcessor::new(&files, "Testing");
        let stats = processor
            .process(|_entry, _ctx| Ok::<(), anyhow::Error>(()))
            .unwrap();

        assert_eq!(stats.total_lines, 0);
        assert_eq!(stats.parsed_entries, 0);
        assert_eq!(stats.files_processed, 1);
    }

    #[test]
    fn test_process_valid_audit_log() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"{{"type": "request", "time": "2025-10-07T10:00:00Z"}}"#
        )
        .unwrap();
        writeln!(
            temp,
            r#"{{"type": "response", "time": "2025-10-07T10:00:01Z"}}"#
        )
        .unwrap();
        temp.flush().unwrap();

        let files = vec![temp.path().to_string_lossy().to_string()];
        let processor = LogProcessor::new(&files, "Testing");

        let mut entry_count = 0;
        let stats = processor
            .process(|_entry, _ctx| {
                entry_count += 1;
                Ok::<(), anyhow::Error>(())
            })
            .unwrap();

        assert_eq!(stats.total_lines, 2);
        assert_eq!(stats.parsed_entries, 2);
        assert_eq!(stats.skipped_lines, 0);
        assert_eq!(entry_count, 2);
    }

    #[test]
    fn test_process_with_invalid_json() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"{{"type": "request", "time": "2025-10-07T10:00:00Z"}}"#
        )
        .unwrap();
        writeln!(temp, r"invalid json line").unwrap();
        writeln!(
            temp,
            r#"{{"type": "response", "time": "2025-10-07T10:00:01Z"}}"#
        )
        .unwrap();
        temp.flush().unwrap();

        let files = vec![temp.path().to_string_lossy().to_string()];
        let processor = LogProcessor::new(&files, "Testing");

        let mut entry_count = 0;
        let stats = processor
            .process(|_entry, _ctx| {
                entry_count += 1;
                Ok::<(), anyhow::Error>(())
            })
            .unwrap();

        assert_eq!(stats.total_lines, 3);
        assert_eq!(stats.parsed_entries, 2);
        assert_eq!(stats.skipped_lines, 1);
        assert_eq!(entry_count, 2);
    }

    #[test]
    fn test_strict_parsing_mode() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"{{"type": "request", "time": "2025-10-07T10:00:00Z"}}"#
        )
        .unwrap();
        writeln!(temp, r"invalid json line").unwrap();
        temp.flush().unwrap();

        let files = vec![temp.path().to_string_lossy().to_string()];
        let processor = LogProcessor::new(&files, "Testing").strict_parsing(true);

        let result = processor.process(|_entry, _ctx| Ok::<(), anyhow::Error>(()));
        assert!(result.is_err());
    }
}
