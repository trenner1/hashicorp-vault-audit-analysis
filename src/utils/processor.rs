//! Unified file processing abstraction for audit log analysis.
//!
//! This module provides a DRY abstraction for processing multiple audit log files
//! with consistent progress tracking, error handling, and support for both
//! parallel and sequential processing modes.

use crate::audit::types::AuditEntry;
use crate::utils::progress::ProgressBar;
use crate::utils::reader::open_file;
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Processing mode for file processing
#[derive(Debug, Clone, Copy)]
pub enum ProcessingMode {
    /// Process files in parallel using all available CPU cores
    Parallel,
    /// Process files sequentially (one at a time)
    Sequential,
    /// Automatically choose based on file count and size
    Auto,
}

/// Configuration for file processing
#[derive(Debug)]
pub struct ProcessorConfig {
    /// Processing mode to use
    pub mode: ProcessingMode,
    /// Progress update frequency (lines)
    pub progress_frequency: usize,
    /// Whether to show detailed per-file completion messages
    pub show_file_completion: bool,
    /// Custom progress label
    pub progress_label: String,
    /// Whether to use strict JSON parsing (fail on any parse error)
    pub strict_parsing: bool,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        Self {
            mode: ProcessingMode::Auto,
            progress_frequency: 2000,
            show_file_completion: true,
            progress_label: "Processing".to_string(),
            strict_parsing: false,
        }
    }
}

/// Statistics collected during processing
#[derive(Debug, Default, Clone)]
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
    /// Merge another stats object into this one
    pub fn merge(&mut self, other: &Self) {
        self.total_lines += other.total_lines;
        self.parsed_entries += other.parsed_entries;
        self.skipped_lines += other.skipped_lines;
        self.files_processed += other.files_processed;
    }

    /// Print a summary of processing statistics
    pub fn report(&self) {
        eprintln!("\nProcessing Summary:");
        eprintln!("  Files processed: {}", self.files_processed);
        eprintln!(
            "  Total lines: {}",
            crate::utils::format::format_number(self.total_lines)
        );
        eprintln!(
            "  Parsed entries: {}",
            crate::utils::format::format_number(self.parsed_entries)
        );
        if self.skipped_lines > 0 {
            let skip_percentage = (self.skipped_lines as f64 / self.total_lines as f64) * 100.0;
            eprintln!(
                "  Skipped lines: {} ({:.2}%)",
                crate::utils::format::format_number(self.skipped_lines),
                skip_percentage
            );
        }
    }
}

/// Unified file processor that handles both parallel and sequential processing
pub struct FileProcessor {
    config: ProcessorConfig,
}

impl FileProcessor {
    /// Create a new file processor with default configuration
    pub fn new() -> Self {
        Self {
            config: ProcessorConfig::default(),
        }
    }

    /// Create a new file processor with custom configuration
    pub const fn with_config(config: ProcessorConfig) -> Self {
        Self { config }
    }

    /// Process multiple files with a streaming line-by-line processor
    ///
    /// This is the main entry point for file processing. It automatically handles:
    /// - Progress tracking with accurate totals and ETA
    /// - Parallel or sequential processing based on configuration
    /// - Error handling and context
    /// - Memory-efficient streaming
    ///
    /// # Arguments
    /// * `files` - List of file paths to process
    /// * `line_processor` - Function that processes individual audit entries
    /// * `aggregator` - Function that combines results from all files
    /// * `initial` - Initial value for the aggregator
    ///
    /// # Example
    /// ```rust,ignore
    /// let processor = FileProcessor::new();
    /// let result = processor.process_files_streaming(
    ///     &files,
    ///     |entry, state| {
    ///         // Process each audit entry
    ///         state.counter += 1;
    ///     },
    ///     |acc, file_result| {
    ///         // Combine results from each file
    ///         acc.merge(file_result)
    ///     },
    ///     MyState::new(),
    /// )?;
    /// ```
    pub fn process_files_streaming<T, F, A>(
        &self,
        files: &[String],
        line_processor: F,
        aggregator: A,
        initial: T,
    ) -> Result<(T, ProcessStats)>
    where
        T: Send + Clone + Sync + 'static,
        F: FnMut(&AuditEntry, &mut T) + Send + Sync + Clone,
        A: Fn(T, T) -> T + Send + Sync,
    {
        if files.is_empty() {
            return Ok((initial, ProcessStats::default()));
        }

        let mode = self.determine_processing_mode(files);

        match mode {
            ProcessingMode::Parallel => {
                self.process_parallel_streaming(files, line_processor, aggregator, initial)
            }
            ProcessingMode::Sequential => {
                self.process_sequential_streaming(files, line_processor, aggregator, initial)
            }
            ProcessingMode::Auto => unreachable!(), // determine_processing_mode resolves this
        }
    }

    /// Process multiple files and collect results into a collection
    ///
    /// This is a convenience method for cases where you want to collect
    /// individual results from each file rather than aggregating.
    #[allow(dead_code)]
    pub fn process_files_collect<T, F>(
        &self,
        files: &[String],
        processor: F,
    ) -> Result<(Vec<T>, ProcessStats)>
    where
        T: Send + 'static,
        F: Fn(&str) -> Result<T> + Send + Sync,
    {
        if files.is_empty() {
            return Ok((Vec::new(), ProcessStats::default()));
        }

        let mode = self.determine_processing_mode(files);

        match mode {
            ProcessingMode::Parallel => self.process_parallel_collect(files, processor),
            ProcessingMode::Sequential => self.process_sequential_collect(files, processor),
            ProcessingMode::Auto => unreachable!(),
        }
    }

    /// Determine the optimal processing mode based on files and configuration
    const fn determine_processing_mode(&self, files: &[String]) -> ProcessingMode {
        match self.config.mode {
            ProcessingMode::Auto => {
                if files.len() == 1 {
                    ProcessingMode::Sequential
                } else if files.len() >= 2 {
                    ProcessingMode::Parallel
                } else {
                    ProcessingMode::Sequential
                }
            }
            mode => mode,
        }
    }

    /// Process files in parallel with streaming
    fn process_parallel_streaming<T, F, A>(
        &self,
        files: &[String],
        line_processor: F,
        aggregator: A,
        initial: T,
    ) -> Result<(T, ProcessStats)>
    where
        T: Send + Clone + Sync + 'static,
        F: FnMut(&AuditEntry, &mut T) + Send + Sync + Clone,
        A: Fn(T, T) -> T + Send + Sync,
    {
        eprintln!("Processing {} files in parallel...", files.len());

        // Pre-scan to determine total work
        eprintln!("Scanning files to determine total work...");
        let total_lines: usize = files
            .par_iter()
            .map(|file_path| count_file_lines(file_path).unwrap_or(0))
            .sum();

        eprintln!(
            "Total lines to process: {}",
            crate::utils::format::format_number(total_lines)
        );

        let processed_lines = Arc::new(AtomicUsize::new(0));
        let progress = Arc::new(Mutex::new(ProgressBar::new(
            total_lines,
            &self.config.progress_label,
        )));

        // Process files in parallel
        let results: Result<Vec<_>> = files
            .par_iter()
            .enumerate()
            .map(|(idx, file_path)| -> Result<(T, ProcessStats)> {
                let mut file_state = initial.clone();
                let mut local_processor = line_processor.clone();

                let progress_ref = (processed_lines.clone(), progress.clone());
                let stats = self.process_single_file_streaming(
                    file_path,
                    &mut local_processor,
                    &mut file_state,
                    Some(&progress_ref),
                )?;

                if self.config.show_file_completion {
                    let lines_count = count_file_lines(file_path)?;
                    if let Ok(progress) = progress.lock() {
                        progress.println(format!(
                            "[{}/{}] ✓ Completed: {} ({} lines)",
                            idx + 1,
                            files.len(),
                            file_path.split('/').next_back().unwrap_or(file_path),
                            crate::utils::format::format_number(lines_count)
                        ));
                    }
                }

                Ok((file_state, stats))
            })
            .collect();

        let results = results?;

        // Finish progress bar with final message
        if let Ok(progress) = progress.lock() {
            progress.finish_with_message(&format!(
                "Processed {} total lines",
                crate::utils::format::format_number(processed_lines.load(Ordering::Relaxed))
            ));
        }

        // Aggregate all results
        let mut combined_stats = ProcessStats::default();
        let final_result = results
            .into_iter()
            .fold(initial, |acc, (file_result, file_stats)| {
                combined_stats.merge(&file_stats);
                aggregator(acc, file_result)
            });

        Ok((final_result, combined_stats))
    }

    /// Process files sequentially with streaming
    fn process_sequential_streaming<T, F, A>(
        &self,
        files: &[String],
        mut line_processor: F,
        aggregator: A,
        initial: T,
    ) -> Result<(T, ProcessStats)>
    where
        T: Send + Clone + Sync,
        F: FnMut(&AuditEntry, &mut T) + Send + Sync,
        A: Fn(T, T) -> T + Send + Sync,
    {
        eprintln!("Processing {} files sequentially...", files.len());

        let mut combined_result = initial;
        let mut combined_stats = ProcessStats::default();

        for (file_idx, file_path) in files.iter().enumerate() {
            eprintln!(
                "[{}/{}] Processing: {}",
                file_idx + 1,
                files.len(),
                file_path
            );

            let mut file_state = combined_result.clone();
            let single_file_stats = self.process_single_file_streaming(
                file_path,
                &mut line_processor,
                &mut file_state,
                None, // No shared progress for sequential
            )?;

            combined_result = aggregator(combined_result, file_state);
            combined_stats.merge(&single_file_stats);

            if self.config.show_file_completion {
                eprintln!(
                    "[{}/{}] ✓ Completed: {} ({} lines)",
                    file_idx + 1,
                    files.len(),
                    file_path.split('/').next_back().unwrap_or(file_path),
                    crate::utils::format::format_number(single_file_stats.total_lines)
                );
            }
        }

        Ok((combined_result, combined_stats))
    }

    /// Process files in parallel and collect individual results
    #[allow(dead_code)]
    #[allow(clippy::unused_self)]
    fn process_parallel_collect<T, F>(
        &self,
        files: &[String],
        processor: F,
    ) -> Result<(Vec<T>, ProcessStats)>
    where
        T: Send + 'static,
        F: Fn(&str) -> Result<T> + Send + Sync,
    {
        eprintln!("Processing {} files in parallel...", files.len());

        let total_lines: usize = files
            .par_iter()
            .map(|file_path| count_file_lines(file_path).unwrap_or(0))
            .sum();

        let results: Result<Vec<_>> = files
            .par_iter()
            .map(|file_path| processor(file_path))
            .collect();

        let stats = ProcessStats {
            total_lines,
            parsed_entries: 0, // Unknown for collected results
            skipped_lines: 0,
            files_processed: files.len(),
        };

        Ok((results?, stats))
    }

    /// Process files sequentially and collect individual results
    #[allow(dead_code)]
    fn process_sequential_collect<T, F>(
        &self,
        files: &[String],
        processor: F,
    ) -> Result<(Vec<T>, ProcessStats)>
    where
        F: Fn(&str) -> Result<T>,
    {
        eprintln!("Processing {} files sequentially...", files.len());

        let mut results = Vec::new();
        let mut total_lines = 0;

        for (file_idx, file_path) in files.iter().enumerate() {
            eprintln!(
                "[{}/{}] Processing: {}",
                file_idx + 1,
                files.len(),
                file_path
            );

            let result = processor(file_path)?;
            let lines_processed = count_file_lines(file_path)?;

            results.push(result);
            total_lines += lines_processed;

            if self.config.show_file_completion {
                eprintln!(
                    "[{}/{}] ✓ Completed: {} ({} lines)",
                    file_idx + 1,
                    files.len(),
                    file_path.split('/').next_back().unwrap_or(file_path),
                    crate::utils::format::format_number(lines_processed)
                );
            }
        }

        let stats = ProcessStats {
            total_lines,
            parsed_entries: 0, // Unknown for collected results
            skipped_lines: 0,
            files_processed: files.len(),
        };

        Ok((results, stats))
    }

    /// Process a single file with streaming and optional progress tracking
    fn process_single_file_streaming<T, F>(
        &self,
        file_path: &str,
        line_processor: &mut F,
        state: &mut T,
        progress: Option<&(Arc<AtomicUsize>, Arc<Mutex<ProgressBar>>)>,
    ) -> Result<ProcessStats>
    where
        F: FnMut(&AuditEntry, &mut T),
    {
        let file =
            open_file(file_path).with_context(|| format!("Failed to open file: {}", file_path))?;
        let reader = BufReader::new(file);

        let mut file_stats = ProcessStats::default();

        for line_result in reader.lines() {
            let line =
                line_result.with_context(|| format!("Failed to read line from {}", file_path))?;

            file_stats.total_lines += 1;

            // Update progress if in parallel mode
            if file_stats.total_lines % self.config.progress_frequency == 0 {
                if let Some((processed_lines, progress_bar)) = &progress {
                    processed_lines.fetch_add(self.config.progress_frequency, Ordering::Relaxed);
                    if let Ok(p) = progress_bar.lock() {
                        p.update(processed_lines.load(Ordering::Relaxed));
                    }
                }
            }

            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }

            // Parse and process entry
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => {
                    file_stats.parsed_entries += 1;
                    line_processor(&entry, state);
                }
                Err(e) => {
                    file_stats.skipped_lines += 1;
                    if self.config.strict_parsing {
                        return Err(e).with_context(|| {
                            format!(
                                "Failed to parse JSON at line {} in {}",
                                file_stats.total_lines, file_path
                            )
                        });
                    }
                    // Skip invalid lines and continue in non-strict mode
                }
            }
        }

        // Update progress for remaining lines
        if let Some((processed_lines, progress_bar)) = &progress {
            let remaining = file_stats.total_lines % self.config.progress_frequency;
            if remaining > 0 {
                processed_lines.fetch_add(remaining, Ordering::Relaxed);
                if let Ok(p) = progress_bar.lock() {
                    p.update(processed_lines.load(Ordering::Relaxed));
                }
            }
        }

        file_stats.files_processed = 1;
        Ok(file_stats)
    }
}

impl Default for FileProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Count lines in a file for progress tracking
fn count_file_lines(file_path: &str) -> Result<usize> {
    let file =
        open_file(file_path).with_context(|| format!("Failed to open file: {}", file_path))?;
    let reader = BufReader::new(file);

    let mut count = 0;
    for line_result in reader.lines() {
        line_result.with_context(|| format!("Failed to read line from {}", file_path))?;
        count += 1;
    }

    Ok(count)
}

/// Convenience builder for creating configured processors
pub struct ProcessorBuilder {
    config: ProcessorConfig,
}

impl ProcessorBuilder {
    /// Create a new processor builder
    pub fn new() -> Self {
        Self {
            config: ProcessorConfig::default(),
        }
    }

    /// Set the processing mode
    #[must_use]
    pub const fn mode(mut self, mode: ProcessingMode) -> Self {
        self.config.mode = mode;
        self
    }

    /// Set progress update frequency
    #[must_use]
    #[allow(dead_code)]
    pub const fn progress_frequency(mut self, frequency: usize) -> Self {
        self.config.progress_frequency = frequency;
        self
    }

    /// Set whether to show file completion messages
    #[must_use]
    #[allow(dead_code)]
    pub const fn show_file_completion(mut self, show: bool) -> Self {
        self.config.show_file_completion = show;
        self
    }

    /// Set custom progress label
    #[must_use]
    pub fn progress_label<S: Into<String>>(mut self, label: S) -> Self {
        self.config.progress_label = label.into();
        self
    }

    /// Enable strict JSON parsing
    #[must_use]
    #[allow(dead_code)]
    pub const fn strict_parsing(mut self, strict: bool) -> Self {
        self.config.strict_parsing = strict;
        self
    }

    /// Build the file processor
    #[must_use]
    pub fn build(self) -> FileProcessor {
        FileProcessor::with_config(self.config)
    }
}

impl Default for ProcessorBuilder {
    fn default() -> Self {
        Self::new()
    }
}
