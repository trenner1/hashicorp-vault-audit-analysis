//! Streaming parser for Vault audit logs.
//!
//! This module provides memory-efficient parsing of audit log files
//! by reading and parsing one line at a time, rather than loading
//! the entire file into memory.
//!
//! # Example
//!
//! ```no_run
//! use vault_audit_tools::audit::parser::AuditLogReader;
//!
//! let mut reader = AuditLogReader::new("audit.log").unwrap();
//! while let Some(entry) = reader.next_entry().unwrap() {
//!     if let Some(auth) = &entry.auth {
//!         if let Some(entity_id) = &auth.entity_id {
//!             println!("Entity: {}", entity_id);
//!         }
//!     }
//! }
//! ```

use super::types::AuditEntry;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Iterator over audit log entries from a file.
///
/// This reader provides streaming access to audit log entries,
/// parsing them one line at a time to minimize memory usage.
/// Invalid JSON lines are automatically skipped.
pub struct AuditLogReader {
    reader: BufReader<File>,
    line_buffer: String,
}

impl AuditLogReader {
    /// Create a new audit log reader from a file path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the audit log file
    ///
    /// # Returns
    ///
    /// Returns `Ok(AuditLogReader)` on success, or an error if the file
    /// cannot be opened.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use vault_audit_tools::audit::parser::AuditLogReader;
    ///
    /// let reader = AuditLogReader::new("audit.log").unwrap();
    /// ```
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path).context("Failed to open audit log file")?;
        Ok(Self {
            reader: BufReader::new(file),
            line_buffer: String::new(),
        })
    }

    /// Read the next valid audit entry, skipping invalid lines.
    ///
    /// Invalid JSON lines are silently skipped and do not cause errors.
    /// This allows processing of audit logs that may contain corrupted
    /// or malformed entries.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(entry))` - Successfully parsed an entry
    /// * `Ok(None)` - End of file reached
    /// * `Err(...)` - I/O error reading the file
    pub fn next_entry(&mut self) -> Result<Option<AuditEntry>> {
        loop {
            self.line_buffer.clear();
            let bytes_read = self.reader.read_line(&mut self.line_buffer)?;

            if bytes_read == 0 {
                return Ok(None); // EOF
            }

            let line = self.line_buffer.trim();
            if line.is_empty() {
                continue;
            }

            match serde_json::from_str(line) {
                Ok(entry) => return Ok(Some(entry)),
                Err(_) => {
                    // Skip invalid lines silently (common in audit logs)
                    continue;
                }
            }
        }
    }
}
