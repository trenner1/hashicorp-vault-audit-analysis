use super::types::AuditEntry;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Iterator over audit log entries from a file
pub struct AuditLogReader {
    reader: BufReader<File>,
    line_buffer: String,
}

impl AuditLogReader {
    /// Create a new audit log reader from a file path
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path).context("Failed to open audit log file")?;
        Ok(Self {
            reader: BufReader::new(file),
            line_buffer: String::new(),
        })
    }

    /// Read the next valid audit entry, skipping invalid lines
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
