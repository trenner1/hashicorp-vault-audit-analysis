//! Smart file reader with automatic decompression support.
//!
//! Provides transparent decompression for .gz and .zst files,
//! allowing analysis of compressed audit logs without manual extraction.
//!
//! # Supported Formats
//!
//! - Plain text files
//! - Gzip compressed files (.gz)
//! - Zstandard compressed files (.zst)
//!
//! # Examples
//!
//! ```no_run
//! use vault_audit_tools::utils::reader::open_file;
//! use std::io::{BufRead, BufReader};
//!
//! // Automatically handles .gz, .zst, or plain text
//! let reader = open_file("audit.log.gz").unwrap();
//! let buf_reader = BufReader::new(reader);
//!
//! for line in buf_reader.lines() {
//!     let line = line.unwrap();
//!     // Process line...
//! }
//! ```

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Opens a file with automatic decompression based on extension.
///
/// Detects file type by extension:
/// - `.gz` → Gzip decompression
/// - `.zst` → Zstandard decompression
/// - Otherwise → Plain file
///
/// # Arguments
///
/// * `path` - Path to the file (compressed or uncompressed)
///
/// # Returns
///
/// A `Read` trait object that transparently handles decompression
///
/// # Examples
///
/// ```no_run
/// use vault_audit_tools::utils::reader::open_file;
/// use std::io::Read;
///
/// let mut reader = open_file("audit.log.gz").unwrap();
/// let mut contents = String::new();
/// reader.read_to_string(&mut contents).unwrap();
/// ```
pub fn open_file(path: impl AsRef<Path>) -> Result<Box<dyn Read + Send>> {
    let path = path.as_ref();
    let file =
        File::open(path).with_context(|| format!("Failed to open file: {}", path.display()))?;

    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match extension {
        "gz" => {
            let decoder = GzDecoder::new(file);
            Ok(Box::new(decoder))
        }
        "zst" => {
            let decoder = zstd::Decoder::new(file).with_context(|| {
                format!("Failed to create zstd decoder for: {}", path.display())
            })?;
            Ok(Box::new(decoder))
        }
        _ => Ok(Box::new(file)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use tempfile::NamedTempFile;

    #[test]
    fn test_plain_file() {
        let mut temp = NamedTempFile::new().unwrap();
        writeln!(temp, "test line 1").unwrap();
        writeln!(temp, "test line 2").unwrap();
        temp.flush().unwrap();

        let reader = open_file(temp.path()).unwrap();
        let buf_reader = BufReader::new(reader);
        let lines: Vec<String> = buf_reader.lines().collect::<Result<_, _>>().unwrap();

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "test line 1");
        assert_eq!(lines[1], "test line 2");
    }

    #[test]
    fn test_gzip_file() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut temp = NamedTempFile::with_suffix(".gz").unwrap();
        {
            let mut encoder = GzEncoder::new(&mut temp, Compression::default());
            writeln!(encoder, "compressed line 1").unwrap();
            writeln!(encoder, "compressed line 2").unwrap();
            encoder.finish().unwrap();
        }
        temp.flush().unwrap();

        let reader = open_file(temp.path()).unwrap();
        let buf_reader = BufReader::new(reader);
        let lines: Vec<String> = buf_reader.lines().collect::<Result<_, _>>().unwrap();

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "compressed line 1");
        assert_eq!(lines[1], "compressed line 2");
    }

    #[test]
    fn test_zstd_file() {
        let mut temp = NamedTempFile::with_suffix(".zst").unwrap();
        {
            let mut encoder = zstd::Encoder::new(&mut temp, 3).unwrap();
            writeln!(encoder, "zstd line 1").unwrap();
            writeln!(encoder, "zstd line 2").unwrap();
            encoder.finish().unwrap();
        }
        temp.flush().unwrap();

        let reader = open_file(temp.path()).unwrap();
        let buf_reader = BufReader::new(reader);
        let lines: Vec<String> = buf_reader.lines().collect::<Result<_, _>>().unwrap();

        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "zstd line 1");
        assert_eq!(lines[1], "zstd line 2");
    }
}
