//! Utility functions and helpers.
//!
//! This module provides common functionality used across multiple commands:
//!
//! - [`progress`] - Progress tracking and display utilities
//! - [`time`] - Timestamp parsing and formatting helpers
//! - [`reader`] - Smart file reader with automatic decompression
//!
//! # Examples
//!
//! ## Parsing timestamps
//!
//! ```no_run
//! use vault_audit_tools::utils::time::parse_timestamp;
//!
//! let timestamp = parse_timestamp("2025-10-20T10:30:00.000Z").unwrap();
//! println!("Parsed: {}", timestamp);
//! ```
//!
//! ## Reading compressed files
//!
//! ```no_run
//! use vault_audit_tools::utils::reader::open_file;
//! use std::io::{BufRead, BufReader};
//!
//! // Automatically decompresses .gz and .zst files
//! let reader = open_file("audit.log.gz").unwrap();
//! let buf_reader = BufReader::new(reader);
//! ```

pub mod progress;
pub mod reader;
pub mod time;
