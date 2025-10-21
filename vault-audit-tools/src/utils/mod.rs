//! Utility functions and helpers.
//!
//! This module provides common functionality used across multiple commands:
//!
//! - [`progress`] - Progress tracking and display utilities
//! - [`time`] - Timestamp parsing and formatting helpers
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
//! ## Formatting numbers with commas
//!
//! ```
//! use vault_audit_tools::utils::progress::format_number;
//!
//! assert_eq!(format_number(1000000), "1,000,000");
//! ```

pub mod progress;
pub mod time;
