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

pub mod progress;
pub mod time;
