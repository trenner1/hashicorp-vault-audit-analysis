//! Core audit log parsing and data structures.
//!
//! This module provides the fundamental types and parsing logic for
//! working with HashiCorp Vault audit logs.
//!
//! ## Key Components
//!
//! - [`types`] - Data structures representing audit log entries
//! - [`parser`] - Streaming JSON parser for audit logs
//!
//! ## Example
//!
//! ```no_run
//! use vault_audit_tools::audit::parser::parse_audit_file;
//!
//! let entries = parse_audit_file("audit.log").unwrap();
//! for entry in entries {
//!     println!("Operation: {}", entry.request.operation);
//! }
//! ```

pub mod parser;
pub mod types;
