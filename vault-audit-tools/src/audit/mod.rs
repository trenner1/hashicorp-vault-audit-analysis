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
//! use vault_audit_tools::audit::parser::AuditLogReader;
//!
//! let mut reader = AuditLogReader::new("audit.log").unwrap();
//! while let Some(entry) = reader.next_entry().unwrap() {
//!     if let Some(request) = &entry.request {
//!         if let Some(operation) = &request.operation {
//!             println!("Operation: {}", operation);
//!         }
//!     }
//! }
//! ```

pub mod parser;
pub mod types;
