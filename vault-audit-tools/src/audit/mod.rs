//! Core audit log parsing and data structures.
//!
//! This module provides the fundamental types for working with
//! HashiCorp Vault audit logs.
//!
//! ## Key Components
//!
//! - [`types`] - Data structures representing audit log entries
//!
//! ## Example
//!
//! ```no_run
//! use vault_audit_tools::audit::types::AuditEntry;
//! use std::fs::File;
//! use std::io::{BufRead, BufReader};
//!
//! let file = File::open("audit.log").unwrap();
//! let reader = BufReader::new(file);
//!
//! for line in reader.lines() {
//!     let line = line.unwrap();
//!     if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
//!         if let Some(request) = &entry.request {
//!             if let Some(operation) = &request.operation {
//!                 println!("Operation: {}", operation);
//!             }
//!         }
//!     }
//! }
//! ```

pub mod types;
