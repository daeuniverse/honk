//! honk-config: Configuration types and parsing for honk.
//!
//! This crate defines the configuration schema for honk — proxy node
//! definitions, routing rules, DNS settings, and subscription management.
//! The primary configuration format is the original dae syntax
//! (`global { ... } node { ... } routing { ... }`), parsed by [`parser`].

pub mod check;
pub mod config;
pub mod diagnostic;
pub mod dns;
pub mod error;
pub mod experimental;
pub mod group;
pub mod node;
pub mod options;
pub mod parser;
pub mod paths;
pub mod routing;
pub mod share_link;
pub mod subscription;
pub mod types;

pub use config::Config;
pub use diagnostic::ConfigDiagnostic;
pub use error::ConfigError;

#[cfg(feature = "conformance")]
pub use parser::conformance;

#[cfg(feature = "fuzz-checks")]
pub mod fuzz_checks;
