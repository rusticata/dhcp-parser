//! # DHCP Parser
//!
//! This crate contains a parser written in pure Rust for the DHCP protocol.
//!
//! See also:
//! - [RFC 1541](https://tools.ietf.org/html/rfc1541): Dynamic Host Configuration Protocol
//! - [RFC 1533](https://tools.ietf.org/html/rfc1533): DHCP Options and BOOTP Vendor Extensions

#![deny(/*missing_docs,*/ unsafe_code,
        unstable_features,
        unused_import_braces, unused_qualifications)]

mod dhcp;
pub use dhcp::*;

mod dhcp_options;
pub use dhcp_options::*;

mod parser;
pub use parser::*;

mod state;
pub use state::*;
