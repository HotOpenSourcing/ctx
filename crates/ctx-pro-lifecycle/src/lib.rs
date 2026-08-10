//! Durable lifecycle authority for ctx Pro.
//!
//! This crate owns release trust, signed manifest and pair interpretation,
//! installation discovery and mutation, deletion state, and the operation
//! guard. `ctx-pro-host` consumes validated artifact identities from here and
//! retains ownership of OS-level executable identity and protocol transport.

pub mod installed_artifact;
pub mod release_manifest;
