//! Durable lifecycle authority for ctx Pro.
//!
//! This crate owns release trust, signed manifest and pair interpretation,
//! installation discovery and mutation, deletion state, and the operation
//! guard. `ctx-pro-host` consumes validated artifact identities from here and
//! retains ownership of OS-level executable identity and protocol transport.

pub mod artifact_delivery;
mod commercial_deletion;
pub mod deletion;
mod graph_key_deletion;
pub mod installation;
pub mod installed_artifact;
pub mod operation;
pub mod release_manifest;
pub mod state_markers;
