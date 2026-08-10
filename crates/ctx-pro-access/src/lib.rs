//! Headless ctx Pro commercial access and credential custody.
//!
//! Product-channel selection, browser and UI orchestration, artifact/helper
//! installation, graph lifecycle, and data-root/installation identity authority
//! remain in the CLI host. This crate accepts those authorities as explicit
//! values and never resolves them from ambient product state.

pub mod authorization;
pub mod commercial_api;
pub mod credential_vault;
#[cfg(feature = "qualification")]
mod qualification_authorizer;
mod request_identity;
pub mod workos_device;
