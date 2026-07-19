//! Rust-native framed telemetry emission and gateway admission.
//!
//! This crate owns the framed plaintext wire contract used between pods and
//! gateways: profile identifiers, nonce/AAD construction, bounded encrypted
//! frame envelopes, fixture emission, replay, and gateway-side admission.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(debug_assertions), deny(warnings))]

mod aad;
mod admission;
mod fixture;
mod frame;
mod nonce;
mod profile;
#[cfg(feature = "std")]
mod replay;

pub use aad::*;
pub use admission::*;
pub use fixture::*;
pub use frame::*;
pub use nonce::*;
pub use profile::*;
#[cfg(feature = "std")]
pub use replay::*;

#[cfg(test)]
mod tests;
