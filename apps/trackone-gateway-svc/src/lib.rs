//! Deployable TrackOne VTL gateway service runtime.

#![cfg_attr(not(debug_assertions), deny(warnings))]

pub mod postgres;
pub mod producer;
pub mod service;
pub mod tsa;
