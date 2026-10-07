//! Deployable TrackOne VTL gateway service runtime.

#![cfg_attr(not(debug_assertions), deny(warnings))]

pub mod config;
pub mod error;
pub mod postgres;
pub mod postgres_connection;
pub mod producer;
pub mod service;
pub mod snapshot;
pub mod tsa;

pub mod timestamp_worker;

pub mod evidence;
