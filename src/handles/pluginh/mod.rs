//! The `plugin://` verbs (the handle itself is `automation/pluginh.rs`).

pub mod available;
pub mod catalog;
pub mod common;
pub mod net;
pub mod paths;
pub mod plugin;
pub mod sign;
pub mod state;
#[cfg(test)]
mod tests;

pub use plugin::*;
pub use state::*;
