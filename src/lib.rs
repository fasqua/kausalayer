//! KausaLayer - Private Transfer on Solana
//!
//! Powered by Stealth Diffusion Protocol (SDP)
//!
//! # Features
//! - Stealth addresses (hide receiver)
//! - Fragmentation (hide amount)
//! - Relay + Tor (hide sender)

pub mod config;
pub mod error;
pub mod core;
pub mod agent;
pub mod relay;

pub use config::Config;
pub use error::{KausaError, Result};

/// KausaLayer version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
