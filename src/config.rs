//! KausaLayer Configuration

use std::env;

/// Configuration for KausaLayer
#[derive(Debug, Clone)]
pub struct Config {
    /// Solana RPC URL
    pub solana_rpc_url: String,
    /// Relay server URL
    pub relay_url: String,
    /// Use Tor for privacy
    pub use_tor: bool,
    /// Protocol fee percentage (0.1 = 0.1%)
    pub protocol_fee_percent: f64,
    /// Minimum number of fragments
    pub min_fragments: u8,
    /// Maximum number of fragments
    pub max_fragments: u8,
    /// Default timing window in milliseconds
    pub timing_window_ms: u64,
    /// Memo prefix for SDP transactions
    pub sdp_memo_prefix: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            solana_rpc_url: "https://api.devnet.solana.com".to_string(),
            relay_url: "http://localhost:8080".to_string(),
            use_tor: false,
            protocol_fee_percent: 0.1,
            min_fragments: 2,
            max_fragments: 6,
            timing_window_ms: 15000,
            sdp_memo_prefix: "SDP:".to_string(),
        }
    }
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        dotenv::dotenv().ok();
        
        Self {
            solana_rpc_url: env::var("SOLANA_RPC_URL")
                .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string()),
            relay_url: env::var("RELAY_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            use_tor: env::var("USE_TOR")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false),
            protocol_fee_percent: env::var("PROTOCOL_FEE_PERCENT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.1),
            min_fragments: env::var("MIN_FRAGMENTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2),
            max_fragments: env::var("MAX_FRAGMENTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(6),
            timing_window_ms: env::var("TIMING_WINDOW_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15000),
            sdp_memo_prefix: env::var("SDP_MEMO_PREFIX")
                .unwrap_or_else(|_| "SDP:".to_string()),
        }
    }
}
