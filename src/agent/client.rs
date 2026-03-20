//! Relay Client - Connect to relay via Tor
use base64::Engine;

use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// Obfuscated relay URL (decoded at runtime)
const RELAY_ENCODED: &str = "a2d2ZmZyaXlwYjZzb2h1dG1qaDZlajRjZTQzeG1idjJ3ZWxyYXBhY2FlNWNwam5scHBwZzNoeWQub25pb24=";

#[derive(Clone)]
pub struct RelayClient {
    client: Client,
    relay_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub wallets_available: usize,
    pub tor_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct TransferRequest {
    pub recipient: String,
    pub amount: f64,
}

#[derive(Debug, Deserialize)]
pub struct TransferResponse {
    pub status: String,
    pub signature: Option<String>,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct BalanceRequest {
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct BalanceResponse {
    pub address: String,
    pub lamports: u64,
}

#[derive(Debug, Serialize)]
pub struct ScanRequest {
    pub view_pubkey: String,
    pub spend_pubkey: String,
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScanResult {
    pub ephemeral_pubkey: String,
    pub stealth_address: String,
    pub amount_lamports: u64,
    pub slot: u64,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct ScanResponse {
    pub transfers: Vec<ScanResult>,
}

#[derive(Debug, Serialize)]
pub struct SubmitRequest {
    pub signed_tx: String,
}

#[derive(Debug, Deserialize)]
pub struct SubmitResponse {
    pub status: String,
    pub signature: Option<String>,
    pub message: String,
}

impl RelayClient {
    /// Create new client with Tor SOCKS5 proxy
    pub fn new() -> Result<Self> {
        // Decode relay URL
        let relay_host = String::from_utf8(
            base64::engine::general_purpose::STANDARD.decode(RELAY_ENCODED)
                .map_err(|e| anyhow!("Failed to decode relay URL: {}", e))?
        ).map_err(|e| anyhow!("Invalid UTF-8: {}", e))?;
        
        let relay_url = format!("http://{}", relay_host);
        
        // Build client with Tor SOCKS5 proxy
        let proxy = reqwest::Proxy::all("socks5h://127.0.0.1:9050")
            .map_err(|e| anyhow!("Failed to create proxy: {}", e))?;
        
        let client = Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| anyhow!("Failed to build client: {}", e))?;
        
        Ok(Self { client, relay_url })
    }
    
    /// Create client without Tor (for testing)
    pub fn new_direct(url: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow!("Failed to build client: {}", e))?;
        
        Ok(Self { 
            client, 
            relay_url: url.to_string(),
        })
    }
    
    /// Health check
    pub async fn health(&self) -> Result<HealthResponse> {
        let resp = self.client
            .get(format!("{}/health", self.relay_url))
            .send()
            .await
            .map_err(|e| anyhow!("Connection failed: {}", e))?;
        
        resp.json().await
            .map_err(|e| anyhow!("Invalid response: {}", e))
    }
    
    /// Send SOL to stealth address
    pub async fn send(&self, recipient: &str, amount: f64) -> Result<TransferResponse> {
        let req = TransferRequest {
            recipient: recipient.to_string(),
            amount,
        };
        
        let resp = self.client
            .post(format!("{}/transfer/direct", self.relay_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| anyhow!("Send failed: {}", e))?;
        
        resp.json().await
            .map_err(|e| anyhow!("Invalid response: {}", e))
    }
    
    /// Check balance of address
    pub async fn balance(&self, address: &str) -> Result<BalanceResponse> {
        let req = BalanceRequest {
            address: address.to_string(),
        };
        
        let resp = self.client
            .post(format!("{}/balance", self.relay_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| anyhow!("Balance check failed: {}", e))?;
        
        resp.json().await
            .map_err(|e| anyhow!("Invalid response: {}", e))
    }
    
    /// Scan for incoming transfers
    pub async fn scan(&self, view_pubkey: &str, spend_pubkey: &str, limit: Option<u32>) -> Result<ScanResponse> {
        let req = ScanRequest {
            view_pubkey: view_pubkey.to_string(),
            spend_pubkey: spend_pubkey.to_string(),
            limit,
        };
        
        let resp = self.client
            .post(format!("{}/scan", self.relay_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| anyhow!("Scan failed: {}", e))?;
        
        resp.json().await
            .map_err(|e| anyhow!("Invalid response: {}", e))
    }
    
    /// Submit signed transaction
    pub async fn submit(&self, signed_tx_base64: &str) -> Result<SubmitResponse> {
        let req = SubmitRequest {
            signed_tx: signed_tx_base64.to_string(),
        };
        
        let resp = self.client
            .post(format!("{}/submit", self.relay_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| anyhow!("Submit failed: {}", e))?;
        
        resp.json().await
            .map_err(|e| anyhow!("Invalid response: {}", e))
    }
}
