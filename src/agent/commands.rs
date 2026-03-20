//! CLI Command Handlers

use anyhow::{Result, anyhow};
use std::path::PathBuf;

use crate::core::{StealthKeys, MetaAddress, lamports_to_sol, save_wallet, load_wallet, wallet_exists, get_wallet_path};
use super::{RelayClient, TransferStorage};

const APP_DIR: &str = ".kausalayer";
const DB_FILE: &str = "transfers.db";

pub fn get_app_dir() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow!("Cannot find home directory"))?;
    let app_dir = home.join(APP_DIR);
    
    if !app_dir.exists() {
        std::fs::create_dir_all(&app_dir)
            .map_err(|e| anyhow!("Cannot create app directory: {}", e))?;
    }
    
    Ok(app_dir)
}

pub fn get_db_path() -> Result<PathBuf> {
    Ok(get_app_dir()?.join(DB_FILE))
}

/// Setup new wallet
pub fn cmd_setup(password: &str) -> Result<String> {
    if wallet_exists(None) {
        return Err(anyhow!("Wallet already exists. Use 'kausalayer address' to view."));
    }
    
    // Generate new keys
    let keys = StealthKeys::new();
    let meta = keys.get_meta_address();
    let meta_encoded = meta.encode();
    
    // Save encrypted
    save_wallet(&keys, password, None)?;
    
    Ok(meta_encoded)
}

/// Load wallet with password
pub fn cmd_load_wallet(password: &str) -> Result<StealthKeys> {
    if !wallet_exists(None) {
        return Err(anyhow!("No wallet found. Run 'kausalayer setup' first."));
    }
    
    load_wallet(password, None).map_err(|e| anyhow!("Failed to load wallet: {}", e))
}

/// Get meta-address
pub fn cmd_address(password: &str) -> Result<String> {
    let keys = cmd_load_wallet(password)?;
    let meta = keys.get_meta_address();
    Ok(meta.encode())
}

/// Send SOL via relay
pub async fn cmd_send(password: &str, recipient: &str, amount: f64) -> Result<String> {
    // Validate recipient
    if !recipient.starts_with("kl_") {
        return Err(anyhow!("Invalid recipient. Must start with 'kl_'"));
    }
    
    // Validate meta-address format
    MetaAddress::decode(recipient)?;
    
    // Validate amount
    if amount < 0.001 {
        return Err(anyhow!("Minimum amount is 0.001 SOL"));
    }
    
    // Load wallet to verify password
    let _keys = cmd_load_wallet(password)?;
    
    // Connect to relay
    let client = RelayClient::new()?;
    
    // Send
    let resp = client.send(recipient, amount).await?;
    
    if resp.status == "success" {
        Ok(resp.signature.unwrap_or_default())
    } else {
        Err(anyhow!("Send failed: {}", resp.message))
    }
}

/// Scan for incoming transfers
pub async fn cmd_scan(password: &str) -> Result<Vec<super::storage::PendingTransfer>> {
    let keys = cmd_load_wallet(password)?;
    let meta = keys.get_meta_address();
    
    let view_pubkey = bs58::encode(&meta.view_pubkey).into_string();
    let spend_pubkey = bs58::encode(&meta.spend_pubkey).into_string();
    
    // Connect to relay
    let client = RelayClient::new()?;
    
    // Scan
    let resp = client.scan(&view_pubkey, &spend_pubkey, Some(100)).await?;
    
    // Store locally
    let db_path = get_db_path()?;
    let storage = TransferStorage::new(&db_path)?;
    
    for transfer in &resp.transfers {
        storage.add_transfer(
            &transfer.ephemeral_pubkey,
            &transfer.stealth_address,
            transfer.amount_lamports,
            transfer.slot,
            &transfer.signature,
        )?;
    }
    
    // Return pending
    storage.get_pending()
}

/// List pending transfers
pub fn cmd_pending() -> Result<Vec<super::storage::PendingTransfer>> {
    let db_path = get_db_path()?;
    let storage = TransferStorage::new(&db_path)?;
    storage.get_pending()
}

/// Claim all pending transfers
pub async fn cmd_claim_all(password: &str) -> Result<Vec<(String, String)>> {
    let keys = cmd_load_wallet(password)?;
    
    let db_path = get_db_path()?;
    let storage = TransferStorage::new(&db_path)?;
    let pending = storage.get_pending()?;
    
    if pending.is_empty() {
        return Err(anyhow!("No pending transfers to claim"));
    }
    
    let client = RelayClient::new()?;
    let mut results = Vec::new();
    
    for transfer in pending {
        // Derive stealth keypair
        let ephemeral_bytes = bs58::decode(&transfer.ephemeral_pubkey)
            .into_vec()
            .map_err(|e| anyhow!("Invalid ephemeral: {}", e))?;
        
        if ephemeral_bytes.len() != 32 {
            continue;
        }
        
        let mut ephemeral_arr = [0u8; 32];
        ephemeral_arr.copy_from_slice(&ephemeral_bytes);
        
        // TODO: Build claim transaction
        // For MVP, placeholder
        results.push((transfer.stealth_address.clone(), "pending_implementation".to_string()));
    }
    
    Ok(results)
}

/// Get balance summary
pub async fn cmd_balance(password: &str) -> Result<(u64, u64)> {
    let _keys = cmd_load_wallet(password)?;
    
    let db_path = get_db_path()?;
    let storage = TransferStorage::new(&db_path)?;
    
    let pending_lamports = storage.get_total_pending_lamports()?;
    
    Ok((0, pending_lamports))
}

/// Check relay status
pub async fn cmd_status() -> Result<super::client::HealthResponse> {
    let client = RelayClient::new()?;
    client.health().await
}
