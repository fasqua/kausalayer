//! Wallet Storage and Encryption for KausaLayer

use std::fs;
use std::path::PathBuf;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{KausaError, Result};
use crate::core::stealth::StealthKeys;

#[derive(Serialize, Deserialize)]
pub struct EncryptedWallet {
    version: u8,
    salt: String,      // hex encoded
    nonce: String,     // hex encoded
    ciphertext: String, // hex encoded
}

#[derive(Serialize, Deserialize)]
struct WalletData {
    spend_key: String,
    view_key: String,
}

pub fn get_wallet_path() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| KausaError::ConfigError("Cannot find home directory".into()))?;
    Ok(home.join(".kausalayer").join("wallet.enc"))
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| KausaError::CryptoError(format!("Key derivation failed: {}", e)))?;
    Ok(key)
}

fn encrypt_data(data: &[u8], password: &str) -> Result<EncryptedWallet> {
    let mut rng = rand::thread_rng();
    
    // Generate random salt (16 bytes)
    let mut salt_bytes = [0u8; 16];
    rng.fill_bytes(&mut salt_bytes);
    
    // Derive key
    let key = derive_key(password, &salt_bytes)?;
    
    // Generate random nonce (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| KausaError::CryptoError(e.to_string()))?;
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| KausaError::CryptoError(format!("Encryption failed: {}", e)))?;
    
    Ok(EncryptedWallet {
        version: 1,
        salt: hex::encode(salt_bytes),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

fn decrypt_data(wallet: &EncryptedWallet, password: &str) -> Result<Vec<u8>> {
    // Decode salt
    let salt_bytes = hex::decode(&wallet.salt)
        .map_err(|e| KausaError::CryptoError(e.to_string()))?;
    
    // Derive key
    let key = derive_key(password, &salt_bytes)?;
    
    // Decode nonce
    let nonce_bytes = hex::decode(&wallet.nonce)
        .map_err(|e| KausaError::CryptoError(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Decode ciphertext
    let ciphertext = hex::decode(&wallet.ciphertext)
        .map_err(|e| KausaError::CryptoError(e.to_string()))?;
    
    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| KausaError::CryptoError(e.to_string()))?;
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| KausaError::CryptoError("Decryption failed - wrong password?".into()))?;
    
    Ok(plaintext)
}

pub fn save_wallet(keys: &StealthKeys, password: &str, path: Option<PathBuf>) -> Result<PathBuf> {
    let wallet_path = path.unwrap_or(get_wallet_path()?);
    
    if let Some(parent) = wallet_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| KausaError::ConfigError(format!("Cannot create directory: {}", e)))?;
    }
    
    let (spend, view) = keys.to_bytes();
    let data = WalletData {
        spend_key: hex::encode(spend),
        view_key: hex::encode(view),
    };
    let json = serde_json::to_vec(&data)
        .map_err(|e| KausaError::ConfigError(e.to_string()))?;
    
    let encrypted = encrypt_data(&json, password)?;
    
    let file_content = serde_json::to_string_pretty(&encrypted)
        .map_err(|e| KausaError::ConfigError(e.to_string()))?;
    fs::write(&wallet_path, file_content)
        .map_err(|e| KausaError::ConfigError(format!("Cannot write wallet: {}", e)))?;
    
    Ok(wallet_path)
}

pub fn load_wallet(password: &str, path: Option<PathBuf>) -> Result<StealthKeys> {
    let wallet_path = path.unwrap_or(get_wallet_path()?);
    
    let content = fs::read_to_string(&wallet_path)
        .map_err(|e| KausaError::ConfigError(format!("Cannot read wallet: {}", e)))?;
    
    let encrypted: EncryptedWallet = serde_json::from_str(&content)
        .map_err(|e| KausaError::ConfigError(format!("Invalid wallet format: {}", e)))?;
    
    let plaintext = decrypt_data(&encrypted, password)?;
    
    let data: WalletData = serde_json::from_slice(&plaintext)
        .map_err(|e| KausaError::ConfigError(format!("Invalid wallet data: {}", e)))?;
    
    let spend_bytes: [u8; 32] = hex::decode(&data.spend_key)
        .map_err(|e| KausaError::CryptoError(e.to_string()))?
        .try_into()
        .map_err(|_| KausaError::CryptoError("Invalid spend key length".into()))?;
    
    let view_bytes: [u8; 32] = hex::decode(&data.view_key)
        .map_err(|e| KausaError::CryptoError(e.to_string()))?
        .try_into()
        .map_err(|_| KausaError::CryptoError("Invalid view key length".into()))?;
    
    StealthKeys::from_bytes(spend_bytes, view_bytes)
}

pub fn wallet_exists(path: Option<PathBuf>) -> bool {
    let wallet_path = path.unwrap_or_else(|| get_wallet_path().unwrap_or_default());
    wallet_path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_save_load_wallet() {
        let temp_path = env::temp_dir().join("kausalayer_test_wallet.enc");
        let original_keys = StealthKeys::new();
        let original_meta = original_keys.get_meta_address_string();
        let password = "test_password_123";
        
        save_wallet(&original_keys, password, Some(temp_path.clone())).unwrap();
        let loaded_keys = load_wallet(password, Some(temp_path.clone())).unwrap();
        let loaded_meta = loaded_keys.get_meta_address_string();
        
        assert_eq!(original_meta, loaded_meta);
        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn test_wrong_password() {
        let temp_path = env::temp_dir().join("kausalayer_test_wrong_pw.enc");
        let keys = StealthKeys::new();
        save_wallet(&keys, "correct_password", Some(temp_path.clone())).unwrap();
        
        let result = load_wallet("wrong_password", Some(temp_path.clone()));
        assert!(result.is_err());
        let _ = fs::remove_file(temp_path);
    }
}
