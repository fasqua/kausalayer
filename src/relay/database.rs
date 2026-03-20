//! Database module for relay server
//! Handles persistent storage of deposit requests

use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;
use solana_sdk::signature::{Keypair, Signer};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};

const DB_PATH: &str = "relay_data.db";
// Encryption key seed loaded from environment variable DB_ENCRYPTION_KEY

/// Status of a deposit request
#[derive(Debug, Clone, PartialEq)]
pub enum RequestStatus {
    Pending,
    Completed,
    Expired,
    RefundPending,
}

impl RequestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Expired => "expired",
            Self::RefundPending => "refund_pending",
        }
    }
    
    pub fn from_str(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "completed" => Self::Completed,
            "expired" => Self::Expired,
            "refund_pending" => Self::RefundPending,
            _ => Self::Pending,
        }
    }
}

/// A deposit request stored in database
#[derive(Debug, Clone)]
pub struct DepositRequest {
    pub request_id: String,
    pub amount_lamports: u64,
    pub fee_lamports: u64,
    pub recipient_meta: String,
    pub deposit_address: String,
    pub status: RequestStatus,
    pub created_at: i64,
    pub expires_at: i64,
    pub completed_at: Option<i64>,
    pub tx_signature: Option<String>,
}

/// A token deposit request stored in database
#[derive(Debug, Clone)]
pub struct TokenDepositRequest {
    pub request_id: String,
    pub token_mint: String,
    pub token_program: String,
    pub token_decimals: u8,
    pub token_amount: u64,
    pub fee_amount: u64,
    pub recipient_meta: String,
    pub deposit_address: String,
    pub deposit_ata: String,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub tx_signature: Option<String>,
}

/// Database wrapper for relay
pub struct RelayDatabase {
    conn: Mutex<Connection>,
    cipher_key: [u8; 32],
}

impl RelayDatabase {
    /// Create or open database
    pub fn new() -> Result<Self, String> {
        Self::new_with_path(DB_PATH)
    }
    
    pub fn new_with_path(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        // Generate encryption key from environment variable
        let seed = std::env::var("DB_ENCRYPTION_KEY")
            .unwrap_or_else(|_| {
                eprintln!("WARNING: DB_ENCRYPTION_KEY not set, using insecure default!");
                "INSECURE_DEFAULT_KEY_CHANGE_ME".to_string()
            });
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let cipher_key: [u8; 32] = hasher.finalize().into();
        
        let db = Self {
            conn: Mutex::new(conn),
            cipher_key,
        };
        
        db.init_tables()?;
        
        Ok(db)
    }
    

    /// Initialize database tables
    fn init_tables(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS deposit_requests (
                request_id      TEXT PRIMARY KEY,
                amount_lamports INTEGER NOT NULL,
                fee_lamports    INTEGER NOT NULL,
                recipient_meta  TEXT NOT NULL,
                deposit_address TEXT NOT NULL,
                deposit_keypair BLOB NOT NULL,
                status          TEXT NOT NULL DEFAULT 'pending',
                created_at      INTEGER NOT NULL,
                expires_at      INTEGER NOT NULL,
                completed_at    INTEGER,
                tx_signature    TEXT
            )",
            [],
        ).map_err(|e| format!("Failed to create table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_status ON deposit_requests(status)",
            [],
        ).map_err(|e| format!("Failed to create index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_expires ON deposit_requests(expires_at)",
            [],
        ).map_err(|e| format!("Failed to create index: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS completed_transfers (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_meta  TEXT NOT NULL,
                stealth_address TEXT NOT NULL,
                ephemeral_pubkey TEXT NOT NULL,
                amount_lamports INTEGER NOT NULL,
                tx_signature    TEXT NOT NULL,
                created_at      INTEGER NOT NULL
            )",
            [],
        ).map_err(|e| format!("Failed to create completed_transfers table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_recipient ON completed_transfers(recipient_meta)",
            [],
        ).map_err(|e| format!("Failed to create recipient index: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS token_transfers (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_meta   TEXT NOT NULL,
                stealth_address  TEXT NOT NULL,
                stealth_ata      TEXT NOT NULL,
                ephemeral_pubkey TEXT NOT NULL,
                token_mint       TEXT NOT NULL,
                token_program    TEXT NOT NULL,
                token_decimals   INTEGER NOT NULL,
                amount           INTEGER NOT NULL,
                sol_amount       INTEGER NOT NULL,
                tx_signature     TEXT NOT NULL,
                created_at       INTEGER NOT NULL
            )",
            [],
        ).map_err(|e| format!("Failed to create token_transfers table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_token_recipient ON token_transfers(recipient_meta)",
            [],
        ).map_err(|e| format!("Failed to create token_recipient index: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS token_deposit_requests (
                request_id       TEXT PRIMARY KEY,
                token_mint       TEXT NOT NULL,
                token_program    TEXT NOT NULL,
                token_decimals   INTEGER NOT NULL,
                token_amount     INTEGER NOT NULL,
                fee_amount       INTEGER NOT NULL,
                recipient_meta   TEXT NOT NULL,
                deposit_address  TEXT NOT NULL,
                deposit_ata      TEXT NOT NULL,
                deposit_keypair  BLOB NOT NULL,
                status           TEXT NOT NULL DEFAULT 'pending',
                created_at       INTEGER NOT NULL,
                expires_at       INTEGER NOT NULL,
                completed_at     INTEGER,
                tx_signature     TEXT
            )",
            [],
        ).map_err(|e| format!("Failed to create token_deposit_requests table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_token_deposit_status ON token_deposit_requests(status)",
            [],
        ).map_err(|e| format!("Failed to create token_deposit_status index: {}", e))?;

        Ok(())
    }
    /// Encrypt keypair bytes
    fn encrypt_keypair(&self, keypair_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(&self.cipher_key)
            .map_err(|e| format!("Cipher error: {}", e))?;
        
        // Generate random nonce
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, keypair_bytes)
            .map_err(|e| format!("Encryption error: {}", e))?;
        
        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt keypair bytes
    fn decrypt_keypair(&self, encrypted: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted.len() < 12 {
            return Err("Invalid encrypted data".to_string());
        }
        
        let cipher = Aes256Gcm::new_from_slice(&self.cipher_key)
            .map_err(|e| format!("Cipher error: {}", e))?;
        
        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];
        
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption error: {}", e))
    }
    
    /// Create new deposit request with fresh keypair
    pub fn create_request(
        &self,
        request_id: &str,
        amount_lamports: u64,
        fee_lamports: u64,
        recipient_meta: &str,
        expires_in_secs: i64,
    ) -> Result<(DepositRequest, Keypair), String> {
        // Generate fresh keypair
        let keypair = Keypair::new();
        let deposit_address = keypair.pubkey().to_string();
        
        // Encrypt keypair
        let keypair_bytes = keypair.to_bytes();
        let encrypted_keypair = self.encrypt_keypair(&keypair_bytes)?;
        
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + expires_in_secs;
        
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO deposit_requests (
                request_id, amount_lamports, fee_lamports, recipient_meta,
                deposit_address, deposit_keypair, status, created_at, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                request_id,
                amount_lamports as i64,
                fee_lamports as i64,
                recipient_meta,
                deposit_address,
                encrypted_keypair,
                "pending",
                now,
                expires_at,
            ],
        ).map_err(|e| format!("Failed to insert request: {}", e))?;
        
        let request = DepositRequest {
            request_id: request_id.to_string(),
            amount_lamports,
            fee_lamports,
            recipient_meta: recipient_meta.to_string(),
            deposit_address,
            status: RequestStatus::Pending,
            created_at: now,
            expires_at,
            completed_at: None,
            tx_signature: None,
        };
        
        Ok((request, keypair))
    }
    
    /// Get deposit request by ID
    pub fn get_request(&self, request_id: &str) -> Result<Option<DepositRequest>, String> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT request_id, amount_lamports, fee_lamports, recipient_meta,
                    deposit_address, status, created_at, expires_at, completed_at, tx_signature
             FROM deposit_requests WHERE request_id = ?1"
        ).map_err(|e| format!("Prepare error: {}", e))?;
        
        let result = stmt.query_row(params![request_id], |row| {
            Ok(DepositRequest {
                request_id: row.get(0)?,
                amount_lamports: row.get::<_, i64>(1)? as u64,
                fee_lamports: row.get::<_, i64>(2)? as u64,
                recipient_meta: row.get(3)?,
                deposit_address: row.get(4)?,
                status: RequestStatus::from_str(&row.get::<_, String>(5)?),
                created_at: row.get(6)?,
                expires_at: row.get(7)?,
                completed_at: row.get(8)?,
                tx_signature: row.get(9)?,
            })
        });
        
        match result {
            Ok(req) => Ok(Some(req)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Query error: {}", e)),
        }
    }
    
    /// Get keypair for request
    pub fn get_keypair(&self, request_id: &str) -> Result<Keypair, String> {
        let conn = self.conn.lock().unwrap();
        
        let encrypted: Vec<u8> = conn.query_row(
            "SELECT deposit_keypair FROM deposit_requests WHERE request_id = ?1",
            params![request_id],
            |row| row.get(0),
        ).map_err(|e| format!("Query error: {}", e))?;
        
        let decrypted = self.decrypt_keypair(&encrypted)?;
        
        if decrypted.len() != 64 {
            return Err("Invalid keypair length".to_string());
        }
        
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&decrypted);
        
        Keypair::from_bytes(&bytes)
            .map_err(|e| format!("Invalid keypair: {}", e))
    }
    
    /// Mark request as completed
    pub fn mark_completed(&self, request_id: &str, tx_signature: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        
        conn.execute(
            "UPDATE deposit_requests SET status = 'completed', completed_at = ?1, tx_signature = ?2
             WHERE request_id = ?3",
            params![now, tx_signature, request_id],
        ).map_err(|e| format!("Update error: {}", e))?;
        
        Ok(())
    }
    
    /// Mark request as expired
    pub fn mark_expired(&self, request_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "UPDATE deposit_requests SET status = 'expired' WHERE request_id = ?1",
            params![request_id],
        ).map_err(|e| format!("Update error: {}", e))?;
        
        Ok(())
    }
    
    /// Get all pending requests that have expired
    pub fn get_expired_requests(&self) -> Result<Vec<DepositRequest>, String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        
        let mut stmt = conn.prepare(
            "SELECT request_id, amount_lamports, fee_lamports, recipient_meta,
                    deposit_address, status, created_at, expires_at, completed_at, tx_signature
             FROM deposit_requests 
             WHERE status = 'pending' AND expires_at < ?1"
        ).map_err(|e| format!("Prepare error: {}", e))?;
        
        let rows = stmt.query_map(params![now], |row| {
            Ok(DepositRequest {
                request_id: row.get(0)?,
                amount_lamports: row.get::<_, i64>(1)? as u64,
                fee_lamports: row.get::<_, i64>(2)? as u64,
                recipient_meta: row.get(3)?,
                deposit_address: row.get(4)?,
                status: RequestStatus::from_str(&row.get::<_, String>(5)?),
                created_at: row.get(6)?,
                expires_at: row.get(7)?,
                completed_at: row.get(8)?,
                tx_signature: row.get(9)?,
            })
        }).map_err(|e| format!("Query error: {}", e))?;
        
        let mut requests = Vec::new();
        for row in rows {
            requests.push(row.map_err(|e| format!("Row error: {}", e))?);
        }
        
        Ok(requests)
    }
    
    /// Cleanup old completed/expired requests (older than 24 hours)
    pub fn cleanup_old_requests(&self) -> Result<usize, String> {
        let conn = self.conn.lock().unwrap();
        let cutoff = chrono::Utc::now().timestamp() - 86400; // 24 hours ago
        
        let deleted = conn.execute(
            "DELETE FROM deposit_requests 
             WHERE (status = 'completed' OR status = 'expired') AND created_at < ?1",
            params![cutoff],
        ).map_err(|e| format!("Delete error: {}", e))?;
        
        Ok(deleted)
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> Result<(usize, usize, usize), String> {
        let conn = self.conn.lock().unwrap();
        
        let pending: i64 = conn.query_row(
            "SELECT COUNT(*) FROM deposit_requests WHERE status = 'pending'",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        
        let completed: i64 = conn.query_row(
            "SELECT COUNT(*) FROM deposit_requests WHERE status = 'completed'",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        
        let expired: i64 = conn.query_row(
            "SELECT COUNT(*) FROM deposit_requests WHERE status = 'expired'",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        Ok((pending as usize, completed as usize, expired as usize))
    }

    // ============ COMPLETED TRANSFERS (untuk scan) ============

    /// Save completed transfer untuk scan
    pub fn save_completed_transfer(
        &self,
        recipient_meta: &str,
        stealth_address: &str,
        ephemeral_pubkey: &str,
        amount_lamports: u64,
        tx_signature: &str,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO completed_transfers (
                recipient_meta, stealth_address, ephemeral_pubkey,
                amount_lamports, tx_signature, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                recipient_meta,
                stealth_address,
                ephemeral_pubkey,
                amount_lamports as i64,
                tx_signature,
                now,
            ],
        ).map_err(|e| format!("Failed to save completed transfer: {}", e))?;

        Ok(())
    }

    /// Get transfers for a recipient meta-address
    pub fn get_transfers_for_recipient(
        &self,
        recipient_meta: &str,
    ) -> Result<Vec<(String, String, u64, String)>, String> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT stealth_address, ephemeral_pubkey, amount_lamports, tx_signature
             FROM completed_transfers
             WHERE recipient_meta = ?1
             ORDER BY created_at DESC"
        ).map_err(|e| format!("Prepare error: {}", e))?;

        let rows = stmt.query_map(params![recipient_meta], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u64,
                row.get::<_, String>(3)?,
            ))
        }).map_err(|e| format!("Query error: {}", e))?;

        let mut transfers = Vec::new();
        for row in rows {
            transfers.push(row.map_err(|e| format!("Row error: {}", e))?);
        }

        Ok(transfers)
    }

    pub fn delete_completed_transfer(&self, stealth_address: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM completed_transfers WHERE stealth_address = ?1",
            params![stealth_address],
        ).map_err(|e| format!("Delete error: {}", e))?;
        Ok(())
    }

    // ============ TOKEN TRANSFER FUNCTIONS ============

    pub fn save_token_transfer(
        &self,
        recipient_meta: &str,
        stealth_address: &str,
        stealth_ata: &str,
        ephemeral_pubkey: &str,
        token_mint: &str,
        token_program: &str,
        token_decimals: u8,
        amount: u64,
        sol_amount: u64,
        tx_signature: &str,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "INSERT INTO token_transfers 
             (recipient_meta, stealth_address, stealth_ata, ephemeral_pubkey, 
              token_mint, token_program, token_decimals, amount, sol_amount, 
              tx_signature, created_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                recipient_meta,
                stealth_address,
                stealth_ata,
                ephemeral_pubkey,
                token_mint,
                token_program,
                token_decimals as i64,
                amount as i64,
                sol_amount as i64,
                tx_signature,
                now,
            ],
        ).map_err(|e| format!("Insert token transfer error: {}", e))?;

        Ok(())
    }

    pub fn create_token_request(
        &self,
        request_id: &str,
        token_mint: &str,
        token_program: &str,
        token_decimals: u8,
        token_amount: u64,
        fee_amount: u64,
        recipient_meta: &str,
        deposit_address: &str,
        deposit_ata: &str,
        keypair_bytes: &[u8],
        expiry_seconds: i64,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expires_at = now + expiry_seconds;

        let encrypted = self.encrypt_keypair(keypair_bytes)?;

        conn.execute(
            "INSERT INTO token_deposit_requests 
             (request_id, token_mint, token_program, token_decimals, token_amount, 
              fee_amount, recipient_meta, deposit_address, deposit_ata, 
              deposit_keypair, status, created_at, expires_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending', ?11, ?12)",
            params![
                request_id,
                token_mint,
                token_program,
                token_decimals as i64,
                token_amount as i64,
                fee_amount as i64,
                recipient_meta,
                deposit_address,
                deposit_ata,
                encrypted,
                now,
                expires_at,
            ],
        ).map_err(|e| format!("Insert token request error: {}", e))?;

        Ok(())
    }

    pub fn get_token_request(&self, request_id: &str) -> Result<Option<TokenDepositRequest>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT request_id, token_mint, token_program, token_decimals, token_amount, 
                    fee_amount, recipient_meta, deposit_address, deposit_ata, status, 
                    created_at, expires_at, tx_signature 
             FROM token_deposit_requests WHERE request_id = ?1"
        ).map_err(|e| format!("Prepare error: {}", e))?;

        let mut rows = stmt.query(params![request_id])
            .map_err(|e| format!("Query error: {}", e))?;

        if let Some(row) = rows.next().map_err(|e| format!("Row error: {}", e))? {
            Ok(Some(TokenDepositRequest {
                request_id: row.get(0).unwrap(),
                token_mint: row.get(1).unwrap(),
                token_program: row.get(2).unwrap(),
                token_decimals: row.get::<_, i64>(3).unwrap() as u8,
                token_amount: row.get::<_, i64>(4).unwrap() as u64,
                fee_amount: row.get::<_, i64>(5).unwrap() as u64,
                recipient_meta: row.get(6).unwrap(),
                deposit_address: row.get(7).unwrap(),
                deposit_ata: row.get(8).unwrap(),
                status: row.get(9).unwrap(),
                created_at: row.get(10).unwrap(),
                expires_at: row.get(11).unwrap(),
                tx_signature: row.get(12).ok(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_token_keypair(&self, request_id: &str) -> Result<solana_sdk::signature::Keypair, String> {
        let conn = self.conn.lock().unwrap();
        let encrypted: Vec<u8> = conn.query_row(
            "SELECT deposit_keypair FROM token_deposit_requests WHERE request_id = ?1",
            params![request_id],
            |row| row.get(0),
        ).map_err(|e| format!("Query error: {}", e))?;

        let decrypted = self.decrypt_keypair(&encrypted)?;
        solana_sdk::signature::Keypair::from_bytes(&decrypted)
            .map_err(|e| format!("Keypair error: {}", e))
    }

    pub fn mark_token_completed(&self, request_id: &str, signature: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "UPDATE token_deposit_requests SET status = 'completed', completed_at = ?1, tx_signature = ?2 WHERE request_id = ?3",
            params![now, signature, request_id],
        ).map_err(|e| format!("Update error: {}", e))?;

        Ok(())
    }

    pub fn get_token_transfers_for_recipient(
        &self,
        recipient_meta: &str,
    ) -> Result<Vec<(String, String, String, String, String, u8, u64, u64, String)>, String> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT stealth_address, stealth_ata, ephemeral_pubkey, token_mint, 
                    token_program, token_decimals, amount, sol_amount, tx_signature 
             FROM token_transfers 
             WHERE recipient_meta = ?1 
             ORDER BY created_at DESC"
        ).map_err(|e| format!("Prepare error: {}", e))?;

        let rows = stmt.query_map(params![recipient_meta], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)? as u8,
                row.get::<_, i64>(6)? as u64,
                row.get::<_, i64>(7)? as u64,
                row.get::<_, String>(8)?,
            ))
        }).map_err(|e| format!("Query error: {}", e))?;

        let mut transfers = Vec::new();
        for row in rows {
            transfers.push(row.map_err(|e| format!("Row error: {}", e))?);
        }

        Ok(transfers)
    }

    pub fn delete_token_transfer(&self, stealth_address: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM token_transfers WHERE stealth_address = ?1",
            params![stealth_address],
        ).map_err(|e| format!("Delete token transfer error: {}", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_database_operations() {
        let db = RelayDatabase::new_with_path(":memory:").unwrap();
        
        // Create request
        let (request, keypair) = db.create_request(
            "req_test_001",
            5_000_000_000, // 5 SOL
            25_000_000,    // 0.025 SOL fee
            "kl_testrecipient",
            1800,          // 30 minutes
        ).unwrap();
        
        assert_eq!(request.request_id, "req_test_001");
        assert_eq!(request.amount_lamports, 5_000_000_000);
        assert_eq!(request.status, RequestStatus::Pending);
        
        // Get request
        let loaded = db.get_request("req_test_001").unwrap().unwrap();
        assert_eq!(loaded.deposit_address, request.deposit_address);
        
        // Get keypair
        let loaded_keypair = db.get_keypair("req_test_001").unwrap();
        assert_eq!(loaded_keypair.pubkey(), keypair.pubkey());
        
        // Mark completed
        db.mark_completed("req_test_001", "tx_signature_123").unwrap();
        let completed = db.get_request("req_test_001").unwrap().unwrap();
        assert_eq!(completed.status, RequestStatus::Completed);
        assert_eq!(completed.tx_signature, Some("tx_signature_123".to_string()));
    }
}
