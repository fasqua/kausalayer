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
    SwapFailed,
}

impl RequestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Expired => "expired",
            Self::RefundPending => "refund_pending",
            Self::SwapFailed => "swap_failed",
        }
    }
    
    pub fn from_str(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "completed" => Self::Completed,
            "expired" => Self::Expired,
            "refund_pending" => Self::RefundPending,
            "swap_failed" => Self::SwapFailed,
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
    pub owner_identifier: Option<String>,
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
    pub owner_identifier: Option<String>,
}

/// An intermediate hop in a multi-hop transfer (for privacy)
#[derive(Debug, Clone)]
pub struct IntermediateHop {
    pub id: i64,
    pub request_id: String,
    pub hop_index: u8,              // 1 or 2
    pub stealth_address: String,
    pub tx_in_signature: Option<String>,
    pub tx_out_signature: Option<String>,
    pub amount_in: Option<u64>,
    pub amount_out: Option<u64>,
    pub status: String,             // pending, completed
    pub created_at: i64,
}

/// A subscription record
#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: i64,
    pub meta_address_hash: String,      // SHA256 hash for privacy
    pub payment_tx_hash: String,
    pub payment_type: String,           // "USDC" or "KAUSA"
    pub payment_amount: u64,            // lamports or token amount
    pub created_at: i64,
    pub expires_at: i64,
    pub is_active: bool,
}

/// An API key record
#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    pub id: i64,
    pub key_prefix: String,             // First 8 chars for lookup (kl_sk_xxx)
    pub key_hash: String,               // SHA256 hash of full key
    pub meta_address_hash: String,      // Owner
    pub name: String,                   // User-defined name
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub is_active: bool,
}

/// An alias record
#[derive(Debug, Clone)]
pub struct AliasRecord {
    pub id: i64,
    pub alias: String,                  // e.g., "kl_edu"
    pub meta_address: String,           // Full meta-address it resolves to
    pub owner_meta_hash: String,        // Owner's meta-address hash
    pub created_at: i64,
    pub is_active: bool,
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
                tx_signature    TEXT,
                owner_identifier TEXT
            )",
            [],
        ).map_err(|e| format!("Failed to create table: {}", e))?;


        // Migration: add owner_identifier column if not exists
        conn.execute(
            "ALTER TABLE deposit_requests ADD COLUMN owner_identifier TEXT",
            [],
        ).ok(); // Ignore error if column already exists
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

        // Intermediate hops for multi-hop privacy transfers (SOL only)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS intermediate_hops (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id       TEXT NOT NULL,
                hop_index        INTEGER NOT NULL,
                stealth_address  TEXT NOT NULL,
                keypair_encrypted BLOB NOT NULL,
                tx_in_signature  TEXT,
                tx_out_signature TEXT,
                amount_in        INTEGER,
                amount_out       INTEGER,
                status           TEXT NOT NULL DEFAULT 'pending',
                created_at       INTEGER NOT NULL
            )",
            [],
        ).map_err(|e| format!("Failed to create intermediate_hops table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hop_request ON intermediate_hops(request_id)",
            [],
        ).map_err(|e| format!("Failed to create hop_request index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hop_created ON intermediate_hops(created_at)",
            [],
        ).map_err(|e| format!("Failed to create hop_created index: {}", e))?;

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

        // ============ SUBSCRIPTION TABLES ============

        conn.execute(
            "CREATE TABLE IF NOT EXISTS subscriptions (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                meta_address_hash  TEXT NOT NULL,
                payment_tx_hash    TEXT NOT NULL UNIQUE,
                payment_type       TEXT NOT NULL,
                payment_amount     INTEGER NOT NULL,
                created_at         INTEGER NOT NULL,
                expires_at         INTEGER NOT NULL,
                is_active          INTEGER NOT NULL DEFAULT 1
            )",
            [],
        ).map_err(|e| format!("Failed to create subscriptions table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sub_meta_hash ON subscriptions(meta_address_hash)",
            [],
        ).map_err(|e| format!("Failed to create sub_meta_hash index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sub_expires ON subscriptions(expires_at)",
            [],
        ).map_err(|e| format!("Failed to create sub_expires index: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS api_keys (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                key_prefix         TEXT NOT NULL,
                key_hash           TEXT NOT NULL UNIQUE,
                meta_address_hash  TEXT NOT NULL,
                name               TEXT NOT NULL DEFAULT '',
                created_at         INTEGER NOT NULL,
                last_used_at       INTEGER,
                is_active          INTEGER NOT NULL DEFAULT 1
            )",
            [],
        ).map_err(|e| format!("Failed to create api_keys table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_apikey_prefix ON api_keys(key_prefix)",
            [],
        ).map_err(|e| format!("Failed to create apikey_prefix index: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_apikey_meta ON api_keys(meta_address_hash)",
            [],
        ).map_err(|e| format!("Failed to create apikey_meta index: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS aliases (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                alias              TEXT NOT NULL UNIQUE,
                meta_address       TEXT NOT NULL,
                owner_meta_hash    TEXT NOT NULL,
                created_at         INTEGER NOT NULL,
                is_active          INTEGER NOT NULL DEFAULT 1
            )",
            [],
        ).map_err(|e| format!("Failed to create aliases table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alias_name ON aliases(alias)",
            [],
        ).map_err(|e| format!("Failed to create alias_name index: {}", e))?;


        // Destination wallets for private swaps
        conn.execute(
            "CREATE TABLE IF NOT EXISTS destination_wallets (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_meta_hash TEXT NOT NULL,
                slot            INTEGER NOT NULL,
                wallet_address  TEXT NOT NULL,
                created_at      INTEGER NOT NULL,
                UNIQUE(owner_meta_hash, slot)
            )",
            [],
        ).map_err(|e| format!("Failed to create destination_wallets table: {}", e))?;
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
        owner_identifier: Option<&str>,
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
                request_id, amount_lamports, fee_lamports, recipient_meta, owner_identifier,
                deposit_address, deposit_keypair, status, created_at, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                request_id,
                amount_lamports as i64,
                fee_lamports as i64,
                recipient_meta,
                owner_identifier,
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
            owner_identifier: owner_identifier.map(|s| s.to_string()),
        };
        
        Ok((request, keypair))
    }
    
    /// Get deposit request by ID
    pub fn get_request(&self, request_id: &str) -> Result<Option<DepositRequest>, String> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT request_id, amount_lamports, fee_lamports, recipient_meta,
                    deposit_address, status, created_at, expires_at, completed_at, tx_signature, owner_identifier
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
                owner_identifier: row.get(10)?,
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

    /// Mark request as swap_failed (for retry/recover)
    pub fn mark_swap_failed(&self, request_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "UPDATE deposit_requests SET status = 'swap_failed' WHERE request_id = ?1",
            params![request_id],
        ).map_err(|e| format!("Update error: {}", e))?;
        
        Ok(())
    }

    /// Get all failed swaps for a specific owner
    pub fn get_failed_swaps_by_owner(&self, owner_identifier: &str) -> Result<Vec<DepositRequest>, String> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT request_id, amount_lamports, fee_lamports, recipient_meta,
                    deposit_address, status, created_at, expires_at, completed_at, tx_signature, owner_identifier
             FROM deposit_requests
             WHERE status = 'swap_failed' AND owner_identifier = ?1
             ORDER BY created_at DESC"
        ).map_err(|e| format!("Prepare error: {}", e))?;

        let rows = stmt.query_map(params![owner_identifier], |row| {
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
                owner_identifier: row.get(10)?,
            })
        }).map_err(|e| format!("Query error: {}", e))?;

        let mut requests = Vec::new();
        for row in rows {
            requests.push(row.map_err(|e| format!("Row error: {}", e))?);
        }

        Ok(requests)
    }
    
    /// Get all pending requests that have expired
    pub fn get_expired_requests(&self) -> Result<Vec<DepositRequest>, String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        
        let mut stmt = conn.prepare(
            "SELECT request_id, amount_lamports, fee_lamports, recipient_meta,
                    deposit_address, status, created_at, expires_at, completed_at, tx_signature, owner_identifier
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
                owner_identifier: row.get(10)?,
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
        owner_identifier: Option<&str>,
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
        owner_identifier: Option<&str>,
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

    // ============ INTERMEDIATE HOPS FUNCTIONS (SOL only) ============

    /// Create intermediate hops for a request (2 hops for privacy)
    pub fn create_intermediate_hops(
        &self,
        request_id: &str,
        hop1_address: &str,
        hop1_keypair_bytes: &[u8],
        hop2_address: &str,
        hop2_keypair_bytes: &[u8],
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        // Encrypt keypairs
        let hop1_encrypted = self.encrypt_keypair(hop1_keypair_bytes)?;
        let hop2_encrypted = self.encrypt_keypair(hop2_keypair_bytes)?;

        // Insert hop 1
        conn.execute(
            "INSERT INTO intermediate_hops (
                request_id, hop_index, stealth_address, keypair_encrypted, status, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![request_id, 1i64, hop1_address, hop1_encrypted, "pending", now],
        ).map_err(|e| format!("Failed to insert hop 1: {}", e))?;

        // Insert hop 2
        conn.execute(
            "INSERT INTO intermediate_hops (
                request_id, hop_index, stealth_address, keypair_encrypted, status, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![request_id, 2i64, hop2_address, hop2_encrypted, "pending", now],
        ).map_err(|e| format!("Failed to insert hop 2: {}", e))?;

        Ok(())
    }

    /// Get intermediate hops for a request
    pub fn get_intermediate_hops(&self, request_id: &str) -> Result<Vec<IntermediateHop>, String> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, request_id, hop_index, stealth_address, tx_in_signature,
                    tx_out_signature, amount_in, amount_out, status, created_at
             FROM intermediate_hops
             WHERE request_id = ?1
             ORDER BY hop_index ASC"
        ).map_err(|e| format!("Prepare error: {}", e))?;

        let rows = stmt.query_map(params![request_id], |row| {
            Ok(IntermediateHop {
                id: row.get(0)?,
                request_id: row.get(1)?,
                hop_index: row.get::<_, i64>(2)? as u8,
                stealth_address: row.get(3)?,
                tx_in_signature: row.get(4)?,
                tx_out_signature: row.get(5)?,
                amount_in: row.get::<_, Option<i64>>(6)?.map(|v| v as u64),
                amount_out: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                status: row.get(8)?,
                created_at: row.get(9)?,
            })
        }).map_err(|e| format!("Query error: {}", e))?;

        let mut hops = Vec::new();
        for row in rows {
            hops.push(row.map_err(|e| format!("Row error: {}", e))?);
        }

        Ok(hops)
    }

    /// Get keypair for a specific hop
    pub fn get_hop_keypair(&self, request_id: &str, hop_index: u8) -> Result<Keypair, String> {
        let conn = self.conn.lock().unwrap();

        let encrypted: Vec<u8> = conn.query_row(
            "SELECT keypair_encrypted FROM intermediate_hops
             WHERE request_id = ?1 AND hop_index = ?2",
            params![request_id, hop_index as i64],
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

    /// Update hop with transaction info
    pub fn update_hop_tx_in(
        &self,
        request_id: &str,
        hop_index: u8,
        tx_signature: &str,
        amount: u64,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE intermediate_hops
             SET tx_in_signature = ?1, amount_in = ?2
             WHERE request_id = ?3 AND hop_index = ?4",
            params![tx_signature, amount as i64, request_id, hop_index as i64],
        ).map_err(|e| format!("Update error: {}", e))?;
        Ok(())
    }

    /// Update hop with outgoing transaction info
    pub fn update_hop_tx_out(
        &self,
        request_id: &str,
        hop_index: u8,
        tx_signature: &str,
        amount: u64,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE intermediate_hops
             SET tx_out_signature = ?1, amount_out = ?2, status = 'completed'
             WHERE request_id = ?3 AND hop_index = ?4",
            params![tx_signature, amount as i64, request_id, hop_index as i64],
        ).map_err(|e| format!("Update error: {}", e))?;
        Ok(())
    }

    /// Cleanup old intermediate hops (older than 24 hours)
    pub fn cleanup_old_hops(&self) -> Result<usize, String> {
        let conn = self.conn.lock().unwrap();
        let cutoff = chrono::Utc::now().timestamp() - 86400; // 24 hours ago

        let deleted = conn.execute(
            "DELETE FROM intermediate_hops WHERE created_at < ?1",
            params![cutoff],
        ).map_err(|e| format!("Delete error: {}", e))?;

        Ok(deleted)
    }

    // ============ TOKEN TRANSFER FUNCTIONS ============

    pub fn save_token_transfer(
        &self,
        recipient_meta: &str,
        owner_identifier: Option<&str>,
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
                owner_identifier,
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
        owner_identifier: Option<&str>,
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
                owner_identifier,
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
                owner_identifier: None,
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
        owner_identifier: Option<&str>,
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

    // ============ SUBSCRIPTION FUNCTIONS ============

    /// Hash a meta-address for privacy storage
    fn hash_meta_address(&self, meta_address: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(meta_address.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Create a new subscription
    pub fn create_subscription(
        &self,
        meta_address: &str,
        payment_tx_hash: &str,
        payment_type: &str,
        payment_amount: u64,
        duration_days: i64,
    ) -> Result<Subscription, String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + (duration_days * 86400);
        let meta_hash = self.hash_meta_address(meta_address);

        conn.execute(
            "INSERT INTO subscriptions (
                meta_address_hash, payment_tx_hash, payment_type, payment_amount,
                created_at, expires_at, is_active
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
            params![meta_hash, payment_tx_hash, payment_type, payment_amount as i64, now, expires_at],
        ).map_err(|e| format!("Failed to create subscription: {}", e))?;

        Ok(Subscription {
            id: conn.last_insert_rowid(),
            meta_address_hash: meta_hash,
            payment_tx_hash: payment_tx_hash.to_string(),
            payment_type: payment_type.to_string(),
            payment_amount,
            created_at: now,
            expires_at,
            is_active: true,
        })
    }

    /// Check if a meta-address has active subscription
    pub fn is_subscribed(&self, meta_address: &str) -> Result<bool, String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        let meta_hash = self.hash_meta_address(meta_address);

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM subscriptions 
             WHERE meta_address_hash = ?1 AND expires_at > ?2 AND is_active = 1",
            params![meta_hash, now],
            |row| row.get(0),
        ).unwrap_or(0);

        Ok(count > 0)
    }

    /// Get active subscription for meta-address
    pub fn get_subscription(&self, meta_address: &str) -> Result<Option<Subscription>, String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        let meta_hash = self.hash_meta_address(meta_address);

        let mut stmt = conn.prepare(
            "SELECT id, meta_address_hash, payment_tx_hash, payment_type, payment_amount,
                    created_at, expires_at, is_active
             FROM subscriptions
             WHERE meta_address_hash = ?1 AND expires_at > ?2 AND is_active = 1
             ORDER BY expires_at DESC LIMIT 1"
        ).map_err(|e| format!("Prepare error: {}", e))?;

        let result = stmt.query_row(params![meta_hash, now], |row| {
            Ok(Subscription {
                id: row.get(0)?,
                meta_address_hash: row.get(1)?,
                payment_tx_hash: row.get(2)?,
                payment_type: row.get(3)?,
                payment_amount: row.get::<_, i64>(4)? as u64,
                created_at: row.get(5)?,
                expires_at: row.get(6)?,
                is_active: row.get::<_, i64>(7)? == 1,
            })
        });

        match result {
            Ok(sub) => Ok(Some(sub)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Query error: {}", e)),
        }
    }

    /// Check if payment tx hash already used
    pub fn is_payment_tx_used(&self, tx_hash: &str) -> Result<bool, String> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM subscriptions WHERE payment_tx_hash = ?1",
            params![tx_hash],
            |row| row.get(0),
        ).unwrap_or(0);
        Ok(count > 0)
    }

    // ============ API KEY FUNCTIONS ============

    /// Generate a new API key
    pub fn create_api_key(
        &self,
        meta_address: &str,
        name: &str,
    ) -> Result<(String, ApiKeyRecord), String> {
        use sha2::{Sha256, Digest};
        
        // Generate random key: kl_sk_<32 random hex chars>
        let random_bytes: [u8; 16] = rand::random();
        let full_key = format!("kl_sk_{}", hex::encode(random_bytes));
        let key_prefix = &full_key[..14]; // "kl_sk_" + 8 chars
        
        // Hash the full key for storage
        let mut hasher = Sha256::new();
        hasher.update(full_key.as_bytes());
        let key_hash = hex::encode(hasher.finalize());
        
        let meta_hash = self.hash_meta_address(meta_address);
        let now = chrono::Utc::now().timestamp();

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO api_keys (
                key_prefix, key_hash, meta_address_hash, name, created_at, is_active
            ) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![key_prefix, key_hash, meta_hash, name, now],
        ).map_err(|e| format!("Failed to create API key: {}", e))?;

        let record = ApiKeyRecord {
            id: conn.last_insert_rowid(),
            key_prefix: key_prefix.to_string(),
            key_hash,
            meta_address_hash: meta_hash,
            name: name.to_string(),
            created_at: now,
            last_used_at: None,
            is_active: true,
        };

        Ok((full_key, record))
    }

    /// Validate an API key and return owner's meta_address_hash
    pub fn validate_api_key(&self, api_key: &str) -> Result<Option<String>, String> {
        use sha2::{Sha256, Digest};
        
        if !api_key.starts_with("kl_sk_") || api_key.len() < 14 {
            return Ok(None);
        }

        let key_prefix = &api_key[..14];
        
        // Hash the provided key
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        let key_hash = hex::encode(hasher.finalize());

        let conn = self.conn.lock().unwrap();
        
        let result: Result<(i64, String), _> = conn.query_row(
            "SELECT id, meta_address_hash FROM api_keys 
             WHERE key_prefix = ?1 AND key_hash = ?2 AND is_active = 1",
            params![key_prefix, key_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );

        match result {
            Ok((id, meta_hash)) => {
                // Update last_used_at
                let now = chrono::Utc::now().timestamp();
                conn.execute(
                    "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
                    params![now, id],
                ).ok();
                Ok(Some(meta_hash))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Query error: {}", e)),
        }
    }

    /// Revoke an API key
    pub fn revoke_api_key(&self, api_key: &str) -> Result<bool, String> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        let key_hash = hex::encode(hasher.finalize());

        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE api_keys SET is_active = 0 WHERE key_hash = ?1",
            params![key_hash],
        ).map_err(|e| format!("Update error: {}", e))?;

        Ok(updated > 0)
    }

    // ============ ALIAS FUNCTIONS ============

    /// Register an alias
    pub fn create_alias(
        &self,
        alias: &str,
        meta_address: &str,
        owner_meta_address: &str,
    ) -> Result<AliasRecord, String> {
        // Validate alias format
        if !alias.starts_with("kl_") {
            return Err("Alias must start with 'kl_'".to_string());
        }
        if alias.len() < 5 || alias.len() > 20 {
            return Err("Alias must be 5-20 characters".to_string());
        }
        // Only alphanumeric and underscore after kl_
        let suffix = &alias[3..];
        if !suffix.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err("Alias can only contain letters, numbers, and underscores".to_string());
        }

        let owner_hash = self.hash_meta_address(owner_meta_address);
        let now = chrono::Utc::now().timestamp();

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO aliases (alias, meta_address, owner_meta_hash, created_at, is_active)
             VALUES (?1, ?2, ?3, ?4, 1)",
            params![alias.to_lowercase(), meta_address, owner_hash, now],
        ).map_err(|e| {
            if e.to_string().contains("UNIQUE constraint") {
                "Alias already taken".to_string()
            } else {
                format!("Failed to create alias: {}", e)
            }
        })?;

        Ok(AliasRecord {
            id: conn.last_insert_rowid(),
            alias: alias.to_lowercase(),
            meta_address: meta_address.to_string(),
            owner_meta_hash: owner_hash,
            created_at: now,
            is_active: true,
        })
    }

    /// Resolve an alias to meta-address
    pub fn resolve_alias(&self, alias: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock().unwrap();
        
        let result: Result<String, _> = conn.query_row(
            "SELECT meta_address FROM aliases WHERE alias = ?1 AND is_active = 1",
            params![alias.to_lowercase()],
            |row| row.get(0),
        );

        match result {
            Ok(meta) => Ok(Some(meta)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Query error: {}", e)),
        }
    }

    /// Check if alias is available
    pub fn is_alias_available(&self, alias: &str) -> Result<bool, String> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM aliases WHERE alias = ?1",
            params![alias.to_lowercase()],
            |row| row.get(0),
        ).unwrap_or(0);
        Ok(count == 0)
    }

    /// List all aliases for a meta-address
    pub fn list_aliases(&self, meta_address: &str) -> Result<Vec<(String, i64)>, String> {
        let conn = self.conn.lock().unwrap();
        let owner_hash = self.hash_meta_address(meta_address);
        
        let mut stmt = conn.prepare(
            "SELECT alias, created_at FROM aliases WHERE owner_meta_hash = ?1 AND is_active = 1 ORDER BY created_at DESC"
        ).map_err(|e| format!("Prepare error: {}", e))?;
        
        let rows = stmt.query_map(params![owner_hash], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        }).map_err(|e| format!("Query error: {}", e))?;
        
        let mut aliases = Vec::new();
        for row in rows {
            if let Ok(alias) = row {
                aliases.push(alias);
            }
        }
        Ok(aliases)
    }

    // ========== Destination Wallets ==========

    /// Add or update destination wallet
    pub fn add_destination_wallet(&self, owner_meta_hash: &str, slot: u8, wallet_address: &str) -> Result<(), String> {
        if slot < 1 || slot > 3 {
            return Err("Slot must be 1, 2, or 3".to_string());
        }
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO destination_wallets (owner_meta_hash, slot, wallet_address, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(owner_meta_hash, slot) DO UPDATE SET wallet_address = ?3, created_at = ?4",
            params![owner_meta_hash, slot, wallet_address, now],
        ).map_err(|e| format!("Failed to add destination wallet: {}", e))?;
        Ok(())
    }

    /// Delete destination wallet
    pub fn delete_destination_wallet(&self, owner_meta_hash: &str, slot: u8) -> Result<bool, String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        let rows = conn.execute(
            "DELETE FROM destination_wallets WHERE owner_meta_hash = ?1 AND slot = ?2",
            params![owner_meta_hash, slot],
        ).map_err(|e| format!("Failed to delete destination wallet: {}", e))?;
        Ok(rows > 0)
    }

    /// List destination wallets for user
    pub fn list_destination_wallets(&self, owner_meta_hash: &str) -> Result<Vec<(u8, String)>, String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT slot, wallet_address FROM destination_wallets WHERE owner_meta_hash = ?1 ORDER BY slot"
        ).map_err(|e| format!("Prepare error: {}", e))?;
        let rows = stmt.query_map(params![owner_meta_hash], |row| {
            Ok((row.get::<_, u8>(0)?, row.get::<_, String>(1)?))
        }).map_err(|e| format!("Query error: {}", e))?;
        let mut wallets = Vec::new();
        for row in rows {
            if let Ok(wallet) = row {
                wallets.push(wallet);
            }
        }
        Ok(wallets)
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
