//! Local storage for pending transfers

use anyhow::{Result, anyhow};
use rusqlite::{Connection, params};
use std::path::PathBuf;

pub struct TransferStorage {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct PendingTransfer {
    pub id: i64,
    pub ephemeral_pubkey: String,
    pub stealth_address: String,
    pub amount_lamports: u64,
    pub slot: u64,
    pub tx_signature: String,
    pub claimed: bool,
    pub claim_signature: Option<String>,
    pub created_at: String,
}

impl TransferStorage {
    pub fn new(path: &PathBuf) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| anyhow!("Failed to open database: {}", e))?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ephemeral_pubkey TEXT NOT NULL,
                stealth_address TEXT NOT NULL UNIQUE,
                amount_lamports INTEGER NOT NULL,
                slot INTEGER NOT NULL,
                tx_signature TEXT NOT NULL,
                claimed INTEGER DEFAULT 0,
                claim_signature TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        ).map_err(|e| anyhow!("Failed to create table: {}", e))?;
        
        Ok(Self { conn })
    }
    
    pub fn add_transfer(
        &self,
        ephemeral_pubkey: &str,
        stealth_address: &str,
        amount_lamports: u64,
        slot: u64,
        tx_signature: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO transfers 
             (ephemeral_pubkey, stealth_address, amount_lamports, slot, tx_signature)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ephemeral_pubkey, stealth_address, amount_lamports, slot, tx_signature],
        ).map_err(|e| anyhow!("Failed to insert: {}", e))?;
        
        Ok(())
    }
    
    pub fn get_pending(&self) -> Result<Vec<PendingTransfer>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ephemeral_pubkey, stealth_address, amount_lamports, 
                    slot, tx_signature, claimed, claim_signature, created_at
             FROM transfers WHERE claimed = 0 ORDER BY slot DESC"
        ).map_err(|e| anyhow!("Query error: {}", e))?;
        
        let rows = stmt.query_map([], |row| {
            Ok(PendingTransfer {
                id: row.get(0)?,
                ephemeral_pubkey: row.get(1)?,
                stealth_address: row.get(2)?,
                amount_lamports: row.get(3)?,
                slot: row.get(4)?,
                tx_signature: row.get(5)?,
                claimed: row.get::<_, i32>(6)? == 1,
                claim_signature: row.get(7)?,
                created_at: row.get(8)?,
            })
        }).map_err(|e| anyhow!("Map error: {}", e))?;
        
        let mut transfers = Vec::new();
        for row in rows {
            transfers.push(row.map_err(|e| anyhow!("Row error: {}", e))?);
        }
        
        Ok(transfers)
    }
    
    pub fn get_all(&self) -> Result<Vec<PendingTransfer>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ephemeral_pubkey, stealth_address, amount_lamports,
                    slot, tx_signature, claimed, claim_signature, created_at
             FROM transfers ORDER BY slot DESC"
        ).map_err(|e| anyhow!("Query error: {}", e))?;
        
        let rows = stmt.query_map([], |row| {
            Ok(PendingTransfer {
                id: row.get(0)?,
                ephemeral_pubkey: row.get(1)?,
                stealth_address: row.get(2)?,
                amount_lamports: row.get(3)?,
                slot: row.get(4)?,
                tx_signature: row.get(5)?,
                claimed: row.get::<_, i32>(6)? == 1,
                claim_signature: row.get(7)?,
                created_at: row.get(8)?,
            })
        }).map_err(|e| anyhow!("Map error: {}", e))?;
        
        let mut transfers = Vec::new();
        for row in rows {
            transfers.push(row.map_err(|e| anyhow!("Row error: {}", e))?);
        }
        
        Ok(transfers)
    }
    
    pub fn mark_claimed(&self, stealth_address: &str, claim_signature: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE transfers SET claimed = 1, claim_signature = ?1 WHERE stealth_address = ?2",
            params![claim_signature, stealth_address],
        ).map_err(|e| anyhow!("Update error: {}", e))?;
        
        Ok(())
    }
    
    pub fn get_total_pending_lamports(&self) -> Result<u64> {
        let total: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(amount_lamports), 0) FROM transfers WHERE claimed = 0",
            [],
            |row| row.get(0),
        ).map_err(|e| anyhow!("Query error: {}", e))?;
        
        Ok(total as u64)
    }
}
