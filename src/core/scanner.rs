//! Scanner for detecting incoming stealth transfers
//!
//! Scans blockchain for transactions with SDP: memo prefix,
//! checks if the stealth addresses belong to our wallet,
//! and tracks claimable balances.

use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::Signature,
};
use solana_client::rpc_config::RpcTransactionConfig;
use solana_transaction_status::{
    EncodedTransaction, UiTransactionEncoding, UiMessage,
};

use crate::error::{KausaError, Result};
use crate::core::stealth::{StealthKeys, StealthAddress};
use crate::Config;

/// A detected stealth transfer that belongs to us
#[derive(Debug, Clone)]
pub struct DetectedTransfer {
    /// Transaction signature
    pub signature: String,
    /// Stealth address that received funds
    pub stealth_pubkey: Pubkey,
    /// Ephemeral public key from memo
    pub ephemeral_pubkey: [u8; 32],
    /// Amount received in lamports
    pub amount: u64,
    /// Block time (unix timestamp)
    pub block_time: Option<i64>,
    /// Whether funds have been claimed
    pub claimed: bool,
}

/// Scanner for monitoring stealth transfers
pub struct Scanner {
    client: RpcClient,
    config: Config,
}

impl Scanner {
    pub fn new(rpc_url: &str, config: Config) -> Self {
        let client = RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        );
        Self { client, config }
    }
    
    pub fn new_devnet(config: Config) -> Self {
        Self::new("https://api.devnet.solana.com", config)
    }
    
    /// Scan recent transactions for a list of potential stealth addresses
    /// Returns transfers that belong to the given keys
    pub fn scan_transactions(
        &self,
        keys: &StealthKeys,
        signatures: Vec<Signature>,
    ) -> Result<Vec<DetectedTransfer>> {
        let mut detected = Vec::new();
        
        for sig in signatures {
            if let Ok(Some(transfer)) = self.check_transaction(keys, &sig) {
                detected.push(transfer);
            }
        }
        
        Ok(detected)
    }
    
    /// Check a single transaction for stealth transfer
    pub fn check_transaction(
        &self,
        keys: &StealthKeys,
        signature: &Signature,
    ) -> Result<Option<DetectedTransfer>> {
        // Fetch transaction
        let config = RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Json),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        };
        
        let tx = self.client
            .get_transaction_with_config(signature, config)
            .map_err(|e| KausaError::RpcError(e.to_string()))?;
        
        // Extract memo from transaction
        let memo = self.extract_memo(&tx.transaction.transaction)?;
        
        // Check if it's an SDP memo
        let ephemeral_pubkey = match self.parse_sdp_memo(&memo) {
            Some(eph) => eph,
            None => return Ok(None), // Not an SDP transaction
        };
        
        // Extract destination address and amount
        let (dest_pubkey, amount) = self.extract_transfer_info(&tx.transaction.transaction)?;
        
        // Create stealth address struct for checking
        let stealth = StealthAddress {
            pubkey: dest_pubkey.to_bytes(),
            ephemeral_pubkey,
        };
        
        // Check if this stealth address belongs to us
        if !keys.check_stealth_address(&stealth)? {
            return Ok(None); // Not ours
        }
        
        // Check current balance (might have been claimed)
        let current_balance = self.client
            .get_balance(&dest_pubkey)
            .unwrap_or(0);
        
        Ok(Some(DetectedTransfer {
            signature: signature.to_string(),
            stealth_pubkey: dest_pubkey,
            ephemeral_pubkey,
            amount,
            block_time: tx.block_time,
            claimed: current_balance == 0,
        }))
    }
    
    /// Extract memo from transaction
    fn extract_memo(&self, tx: &EncodedTransaction) -> Result<String> {
        match tx {
            EncodedTransaction::Json(ui_tx) => {
                match &ui_tx.message {
                    UiMessage::Raw(raw) => {
                        // Look for memo instruction
                        for ix in &raw.instructions {
                            // Memo program index check
                            let program_idx = ix.program_id_index as usize;
                            if program_idx < raw.account_keys.len() {
                                let program_id = &raw.account_keys[program_idx];
                                if program_id == "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr" {
                                    // Decode memo data
                                    if let Ok(data) = bs58::decode(&ix.data).into_vec() {
                                        if let Ok(memo) = String::from_utf8(data) {
                                            return Ok(memo);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    UiMessage::Parsed(_) => {
                        // Handle parsed format if needed
                    }
                }
            }
            _ => {}
        }
        
        Err(KausaError::ParseError("No memo found".into()))
    }
    
    /// Parse SDP memo and extract ephemeral pubkey
    fn parse_sdp_memo(&self, memo: &str) -> Option<[u8; 32]> {
        if !memo.starts_with(&self.config.sdp_memo_prefix) {
            return None;
        }
        
        let eph_str = &memo[self.config.sdp_memo_prefix.len()..];
        let eph_bytes = bs58::decode(eph_str).into_vec().ok()?;
        
        if eph_bytes.len() != 32 {
            return None;
        }
        
        let mut eph = [0u8; 32];
        eph.copy_from_slice(&eph_bytes);
        Some(eph)
    }
    
    /// Extract transfer destination and amount
    fn extract_transfer_info(&self, tx: &EncodedTransaction) -> Result<(Pubkey, u64)> {
        match tx {
            EncodedTransaction::Json(ui_tx) => {
                match &ui_tx.message {
                    UiMessage::Raw(raw) => {
                        // First instruction should be the transfer
                        if let Some(ix) = raw.instructions.first() {
                            // Account indices: 0=from, 1=to for system transfer
                            if ix.accounts.len() >= 2 {
                                let to_idx = ix.accounts[1] as usize;
                                if to_idx < raw.account_keys.len() {
                                    let dest = raw.account_keys[to_idx]
                                        .parse::<Pubkey>()
                                        .map_err(|e| KausaError::ParseError(e.to_string()))?;
                                    
                                    // Get amount from post-balances vs pre-balances
                                    // For now, use a placeholder - actual implementation
                                    // would parse the instruction data
                                    return Ok((dest, 0)); // Amount filled later
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        
        Err(KausaError::ParseError("Could not extract transfer info".into()))
    }
    
    /// Scan for transfers to a specific address
    pub fn scan_address(
        &self,
        keys: &StealthKeys,
        address: &Pubkey,
    ) -> Result<Option<DetectedTransfer>> {
        // Get signatures for this address
        let sigs = self.client
            .get_signatures_for_address(address)
            .map_err(|e| KausaError::RpcError(e.to_string()))?;
        
        // Check each transaction
        for sig_info in sigs {
            let sig = sig_info.signature.parse::<Signature>()
                .map_err(|e| KausaError::ParseError(e.to_string()))?;
            
            if let Ok(Some(transfer)) = self.check_transaction(keys, &sig) {
                return Ok(Some(transfer));
            }
        }
        
        Ok(None)
    }
    
    /// Get balance of a stealth address
    pub fn get_stealth_balance(&self, stealth_pubkey: &Pubkey) -> Result<u64> {
        self.client
            .get_balance(stealth_pubkey)
            .map_err(|e| KausaError::RpcError(e.to_string()))
    }
    
    /// Check multiple stealth addresses for claimable balances
    pub fn check_claimable(
        &self,
        keys: &StealthKeys,
        stealth_addresses: &[StealthAddress],
    ) -> Result<Vec<(StealthAddress, u64)>> {
        let mut claimable = Vec::new();
        
        for stealth in stealth_addresses {
            // Verify ownership
            if !keys.check_stealth_address(stealth)? {
                continue;
            }
            
            let pubkey = Pubkey::new_from_array(stealth.pubkey);
            let balance = self.get_stealth_balance(&pubkey)?;
            
            if balance > 0 {
                claimable.push((stealth.clone(), balance));
            }
        }
        
        Ok(claimable)
    }
}

/// Simple in-memory storage for detected transfers
#[derive(Default)]
pub struct TransferStore {
    transfers: Vec<DetectedTransfer>,
}

impl TransferStore {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn add(&mut self, transfer: DetectedTransfer) {
        // Check for duplicates
        if !self.transfers.iter().any(|t| t.signature == transfer.signature) {
            self.transfers.push(transfer);
        }
    }
    
    pub fn get_unclaimed(&self) -> Vec<&DetectedTransfer> {
        self.transfers.iter().filter(|t| !t.claimed).collect()
    }
    
    pub fn get_all(&self) -> &[DetectedTransfer] {
        &self.transfers
    }
    
    pub fn mark_claimed(&mut self, signature: &str) {
        for t in &mut self.transfers {
            if t.signature == signature {
                t.claimed = true;
            }
        }
    }
    
    pub fn total_unclaimed(&self) -> u64 {
        self.transfers.iter()
            .filter(|t| !t.claimed)
            .map(|t| t.amount)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_store() {
        let mut store = TransferStore::new();
        
        let transfer = DetectedTransfer {
            signature: "test_sig_123".to_string(),
            stealth_pubkey: Pubkey::new_unique(),
            ephemeral_pubkey: [1u8; 32],
            amount: 1_000_000,
            block_time: Some(1234567890),
            claimed: false,
        };
        
        store.add(transfer.clone());
        assert_eq!(store.get_all().len(), 1);
        assert_eq!(store.get_unclaimed().len(), 1);
        assert_eq!(store.total_unclaimed(), 1_000_000);
        
        // Duplicate should not be added
        store.add(transfer);
        assert_eq!(store.get_all().len(), 1);
        
        // Mark as claimed
        store.mark_claimed("test_sig_123");
        assert_eq!(store.get_unclaimed().len(), 0);
        assert_eq!(store.total_unclaimed(), 0);
    }

    #[test]
    fn test_parse_sdp_memo() {
        let config = Config::default();
        let scanner = Scanner::new_devnet(config.clone());
        
        // Valid memo
        // Generate test ephemeral key (32 bytes -> base58)
        let test_eph_bytes: [u8; 32] = [1u8; 32];
        let test_eph_b58 = bs58::encode(&test_eph_bytes).into_string();
        let memo = format!("{}{}", config.sdp_memo_prefix, test_eph_b58);
        let result = scanner.parse_sdp_memo(&memo);
        assert!(result.is_some());
        
        // Invalid prefix
        let bad_memo = format!("WRONG:{}", test_eph_b58);
        assert!(scanner.parse_sdp_memo(&bad_memo).is_none());
        
        // Empty
        assert!(scanner.parse_sdp_memo("").is_none());
    }
}
