//! Transaction Builder for KausaLayer
//! Builds Solana transactions with stealth address + memo

use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};

use crate::error::{KausaError, Result};
use crate::core::stealth::StealthAddress;
use crate::core::fragmenter::Fragment;
use crate::Config;

/// Memo program ID (SPL Memo)
pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// A prepared transaction ready to be sent
#[derive(Debug, Clone)]
pub struct PreparedTransaction {
    /// The serialized transaction bytes
    pub transaction: Transaction,
    /// Amount in lamports
    pub amount: u64,
    /// Delay before sending (ms)
    pub delay_ms: u64,
    /// Stealth address destination
    pub stealth_pubkey: [u8; 32],
    /// Ephemeral key (for memo)
    pub ephemeral_pubkey: [u8; 32],
}

/// Transaction Builder
pub struct TransactionBuilder {
    config: Config,
}

impl TransactionBuilder {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
    
    /// Build a single stealth transfer transaction
    /// Includes: SOL transfer + Memo with ephemeral key
    pub fn build_stealth_transfer(
        &self,
        payer: &Keypair,
        stealth: &StealthAddress,
        amount_lamports: u64,
        recent_blockhash: solana_sdk::hash::Hash,
    ) -> Result<Transaction> {
        // Destination is the stealth pubkey
        let destination = Pubkey::new_from_array(stealth.pubkey);
        
        // 1. SOL transfer instruction
        let transfer_ix = system_instruction::transfer(
            &payer.pubkey(),
            &destination,
            amount_lamports,
        );
        
        // 2. Memo instruction with ephemeral pubkey
        // Format: "SDP:<base58_ephemeral_pubkey>"
        let memo_data = format!(
            "{}{}",
            self.config.sdp_memo_prefix,
            bs58::encode(&stealth.ephemeral_pubkey).into_string()
        );
        let memo_ix = self.build_memo_instruction(&memo_data, &payer.pubkey());
        
        // Build transaction
        let message = Message::new(
            &[transfer_ix, memo_ix],
            Some(&payer.pubkey()),
        );
        
        let mut tx = Transaction::new_unsigned(message);
        tx.sign(&[payer], recent_blockhash);
        
        Ok(tx)
    }
    
    /// Build memo instruction
    fn build_memo_instruction(&self, memo: &str, signer: &Pubkey) -> Instruction {
        let memo_program_id = MEMO_PROGRAM_ID.parse::<Pubkey>().unwrap();
        
        Instruction {
            program_id: memo_program_id,
            accounts: vec![AccountMeta::new_readonly(*signer, true)],
            data: memo.as_bytes().to_vec(),
        }
    }
    
    /// Build multiple transactions for fragmented transfer
    pub fn build_fragmented_transfer(
        &self,
        payer: &Keypair,
        stealth_addresses: Vec<StealthAddress>,
        fragments: Vec<Fragment>,
        recent_blockhash: solana_sdk::hash::Hash,
    ) -> Result<Vec<PreparedTransaction>> {
        if stealth_addresses.len() != fragments.len() {
            return Err(KausaError::TransactionError(
                "Stealth addresses count must match fragments count".into()
            ));
        }
        
        let mut prepared = Vec::with_capacity(fragments.len());
        
        for (stealth, fragment) in stealth_addresses.iter().zip(fragments.iter()) {
            let tx = self.build_stealth_transfer(
                payer,
                stealth,
                fragment.amount,
                recent_blockhash,
            )?;
            
            prepared.push(PreparedTransaction {
                transaction: tx,
                amount: fragment.amount,
                delay_ms: fragment.delay_ms,
                stealth_pubkey: stealth.pubkey,
                ephemeral_pubkey: stealth.ephemeral_pubkey,
            });
        }
        
        // Sort by delay for proper execution order
        prepared.sort_by_key(|p| p.delay_ms);
        
        Ok(prepared)
    }
    
    /// Calculate total transaction fee estimate
    pub fn estimate_fee(&self, num_fragments: usize) -> u64 {
        // Base fee per signature (~5000 lamports)
        // + memo instruction cost (~small)
        // Conservative estimate: 10000 lamports per transaction
        10_000 * num_fragments as u64
    }
    
    /// Calculate protocol fee (0.1% of amount)
    pub fn calculate_protocol_fee(&self, amount_lamports: u64) -> u64 {
        ((amount_lamports as f64) * (self.config.protocol_fee_percent / 100.0)) as u64
    }
    
    /// Calculate total cost (amount + tx fees + protocol fee)
    pub fn calculate_total_cost(
        &self,
        amount_lamports: u64,
        num_fragments: usize,
    ) -> (u64, u64, u64, u64) {
        let tx_fee = self.estimate_fee(num_fragments);
        let protocol_fee = self.calculate_protocol_fee(amount_lamports);
        let total = amount_lamports + tx_fee + protocol_fee;
        
        (amount_lamports, tx_fee, protocol_fee, total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::stealth::{StealthKeys, create_stealth_address};
    use crate::core::fragmenter::Fragmenter;
    use solana_sdk::hash::Hash;

    #[test]
    fn test_build_stealth_transfer() {
        let config = Config::default();
        let builder = TransactionBuilder::new(config);
        
        // Generate test keys
        let payer = Keypair::new();
        let receiver = StealthKeys::new();
        let stealth = create_stealth_address(&receiver.get_meta_address()).unwrap();
        
        // Build transaction
        let blockhash = Hash::new_unique();
        let tx = builder.build_stealth_transfer(&payer, &stealth, 1_000_000, blockhash);
        
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        
        // Should have 2 instructions: transfer + memo
        assert_eq!(tx.message.instructions.len(), 2);
    }

    #[test]
    fn test_build_fragmented_transfer() {
        let config = Config::default();
        let builder = TransactionBuilder::new(config);
        
        let payer = Keypair::new();
        let receiver = StealthKeys::new();
        let meta = receiver.get_meta_address();
        
        // Create fragments
        let fragmenter = Fragmenter::new(3, 3, 0);
        let fragments = fragmenter.fragment_instant(1_000_000_000).unwrap();
        
        // Create stealth addresses for each fragment
        let stealth_addresses: Vec<StealthAddress> = (0..fragments.len())
            .map(|_| create_stealth_address(&meta).unwrap())
            .collect();
        
        // Build transactions
        let blockhash = Hash::new_unique();
        let prepared = builder.build_fragmented_transfer(
            &payer,
            stealth_addresses,
            fragments,
            blockhash,
        );
        
        assert!(prepared.is_ok());
        let prepared = prepared.unwrap();
        assert_eq!(prepared.len(), 3);
        
        // Verify total amount
        let total: u64 = prepared.iter().map(|p| p.amount).sum();
        assert_eq!(total, 1_000_000_000);
    }

    #[test]
    fn test_fee_calculation() {
        let config = Config::default();
        let builder = TransactionBuilder::new(config);
        
        // Protocol fee: 0.1% of 1 SOL = 0.001 SOL = 1_000_000 lamports
        let protocol_fee = builder.calculate_protocol_fee(1_000_000_000);
        assert_eq!(protocol_fee, 1_000_000);
        
        // Total cost calculation
        let (amount, tx_fee, proto_fee, total) = builder.calculate_total_cost(1_000_000_000, 4);
        assert_eq!(amount, 1_000_000_000);
        assert_eq!(tx_fee, 40_000); // 4 * 10000
        assert_eq!(proto_fee, 1_000_000);
        assert_eq!(total, 1_001_040_000);
    }
}
