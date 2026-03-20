//! Token Helper Module for SPL Token and Token-2022 support

use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    system_instruction,
};
use solana_client::rpc_client::RpcClient;
use std::str::FromStr;

// Program IDs
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

// Constants
pub const SOL_FOR_RENT: u64 = 7_000_000; // 0.007 SOL for Token-2022
pub const ATA_RENT: u64 = 2_074_080; // ~0.00207 SOL per Token-2022 ATA
pub const TOKEN_FEE_BPS: u64 = 50; // 0.5% = 50 basis points

/// Token info returned from mint query
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub mint: Pubkey,
    pub decimals: u8,
    pub token_program: Pubkey,
    pub has_transfer_fee: bool,
    pub transfer_fee_bps: u16,
}

/// Detect which token program owns the mint
pub fn detect_token_program(client: &RpcClient, mint: &Pubkey) -> Result<Pubkey, String> {
    let account = client.get_account(mint)
        .map_err(|e| format!("Failed to get mint account: {}", e))?;
    
    let token_program = Pubkey::from_str(TOKEN_PROGRAM_ID).unwrap();
    let token_2022_program = Pubkey::from_str(TOKEN_2022_PROGRAM_ID).unwrap();
    
    if account.owner == token_program {
        Ok(token_program)
    } else if account.owner == token_2022_program {
        Ok(token_2022_program)
    } else {
        Err(format!("Unknown token program: {}", account.owner))
    }
}

/// Get token decimals from mint
pub fn get_token_decimals(client: &RpcClient, mint: &Pubkey) -> Result<u8, String> {
    let account = client.get_account(mint)
        .map_err(|e| format!("Failed to get mint account: {}", e))?;
    
    // Mint data layout: decimals is at offset 44 (1 byte)
    if account.data.len() < 45 {
        return Err("Invalid mint data".to_string());
    }
    
    Ok(account.data[44])
}

/// Get full token info
pub fn get_token_info(client: &RpcClient, mint: &Pubkey) -> Result<TokenInfo, String> {
    let token_program = detect_token_program(client, mint)?;
    let decimals = get_token_decimals(client, mint)?;
    
    // TODO: Check for transfer fee extension in Token-2022
    // For now, assume no transfer fee
    let has_transfer_fee = false;
    let transfer_fee_bps = 0;
    
    Ok(TokenInfo {
        mint: *mint,
        decimals,
        token_program,
        has_transfer_fee,
        transfer_fee_bps,
    })
}

/// Derive Associated Token Account address
pub fn get_ata_address(wallet: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    let ata_program = Pubkey::from_str(ATA_PROGRAM_ID).unwrap();
    
    let seeds = &[
        wallet.as_ref(),
        token_program.as_ref(),
        mint.as_ref(),
    ];
    
    let (ata, _bump) = Pubkey::find_program_address(seeds, &ata_program);
    ata
}

/// Check if ATA exists
pub fn ata_exists(client: &RpcClient, ata: &Pubkey) -> bool {
    match client.get_account(ata) {
        Ok(account) => account.lamports > 0,
        Err(_) => false,
    }
}

/// Get token balance for an ATA
pub fn get_token_balance(client: &RpcClient, ata: &Pubkey) -> Result<u64, String> {
    let account = client.get_account(ata)
        .map_err(|e| format!("Failed to get ATA: {}", e))?;
    
    // Token account data layout: amount is at offset 64 (8 bytes, little-endian)
    if account.data.len() < 72 {
        return Err("Invalid token account data".to_string());
    }
    
    let amount = u64::from_le_bytes(account.data[64..72].try_into().unwrap());
    Ok(amount)
}

/// Create instruction to create ATA
pub fn create_ata_instruction(
    payer: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    let ata_program = Pubkey::from_str(ATA_PROGRAM_ID).unwrap();
    let ata = get_ata_address(wallet, mint, token_program);
    
    spl_associated_token_account::instruction::create_associated_token_account(
        payer,
        wallet,
        mint,
        token_program,
    )
}

/// Create instruction to transfer tokens
pub fn transfer_token_instruction(
    source_ata: &Pubkey,
    destination_ata: &Pubkey,
    authority: &Pubkey,
    mint: &Pubkey,
    amount: u64,
    decimals: u8,
    token_program: &Pubkey,
) -> Result<Instruction, String> {
    let token_2022 = Pubkey::from_str(TOKEN_2022_PROGRAM_ID).unwrap();
    
    if *token_program == token_2022 {
        spl_token_2022::instruction::transfer_checked(
            token_program,
            source_ata,
            mint,
            destination_ata,
            authority,
            &[],
            amount,
            decimals,
        ).map_err(|e| format!("Failed to create transfer instruction: {}", e))
    } else {
        spl_token::instruction::transfer_checked(
            token_program,
            source_ata,
            mint,
            destination_ata,
            authority,
            &[],
            amount,
            decimals,
        ).map_err(|e| format!("Failed to create transfer instruction: {}", e))
    }
}

/// Create instruction to close token account (refund rent)
pub fn close_ata_instruction(
    ata: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    token_program: &Pubkey,
) -> Result<Instruction, String> {
    let token_2022 = Pubkey::from_str(TOKEN_2022_PROGRAM_ID).unwrap();
    
    if *token_program == token_2022 {
        spl_token_2022::instruction::close_account(
            token_program,
            ata,
            destination,
            authority,
            &[],
        ).map_err(|e| format!("Failed to create close instruction: {}", e))
    } else {
        spl_token::instruction::close_account(
            token_program,
            ata,
            destination,
            authority,
            &[],
        ).map_err(|e| format!("Failed to create close instruction: {}", e))
    }
}

/// Calculate fee breakdown
pub fn calculate_fee_breakdown(amount: u64, token_transfer_fee_bps: u16) -> FeeBreakdown {
    // Token's built-in transfer fee (if any)
    let token_fee = if token_transfer_fee_bps > 0 {
        amount * (token_transfer_fee_bps as u64) / 10000
    } else {
        0
    };
    
    let after_token_fee = amount - token_fee;
    
    // KausaLayer fee (0.5%)
    let kausa_fee = after_token_fee * TOKEN_FEE_BPS / 10000;
    
    // Net to receiver
    let net_amount = after_token_fee - kausa_fee;
    
    FeeBreakdown {
        gross_amount: amount,
        token_fee,
        kausa_fee,
        net_amount,
        sol_required: SOL_FOR_RENT,
    }
}

#[derive(Debug, Clone)]
pub struct FeeBreakdown {
    pub gross_amount: u64,
    pub token_fee: u64,
    pub kausa_fee: u64,
    pub net_amount: u64,
    pub sol_required: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fee_calculation() {
        // 1000 tokens, no token transfer fee
        let breakdown = calculate_fee_breakdown(1000, 0);
        assert_eq!(breakdown.gross_amount, 1000);
        assert_eq!(breakdown.token_fee, 0);
        assert_eq!(breakdown.kausa_fee, 5); // 0.5% of 1000 = 5
        assert_eq!(breakdown.net_amount, 995);
        
        // 1000 tokens, 1% token transfer fee
        let breakdown = calculate_fee_breakdown(1000, 100); // 100 bps = 1%
        assert_eq!(breakdown.gross_amount, 1000);
        assert_eq!(breakdown.token_fee, 10); // 1% of 1000 = 10
        assert_eq!(breakdown.kausa_fee, 4); // 0.5% of 990 = 4.95 → 4
        assert_eq!(breakdown.net_amount, 986); // 990 - 4 = 986
    }
    
    #[test]
    fn test_sol_for_rent() {
        assert_eq!(SOL_FOR_RENT, 7_000_000); // 0.007 SOL
    }
}
