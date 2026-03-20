//! KausaLayer Relay Server v2
//!
//! Features:
//! - Unique deposit address per request (secure)
//! - SQLite persistent storage
//! - Auto-cleanup expired requests

use axum::{
    extract::{State, Query},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::Signer,
    system_instruction,
    transaction::Transaction,
};
use std::sync::Arc;
use std::str::FromStr;
use tokio::net::TcpListener;
use tracing::{info, warn, error};

use kausalayer::core::{
    MetaAddress, create_stealth_address,
    lamports_to_sol, sol_to_lamports,
};
use kausalayer::relay::RelayDatabase;
use kausalayer::Config;

// ============ CONSTANTS ============

const FEE_PERCENT: f64 = 0.5;
const TX_FEE_LAMPORTS: u64 = 5_000;
const MIN_AMOUNT_SOL: f64 = 0.001;
const EXPIRY_SECONDS: i64 = 1800;
const FEE_WALLET: &str = "2npLHoqTHragQHM8sLvT7T9q26UDtos1it1TA7ZVGGHW";

// ============ STATE ============

struct RelayState {
    client: RpcClient,
    config: Config,
    db: RelayDatabase,
    fee_wallet: Pubkey,
}

impl RelayState {
    fn new(rpc_url: &str) -> Self {
        let client = RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        );
        let db = RelayDatabase::new().expect("Failed to initialize database");
        let fee_wallet = Pubkey::from_str(FEE_WALLET).expect("Invalid fee wallet");

        info!("Relay initialized");
        info!("  Fee wallet: {}", fee_wallet);
        info!("  Fee percent: {}%", FEE_PERCENT);
        info!("  Expiry: {} minutes", EXPIRY_SECONDS / 60);

        if let Ok((pending, completed, expired)) = db.get_stats() {
            info!("  DB stats - Pending: {}, Completed: {}, Expired: {}", pending, completed, expired);
        }

        Self { client, config: Config::default(), db, fee_wallet }
    }
}

// ============ REQUEST/RESPONSE TYPES ============

#[derive(Debug, Deserialize)]
struct TransferRequest {
    recipient: String,
    amount: f64,
}

#[derive(Debug, Serialize)]
struct DepositInstructions {
    request_id: String,
    deposit_address: String,
    deposit_amount: f64,
    amount: f64,
    fee: f64,
    tx_fee: f64,
    expires_at: i64,
    expires_in_seconds: i64,
}

#[derive(Debug, Deserialize)]
struct ExecuteRequest {
    request_id: String,
}

#[derive(Debug, Serialize)]
struct TransferResult {
    status: String,
    signature: Option<String>,
    message: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    pending_requests: usize,
    completed_requests: usize,
}

#[derive(Debug, Serialize)]
struct InfoResponse {
    name: String,
    version: String,
    fee_percent: f64,
    min_amount: f64,
    expiry_minutes: i64,
}

#[derive(Debug, Deserialize)]
struct BalanceRequest {
    address: String,
}

#[derive(Debug, Serialize)]
struct BalanceResponse {
    address: String,
    lamports: u64,
    sol: f64,
}

#[derive(Debug, Deserialize)]
struct StatusRequest {
    request_id: String,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    request_id: String,
    status: String,
    deposit_address: String,
    amount: f64,
    deposit_received: f64,
    is_funded: bool,
    expires_at: i64,
    tx_signature: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ScanRequest {
    view_pubkey: String,
    spend_pubkey: String,
}

#[derive(Debug, Serialize)]
struct ScanResult {
    ephemeral_pubkey: String,
    stealth_address: String,
    amount_lamports: u64,
    signature: String,
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    transfers: Vec<ScanResult>,
}

#[derive(Debug, Serialize)]
struct BlockhashResponse {
    blockhash: String,
}

#[derive(Debug, Deserialize)]
struct SubmitRequest {
    signed_tx: String,
}

#[derive(Debug, Serialize)]
struct SubmitResponse {
    status: String,
    signature: String,
    message: String,
}

// ============ HANDLERS ============

async fn health(State(state): State<Arc<RelayState>>) -> Json<HealthResponse> {
    let (pending, completed, _) = state.db.get_stats().unwrap_or((0, 0, 0));
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        pending_requests: pending,
        completed_requests: completed,
    })
}

async fn info_handler() -> Json<InfoResponse> {
    Json(InfoResponse {
        name: "KausaLayer Relay".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        fee_percent: FEE_PERCENT,
        min_amount: MIN_AMOUNT_SOL,
        expiry_minutes: EXPIRY_SECONDS / 60,
    })
}

async fn get_balance(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<BalanceRequest>,
) -> Result<Json<BalanceResponse>, (StatusCode, String)> {
    let pubkey = Pubkey::from_str(&req.address)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid address: {}", e)))?;
    let lamports = state.client.get_balance(&pubkey)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("RPC error: {}", e)))?;
    Ok(Json(BalanceResponse {
        address: req.address,
        lamports,
        sol: lamports_to_sol(lamports),
    }))
}

async fn request_transfer(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<TransferRequest>,
) -> Result<Json<DepositInstructions>, (StatusCode, String)> {
    info!("Transfer request: {} SOL to {}...", req.amount, &req.recipient[..20.min(req.recipient.len())]);

    MetaAddress::decode(&req.recipient)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid recipient: {}", e)))?;

    if req.amount < MIN_AMOUNT_SOL {
        return Err((StatusCode::BAD_REQUEST, format!("Minimum amount is {} SOL", MIN_AMOUNT_SOL)));
    }

    let amount_lamports = sol_to_lamports(req.amount);
    let fee_lamports = ((amount_lamports as f64) * FEE_PERCENT / 100.0) as u64;
    let total_deposit = amount_lamports + fee_lamports + TX_FEE_LAMPORTS;
    let request_id = format!("req_{}", chrono::Utc::now().timestamp_millis());

    let (request, _keypair) = state.db.create_request(
        &request_id, amount_lamports, fee_lamports, &req.recipient, EXPIRY_SECONDS,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    info!("Created request {} with deposit address {}", request_id, request.deposit_address);
    let now = chrono::Utc::now().timestamp();

    Ok(Json(DepositInstructions {
        request_id,
        deposit_address: request.deposit_address,
        deposit_amount: lamports_to_sol(total_deposit),
        amount: req.amount,
        fee: lamports_to_sol(fee_lamports),
        tx_fee: lamports_to_sol(TX_FEE_LAMPORTS),
        expires_at: request.expires_at,
        expires_in_seconds: request.expires_at - now,
    }))
}

async fn check_status(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<StatusRequest>,
) -> Result<Json<StatusResponse>, (StatusCode, String)> {
    let request = state.db.get_request(&req.request_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .ok_or((StatusCode::NOT_FOUND, "Request not found".to_string()))?;

    let deposit_pubkey = Pubkey::from_str(&request.deposit_address)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid address: {}", e)))?;

    let current_balance = state.client.get_balance(&deposit_pubkey).unwrap_or(0);
    let required = request.amount_lamports + request.fee_lamports + TX_FEE_LAMPORTS;

    Ok(Json(StatusResponse {
        request_id: request.request_id,
        status: request.status.as_str().to_string(),
        deposit_address: request.deposit_address,
        amount: lamports_to_sol(request.amount_lamports),
        deposit_received: lamports_to_sol(current_balance),
        is_funded: current_balance >= required,
        expires_at: request.expires_at,
        tx_signature: request.tx_signature,
    }))
}

async fn execute_transfer(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<TransferResult>, (StatusCode, String)> {
    info!("Execute request: {}", req.request_id);

    let request = state.db.get_request(&req.request_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .ok_or((StatusCode::NOT_FOUND, "Request not found".to_string()))?;

    if request.status != kausalayer::relay::RequestStatus::Pending {
        return Err((StatusCode::BAD_REQUEST, format!("Request status is '{}', not 'pending'", request.status.as_str())));
    }

    let now = chrono::Utc::now().timestamp();
    if now > request.expires_at {
        state.db.mark_expired(&req.request_id).ok();
        return Err((StatusCode::BAD_REQUEST, "Request has expired".to_string()));
    }

    let deposit_pubkey = Pubkey::from_str(&request.deposit_address)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid address: {}", e)))?;

    let current_balance = state.client.get_balance(&deposit_pubkey)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("RPC error: {}", e)))?;

    let required = request.amount_lamports + request.fee_lamports + TX_FEE_LAMPORTS;

    if current_balance < required {
        return Ok(Json(TransferResult {
            status: "pending".to_string(),
            signature: None,
            message: format!("Deposit not received. Required: {} SOL, Current: {} SOL",
                lamports_to_sol(required), lamports_to_sol(current_balance)),
        }));
    }

    info!("Deposit confirmed: {} SOL", lamports_to_sol(current_balance));

    let deposit_keypair = state.db.get_keypair(&req.request_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Keypair error: {}", e)))?;

    let meta = MetaAddress::decode(&request.recipient_meta)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid recipient: {}", e)))?;

    let stealth = create_stealth_address(&meta)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Stealth error: {}", e)))?;

    let stealth_pubkey = Pubkey::new_from_array(stealth.pubkey);
    info!("Sending {} SOL to stealth address {}", lamports_to_sol(request.amount_lamports), stealth_pubkey);

    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Blockhash error: {}", e)))?;

    let transfer_ix = system_instruction::transfer(&deposit_keypair.pubkey(), &stealth_pubkey, request.amount_lamports);
    let fee_ix = system_instruction::transfer(&deposit_keypair.pubkey(), &state.fee_wallet, request.fee_lamports);
    let memo_data = format!("SDP:{}", bs58::encode(&stealth.ephemeral_pubkey).into_string());
    let memo_ix = spl_memo::build_memo(memo_data.as_bytes(), &[&deposit_keypair.pubkey()]);

    let tx = Transaction::new_signed_with_payer(
        &[transfer_ix, fee_ix, memo_ix],
        Some(&deposit_keypair.pubkey()),
        &[&deposit_keypair],
        blockhash,
    );

    match state.client.send_and_confirm_transaction(&tx) {
        Ok(signature) => {
            info!("Transfer successful: {}", signature);
            state.db.mark_completed(&req.request_id, &signature.to_string())
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?;
            // Save untuk scan
            let stealth_addr_str = stealth_pubkey.to_string();
            let ephemeral_str = bs58::encode(&stealth.ephemeral_pubkey).into_string();
            state.db.save_completed_transfer(
                &request.recipient_meta,
                &stealth_addr_str,
                &ephemeral_str,
                request.amount_lamports,
                &signature.to_string(),
            ).ok(); // Ignore error, non-critical
            Ok(Json(TransferResult {
                status: "success".to_string(),
                signature: Some(signature.to_string()),
                message: format!("{} SOL sent privately", lamports_to_sol(request.amount_lamports)),
            }))
        }
        Err(e) => {
            error!("Transfer failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Transaction failed: {}", e)))
        }
    }
}

async fn cleanup_expired(State(state): State<Arc<RelayState>>) -> Json<serde_json::Value> {
    let expired = state.db.get_expired_requests().unwrap_or_default();
    let mut cleaned = 0;
    let mut with_balance = 0;

    for req in expired {
        if let Ok(pubkey) = Pubkey::from_str(&req.deposit_address) {
            let balance = state.client.get_balance(&pubkey).unwrap_or(0);
            if balance > 0 {
                with_balance += 1;
                warn!("Request {} has {} SOL remaining", req.request_id, lamports_to_sol(balance));
            } else {
                state.db.mark_expired(&req.request_id).ok();
                cleaned += 1;
            }
        }
    }

    let deleted = state.db.cleanup_old_requests().unwrap_or(0);
    Json(serde_json::json!({
        "cleaned": cleaned,
        "with_balance": with_balance,
        "deleted_old": deleted
    }))
}

async fn scan_transfers(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    info!("Scan request for view_pubkey: {}...", &req.view_pubkey[..8.min(req.view_pubkey.len())]);

    // Decode pubkeys from base58
    let spend_bytes = bs58::decode(&req.spend_pubkey)
        .into_vec()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid spend_pubkey: {}", e)))?;
    let view_bytes = bs58::decode(&req.view_pubkey)
        .into_vec()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid view_pubkey: {}", e)))?;

    if spend_bytes.len() != 32 || view_bytes.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, "Pubkeys must be 32 bytes".to_string()));
    }

    // Reconstruct meta-address: kl_ + bs58(spend || view)
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&spend_bytes);
    combined.extend_from_slice(&view_bytes);
    let recipient_meta = format!("kl_{}", bs58::encode(&combined).into_string());

    // Query database
    let db_transfers = state.db.get_transfers_for_recipient(&recipient_meta)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?;

    // Convert to response format
    let transfers: Vec<ScanResult> = db_transfers
        .into_iter()
        .map(|(stealth_addr, ephemeral, amount, sig)| ScanResult {
            stealth_address: stealth_addr,
            ephemeral_pubkey: ephemeral,
            amount_lamports: amount,
            signature: sig,
        })
        .collect();

    info!("Found {} transfers", transfers.len());
    Ok(Json(ScanResponse { transfers }))
}

async fn get_blockhash(
    State(state): State<Arc<RelayState>>,
) -> Result<Json<BlockhashResponse>, (StatusCode, String)> {
    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("RPC error: {}", e)))?;
    Ok(Json(BlockhashResponse { blockhash: blockhash.to_string() }))
}

async fn submit_transaction(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>, (StatusCode, String)> {
    use base64::Engine;
    info!("Submit signed transaction");

    let tx_bytes = base64::engine::general_purpose::STANDARD
        .decode(&req.signed_tx)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid base64: {}", e)))?;

    let tx: Transaction = bincode::deserialize(&tx_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid transaction: {}", e)))?;

    match state.client.send_and_confirm_transaction(&tx) {
        Ok(signature) => {
            info!("Transaction submitted: {}", signature);
            Ok(Json(SubmitResponse {
                status: "success".to_string(),
                signature: signature.to_string(),
                message: "Transaction confirmed".to_string(),
            }))
        }
        Err(e) => {
            error!("Transaction failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Transaction failed: {}", e)))
        }
    }
}

#[derive(Debug, Deserialize)]
struct ClaimCompleteRequest {
    stealth_address: String,
}

#[derive(Debug, Serialize)]
struct ClaimCompleteResponse {
    status: String,
    message: String,
}

async fn claim_complete(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<ClaimCompleteRequest>,
) -> Result<Json<ClaimCompleteResponse>, (StatusCode, String)> {
    info!("Claim complete for stealth: {}...", &req.stealth_address[..8.min(req.stealth_address.len())]);

    state.db.delete_completed_transfer(&req.stealth_address)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?;

    Ok(Json(ClaimCompleteResponse {
        status: "success".to_string(),
        message: "Transfer marked as claimed".to_string(),
    }))
}

// ============ TOKEN TRANSFER TYPES ============

#[derive(Debug, Deserialize)]
struct TokenTransferRequest {
    token_mint: String,
    amount: u64,
    recipient_meta: String,
}

#[derive(Debug, Serialize)]
struct TokenDepositInstructions {
    request_id: String,
    token_mint: String,
    token_decimals: u8,
    token_amount: u64,
    fee_amount: u64,
    net_amount: u64,
    sol_required: u64,
    deposit_address: String,
    deposit_ata: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct TokenExecuteRequest {
    request_id: String,
}

#[derive(Debug, Serialize)]
struct TokenTransferResult {
    status: String,
    signature: Option<String>,
    message: String,
}

#[derive(Debug, Serialize)]
struct TokenPrepareResponse {
    status: String,
    request_id: String,
    deposit_ata: String,
    ata_created: bool,
    signature: Option<String>,
    message: String,
}

#[derive(Debug, Serialize)]
struct TokenScanResult {
    stealth_address: String,
    stealth_ata: String,
    ephemeral_pubkey: String,
    token_mint: String,
    token_decimals: u8,
    amount: u64,
    sol_amount: u64,
    signature: String,
}

#[derive(Debug, Serialize)]
struct TokenScanResponse {
    transfers: Vec<TokenScanResult>,
}

// ============ TOKEN HANDLERS ============

async fn token_request_transfer(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<TokenTransferRequest>,
) -> Result<Json<TokenDepositInstructions>, (StatusCode, String)> {
    use std::str::FromStr;
    use kausalayer::relay::token::{get_token_info, get_ata_address, calculate_fee_breakdown, SOL_FOR_RENT};

    let mint = solana_sdk::pubkey::Pubkey::from_str(&req.token_mint)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid mint: {}", e)))?;

    // Get token info
    let token_info = get_token_info(&state.client, &mint)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Token error: {}", e)))?;

    // Calculate fees
    let breakdown = calculate_fee_breakdown(req.amount, token_info.transfer_fee_bps);

    info!("Token transfer request: {} tokens to {}...", req.amount, &req.recipient_meta[..20.min(req.recipient_meta.len())]);

    // Generate deposit keypair
    let deposit_keypair = solana_sdk::signature::Keypair::new();
    let deposit_address = deposit_keypair.pubkey();
    let deposit_ata = get_ata_address(&deposit_address, &mint, &token_info.token_program);

    // Create request ID
    let request_id = format!("tok_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());


    // Save to database
    state.db.create_token_request(
        &request_id,
        &req.token_mint,
        &token_info.token_program.to_string(),
        token_info.decimals,
        req.amount,
        breakdown.kausa_fee,
        &req.recipient_meta,
        &deposit_address.to_string(),
        &deposit_ata.to_string(),
        &deposit_keypair.to_bytes(),
        EXPIRY_SECONDS,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?;

    info!("Created token request {} with deposit {} and ATA {}", request_id, deposit_address, deposit_ata);

    Ok(Json(TokenDepositInstructions {
        request_id,
        token_mint: req.token_mint,
        token_decimals: token_info.decimals,
        token_amount: req.amount,
        fee_amount: breakdown.kausa_fee,
        net_amount: breakdown.net_amount,
        sol_required: SOL_FOR_RENT,
        deposit_address: deposit_address.to_string(),
        deposit_ata: deposit_ata.to_string(),
        expires_in: EXPIRY_SECONDS as u64,
    }))
}

async fn token_prepare_ata(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<TokenExecuteRequest>,
) -> Result<Json<TokenPrepareResponse>, (StatusCode, String)> {
    use std::str::FromStr;
    use solana_sdk::{
        pubkey::Pubkey,
        transaction::Transaction,
    };
    use kausalayer::relay::token::{get_ata_address, create_ata_instruction, ata_exists, SOL_FOR_RENT, ATA_RENT};

    info!("Token prepare ATA request: {}", req.request_id);

    // Get request from database
    let request = state.db.get_token_request(&req.request_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?
        .ok_or((StatusCode::NOT_FOUND, "Request not found".to_string()))?;

    if request.status != "pending" {
        return Err((StatusCode::BAD_REQUEST, format!("Request status is {}", request.status)));
    }

    // Check SOL balance
    let deposit_pubkey = Pubkey::from_str(&request.deposit_address)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid deposit address: {}", e)))?;
    let sol_balance = state.client.get_balance(&deposit_pubkey)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("RPC error: {}", e)))?;

    if sol_balance < SOL_FOR_RENT {
        return Err((StatusCode::BAD_REQUEST, format!(
            "Insufficient SOL: {} lamports < {} required. Please send SOL first.",
            sol_balance, SOL_FOR_RENT
        )));
    }

    // Parse token info
    let token_program = Pubkey::from_str(&request.token_program)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid token program: {}", e)))?;
    let mint = Pubkey::from_str(&request.token_mint)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid mint: {}", e)))?;

    // Check if ATA already exists
    let deposit_ata = Pubkey::from_str(&request.deposit_ata)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid deposit ATA: {}", e)))?;

    if ata_exists(&state.client, &deposit_ata) {
        info!("ATA already exists: {}", deposit_ata);
        return Ok(Json(TokenPrepareResponse {
            status: "ready".to_string(),
            request_id: req.request_id,
            deposit_ata: request.deposit_ata,
            ata_created: false,
            signature: None,
            message: "ATA already exists. You can send tokens now.".to_string(),
        }));
    }

    // Get deposit keypair to sign transaction
    let deposit_keypair = state.db.get_token_keypair(&req.request_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Keypair error: {}", e)))?;

    // Create ATA instruction
    let create_ata_ix = create_ata_instruction(&deposit_pubkey, &deposit_pubkey, &mint, &token_program);

    // Get blockhash and send transaction
    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Blockhash error: {}", e)))?;

    let tx = Transaction::new_signed_with_payer(
        &[create_ata_ix],
        Some(&deposit_pubkey),
        &[&deposit_keypair],
        blockhash,
    );

    match state.client.send_and_confirm_transaction(&tx) {
        Ok(signature) => {
            info!("ATA created successfully: {} (sig: {})", deposit_ata, signature);
            Ok(Json(TokenPrepareResponse {
                status: "ready".to_string(),
                request_id: req.request_id,
                deposit_ata: request.deposit_ata,
                ata_created: true,
                signature: Some(signature.to_string()),
                message: "ATA created successfully. You can send tokens now.".to_string(),
            }))
        }
        Err(e) => {
            error!("Failed to create ATA: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create ATA: {}", e)))
        }
    }
}

async fn token_scan_transfers(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<TokenScanResponse>, (StatusCode, String)> {
    info!("Token scan request for view_pubkey: {}...", &req.view_pubkey[..8.min(req.view_pubkey.len())]);

    // Decode pubkeys from base58
    let spend_bytes = bs58::decode(&req.spend_pubkey)
        .into_vec()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid spend_pubkey: {}", e)))?;
    let view_bytes = bs58::decode(&req.view_pubkey)
        .into_vec()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid view_pubkey: {}", e)))?;

    if spend_bytes.len() != 32 || view_bytes.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, "Pubkeys must be 32 bytes".to_string()));
    }

    // Reconstruct meta-address
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&spend_bytes);
    combined.extend_from_slice(&view_bytes);
    let recipient_meta = format!("kl_{}", bs58::encode(&combined).into_string());

    // Query database
    let db_transfers = state.db.get_token_transfers_for_recipient(&recipient_meta)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?;

    // Convert to response format
    let transfers: Vec<TokenScanResult> = db_transfers
        .into_iter()
        .map(|(stealth_addr, stealth_ata, ephemeral, mint, program, decimals, amount, sol, sig)| TokenScanResult {
            stealth_address: stealth_addr,
            stealth_ata,
            ephemeral_pubkey: ephemeral,
            token_mint: mint,
            token_decimals: decimals,
            amount,
            sol_amount: sol,
            signature: sig,
        })
        .collect();

    info!("Found {} token transfers", transfers.len());
    Ok(Json(TokenScanResponse { transfers }))
}

async fn token_execute_transfer(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<TokenExecuteRequest>,
) -> Result<Json<TokenTransferResult>, (StatusCode, String)> {
    use std::str::FromStr;
    use solana_sdk::{
        pubkey::Pubkey,
        transaction::Transaction,
        system_instruction,
    };
    use kausalayer::relay::token::{get_ata_address, create_ata_instruction, transfer_token_instruction, SOL_FOR_RENT};
    use kausalayer::core::stealth::{MetaAddress, create_stealth_address};

    info!("Token execute request: {}", req.request_id);

    // Get request from database
    let request = state.db.get_token_request(&req.request_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?
        .ok_or((StatusCode::NOT_FOUND, "Request not found".to_string()))?;

    if request.status != "pending" {
        return Err((StatusCode::BAD_REQUEST, format!("Request status is {}", request.status)));
    }

    // Check SOL balance
    let deposit_pubkey = Pubkey::from_str(&request.deposit_address)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid deposit address: {}", e)))?;
    let sol_balance = state.client.get_balance(&deposit_pubkey)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("RPC error: {}", e)))?;

    if sol_balance < SOL_FOR_RENT {
        return Err((StatusCode::BAD_REQUEST, format!("Insufficient SOL: {} < {}", sol_balance, SOL_FOR_RENT)));
    }

    // Check token balance
    let deposit_ata = Pubkey::from_str(&request.deposit_ata)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid deposit ATA: {}", e)))?;
    let token_balance = kausalayer::relay::token::get_token_balance(&state.client, &deposit_ata)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Token not received yet: {}", e)))?;

    if token_balance < request.token_amount {
        return Err((StatusCode::BAD_REQUEST, format!("Insufficient tokens: {} < {}", token_balance, request.token_amount)));
    }

    info!("Token deposit confirmed: {} tokens + {} SOL", token_balance, sol_balance);

    // Parse recipient meta-address and generate stealth address
    let meta = MetaAddress::decode(&request.recipient_meta)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid meta-address: {}", e)))?;
    let stealth = create_stealth_address(&meta)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Stealth error: {:?}", e)))?;
    let stealth_pubkey = Pubkey::new_from_array(stealth.pubkey);

    // Get deposit keypair
    let deposit_keypair = state.db.get_token_keypair(&req.request_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Keypair error: {}", e)))?;

    // Token program and mint
    let token_program = Pubkey::from_str(&request.token_program)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid token program: {}", e)))?;
    let mint = Pubkey::from_str(&request.token_mint)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid mint: {}", e)))?;

    // Derive stealth ATA
    let stealth_ata = get_ata_address(&stealth_pubkey, &mint, &token_program);

    // Fee wallet ATA
    let fee_wallet = Pubkey::from_str(FEE_WALLET).unwrap();
    let fee_ata = get_ata_address(&fee_wallet, &mint, &token_program);

    // Calculate amounts
    let net_amount = request.token_amount - request.fee_amount;

    // Build transaction
    let mut instructions = vec![];
    let mut ata_cost: u64 = 0;

    // 1. Create stealth ATA
    instructions.push(create_ata_instruction(&deposit_pubkey, &stealth_pubkey, &mint, &token_program));
    ata_cost += kausalayer::relay::token::ATA_RENT;

    // 2. Create fee ATA if needed (deposit pays)
    let fee_ata_exists = kausalayer::relay::token::ata_exists(&state.client, &fee_ata);
    if !fee_ata_exists {
        instructions.push(create_ata_instruction(&deposit_pubkey, &fee_wallet, &mint, &token_program));
        ata_cost += kausalayer::relay::token::ATA_RENT;
    }

    // 3. Transfer tokens to stealth
    instructions.push(transfer_token_instruction(
        &deposit_ata, &stealth_ata, &deposit_pubkey, &mint,
        net_amount, request.token_decimals, &token_program
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Transfer error: {}", e)))?);

    // 4. Transfer fee to fee wallet
    if request.fee_amount > 0 {
        instructions.push(transfer_token_instruction(
            &deposit_ata, &fee_ata, &deposit_pubkey, &mint,
            request.fee_amount, request.token_decimals, &token_program
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Fee transfer error: {}", e)))?);
    }

    // 5. Transfer remaining SOL to stealth (for claim later)
    // Calculate: sol_balance - ata_cost - tx_fee buffer - rent_exempt_minimum
    // Fee payer must remain rent-exempt during transaction execution
    let rent_exempt_min = 890880_u64; // Minimum rent for account to not be purged
    let reserved = ata_cost + 50000 + rent_exempt_min; // ATA costs + tx fee + rent
    let sol_to_stealth = sol_balance.saturating_sub(reserved);
    // Only transfer if there's meaningful SOL left (> 0.001 SOL)
    if sol_to_stealth > 100_000 {
        instructions.push(system_instruction::transfer(&deposit_pubkey, &stealth_pubkey, sol_to_stealth));
    }

    // 6. Add memo with ephemeral pubkey
    let ephemeral_str = bs58::encode(&stealth.ephemeral_pubkey).into_string();
    instructions.push(spl_memo::build_memo(format!("SDP:{}", ephemeral_str).as_bytes(), &[]));

    // Get blockhash and send
    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Blockhash error: {}", e)))?;

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&deposit_pubkey),
        &[&deposit_keypair],
        blockhash,
    );

    match state.client.send_and_confirm_transaction(&tx) {
        Ok(signature) => {
            info!("Token transfer successful: {}", signature);
            state.db.mark_token_completed(&req.request_id, &signature.to_string()).ok();

            // Save to token_transfers for scan
            state.db.save_token_transfer(
                &request.recipient_meta,
                &stealth_pubkey.to_string(),
                &stealth_ata.to_string(),
                &ephemeral_str,
                &request.token_mint,
                &request.token_program,
                request.token_decimals,
                net_amount,
                sol_to_stealth,
                &signature.to_string(),
            ).ok();

            Ok(Json(TokenTransferResult {
                status: "success".to_string(),
                signature: Some(signature.to_string()),
                message: format!("{} tokens sent privately", net_amount),
            }))
        }
        Err(e) => {
            error!("Token transfer failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Transaction failed: {}", e)))
        }
    }
}

async fn token_claim_complete(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<ClaimCompleteRequest>,
) -> Result<Json<ClaimCompleteResponse>, (StatusCode, String)> {
    info!("Token claim complete for stealth: {}...", &req.stealth_address[..8.min(req.stealth_address.len())]);

    state.db.delete_token_transfer(&req.stealth_address)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?;

    Ok(Json(ClaimCompleteResponse {
        status: "success".to_string(),
        message: "Token transfer marked as claimed".to_string(),
    }))
}


// Token info endpoint
#[derive(Deserialize)]
struct TokenInfoQuery {
    mint: String,
}

#[derive(Serialize)]
struct TokenInfoResponse {
    mint: String,
    decimals: u8,
    program: String,
    symbol: String,
}

async fn token_info(
    State(state): State<Arc<RelayState>>,
    Query(query): Query<TokenInfoQuery>,
) -> Result<Json<TokenInfoResponse>, (StatusCode, String)> {
    use kausalayer::relay::token::get_token_info;
    use std::str::FromStr;

    let mint_pubkey = Pubkey::from_str(&query.mint)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid mint address".to_string()))?;

    let info = get_token_info(&state.client, &mint_pubkey)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to get token info: {}", e)))?;
    Ok(Json(TokenInfoResponse {
        mint: query.mint,
        decimals: info.decimals,
        program: info.token_program.to_string(),
        symbol: "tokens".to_string(), // Could fetch from metadata later
    }))
}
// ============ MAIN ============

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();
    dotenv::dotenv().ok();

    info!("🚀 Starting KausaLayer Relay Server v2...\n");

    let port: u16 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(3030);
    let rpc_url = std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

    info!("RPC: {} (API key hidden)", rpc_url.split("?").next().unwrap_or("unknown"));
    info!("Port: {}", port);
    info!("Fee wallet: {}", FEE_WALLET);

    let state = Arc::new(RelayState::new(&rpc_url));

    if let Ok((pending, completed, expired)) = state.db.get_stats() {
        println!("\n📊 Database Stats:");
        println!("   Pending: {}", pending);
        println!("   Completed: {}", completed);
        println!("   Expired: {}", expired);
    }

    println!("\n💰 Fee Configuration:");
    println!("   Fee: {}%", FEE_PERCENT);
    println!("   Min amount: {} SOL", MIN_AMOUNT_SOL);
    println!("   Expiry: {} minutes", EXPIRY_SECONDS / 60);

    let app = Router::new()
        .route("/health", get(health))
        .route("/info", get(info_handler))
        .route("/balance", post(get_balance))
        .route("/transfer/request", post(request_transfer))
        .route("/transfer/status", post(check_status))
        .route("/transfer/execute", post(execute_transfer))
        .route("/scan", post(scan_transfers))
        .route("/cleanup", post(cleanup_expired))
        .route("/blockhash", get(get_blockhash))
        .route("/submit", post(submit_transaction))
        .route("/claim/complete", post(claim_complete))
            .route("/token/info", get(token_info))
        .route("/token/request", post(token_request_transfer))
        .route("/token/prepare", post(token_prepare_ata))
        .route("/token/scan", post(token_scan_transfers))
        .route("/token/execute", post(token_execute_transfer))
        .route("/token/claim/complete", post(token_claim_complete))
        .with_state(state.clone());

    // Background cleanup task - every 5 minutes
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            info!("Running auto cleanup...");
            let expired = cleanup_state.db.get_expired_requests().unwrap_or_default();
            let mut cleaned = 0;
            for req in expired {
                cleanup_state.db.mark_expired(&req.request_id).ok();
                cleaned += 1;
            }
            let deleted = cleanup_state.db.cleanup_old_requests().unwrap_or(0);
            if cleaned > 0 || deleted > 0 {
                info!("Cleanup done: {} marked expired, {} old records deleted", cleaned, deleted);
            }
        }
    });

    println!("\n🌐 Relay server started on port {}", port);
    println!("🧅 Tor hidden service active\n");

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
