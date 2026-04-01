//! KausaLayer Relay Server v2
//!
//! Features:
//! - Unique deposit address per request (secure)
//! - SQLite persistent storage
//! - Auto-cleanup expired requests
//! - API Key authentication for protected endpoints

use axum::{
    extract::{State, Query},
    http::{StatusCode, Request, HeaderMap},
    routing::{get, post},
    Json, Router,
    middleware::{self, Next},
    response::Response,
};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use base64::Engine;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::Signer,
    system_instruction,
    transaction::Transaction,
};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
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
const TX_FEE_LAMPORTS: u64 = 5_000;          // Per transaction
const TX_FEE_TOTAL: u64 = 15_000;            // 3 transactions for 3-hop
const MIN_AMOUNT_SOL: f64 = 0.001;
const EXPIRY_SECONDS: i64 = 1800;
const FEE_WALLET: &str = "Nd5yLUNpZwqQ9GzMt1TmbwBNfR5EYpjrNWuHbQh9SDP";

// Subscription constants
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const KAUSA_MINT: &str = "BWXSNRBKMviG68MqavyssnzDq4qSArcN7eNYjqEfpump";
const USDC_DECIMALS: u8 = 6;
const KAUSA_DECIMALS: u8 = 6;
const SUBSCRIPTION_USDC_AMOUNT: u64 = 20_000_000;  // $20 USDC
const SUBSCRIPTION_KAUSA_USD: f64 = 15.0;          // $15 worth of KAUSA
const PRICE_CACHE_SECONDS: u64 = 300;              // 5 minutes

// ============ STATE ============

use std::sync::RwLock;

/// Cached KAUSA price from DexScreener
#[derive(Debug, Clone)]
struct PriceCache {
    kausa_price_usd: f64,
    kausa_required: u64,      // Amount needed for $15
    last_updated: i64,
}

impl Default for PriceCache {
    fn default() -> Self {
        Self {
            kausa_price_usd: 0.0,
            kausa_required: 0,
            last_updated: 0,
        }
    }
}

// Rate limiter: tracks (request_count, window_start_timestamp)
struct RateLimiter {
    requests: HashMap<String, (u32, i64)>,
}

impl RateLimiter {
    fn new() -> Self {
        Self { requests: HashMap::new() }
    }

    fn check_and_increment(&mut self, key: &str, limit: u32, window_secs: i64) -> bool {
        let now = chrono::Utc::now().timestamp();
        
        if let Some((count, window_start)) = self.requests.get_mut(key) {
            if now - *window_start >= window_secs {
                // Reset window
                *count = 1;
                *window_start = now;
                true
            } else if *count < limit {
                *count += 1;
                true
            } else {
                false // Rate limited
            }
        } else {
            self.requests.insert(key.to_string(), (1, now));
            true
        }
    }

    fn cleanup_old_entries(&mut self, window_secs: i64) {
        let now = chrono::Utc::now().timestamp();
        self.requests.retain(|_, (_, start)| now - *start < window_secs * 2);
    }
}

struct RelayState {
    client: RpcClient,
    config: Config,
    db: RelayDatabase,
    fee_wallet: Pubkey,
    api_key: Option<String>,
    price_cache: RwLock<PriceCache>,
    rate_limiter: Mutex<RateLimiter>,
}

impl RelayState {
    fn new(rpc_url: &str) -> Self {
        let client = RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        );
        let db = RelayDatabase::new().expect("Failed to initialize database");
        let fee_wallet = Pubkey::from_str(FEE_WALLET).expect("Invalid fee wallet");
        let api_key = std::env::var("API_KEY").ok();

        info!("Relay initialized");
        info!("  Fee wallet: {}", fee_wallet);
        info!("  Fee percent: {}%", FEE_PERCENT);
        info!("  Expiry: {} minutes", EXPIRY_SECONDS / 60);
        info!("  API Key: {}", if api_key.is_some() { "configured" } else { "NOT SET (all endpoints public!)" });

        if let Ok((pending, completed, expired)) = db.get_stats() {
            info!("  DB stats - Pending: {}, Completed: {}, Expired: {}", pending, completed, expired);
        }

        Self { 
            client, 
            config: Config::default(), 
            db, 
            fee_wallet, 
            api_key,
            price_cache: RwLock::new(PriceCache::default()),
            rate_limiter: Mutex::new(RateLimiter::new()),
        }
    }

    /// Get cached KAUSA price
    fn get_kausa_price(&self) -> PriceCache {
        self.price_cache.read().unwrap().clone()
    }

    /// Update KAUSA price cache
    fn update_kausa_price(&self, price_usd: f64) {
        let required = if price_usd > 0.0 {
            ((SUBSCRIPTION_KAUSA_USD / price_usd) * 1_000_000.0) as u64  // 6 decimals
        } else {
            0
        };
        let mut cache = self.price_cache.write().unwrap();
        cache.kausa_price_usd = price_usd;
        cache.kausa_required = required;
        cache.last_updated = chrono::Utc::now().timestamp();
    }
}

// ============ API KEY MIDDLEWARE ============

// Whitelisted origins - our own apps don't need API key
const WHITELISTED_ORIGINS: &[&str] = &[
    "https://kausalayer.com",
    "https://www.kausalayer.com",
    "https://kausalayer.vercel.app",
    "http://localhost:3000",
    "http://localhost:5173",
];

async fn require_api_key(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Check if request is from whitelisted origin (our own apps)
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        if WHITELISTED_ORIGINS.iter().any(|&allowed| origin == allowed) {
            return Ok(next.run(request).await);
        }
    }

    // If no API key configured, allow all requests
    let expected_key = match &state.api_key {
        Some(key) => key,
        None => return Ok(next.run(request).await),
    };

    // Check Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let provided_key = &header[7..];
            // Check master key first (from env)
            if provided_key == expected_key {
                return Ok(next.run(request).await);
            }
            // Then check user-generated keys from database
            match state.db.validate_api_key(provided_key) {
                Ok(Some(_)) => {
                    // Rate limit: 120 requests per minute per API key
                    let mut limiter = state.rate_limiter.lock().await;
                    if !limiter.check_and_increment(provided_key, 120, 60) {
                        return Err((
                            StatusCode::TOO_MANY_REQUESTS,
                            Json(serde_json::json!({
                                "error": "Rate limit exceeded",
                                "message": "Too many requests. Limit: 120 requests per minute.",
                                "retry_after": 60
                            }))
                        ));
                    }
                    // Cleanup old entries periodically
                    if limiter.requests.len() > 1000 {
                        limiter.cleanup_old_entries(60);
                    }
                    Ok(next.run(request).await)
                },
                _ => Err((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "Invalid API key",
                        "message": "The provided API key is not valid"
                    }))
                ))
            }
        }
        Some(_) => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Invalid authorization format",
                "message": "Use 'Authorization: Bearer <your_api_key>'"
            }))
        )),
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "API key required",
                "message": "This endpoint requires authentication. Add 'Authorization: Bearer <your_api_key>' header."
            }))
        )),
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

#[derive(Debug, Deserialize)]
struct RetrySwapRequest {
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct RecoverRequest {
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct FailedSwapsRequest {
    owner_identifier: String,
}

#[derive(Debug, Serialize)]
struct FailedSwapInfo {
    request_id: String,
    amount_lamports: u64,
    destination: String,
    created_at: i64,
}

#[derive(Debug, Serialize)]
struct FailedSwapsResponse {
    swaps: Vec<FailedSwapInfo>,
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
}

#[derive(Debug, Serialize)]
struct InfoResponse {
    name: String,
    version: String,
    fee_percent: f64,
    min_amount: f64,
    expiry_minutes: i64,
    token_support: TokenSupportInfo,
}

#[derive(Debug, Serialize)]
struct TokenSupportInfo {
    enabled: bool,
    supported_programs: Vec<String>,
    sol_required_for_ata: f64,
    ata_rent: f64,
}

#[derive(Debug, Serialize)]
struct StatsResponse {
    pending_requests: usize,
    completed_requests: usize,
    expired_requests: usize,
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

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn info_handler() -> Json<InfoResponse> {
    Json(InfoResponse {
        name: "KausaLayer Relay".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        fee_percent: FEE_PERCENT,
        min_amount: MIN_AMOUNT_SOL,
        expiry_minutes: EXPIRY_SECONDS / 60,
        token_support: TokenSupportInfo {
            enabled: true,
            supported_programs: vec![
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),  // SPL Token
                "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb".to_string(),  // Token-2022
            ],
            sol_required_for_ata: 0.007,
            ata_rent: 0.00207,
        },
    })
}

async fn get_stats(State(state): State<Arc<RelayState>>) -> Json<StatsResponse> {
    let (pending, completed, expired) = state.db.get_stats().unwrap_or((0, 0, 0));
    Json(StatsResponse {
        pending_requests: pending,
        completed_requests: completed,
        expired_requests: expired,
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

    // Resolve alias if recipient is short (alias format: kl_xxx where xxx is 2-17 chars)
    // Full meta-address is much longer (~100+ chars)
    let recipient = if req.recipient.starts_with("kl_") && req.recipient.len() < 50 {
        // This looks like an alias, try to resolve it
        match state.db.resolve_alias(&req.recipient) {
            Ok(Some(resolved)) => {
                info!("Resolved alias {} -> {}...", req.recipient, &resolved[..30]);
                resolved
            },
            Ok(None) => {
                return Err((StatusCode::NOT_FOUND, format!("Alias '{}' not found", req.recipient)));
            },
            Err(e) => {
                return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Alias resolution error: {}", e)));
            }
        }
    } else {
        req.recipient.clone()
    };

    MetaAddress::decode(&recipient)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid recipient: {}", e)))?;

    if req.amount < MIN_AMOUNT_SOL {
        return Err((StatusCode::BAD_REQUEST, format!("Minimum amount is {} SOL", MIN_AMOUNT_SOL)));
    }
    let amount_lamports = sol_to_lamports(req.amount);

    // Check if recipient is a subscriber (fee waiver)
    let is_subscriber = state.db.is_subscribed(&recipient).unwrap_or(false);
    let fee_lamports = if is_subscriber {
        info!("Recipient {} is subscriber - fee waived in request", recipient);
        0
    } else {
        ((amount_lamports as f64) * FEE_PERCENT / 100.0) as u64
    };
    // Use TX_FEE_TOTAL for 3-hop transfer (3 transactions)
    let total_deposit = amount_lamports + fee_lamports + TX_FEE_TOTAL;
    let request_id = format!("req_{}", chrono::Utc::now().timestamp_millis());

    let (request, _keypair) = state.db.create_request(
        &request_id, amount_lamports, fee_lamports, &recipient, None, EXPIRY_SECONDS,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    // Generate 2 intermediate stealth keypairs for 3-hop privacy
    let hop1_keypair = solana_sdk::signature::Keypair::new();
    let hop2_keypair = solana_sdk::signature::Keypair::new();

    state.db.create_intermediate_hops(
        &request_id,
        &hop1_keypair.pubkey().to_string(),
        &hop1_keypair.to_bytes(),
        &hop2_keypair.pubkey().to_string(),
        &hop2_keypair.to_bytes(),
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create intermediate hops: {}", e)))?;

    info!("Created request {} with deposit address {} and 2 intermediate hops", request_id, request.deposit_address);
    let now = chrono::Utc::now().timestamp();

    Ok(Json(DepositInstructions {
        request_id,
        deposit_address: request.deposit_address,
        deposit_amount: lamports_to_sol(total_deposit),
        amount: req.amount,
        fee: lamports_to_sol(fee_lamports),
        tx_fee: lamports_to_sol(TX_FEE_TOTAL),
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

    // Use TX_FEE_TOTAL for 3-hop
    let required = request.amount_lamports + request.fee_lamports + TX_FEE_TOTAL;

    if current_balance < required {
        return Ok(Json(TransferResult {
            status: "pending".to_string(),
            signature: None,
            message: format!("Deposit not received. Required: {} SOL, Current: {} SOL",
                lamports_to_sol(required), lamports_to_sol(current_balance)),
        }));
    }

    info!("Deposit confirmed: {} SOL - Starting 3-hop transfer", lamports_to_sol(current_balance));

    // Get all keypairs
    let deposit_keypair = state.db.get_keypair(&req.request_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Keypair error: {}", e)))?;

    let hop1_keypair = state.db.get_hop_keypair(&req.request_id, 1)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Hop1 keypair error: {}", e)))?;

    let hop2_keypair = state.db.get_hop_keypair(&req.request_id, 2)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Hop2 keypair error: {}", e)))?;


    // Check if this is a swap request
    if request.recipient_meta.starts_with("swap:") {
        return execute_swap_transfer(&state, &req.request_id, &request, &deposit_keypair, &hop1_keypair, &hop2_keypair).await;
    }
    // Create final stealth address for receiver
    let meta = MetaAddress::decode(&request.recipient_meta)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid recipient: {}", e)))?;

    let stealth = create_stealth_address(&meta)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Stealth error: {}", e)))?;

    let stealth_pubkey = Pubkey::new_from_array(stealth.pubkey);

    // Calculate amounts for each hop
    // TX 1: deposit -> hop1 (amount + fee for remaining 2 TXs)
    // TX 2: hop1 -> hop2 (amount + fee for remaining 1 TX)
    // TX 3: hop2 -> final stealth (amount) + fee_wallet (protocol fee)
    let amount_for_hop1 = request.amount_lamports + request.fee_lamports + TX_FEE_LAMPORTS * 2;
    let amount_for_hop2 = request.amount_lamports + request.fee_lamports + TX_FEE_LAMPORTS;

    // ========== TX 1: Deposit -> Hop1 ==========
    info!("TX 1: Deposit -> Hop1 ({} SOL)", lamports_to_sol(amount_for_hop1));

    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Blockhash error: {}", e)))?;

    let tx1 = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&deposit_keypair.pubkey(), &hop1_keypair.pubkey(), amount_for_hop1)],
        Some(&deposit_keypair.pubkey()),
        &[&deposit_keypair],
        blockhash,
    );

    let sig1 = state.client.send_and_confirm_transaction(&tx1)
        .map_err(|e| {
            error!("TX 1 failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("TX 1 failed: {}", e))
        })?;

    info!("TX 1 success: {}", sig1);
    state.db.update_hop_tx_in(&req.request_id, 1, &sig1.to_string(), amount_for_hop1).ok();

    // ========== TX 2: Hop1 -> Hop2 ==========
    info!("TX 2: Hop1 -> Hop2 ({} SOL)", lamports_to_sol(amount_for_hop2));

    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Blockhash error: {}", e)))?;

    let tx2 = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&hop1_keypair.pubkey(), &hop2_keypair.pubkey(), amount_for_hop2)],
        Some(&hop1_keypair.pubkey()),
        &[&hop1_keypair],
        blockhash,
    );

    let sig2 = state.client.send_and_confirm_transaction(&tx2)
        .map_err(|e| {
            error!("TX 2 failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("TX 2 failed: {}", e))
        })?;

    info!("TX 2 success: {}", sig2);
    state.db.update_hop_tx_out(&req.request_id, 1, &sig2.to_string(), amount_for_hop2).ok();
    state.db.update_hop_tx_in(&req.request_id, 2, &sig2.to_string(), amount_for_hop2).ok();

    // ========== TX 3: Hop2 -> Final Stealth + Fee Wallet ==========
    
    // Check if recipient has active subscription (fee waiver)
    let is_subscriber = state.db.is_subscribed(&request.recipient_meta).unwrap_or(false);
    let actual_fee = if is_subscriber {
        info!("Subscriber detected - waiving platform fee");
        0
    } else {
        request.fee_lamports
    };
    
    // Subscriber gets full amount (fee_lamports added back to transfer)
    let actual_transfer_amount = if is_subscriber {
        request.amount_lamports + request.fee_lamports
    } else {
        request.amount_lamports
    };

    info!("TX 3: Hop2 -> Stealth ({} SOL) + Fee Wallet ({} SOL){}",
        lamports_to_sol(actual_transfer_amount), lamports_to_sol(actual_fee),
        if is_subscriber { " [SUBSCRIBER - FEE WAIVED]" } else { "" });

    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Blockhash error: {}", e)))?;

    let transfer_ix = system_instruction::transfer(&hop2_keypair.pubkey(), &stealth_pubkey, actual_transfer_amount);
    let memo_data = format!("SDP:{}", bs58::encode(&stealth.ephemeral_pubkey).into_string());
    let memo_ix = spl_memo::build_memo(memo_data.as_bytes(), &[&hop2_keypair.pubkey()]);

    // Build transaction - include fee only if not subscriber
    let tx3 = if actual_fee > 0 {
        let fee_ix = system_instruction::transfer(&hop2_keypair.pubkey(), &state.fee_wallet, actual_fee);
        Transaction::new_signed_with_payer(
            &[transfer_ix, fee_ix, memo_ix],
            Some(&hop2_keypair.pubkey()),
            &[&hop2_keypair],
            blockhash,
        )
    } else {
        // Subscriber: no fee instruction
        Transaction::new_signed_with_payer(
            &[transfer_ix, memo_ix],
            Some(&hop2_keypair.pubkey()),
            &[&hop2_keypair],
            blockhash,
        )
    };

    match state.client.send_and_confirm_transaction(&tx3) {
        Ok(signature) => {
            info!("TX 3 success: {} - 3-hop transfer complete!", signature);

            state.db.update_hop_tx_out(&req.request_id, 2, &signature.to_string(), request.amount_lamports).ok();
            state.db.mark_completed(&req.request_id, &signature.to_string())
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?;

            // Save untuk scan (only final stealth address matters for receiver)
            let stealth_addr_str = stealth_pubkey.to_string();
            let ephemeral_str = bs58::encode(&stealth.ephemeral_pubkey).into_string();
            state.db.save_completed_transfer(
                &request.recipient_meta,
                None, // owner_identifier
                &stealth_addr_str,
                &ephemeral_str,
                request.amount_lamports,
                &signature.to_string(),
            ).ok();

            Ok(Json(TransferResult {
                status: "success".to_string(),
                signature: Some(signature.to_string()),
                message: format!("{} SOL sent privately via 3-hop transfer", lamports_to_sol(request.amount_lamports)),
            }))
        }
        Err(e) => {
            error!("TX 3 failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("TX 3 failed: {}", e)))
        }
    }
}


// Execute swap transfer - handles Jupiter swap after 3-hop privacy transfer
async fn execute_swap_transfer(
    state: &Arc<RelayState>,
    request_id: &str,
    request: &kausalayer::relay::DepositRequest,
    deposit_keypair: &solana_sdk::signature::Keypair,
    hop1_keypair: &solana_sdk::signature::Keypair,
    hop2_keypair: &solana_sdk::signature::Keypair,
) -> Result<Json<TransferResult>, (StatusCode, String)> {
    // Parse swap data from recipient_meta: "swap:{token_mint}:{destination}"
    let parts: Vec<&str> = request.recipient_meta.split(':').collect();
    if parts.len() != 3 {
        return Err((StatusCode::BAD_REQUEST, "Invalid swap format".to_string()));
    }
    let token_mint = parts[1];
    let destination = parts[2];
    
    info!("Executing SWAP: {} lamports -> {} to {}", request.amount_lamports, token_mint, destination);
    
    // Calculate amounts for hops (same as regular transfer)
    let amount_for_hop1 = request.amount_lamports + request.fee_lamports + TX_FEE_LAMPORTS * 2;
    let amount_for_hop2 = request.amount_lamports + request.fee_lamports + TX_FEE_LAMPORTS;
    
    // ========== TX 1: Deposit -> Hop1 ==========
    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Blockhash error: {}", e)))?;
    
    let tx1 = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&deposit_keypair.pubkey(), &hop1_keypair.pubkey(), amount_for_hop1)],
        Some(&deposit_keypair.pubkey()),
        &[deposit_keypair],
        blockhash,
    );
    
    let sig1 = state.client.send_and_confirm_transaction(&tx1)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("TX 1 failed: {}", e)))?;
    info!("Swap TX 1 success: {}", sig1);
    
    // ========== TX 2: Hop1 -> Hop2 ==========
    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Blockhash error: {}", e)))?;
    
    let tx2 = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&hop1_keypair.pubkey(), &hop2_keypair.pubkey(), amount_for_hop2)],
        Some(&hop1_keypair.pubkey()),
        &[hop1_keypair],
        blockhash,
    );
    
    let sig2 = state.client.send_and_confirm_transaction(&tx2)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("TX 2 failed: {}", e)))?;
    info!("Swap TX 2 success: {}", sig2);
    
    
    // ========== Execute Jupiter Swap from Hop2 ==========
    // Get actual balance in hop2 after fee transfer
    let hop2_balance = state.client.get_balance(&hop2_keypair.pubkey())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Balance check failed: {}", e)))?;
    // Reserve fee (0.5%) + 0.003 SOL for gas fees
    let swap_amount = hop2_balance.saturating_sub(request.fee_lamports + 10_000_000); // Reserve 10k lamports for tx fee
    let destination_pubkey = Pubkey::from_str(destination)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid destination: {}", e)))?;
    match execute_jupiter_swap(state, hop2_keypair, swap_amount, token_mint, &destination_pubkey).await {
        Ok(swap_sig) => {
            info!("Jupiter swap success: {}", swap_sig);

            // TX 5: Transfer protocol fee to fee wallet
            let blockhash = state.client.get_latest_blockhash()
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Blockhash error: {}", e)))?;
            let fee_ix = system_instruction::transfer(&hop2_keypair.pubkey(), &state.fee_wallet, request.fee_lamports);
            let tx5 = Transaction::new_signed_with_payer(
                &[fee_ix],
                Some(&hop2_keypair.pubkey()),
                &[hop2_keypair],
                blockhash,
            );
            state.client.send_and_confirm_transaction(&tx5)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Fee transfer failed: {}", e)))?;
            info!("TX 5 success: fee sent to fee wallet");

            // TX 6: Transfer remaining SOL to destination
            let remaining_sol = state.client.get_balance(&hop2_keypair.pubkey()).unwrap_or(0);
            if remaining_sol > 900_000 {
                let blockhash = state.client.get_latest_blockhash().unwrap();
                let sol_ix = system_instruction::transfer(&hop2_keypair.pubkey(), &destination_pubkey, remaining_sol - 900_000);
                let tx6 = Transaction::new_signed_with_payer(
                    &[sol_ix],
                    Some(&hop2_keypair.pubkey()),
                    &[hop2_keypair],
                    blockhash,
                );
                if let Ok(_) = state.client.send_and_confirm_transaction(&tx6) {
                    info!("TX 6 success: remaining {} SOL sent to destination", lamports_to_sol(remaining_sol - 900_000));
                }
            }
            state.db.mark_completed(request_id, &swap_sig.to_string()).ok();

            Ok(Json(TransferResult {
                status: "success".to_string(),
                signature: Some(swap_sig.to_string()),
                message: format!("Swapped {} SOL to tokens - sent to {}",
                    lamports_to_sol(swap_amount), destination),
            }))
        }
        Err(e) => {
            // Mark as swap_failed so user can retry or recover
            state.db.mark_swap_failed(request_id).ok();
            error!("Jupiter swap failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Swap failed: {}", e)))
        }
    }
}

// ============ RETRY SWAP ============
async fn retry_swap(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<RetrySwapRequest>,
) -> Result<Json<TransferResult>, (StatusCode, String)> {
    info!("Retry swap request: {}", req.request_id);

    // Get request from DB
    let request = state.db.get_request(&req.request_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?
        .ok_or((StatusCode::NOT_FOUND, "Request not found".to_string()))?;

    // Check status is swap_failed
    if request.status != kausalayer::relay::RequestStatus::SwapFailed {
        return Err((StatusCode::BAD_REQUEST, 
            format!("Request status is '{}', must be 'swap_failed' to retry", request.status.as_str())));
    }

    // Parse swap data from recipient_meta: "swap:{token_mint}:{destination}"
    let parts: Vec<&str> = request.recipient_meta.split(':').collect();
    if parts.len() != 3 {
        return Err((StatusCode::BAD_REQUEST, "Invalid swap format in request".to_string()));
    }
    let token_mint = parts[1];
    let destination = parts[2];

    // Get hop2 keypair
    let hop2_keypair = state.db.get_hop_keypair(&req.request_id, 2)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Keypair error: {}", e)))?;

    // Check hop2 balance
    let hop2_balance = state.client.get_balance(&hop2_keypair.pubkey())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Balance check failed: {}", e)))?;

    if hop2_balance < 10_000_000 {
        return Err((StatusCode::BAD_REQUEST, 
            format!("Insufficient balance in hop2: {} lamports", hop2_balance)));
    }

    // Calculate swap amount (reserve for fees)
    let swap_amount = hop2_balance.saturating_sub(request.fee_lamports + 10_000_000);
    let destination_pubkey = Pubkey::from_str(destination)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid destination: {}", e)))?;

    info!("Retrying swap: {} lamports -> {} to {}", swap_amount, token_mint, destination);

    // Execute Jupiter swap
    match execute_jupiter_swap(&state, &hop2_keypair, swap_amount, token_mint, &destination_pubkey).await {
        Ok(swap_sig) => {
            info!("Retry swap success: {}", swap_sig);

            // Transfer fee to fee wallet
            let blockhash = state.client.get_latest_blockhash()
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Blockhash error: {}", e)))?;
            let fee_ix = system_instruction::transfer(&hop2_keypair.pubkey(), &state.fee_wallet, request.fee_lamports);
            let fee_tx = Transaction::new_signed_with_payer(
                &[fee_ix],
                Some(&hop2_keypair.pubkey()),
                &[&hop2_keypair],
                blockhash,
            );
            state.client.send_and_confirm_transaction(&fee_tx).ok();

            // Transfer remaining SOL to destination
            let remaining_sol = state.client.get_balance(&hop2_keypair.pubkey()).unwrap_or(0);
            if remaining_sol > 900_000 {
                let blockhash = state.client.get_latest_blockhash().unwrap();
                let sol_ix = system_instruction::transfer(&hop2_keypair.pubkey(), &destination_pubkey, remaining_sol - 900_000);
                let sol_tx = Transaction::new_signed_with_payer(
                    &[sol_ix],
                    Some(&hop2_keypair.pubkey()),
                    &[&hop2_keypair],
                    blockhash,
                );
                state.client.send_and_confirm_transaction(&sol_tx).ok();
            }

            // Mark as completed
            state.db.mark_completed(&req.request_id, &swap_sig).ok();

            Ok(Json(TransferResult {
                status: "success".to_string(),
                signature: Some(swap_sig.clone()),
                message: format!("Retry swap successful: {}", swap_sig),
            }))
        }
        Err(e) => {
            error!("Retry swap failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Retry swap failed: {}", e)))
        }
    }
}

// ============ RECOVER FUNDS ============
async fn recover_funds(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<RecoverRequest>,
) -> Result<Json<TransferResult>, (StatusCode, String)> {
    info!("Recover funds request: {}", req.request_id);


    // Get request from DB
    let request = state.db.get_request(&req.request_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?
        .ok_or((StatusCode::NOT_FOUND, "Request not found".to_string()))?;

    // Check status is swap_failed
    if request.status != kausalayer::relay::RequestStatus::SwapFailed {
        return Err((StatusCode::BAD_REQUEST, 
            format!("Request status is '{}', must be 'swap_failed' to recover", request.status.as_str())));
    }

    // Parse destination from recipient_meta: "swap:{token_mint}:{destination}"
    let parts: Vec<&str> = request.recipient_meta.split(':').collect();
    if parts.len() != 3 {
        return Err((StatusCode::BAD_REQUEST, "Invalid swap format in request".to_string()));
    }
    let destination = parts[2];
    let recover_pubkey = Pubkey::from_str(destination)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid destination: {}", e)))?;

    // Get hop2 keypair
    let hop2_keypair = state.db.get_hop_keypair(&req.request_id, 2)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Keypair error: {}", e)))?;

    // Check hop2 balance
    let hop2_balance = state.client.get_balance(&hop2_keypair.pubkey())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Balance check failed: {}", e)))?;

    if hop2_balance < 10_000 {
        return Err((StatusCode::BAD_REQUEST, 
            format!("No funds to recover in hop2: {} lamports", hop2_balance)));
    }

    info!("Recovering {} lamports from hop2 to {}", hop2_balance, destination);

    // Transfer all SOL to recover wallet (minus tx fee)
    let transfer_amount = hop2_balance.saturating_sub(5000);
    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Blockhash error: {}", e)))?;

    let transfer_ix = system_instruction::transfer(&hop2_keypair.pubkey(), &recover_pubkey, transfer_amount);
    let tx = Transaction::new_signed_with_payer(
        &[transfer_ix],
        Some(&hop2_keypair.pubkey()),
        &[&hop2_keypair],
        blockhash,
    );

    let sig = state.client.send_and_confirm_transaction(&tx)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Transfer failed: {}", e)))?;

    info!("Recovery successful: {} - {} SOL sent to {}", sig, lamports_to_sol(transfer_amount), destination);

    // Mark as completed (recovered)
    state.db.mark_completed(&req.request_id, &sig.to_string()).ok();

    Ok(Json(TransferResult {
        status: "success".to_string(),
        signature: Some(sig.to_string()),
        message: format!("Recovered {} SOL to {}", lamports_to_sol(transfer_amount), destination),
    }))
}

// ============ GET FAILED SWAPS ============
async fn get_failed_swaps(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<FailedSwapsRequest>,
) -> Result<Json<FailedSwapsResponse>, (StatusCode, String)> {
    info!("Get failed swaps request for owner: {}...", &req.owner_identifier[..16.min(req.owner_identifier.len())]);

    let requests = state.db.get_failed_swaps_by_owner(&req.owner_identifier)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?;

    let swaps: Vec<FailedSwapInfo> = requests
        .into_iter()
        .filter_map(|r| {
            // Parse destination from recipient_meta: "swap:{token_mint}:{destination}"
            let parts: Vec<&str> = r.recipient_meta.split(':').collect();
            if parts.len() == 3 {
                Some(FailedSwapInfo {
                    request_id: r.request_id,
                    amount_lamports: r.amount_lamports,
                    destination: parts[2].to_string(),
                    created_at: r.created_at,
                })
            } else {
                None
            }
        })
        .collect();

    info!("Found {} failed swaps", swaps.len());
    Ok(Json(FailedSwapsResponse { swaps }))
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
    let db_transfers = state.db.get_transfers_for_recipient(&recipient_meta, None)
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
        None, // owner_identifier
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
    let db_transfers = state.db.get_token_transfers_for_recipient(&recipient_meta, None)
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
                None, // owner_identifier
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

// ============ SUBSCRIPTION HANDLERS ============

#[derive(Deserialize)]
struct SubscribeRequest {
    meta_address: String,
    payment_tx_hash: String,
    payment_type: String,  // "USDC" or "KAUSA"
}

#[derive(Serialize)]
struct SubscribeResponse {
    success: bool,
    message: String,
    expires_at: Option<i64>,
}

async fn subscribe_verify(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<SubscribeRequest>,
) -> Result<Json<SubscribeResponse>, (StatusCode, String)> {
    use solana_sdk::signature::Signature;
    use solana_transaction_status::UiTransactionEncoding;
    use std::str::FromStr;

    // Validate payment type
    if req.payment_type != "USDC" && req.payment_type != "KAUSA" {
        return Err((StatusCode::BAD_REQUEST, "Invalid payment type. Use USDC or KAUSA".to_string()));
    }

    // Check if tx already used
    if state.db.is_payment_tx_used(&req.payment_tx_hash).unwrap_or(false) {
        return Err((StatusCode::BAD_REQUEST, "Payment transaction already used".to_string()));
    }

    // Parse signature
    let signature = Signature::from_str(&req.payment_tx_hash)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid transaction signature".to_string()))?;

    // Fetch transaction from chain
    let tx = state.client
        .get_transaction(&signature, UiTransactionEncoding::Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Transaction not found or not confirmed: {}", e)))?;

    // Check if transaction was successful
    if let Some(meta) = &tx.transaction.meta {
        if meta.err.is_some() {
            return Err((StatusCode::BAD_REQUEST, "Transaction failed on-chain".to_string()));
        }
    }

    // Determine required amount based on payment type
    let (required_mint, required_amount): (&str, u64) = if req.payment_type == "USDC" {
        (USDC_MINT, SUBSCRIPTION_USDC_AMOUNT)
    } else {
        // KAUSA - get required amount from price cache
        let cache = state.get_kausa_price();
        if cache.kausa_required == 0 {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "KAUSA price not available. Try again later.".to_string()));
        }
        (KAUSA_MINT, cache.kausa_required)
    };

    // Parse transaction to verify token transfer
    // For SPL Token transfers, we need to check the inner instructions
    // The transaction should contain a transfer to fee_wallet's ATA
    
    let fee_wallet_str = FEE_WALLET;
    let mut verified_amount: u64 = 0;
    let mut payment_verified = false;

    // Get transaction message for account keys
    // Check pre/post token balances for the transfer
    if let Some(meta) = &tx.transaction.meta {
        use solana_transaction_status::option_serializer::OptionSerializer;
        
        let pre_balances: Vec<_> = match &meta.pre_token_balances {
            OptionSerializer::Some(b) => b.clone(),
            _ => vec![],
        };
        let post_balances: Vec<_> = match &meta.post_token_balances {
            OptionSerializer::Some(b) => b.clone(),
            _ => vec![],
        };

        // Find fee_wallet's token account balance change
        for post in post_balances.iter() {
            let owner_str: String = match &post.owner {
                OptionSerializer::Some(o) => o.clone(),
                _ => continue,
            };
            
            // Check if owner is our fee_wallet and mint matches
            if owner_str == fee_wallet_str && post.mint == required_mint {
                let post_amount = post.ui_token_amount.amount.parse::<u64>().unwrap_or(0);
                
                // Find corresponding pre-balance
                let pre_amount = pre_balances.iter()
                    .find(|pre| {
                        let pre_owner: String = match &pre.owner {
                            OptionSerializer::Some(o) => o.clone(),
                            _ => return false,
                        };
                        pre_owner == fee_wallet_str && pre.mint == required_mint
                    })
                    .map(|pre| pre.ui_token_amount.amount.parse::<u64>().unwrap_or(0))
                    .unwrap_or(0);

                verified_amount = post_amount.saturating_sub(pre_amount);
                
                if verified_amount >= required_amount {
                    payment_verified = true;
                }
                break;
            }
        }
    }

    if !payment_verified {
        return Err((StatusCode::BAD_REQUEST, format!(
            "Payment verification failed. Required: {} tokens to fee wallet {}. Found: {} tokens.",
            required_amount as f64 / 1_000_000.0,
            fee_wallet_str,
            verified_amount as f64 / 1_000_000.0
        )));
    }

    // Create subscription (30 days)
    match state.db.create_subscription(
        &req.meta_address,
        &req.payment_tx_hash,
        &req.payment_type,
        verified_amount,
        30, // 30 days
    ) {
        Ok(sub) => {
            info!("Subscription created: {} paid {} {} (tx: {})", 
                &req.meta_address[..20], 
                verified_amount as f64 / 1_000_000.0,
                req.payment_type,
                &req.payment_tx_hash[..16]);
            Ok(Json(SubscribeResponse {
                success: true,
                message: format!("Subscription activated! {} {} received.", 
                    verified_amount as f64 / 1_000_000.0, 
                    req.payment_type),
                expires_at: Some(sub.expires_at),
            }))
        },
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create subscription: {}", e))),
    }
}

#[derive(Deserialize)]
struct CheckSubscriptionRequest {
    meta_address: String,
}

#[derive(Serialize)]
struct CheckSubscriptionResponse {
    is_subscribed: bool,
    expires_at: Option<i64>,
    payment_type: Option<String>,
}

async fn check_subscription(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<CheckSubscriptionRequest>,
) -> Json<CheckSubscriptionResponse> {
    match state.db.get_subscription(&req.meta_address) {
        Ok(Some(sub)) => Json(CheckSubscriptionResponse {
            is_subscribed: true,
            expires_at: Some(sub.expires_at),
            payment_type: Some(sub.payment_type),
        }),
        _ => Json(CheckSubscriptionResponse {
            is_subscribed: false,
            expires_at: None,
            payment_type: None,
        }),
    }
}

// ============ ALIAS HANDLERS ============

#[derive(Deserialize)]
struct RegisterAliasRequest {
    alias: String,
    meta_address: String,
    owner_meta_address: String,
}

#[derive(Serialize)]
struct AliasResponse {
    success: bool,
    alias: Option<String>,
    message: String,
}

async fn register_alias(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<RegisterAliasRequest>,
) -> Result<Json<AliasResponse>, (StatusCode, String)> {
    // Check if owner is subscribed
    if !state.db.is_subscribed(&req.owner_meta_address).unwrap_or(false) {
        return Err((StatusCode::FORBIDDEN, "Active subscription required to register alias".to_string()));
    }

    // Check alias availability
    if !state.db.is_alias_available(&req.alias).unwrap_or(false) {
        return Err((StatusCode::CONFLICT, "Alias already taken".to_string()));
    }

    // Create alias
    match state.db.create_alias(&req.alias, &req.meta_address, &req.owner_meta_address) {
        Ok(alias) => Ok(Json(AliasResponse {
            success: true,
            alias: Some(alias.alias),
            message: "Alias registered successfully".to_string(),
        })),
        Err(e) => Err((StatusCode::BAD_REQUEST, e)),
    }
}

#[derive(Deserialize)]
struct ResolveAliasQuery {
    alias: String,
}

#[derive(Serialize)]
struct ResolveAliasResponse {
    found: bool,
    alias: String,
    meta_address: Option<String>,
}

async fn resolve_alias(
    State(state): State<Arc<RelayState>>,
    Query(query): Query<ResolveAliasQuery>,
) -> Json<ResolveAliasResponse> {
    match state.db.resolve_alias(&query.alias) {
        Ok(Some(meta)) => Json(ResolveAliasResponse {
            found: true,
            alias: query.alias,
            meta_address: Some(meta),
        }),
        _ => Json(ResolveAliasResponse {
            found: false,
            alias: query.alias,
            meta_address: None,
        }),
    }
}

#[derive(Serialize)]
struct CheckAliasResponse {
    alias: String,
    available: bool,
}

async fn check_alias_available(
    State(state): State<Arc<RelayState>>,
    Query(query): Query<ResolveAliasQuery>,
) -> Json<CheckAliasResponse> {
    let available = state.db.is_alias_available(&query.alias).unwrap_or(true);
    Json(CheckAliasResponse {
        alias: query.alias,
        available,
    })
}

#[derive(Deserialize)]
struct ListAliasesQuery {
    meta_address: String,
}

#[derive(Serialize)]
struct AliasInfo {
    alias: String,
    created_at: i64,
}

#[derive(Serialize)]
struct ListAliasesResponse {
    aliases: Vec<AliasInfo>,
}

async fn list_aliases(
    State(state): State<Arc<RelayState>>,
    Query(query): Query<ListAliasesQuery>,
) -> Json<ListAliasesResponse> {
    let aliases = state.db.list_aliases(&query.meta_address).unwrap_or_default();
    Json(ListAliasesResponse {
        aliases: aliases.into_iter().map(|(alias, created_at)| AliasInfo {
            alias,
            created_at,
        }).collect(),
    })
}

// ============ API KEY HANDLERS ============

#[derive(Deserialize)]
struct GenerateApiKeyRequest {
    meta_address: String,
    name: String,
}

#[derive(Serialize)]
struct ApiKeyResponse {
    success: bool,
    api_key: Option<String>,
    key_prefix: Option<String>,
    message: String,
}

async fn generate_api_key(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<GenerateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, (StatusCode, String)> {
    // Check if user is subscribed
    if !state.db.is_subscribed(&req.meta_address).unwrap_or(false) {
        return Err((StatusCode::FORBIDDEN, "Active subscription required to generate API key".to_string()));
    }

    // Generate API key
    match state.db.create_api_key(&req.meta_address, &req.name) {
        Ok((full_key, record)) => Ok(Json(ApiKeyResponse {
            success: true,
            api_key: Some(full_key),
            key_prefix: Some(record.key_prefix),
            message: "API key generated. Save it now - it won't be shown again!".to_string(),
        })),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate API key: {}", e))),
    }
}

#[derive(Deserialize)]
struct RevokeApiKeyRequest {
    api_key: String,
}

async fn revoke_api_key(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<RevokeApiKeyRequest>,
) -> Json<serde_json::Value> {
    let revoked = state.db.revoke_api_key(&req.api_key).unwrap_or(false);
    Json(serde_json::json!({
        "success": revoked,
        "message": if revoked { "API key revoked" } else { "API key not found" }
    }))
}

// ============ DESTINATION WALLETS ============

#[derive(Debug, Deserialize)]
struct AddDestinationRequest {
    meta_address: String,
    slot: u8,
    wallet_address: String,
}

#[derive(Debug, Deserialize)]
struct DeleteDestinationRequest {
    meta_address: String,
    slot: u8,
}

#[derive(Debug, Deserialize)]
struct ListDestinationRequest {
    meta_address: String,
}

#[derive(Debug, Serialize)]
struct DestinationWallet {
    slot: u8,
    wallet_address: String,
}


// ============ DIVERSIFICATION STRUCTS ============

#[derive(Debug, Deserialize)]
struct DiversifyRouteInput {
    slot: u8,
    value: f64,  // percentage or fixed amount depending on mode
}

#[derive(Debug, Deserialize)]
struct DiversifyRequest {
    meta_address: String,
    total_amount: f64,  // in SOL
    distribution_mode: String,  // "equal", "percentage", "fixed"
    routes: Vec<DiversifyRouteInput>,
}

#[derive(Debug, Serialize)]
struct DiversifyRouteOutput {
    slot: u8,
    wallet: String,
    amount: f64,
    percentage: Option<f64>,
}

#[derive(Debug, Serialize)]
struct DiversifyResponse {
    success: bool,
    request_id: Option<String>,
    deposit_address: Option<String>,
    deposit_amount: Option<f64>,
    total_amount: Option<f64>,
    fee: Option<f64>,
    network_fee: Option<f64>,
    routes: Option<Vec<DiversifyRouteOutput>>,
    expires_in: Option<i64>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiversifyStatusRequest {
    request_id: String,
}

#[derive(Debug, Serialize)]
struct DiversifyRouteStatus {
    slot: u8,
    status: String,
    amount: f64,
    signature: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct DiversifyStatusResponse {
    request_id: String,
    status: String,
    is_funded: bool,
    deposit_received: Option<f64>,
    deposit_required: Option<f64>,
    routes_completed: Option<u8>,
    routes_total: Option<u8>,
    routes: Option<Vec<DiversifyRouteStatus>>,
    expires_at: Option<i64>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiversifyExecuteRequest {
    request_id: String,
}

// ============ DIVERSIFICATION HANDLERS ============

async fn diversify_request(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<DiversifyRequest>,
) -> Json<DiversifyResponse> {
    info!("Diversify request: {} SOL, mode: {}, routes: {}", 
          req.total_amount, req.distribution_mode, req.routes.len());

    // Validation: minimum 1 SOL
    if req.total_amount < 1.0 {
        return Json(DiversifyResponse {
            success: false,
            error: Some("Minimum deposit is 1 SOL".to_string()),
            ..Default::default()
        });
    }

    // Validation: max 5 destinations
    if req.routes.len() > 5 {
        return Json(DiversifyResponse {
            success: false,
            error: Some("Maximum 5 destinations allowed".to_string()),
            ..Default::default()
        });
    }

    // Validation: at least 2 destinations
    if req.routes.len() < 2 {
        return Json(DiversifyResponse {
            success: false,
            error: Some("Minimum 2 destinations required".to_string()),
            ..Default::default()
        });
    }

    // Hash meta address
    let mut hasher = Sha256::new();
    hasher.update(req.meta_address.as_bytes());
    let owner_hash = format!("{:x}", hasher.finalize());

    // Get destination wallets
    let wallets = match state.db.list_destination_wallets(&owner_hash) {
        Ok(w) => w,
        Err(e) => {
            return Json(DiversifyResponse {
                success: false,
                error: Some(format!("Failed to get wallets: {}", e)),
                ..Default::default()
            });
        }
    };

    let wallet_map: std::collections::HashMap<u8, String> = wallets.into_iter().collect();

    // Validate all slots exist
    for route in &req.routes {
        if !wallet_map.contains_key(&route.slot) {
            return Json(DiversifyResponse {
                success: false,
                error: Some(format!("Slot {} is empty. Please add wallet first.", route.slot)),
                ..Default::default()
            });
        }
    }

    // Calculate distribution
    let total_lamports = sol_to_lamports(req.total_amount);
    let mut route_amounts: Vec<(u8, String, u64, Option<f64>)> = Vec::new();

    match req.distribution_mode.as_str() {
        "equal" => {
            let amount_each = total_lamports / req.routes.len() as u64;
            for route in &req.routes {
                let wallet = wallet_map.get(&route.slot).unwrap().clone();
                let pct = 100.0 / req.routes.len() as f64;
                route_amounts.push((route.slot, wallet, amount_each, Some(pct)));
            }
        },
        "percentage" => {
            let total_pct: f64 = req.routes.iter().map(|r| r.value).sum();
            if (total_pct - 100.0).abs() > 0.01 {
                return Json(DiversifyResponse {
                    success: false,
                    error: Some(format!("Percentages must total 100% (got {}%)", total_pct)),
                    ..Default::default()
                });
            }
            for route in &req.routes {
                let wallet = wallet_map.get(&route.slot).unwrap().clone();
                let amount = ((total_lamports as f64) * (route.value / 100.0)) as u64;
                route_amounts.push((route.slot, wallet, amount, Some(route.value)));
            }
        },
        "fixed" => {
            let total_fixed: f64 = req.routes.iter().map(|r| r.value).sum();
            if (total_fixed - req.total_amount).abs() > 0.001 {
                return Json(DiversifyResponse {
                    success: false,
                    error: Some(format!("Fixed amounts must total {} SOL (got {} SOL)", 
                                       req.total_amount, total_fixed)),
                    ..Default::default()
                });
            }
            for route in &req.routes {
                let wallet = wallet_map.get(&route.slot).unwrap().clone();
                let amount = sol_to_lamports(route.value);
                route_amounts.push((route.slot, wallet, amount, None));
            }
        },
        _ => {
            return Json(DiversifyResponse {
                success: false,
                error: Some("Invalid distribution mode. Use: equal, percentage, or fixed".to_string()),
                ..Default::default()
            });
        }
    }

    // Check if subscriber (fee waiver)
    let is_subscriber = state.db.is_subscribed(&req.meta_address).unwrap_or(false);
    let fee_lamports = if is_subscriber {
        info!("Subscriber detected - fee waived");
        0
    } else {
        ((total_lamports as f64) * FEE_PERCENT / 100.0) as u64
    };

    // Network fee: 3 transactions per route (deposit->hop1, hop1->hop2, hop2->dest)
    // Network fee: 3 tx per route + rent buffer + safety buffer
    let network_fee = TX_FEE_LAMPORTS * 3 * route_amounts.len() as u64 + 1_500_000;
    let total_deposit = total_lamports + fee_lamports + network_fee;

    // Create request
    let request_id = format!("div_{}", chrono::Utc::now().timestamp_millis());
    
    let (div_request, _keypair) = match state.db.create_diversification_request(
        &request_id,
        &req.meta_address,
        total_lamports,
        fee_lamports,
        network_fee,
        &req.distribution_mode,
        EXPIRY_SECONDS,
    ) {
        Ok(r) => r,
        Err(e) => {
            return Json(DiversifyResponse {
                success: false,
                error: Some(format!("Failed to create request: {}", e)),
                ..Default::default()
            });
        }
    };

    // Add routes
    for (idx, (slot, wallet, amount, pct)) in route_amounts.iter().enumerate() {
        if let Err(e) = state.db.add_diversification_route(
            &request_id,
            idx as u8,
            *slot,
            wallet,
            *amount,
            *pct,
        ) {
            error!("Failed to add route: {}", e);
        }
    }

    let now = chrono::Utc::now().timestamp();
    let routes_output: Vec<DiversifyRouteOutput> = route_amounts.iter()
        .map(|(slot, wallet, amount, pct)| DiversifyRouteOutput {
            slot: *slot,
            wallet: wallet.clone(),
            amount: lamports_to_sol(*amount),
            percentage: *pct,
        })
        .collect();

    info!("Created diversification request {} with {} routes", request_id, routes_output.len());

    Json(DiversifyResponse {
        success: true,
        request_id: Some(request_id),
        deposit_address: Some(div_request.deposit_address),
        deposit_amount: Some(lamports_to_sol(total_deposit)),
        total_amount: Some(req.total_amount),
        fee: Some(lamports_to_sol(fee_lamports)),
        network_fee: Some(lamports_to_sol(network_fee)),
        routes: Some(routes_output),
        expires_in: Some(div_request.expires_at - now),
        error: None,
    })
}

impl Default for DiversifyResponse {
    fn default() -> Self {
        Self {
            success: false,
            request_id: None,
            deposit_address: None,
            deposit_amount: None,
            total_amount: None,
            fee: None,
            network_fee: None,
            routes: None,
            expires_in: None,
            error: None,
        }
    }
}

async fn diversify_status(
    State(state): State<Arc<RelayState>>,
    Query(req): Query<DiversifyStatusRequest>,
) -> Json<DiversifyStatusResponse> {
    let request = match state.db.get_diversification_request(&req.request_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Json(DiversifyStatusResponse {
                request_id: req.request_id,
                status: "not_found".to_string(),
                is_funded: false,
                deposit_received: None,
                deposit_required: None,
                routes_completed: None,
                routes_total: None,
                routes: None,
                expires_at: None,
                error: Some("Request not found".to_string()),
            });
        },
        Err(e) => {
            return Json(DiversifyStatusResponse {
                request_id: req.request_id,
                status: "error".to_string(),
                is_funded: false,
                deposit_received: None,
                deposit_required: None,
                routes_completed: None,
                routes_total: None,
                routes: None,
                expires_at: None,
                error: Some(format!("Database error: {}", e)),
            });
        }
    };

    // Check deposit balance
    let deposit_pubkey = match Pubkey::from_str(&request.deposit_address) {
        Ok(p) => p,
        Err(_) => {
            return Json(DiversifyStatusResponse {
                request_id: req.request_id,
                status: "error".to_string(),
                is_funded: false,
                deposit_received: None,
                deposit_required: None,
                routes_completed: None,
                routes_total: None,
                routes: None,
                expires_at: None,
                error: Some("Invalid deposit address".to_string()),
            });
        }
    };

    let balance = state.client.get_balance(&deposit_pubkey).unwrap_or(0);
    let required = request.total_amount + request.fee_amount + request.network_fee;
    let is_funded = balance >= required;

    // Get routes
    let routes = match state.db.get_diversification_routes(&req.request_id) {
        Ok(r) => r,
        Err(_) => vec![],
    };

    let routes_completed = routes.iter().filter(|r| r.status == "completed").count() as u8;
    let routes_total = routes.len() as u8;

    let route_statuses: Vec<DiversifyRouteStatus> = routes.iter()
        .map(|r| DiversifyRouteStatus {
            slot: r.destination_slot,
            status: r.status.clone(),
            amount: lamports_to_sol(r.amount),
            signature: r.tx3_signature.clone(),
            error: r.error_message.clone(),
        })
        .collect();

    Json(DiversifyStatusResponse {
        request_id: request.request_id,
        status: request.status,
        is_funded,
        deposit_received: Some(lamports_to_sol(balance)),
        deposit_required: Some(lamports_to_sol(required)),
        routes_completed: Some(routes_completed),
        routes_total: Some(routes_total),
        routes: Some(route_statuses),
        expires_at: Some(request.expires_at),
        error: None,
    })
}

async fn diversify_execute(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<DiversifyExecuteRequest>,
) -> Json<serde_json::Value> {
    info!("Execute diversification: {}", req.request_id);

    // Get request
    let request = match state.db.get_diversification_request(&req.request_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Json(serde_json::json!({
                "success": false,
                "error": "Request not found"
            }));
        },
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Database error: {}", e)
            }));
        }
    };

    // Check status
    if request.status != "pending" && request.status != "funded" {
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Request status is '{}', cannot execute", request.status)
        }));
    }

    // Get deposit keypair
    let deposit_keypair = match state.db.get_diversification_keypair(&req.request_id) {
        Ok(k) => k,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to get keypair: {}", e)
            }));
        }
    };

    // Check balance
    let balance = state.client.get_balance(&deposit_keypair.pubkey()).unwrap_or(0);
    let required = request.total_amount + request.fee_amount + request.network_fee;

    if balance < required {
        return Json(serde_json::json!({
            "success": false,
            "error": format!("Insufficient deposit: {} < {} SOL required", 
                           lamports_to_sol(balance), lamports_to_sol(required))
        }));
    }

    // Mark as funded if not already
    if request.status == "pending" {
        state.db.update_diversification_status(&req.request_id, "funded").ok();
    }

    // Get routes
    let routes = match state.db.get_diversification_routes(&req.request_id) {
        Ok(r) => r,
        Err(e) => {
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to get routes: {}", e)
            }));
        }
    };

    // Update status to processing
    state.db.update_diversification_status(&req.request_id, "processing").ok();

    // Deduct fee first (if any)
    if request.fee_amount > 0 {
        let blockhash = match state.client.get_latest_blockhash() {
            Ok(b) => b,
            Err(e) => {
                return Json(serde_json::json!({
                    "success": false,
                    "error": format!("Blockhash error: {}", e)
                }));
            }
        };

        let fee_ix = system_instruction::transfer(
            &deposit_keypair.pubkey(),
            &state.fee_wallet,
            request.fee_amount,
        );

        let fee_tx = Transaction::new_signed_with_payer(
            &[fee_ix],
            Some(&deposit_keypair.pubkey()),
            &[&deposit_keypair],
            blockhash,
        );

        if let Err(e) = state.client.send_and_confirm_transaction(&fee_tx) {
            error!("Fee transfer failed: {}", e);
            // Continue anyway, fee collection is best-effort
        } else {
            info!("Fee collected: {} SOL", lamports_to_sol(request.fee_amount));
        }
    }

    // Execute routes sequentially
    let mut completed = 0;
    let mut failed = 0;
    let total_routes = routes.len();

    for (route_idx, route) in routes.into_iter().enumerate() {
        let is_last_route = route_idx == total_routes - 1;
        
        info!("Executing route {} -> slot {} ({} SOL) [last={}]", 
              route.route_index, route.destination_slot, lamports_to_sol(route.amount), is_last_route);

        state.db.update_route_status(route.id, "processing").ok();

        // Generate hop keypairs
        let hop1 = solana_sdk::signature::Keypair::new();
        let hop2 = solana_sdk::signature::Keypair::new();

        // Save hop keypairs
        state.db.update_route_keypairs(
            route.id,
            &hop1.pubkey().to_string(),
            &hop1.to_bytes(),
            &hop2.pubkey().to_string(),
            &hop2.to_bytes(),
        ).ok();

        // Calculate amounts - last route takes remaining balance
        let (amount_for_hop1, actual_route_amount) = if is_last_route {
            // Get remaining balance from deposit address
            let deposit_balance = state.client.get_balance(&deposit_keypair.pubkey()).unwrap_or(0);
            // Reserve for TX1 fee only (TX2 and TX3 fees come from hop amounts)
            let available = deposit_balance.saturating_sub(TX_FEE_LAMPORTS);
            // amount_for_hop1 includes TX2 and TX3 fees
            let hop1_amount = available;
            // actual amount to destination = hop1 - 2*TX_FEE
            let dest_amount = hop1_amount.saturating_sub(TX_FEE_LAMPORTS * 2);
            info!("Last route: deposit_balance={}, available={}, dest_amount={}", 
                  deposit_balance, available, dest_amount);
            (hop1_amount, dest_amount)
        } else {
            (route.amount + TX_FEE_LAMPORTS * 2, route.amount)
        };
        let amount_for_hop2 = actual_route_amount + TX_FEE_LAMPORTS;

        // TX1: deposit -> hop1
        let blockhash = match state.client.get_latest_blockhash() {
            Ok(b) => b,
            Err(e) => {
                state.db.update_route_error(route.id, &format!("Blockhash error: {}", e)).ok();
                failed += 1;
                continue;
            }
        };

        let tx1_ix = system_instruction::transfer(
            &deposit_keypair.pubkey(),
            &hop1.pubkey(),
            amount_for_hop1,
        );

        let tx1 = Transaction::new_signed_with_payer(
            &[tx1_ix],
            Some(&deposit_keypair.pubkey()),
            &[&deposit_keypair],
            blockhash,
        );

        let tx1_sig = match state.client.send_and_confirm_transaction(&tx1) {
            Ok(s) => {
                state.db.update_route_tx(route.id, 1, &s.to_string()).ok();
                s
            },
            Err(e) => {
                state.db.update_route_error(route.id, &format!("TX1 failed: {}", e)).ok();
                failed += 1;
                continue;
            }
        };
        info!("TX1 success: {}", tx1_sig);

        // TX2: hop1 -> hop2
        let blockhash = match state.client.get_latest_blockhash() {
            Ok(b) => b,
            Err(e) => {
                state.db.update_route_error(route.id, &format!("Blockhash error: {}", e)).ok();
                failed += 1;
                continue;
            }
        };

        let tx2_ix = system_instruction::transfer(
            &hop1.pubkey(),
            &hop2.pubkey(),
            amount_for_hop2,
        );

        let tx2 = Transaction::new_signed_with_payer(
            &[tx2_ix],
            Some(&hop1.pubkey()),
            &[&hop1],
            blockhash,
        );

        let tx2_sig = match state.client.send_and_confirm_transaction(&tx2) {
            Ok(s) => {
                state.db.update_route_tx(route.id, 2, &s.to_string()).ok();
                s
            },
            Err(e) => {
                state.db.update_route_error(route.id, &format!("TX2 failed: {}", e)).ok();
                failed += 1;
                continue;
            }
        };
        info!("TX2 success: {}", tx2_sig);

        // TX3: hop2 -> destination
        let blockhash = match state.client.get_latest_blockhash() {
            Ok(b) => b,
            Err(e) => {
                state.db.update_route_error(route.id, &format!("Blockhash error: {}", e)).ok();
                failed += 1;
                continue;
            }
        };

        let dest_pubkey = match Pubkey::from_str(&route.destination_wallet) {
            Ok(p) => p,
            Err(e) => {
                state.db.update_route_error(route.id, &format!("Invalid destination: {}", e)).ok();
                failed += 1;
                continue;
            }
        };

        let tx3_ix = system_instruction::transfer(
            &hop2.pubkey(),
            &dest_pubkey,
            actual_route_amount,
        );

        let tx3 = Transaction::new_signed_with_payer(
            &[tx3_ix],
            Some(&hop2.pubkey()),
            &[&hop2],
            blockhash,
        );

        match state.client.send_and_confirm_transaction(&tx3) {
            Ok(s) => {
                state.db.update_route_tx(route.id, 3, &s.to_string()).ok();
                state.db.update_route_status(route.id, "completed").ok();
                info!("TX3 success: {} -> route {} complete", s, route.route_index);
                completed += 1;
            },
            Err(e) => {
                state.db.update_route_error(route.id, &format!("TX3 failed: {}", e)).ok();
                failed += 1;
            }
        };
    }

    // Update final status
    let final_status = if failed == 0 {
        "completed"
    } else if completed == 0 {
        "failed"
    } else {
        "partial"
    };

    state.db.update_diversification_status(&req.request_id, final_status).ok();

    Json(serde_json::json!({
        "success": failed == 0,
        "status": final_status,
        "routes_completed": completed,
        "routes_failed": failed,
        "message": format!("{}/{} routes completed", completed, completed + failed)
    }))
}
async fn add_destination_wallet(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<AddDestinationRequest>,
) -> Json<serde_json::Value> {
    // Hash meta address for privacy
    let mut hasher = Sha256::new();
    hasher.update(req.meta_address.as_bytes());
    let owner_hash = format!("{:x}", hasher.finalize());
    match state.db.add_destination_wallet(&owner_hash, req.slot, &req.wallet_address) {
        Ok(()) => Json(serde_json::json!({
            "success": true,
            "message": format!("Wallet {} saved to slot {}", req.wallet_address, req.slot)
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e
        }))
    }
}

async fn delete_destination_wallet(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<DeleteDestinationRequest>,
) -> Json<serde_json::Value> {
    let mut hasher = Sha256::new();
    hasher.update(req.meta_address.as_bytes());
    let owner_hash = format!("{:x}", hasher.finalize());
    match state.db.delete_destination_wallet(&owner_hash, req.slot) {
        Ok(deleted) => Json(serde_json::json!({
            "success": deleted,
            "message": if deleted { format!("Wallet slot {} removed", req.slot) } else { "Slot not found".to_string() }
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e
        }))
    }
}

async fn list_destination_wallets(
    State(state): State<Arc<RelayState>>,
    Query(req): Query<ListDestinationRequest>,
) -> Json<serde_json::Value> {
    let mut hasher = Sha256::new();
    hasher.update(req.meta_address.as_bytes());
    let owner_hash = format!("{:x}", hasher.finalize());
    match state.db.list_destination_wallets(&owner_hash) {
        Ok(wallets) => {
            let list: Vec<DestinationWallet> = wallets.into_iter()
                .map(|(slot, addr)| DestinationWallet { slot, wallet_address: addr })
                .collect();
            Json(serde_json::json!({
                "success": true,
                "wallets": list
            }))
        },
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e
        }))
    }
}


// ============ JUPITER SWAP ============

const SOL_MINT: &str = "So11111111111111111111111111111111111111112";

#[derive(Debug, Deserialize)]
struct SwapRequest {
    #[serde(default)]
    user_wallet: String,
    amount: f64,
    token_mint: String,
    destination: String,
}

#[derive(Debug, Serialize)]
struct SwapRequestResponse {
    success: bool,
    request_id: Option<String>,
    transaction: Option<String>,
    intermediate_address: Option<String>,
    estimated_output: Option<String>,
    fee: Option<f64>,
    deposit_amount: Option<f64>,
    expires_in: Option<i64>,
    message: Option<String>,
}

async fn request_swap(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<SwapRequest>,
) -> Json<SwapRequestResponse> {
    if req.amount < 0.01 {
        return Json(SwapRequestResponse {
            success: false, request_id: None, transaction: None,
            intermediate_address: None, estimated_output: None, fee: None, deposit_amount: None,
            expires_in: None, message: Some("Minimum swap is 0.01 SOL".into()),
        });
    }
    
    // Get Jupiter quote
    let amount_lamports = sol_to_lamports(req.amount);
    let quote = match get_jupiter_quote(amount_lamports, &req.token_mint).await {
        Ok(q) => q,
        Err(e) => return Json(SwapRequestResponse {
            success: false, request_id: None, transaction: None,
            intermediate_address: None, estimated_output: None, fee: None, deposit_amount: None,
            expires_in: None, message: Some(format!("Quote failed: {}", e)),
        }),
    };
    
    let fee_lamports = ((amount_lamports as f64) * FEE_PERCENT / 100.0) as u64;
    let total_deposit = amount_lamports + fee_lamports + TX_FEE_TOTAL;
    let request_id = format!("swap_{}", chrono::Utc::now().timestamp_millis());
    
    // Hash destination as owner_identifier for ownership validation
    let mut hasher = Sha256::new();
    hasher.update(req.destination.as_bytes());
    let owner_hash = format!("{:x}", hasher.finalize());
    
    let (request, _) = match state.db.create_request(
        &request_id, amount_lamports, fee_lamports,
        &format!("swap:{}:{}", req.token_mint, req.destination),
        Some(&owner_hash),
        EXPIRY_SECONDS,
    ) {
        Ok(r) => r,
        Err(e) => return Json(SwapRequestResponse {
            success: false, request_id: None, transaction: None,
            intermediate_address: None, estimated_output: None, fee: None, deposit_amount: None,
            expires_in: None, message: Some(format!("DB error: {}", e)),
        }),
    };

    // Generate 2 intermediate stealth keypairs for 3-hop privacy (same as regular transfer)
    let hop1_keypair = solana_sdk::signature::Keypair::new();
    let hop2_keypair = solana_sdk::signature::Keypair::new();
    if let Err(e) = state.db.create_intermediate_hops(
        &request_id,
        &hop1_keypair.pubkey().to_string(),
        &hop1_keypair.to_bytes(),
        &hop2_keypair.pubkey().to_string(),
        &hop2_keypair.to_bytes(),
    ) {
        return Json(SwapRequestResponse {
            success: false, request_id: None, transaction: None,
            intermediate_address: None, estimated_output: None, fee: None, deposit_amount: None,
            expires_in: None, message: Some(format!("Failed to create hops: {}", e)),
        });
    }
    
    info!("Swap request {}: {} SOL -> {} to {}", request_id, req.amount, req.token_mint, req.destination);
    
    Json(SwapRequestResponse {
        success: true,
        request_id: Some(request_id),
        transaction: None, // TODO: build unsigned tx
        intermediate_address: Some(request.deposit_address),
        estimated_output: Some(quote.out_amount),
        fee: Some(lamports_to_sol(fee_lamports)),
        deposit_amount: Some(lamports_to_sol(total_deposit)),
        expires_in: Some(EXPIRY_SECONDS),
        message: None,
    })
}

#[derive(Debug, Deserialize)]
struct JupiterQuoteResponse {
    #[serde(rename = "outAmount")]
    out_amount: String,
}

async fn get_jupiter_quote(amount_lamports: u64, output_mint: &str) -> Result<JupiterQuoteResponse, String> {
    let url = format!(
        "https://api.jup.ag/swap/v1/quote?inputMint={}&outputMint={}&amount={}&slippageBps=100",
        SOL_MINT, output_mint, amount_lamports
    );
    
    let client = reqwest::Client::new();
    let resp = client.get(&url)
        .header("x-api-key", std::env::var("JUPITER_API_KEY").unwrap_or_default())
        .send().await.map_err(|e| e.to_string())?;
    
    if !resp.status().is_success() {
        return Err(format!("Jupiter error: {}", resp.status()));
    }
    
    resp.json().await.map_err(|e| e.to_string())
}

// Execute Jupiter swap via Node.js script
async fn execute_jupiter_swap(
    _state: &Arc<RelayState>,
    signer_keypair: &solana_sdk::signature::Keypair,
    amount_lamports: u64,
    output_mint: &str,
    destination: &Pubkey,
) -> Result<String, String> {
    use std::process::Command;
    
    // Convert keypair to base58
    let privkey_bs58 = bs58::encode(signer_keypair.to_bytes()).into_string();
    
    info!("Calling Jupiter swap script: {} lamports -> {} to {}", 
        amount_lamports, output_mint, destination);
    
    let output = Command::new("node")
        .arg("/root/kausalayer/scripts/swap.js")
        .arg(&privkey_bs58)
        .arg(amount_lamports.to_string())
        .arg(output_mint)
        .arg(destination.to_string())
        .output()
        .map_err(|e| format!("Failed to run swap script: {}", e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Swap script failed: {}", stderr));
    }
    
    let signature = String::from_utf8_lossy(&output.stdout).trim().to_string();
    info!("Jupiter swap success: {}", signature);
    
    Ok(signature)
}

// Helper: get ATA address as string
fn get_ata_address_string(wallet: &Pubkey, mint_str: &str) -> String {
    let mint = Pubkey::from_str(mint_str).unwrap_or_default();
    let (ata, _) = Pubkey::find_program_address(
        &[
            wallet.as_ref(),
            spl_token::id().as_ref(),
            mint.as_ref(),
        ],
        &spl_associated_token_account::id(),
    );
    ata.to_string()
}
// ============ PRICE FETCH ============

/// Fetch KAUSA price from DexScreener
async fn fetch_kausa_price() -> Result<f64, String> {
    let url = format!(
        "https://api.dexscreener.com/latest/dex/tokens/{}",
        KAUSA_MINT
    );
    
    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;
    
    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("JSON parse error: {}", e))?;
    
    // DexScreener returns { pairs: [{ priceUsd: "0.001234" }, ...] }
    let price_str = json["pairs"]
        .get(0)
        .and_then(|p| p["priceUsd"].as_str())
        .ok_or("No price found")?;
    
    price_str.parse::<f64>().map_err(|e| format!("Price parse error: {}", e))
}

/// Background task to update KAUSA price every 5 minutes
async fn price_update_task(state: Arc<RelayState>) {
    loop {
        match fetch_kausa_price().await {
            Ok(price) => {
                state.update_kausa_price(price);
                let cache = state.get_kausa_price();
                info!("Price updated: KAUSA = ${:.6}, Required for sub: {} KAUSA", 
                    cache.kausa_price_usd, 
                    cache.kausa_required as f64 / 1_000_000.0);
            }
            Err(e) => {
                tracing::warn!("Failed to fetch KAUSA price: {}", e);
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(PRICE_CACHE_SECONDS)).await;
    }
}

// GET /subscribe/price - Get current subscription prices
#[derive(Serialize)]
struct SubscriptionPriceResponse {
    usdc_amount: f64,           // 20.0
    kausa_price_usd: f64,       // Current price
    kausa_amount: f64,          // Required KAUSA tokens
    kausa_value_usd: f64,       // 15.0
    last_updated: i64,
    cache_seconds: u64,
}

async fn get_subscription_price(
    State(state): State<Arc<RelayState>>,
) -> Json<SubscriptionPriceResponse> {
    let cache = state.get_kausa_price();
    Json(SubscriptionPriceResponse {
        usdc_amount: 20.0,
        kausa_price_usd: cache.kausa_price_usd,
        kausa_amount: cache.kausa_required as f64 / 1_000_000.0,
        kausa_value_usd: SUBSCRIPTION_KAUSA_USD,
        last_updated: cache.last_updated,
        cache_seconds: PRICE_CACHE_SECONDS,
    })
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

    // Public routes (no API key required)
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/info", get(info_handler))
        .route("/subscribe/price", get(get_subscription_price))
        .with_state(state.clone());

    // Spawn background task for price updates
    let price_state = state.clone();
    tokio::spawn(async move {
        price_update_task(price_state).await;
    });

    // Protected routes (API key required)
    let protected_routes = Router::new()
        .route("/stats", get(get_stats))
        .route("/balance", post(get_balance))
        .route("/transfer/request", post(request_transfer))
        .route("/transfer/status", post(check_status))
        .route("/transfer/execute", post(execute_transfer))
        .route("/transfer/retry", post(retry_swap))
        .route("/transfer/recover", post(recover_funds))
        .route("/transfer/failed", post(get_failed_swaps))
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
        // Subscription routes
        .route("/subscribe/verify", post(subscribe_verify))
        .route("/subscribe/check", post(check_subscription))
        // Alias routes
        .route("/alias/register", post(register_alias))
        .route("/alias/resolve", get(resolve_alias))
        .route("/alias/check", get(check_alias_available))
        .route("/alias/list", get(list_aliases))
        // API Key routes
        .route("/api-key/generate", post(generate_api_key))
        .route("/api-key/revoke", post(revoke_api_key))
        // Destination wallet routes
        .route("/wallet/destination/add", post(add_destination_wallet))
        .route("/wallet/destination/delete", post(delete_destination_wallet))
        .route("/wallet/destination/list", get(list_destination_wallets))
        // Diversification routes
        .route("/transfer/diversify/request", post(diversify_request))
        .route("/transfer/diversify/status", get(diversify_status))
        .route("/transfer/diversify/execute", post(diversify_execute))
        .route("/swap/request", post(request_swap))
        .layer(middleware::from_fn_with_state(state.clone(), require_api_key))
        .with_state(state.clone());

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes);

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
            let hops_deleted = cleanup_state.db.cleanup_old_hops().unwrap_or(0);
            if cleaned > 0 || deleted > 0 || hops_deleted > 0 {
                info!("Cleanup done: {} marked expired, {} old records deleted, {} old hops deleted", cleaned, deleted, hops_deleted);
            }
        }
    });

    println!("\n🌐 Relay server started on port {}", port);
    println!("🧅 Tor hidden service active");
    println!("🔐 API Key: {}\n", if state.api_key.is_some() { "ENABLED" } else { "DISABLED (public access)" });

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
