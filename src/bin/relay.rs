//! KausaLayer Relay Server
//! 
//! Provides anonymous transaction relay via Tor hidden service.
//! Users connect via .onion address, relay submits transactions
//! from a pool of wallets to hide the original sender.

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    signature::{Keypair, Signer},
    pubkey::Pubkey,
};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tokio::net::TcpListener;
use tracing::{info, warn, error};

use kausalayer::core::{
    MetaAddress, create_stealth_address, TransactionBuilder,
    lamports_to_sol, sol_to_lamports,
};
use kausalayer::Config;

/// Relay server state
struct RelayState {
    /// RPC client
    client: RpcClient,
    /// Config
    config: Config,
    /// Wallet pool (for rotating senders)
    wallet_pool: Vec<Keypair>,
    /// Current wallet index
    current_wallet: Mutex<usize>,
    /// Pending deposits: deposit_address -> (amount, recipient_meta, created_at)
    pending_deposits: Mutex<HashMap<String, PendingDeposit>>,
    /// Protocol fee percentage
    fee_percent: f64,
}

#[derive(Clone)]
struct PendingDeposit {
    amount_lamports: u64,
    recipient_meta: String,
    deposit_address: Pubkey,
    created_at: i64,
}

/// Request to create a relay transfer
#[derive(Debug, Deserialize)]
struct RelayRequest {
    /// Recipient meta-address (kl_xxx)
    recipient: String,
    /// Amount in SOL
    amount: f64,
}

/// Response with deposit instructions
#[derive(Debug, Serialize)]
struct DepositInstructions {
    /// Address to send SOL to
    deposit_address: String,
    /// Amount to deposit (including fees)
    deposit_amount: f64,
    /// Protocol fee
    fee: f64,
    /// Expiry time (unix timestamp)
    expires_at: i64,
    /// Unique request ID
    request_id: String,
}

/// Transfer status response
#[derive(Debug, Serialize)]
struct TransferStatus {
    status: String,
    signature: Option<String>,
    message: String,
}

/// Health check response
#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    wallets_available: usize,
    tor_enabled: bool,
}

impl RelayState {
    fn new(rpc_url: &str) -> Self {
        let client = RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        );
        
        // Generate wallet pool (in production, load from encrypted storage)
        let mut wallet_pool = Vec::new();
        for _ in 0..3 {
            wallet_pool.push(Keypair::new());
        }
        
        info!("Relay initialized with {} wallets", wallet_pool.len());
        for (i, kp) in wallet_pool.iter().enumerate() {
            info!("  Wallet {}: {}", i + 1, kp.pubkey());
        }
        
        Self {
            client,
            config: Config::default(),
            wallet_pool,
            current_wallet: Mutex::new(0),
            pending_deposits: Mutex::new(HashMap::new()),
            fee_percent: 0.5, // 0.5% relay fee
        }
    }
    
    fn get_next_wallet(&self) -> &Keypair {
        let mut idx = self.current_wallet.lock().unwrap();
        let wallet = &self.wallet_pool[*idx];
        *idx = (*idx + 1) % self.wallet_pool.len();
        wallet
    }
    
    fn get_total_balance(&self) -> u64 {
        self.wallet_pool.iter()
            .map(|kp| self.client.get_balance(&kp.pubkey()).unwrap_or(0))
            .sum()
    }
}

/// Health check endpoint
async fn health(State(state): State<Arc<RelayState>>) -> Json<HealthResponse> {
    let available = state.wallet_pool.iter()
        .filter(|kp| {
            state.client.get_balance(&kp.pubkey()).unwrap_or(0) > 10_000_000
        })
        .count();
    
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        wallets_available: available,
        tor_enabled: true,
    })
}

/// Get relay info
async fn info(State(state): State<Arc<RelayState>>) -> Json<serde_json::Value> {
    let total_balance = state.get_total_balance();
    
    Json(serde_json::json!({
        "name": "KausaLayer Relay",
        "version": env!("CARGO_PKG_VERSION"),
        "fee_percent": state.fee_percent,
        "min_amount": 0.01,
        "max_amount": lamports_to_sol(total_balance / 2), // Max 50% of pool
        "supported_tokens": ["SOL"],
    }))
}

/// Request a relay transfer
async fn request_transfer(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<RelayRequest>,
) -> Result<Json<DepositInstructions>, (StatusCode, String)> {
    // Validate recipient meta-address
    let _meta = MetaAddress::decode(&req.recipient)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid recipient: {}", e)))?;
    
    // Validate amount
    if req.amount < 0.01 {
        return Err((StatusCode::BAD_REQUEST, "Minimum amount is 0.01 SOL".to_string()));
    }
    
    let amount_lamports = sol_to_lamports(req.amount);
    let fee_lamports = (amount_lamports as f64 * state.fee_percent / 100.0) as u64;
    let total_deposit = amount_lamports + fee_lamports + 10_000; // +10k for tx fee
    
    // Generate unique deposit address (use one of pool wallets for simplicity)
    // In production, would generate unique address per request
    let deposit_wallet = state.get_next_wallet();
    let deposit_address = deposit_wallet.pubkey();
    
    // Create request ID
    let request_id = format!("req_{}", chrono::Utc::now().timestamp_millis());
    
    // Store pending deposit
    let pending = PendingDeposit {
        amount_lamports,
        recipient_meta: req.recipient.clone(),
        deposit_address,
        created_at: chrono::Utc::now().timestamp(),
    };
    
    {
        let mut deposits = state.pending_deposits.lock().unwrap();
        deposits.insert(request_id.clone(), pending);
    }
    
    let expires_at = chrono::Utc::now().timestamp() + 3600; // 1 hour
    
    Ok(Json(DepositInstructions {
        deposit_address: deposit_address.to_string(),
        deposit_amount: lamports_to_sol(total_deposit),
        fee: lamports_to_sol(fee_lamports),
        expires_at,
        request_id,
    }))
}

/// Execute a pending transfer (called after deposit confirmed)
async fn execute_transfer(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<TransferStatus>, (StatusCode, String)> {
    let request_id = req.get("request_id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Missing request_id".to_string()))?;
    
    // Get pending deposit
    let pending = {
        let deposits = state.pending_deposits.lock().unwrap();
        deposits.get(request_id).cloned()
    };
    
    let pending = pending.ok_or((StatusCode::NOT_FOUND, "Request not found".to_string()))?;
    
    // Check deposit received
    let deposit_balance = state.client.get_balance(&pending.deposit_address)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    if deposit_balance < pending.amount_lamports {
        return Ok(Json(TransferStatus {
            status: "pending".to_string(),
            signature: None,
            message: format!(
                "Waiting for deposit. Required: {} SOL, Current: {} SOL",
                lamports_to_sol(pending.amount_lamports),
                lamports_to_sol(deposit_balance)
            ),
        }));
    }
    
    // Parse recipient and create stealth address
    let meta = MetaAddress::decode(&pending.recipient_meta)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    
    let stealth = create_stealth_address(&meta)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Build and send transaction from relay wallet
    let relay_wallet = state.get_next_wallet();
    let builder = TransactionBuilder::new(state.config.clone());
    
    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let tx = builder.build_stealth_transfer(
        relay_wallet,
        &stealth,
        pending.amount_lamports,
        blockhash,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Send transaction
    match state.client.send_and_confirm_transaction(&tx) {
        Ok(sig) => {
            info!("Relay transfer successful: {}", sig);
            
            // Remove from pending
            {
                let mut deposits = state.pending_deposits.lock().unwrap();
                deposits.remove(request_id);
            }
            
            Ok(Json(TransferStatus {
                status: "success".to_string(),
                signature: Some(sig.to_string()),
                message: "Transfer completed successfully".to_string(),
            }))
        }
        Err(e) => {
            error!("Relay transfer failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// Direct relay (for testing - no deposit required)
async fn direct_relay(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<RelayRequest>,
) -> Result<Json<TransferStatus>, (StatusCode, String)> {
    info!("Direct relay request: {} SOL to {}", req.amount, req.recipient);
    
    // Parse recipient
    let meta = MetaAddress::decode(&req.recipient)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid recipient: {}", e)))?;
    
    // Create stealth address
    let stealth = create_stealth_address(&meta)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let stealth_pubkey = Pubkey::new_from_array(stealth.pubkey);
    info!("Stealth address: {}", stealth_pubkey);
    
    // Get relay wallet with sufficient balance
    let amount_lamports = sol_to_lamports(req.amount);
    let relay_wallet = state.wallet_pool.iter()
        .find(|kp| {
            state.client.get_balance(&kp.pubkey()).unwrap_or(0) > amount_lamports + 10_000
        })
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "No wallet with sufficient balance".to_string()))?;
    
    info!("Using relay wallet: {}", relay_wallet.pubkey());
    
    // Build transaction
    let builder = TransactionBuilder::new(state.config.clone());
    let blockhash = state.client.get_latest_blockhash()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let tx = builder.build_stealth_transfer(
        relay_wallet,
        &stealth,
        amount_lamports,
        blockhash,
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Send
    match state.client.send_and_confirm_transaction(&tx) {
        Ok(sig) => {
            info!("Direct relay successful: {}", sig);
            Ok(Json(TransferStatus {
                status: "success".to_string(),
                signature: Some(sig.to_string()),
                message: format!("Relayed {} SOL to stealth address", req.amount),
            }))
        }
        Err(e) => {
            error!("Direct relay failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();
    
    info!("🚀 Starting KausaLayer Relay Server...\n");
    
    // Parse args
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args.get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3030);
    
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    
    info!("RPC URL: {}", rpc_url);
    info!("Port: {}", port);
    
    // Initialize state
    let state = Arc::new(RelayState::new(&rpc_url));
    
    // Print wallet addresses for funding
    println!("\n📬 Relay Wallet Addresses (need funding):");
    for (i, kp) in state.wallet_pool.iter().enumerate() {
        let balance = state.client.get_balance(&kp.pubkey()).unwrap_or(0);
        println!("   Wallet {}: {} ({} SOL)", i + 1, kp.pubkey(), lamports_to_sol(balance));
    }
    println!();
    
    // Build router
    let app = Router::new()
        .route("/health", get(health))
        .route("/info", get(info))
        .route("/transfer/request", post(request_transfer))
        .route("/transfer/execute", post(execute_transfer))
        .route("/transfer/direct", post(direct_relay))
        .with_state(state);
    
    // Start server
    let addr = format!("127.0.0.1:{}", port);
    println!("🌐 Relay server listening on http://{}", addr);
    println!("🧅 To enable Tor, configure hidden service for port {}\n", port);
    
    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
