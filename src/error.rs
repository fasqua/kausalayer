//! Error types for KausaLayer

use thiserror::Error;

#[derive(Error, Debug)]
pub enum KausaError {
    #[error("Crypto error: {0}")]
    CryptoError(String),
    
    #[error("Invalid meta-address: {0}")]
    InvalidMetaAddress(String),
    
    #[error("Invalid stealth address: {0}")]
    InvalidStealthAddress(String),
    
    #[error("Transaction error: {0}")]
    TransactionError(String),
    
    #[error("Fragment error: {0}")]
    FragmentError(String),
    
    #[error("Wallet error: {0}")]
    WalletError(String),
    
    #[error("RPC error: {0}")]
    RpcError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Config error: {0}")]
    ConfigError(String),
}

pub type Result<T> = std::result::Result<T, KausaError>;
