//! Stealth Address Implementation for KausaLayer (V2)
//!
//! Uses Derived Keypair scheme - generates deterministic Ed25519 keypairs
//! that can actually sign transactions.
//!
//! Flow:
//! 1. Receiver has spend_key and view_key
//! 2. Sender generates ephemeral keypair, computes shared_secret
//! 3. stealth_seed = hash(spend_pubkey || shared_secret)
//! 4. stealth_keypair = Keypair::from_seed(stealth_seed)
//! 5. Receiver can derive the SAME keypair and claim funds

use ed25519_dalek::{SecretKey, PublicKey};
use solana_sdk::signature::{Keypair, Signer};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

use crate::error::{KausaError, Result};

pub const META_ADDRESS_PREFIX: &str = "kl_";

/// Stealth wallet keys for a user
#[derive(Clone)]
pub struct StealthKeys {
    spend_secret: [u8; 32],
    spend_public: [u8; 32],
    view_secret: [u8; 32],
    view_public: [u8; 32],
}

/// A one-time stealth address with ephemeral key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthAddress {
    /// The stealth public key (Solana address)
    pub pubkey: [u8; 32],
    /// Ephemeral public key (published in memo for receiver)
    pub ephemeral_pubkey: [u8; 32],
}

/// Meta-address that receiver shares publicly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaAddress {
    pub spend_pubkey: [u8; 32],
    pub view_pubkey: [u8; 32],
}

pub fn generate_stealth_keys() -> StealthKeys {
    StealthKeys::new()
}

/// Helper: Create Solana Keypair from 32-byte seed
fn keypair_from_seed(seed: &[u8; 32]) -> Result<Keypair> {
    let secret = SecretKey::from_bytes(seed)
        .map_err(|e| KausaError::CryptoError(e.to_string()))?;
    let public = PublicKey::from(&secret);
    
    let mut full_key = [0u8; 64];
    full_key[..32].copy_from_slice(seed);
    full_key[32..].copy_from_slice(public.as_bytes());
    
    Keypair::from_bytes(&full_key)
        .map_err(|e| KausaError::CryptoError(e.to_string()))
}

/// Compute shared secret: hash(view_pubkey || ephemeral_pubkey)
/// Both sender and receiver can compute this!
fn compute_shared_secret(view_pub: &[u8; 32], eph_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"KausaLayer_shared_v2");
    h.update(view_pub);
    h.update(eph_pub);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Derive stealth seed: hash(spend_pubkey || shared_secret)
fn derive_stealth_seed(spend_pub: &[u8; 32], shared: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"KausaLayer_stealth_v2");
    h.update(spend_pub);
    h.update(shared);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

impl StealthKeys {
    pub fn new() -> Self {
        let spend_kp = Keypair::new();
        let view_kp = Keypair::new();
        
        Self {
            spend_secret: spend_kp.secret().to_bytes(),
            spend_public: spend_kp.pubkey().to_bytes(),
            view_secret: view_kp.secret().to_bytes(),
            view_public: view_kp.pubkey().to_bytes(),
        }
    }
    
    pub fn from_bytes(spend_bytes: [u8; 32], view_bytes: [u8; 32]) -> Result<Self> {
        let spend_kp = keypair_from_seed(&spend_bytes)?;
        let view_kp = keypair_from_seed(&view_bytes)?;
        
        Ok(Self {
            spend_secret: spend_bytes,
            spend_public: spend_kp.pubkey().to_bytes(),
            view_secret: view_bytes,
            view_public: view_kp.pubkey().to_bytes(),
        })
    }
    
    pub fn to_bytes(&self) -> ([u8; 32], [u8; 32]) {
        (self.spend_secret, self.view_secret)
    }
    
    pub fn get_meta_address(&self) -> MetaAddress {
        MetaAddress {
            spend_pubkey: self.spend_public,
            view_pubkey: self.view_public,
        }
    }
    
    pub fn get_meta_address_string(&self) -> String {
        self.get_meta_address().encode()
    }
    
    pub fn get_view_key(&self) -> [u8; 32] {
        self.view_secret
    }
    
    /// Check if a stealth address belongs to us
    pub fn check_stealth_address(&self, stealth: &StealthAddress) -> Result<bool> {
        // Recompute the stealth keypair
        let shared = compute_shared_secret(&self.view_public, &stealth.ephemeral_pubkey);
        let seed = derive_stealth_seed(&self.spend_public, &shared);
        let derived_kp = keypair_from_seed(&seed)?;
        
        // Check if derived pubkey matches
        Ok(derived_kp.pubkey().to_bytes() == stealth.pubkey)
    }
    
    /// Derive the stealth keypair for claiming funds
    /// Returns a Solana Keypair that can sign transactions!
    pub fn derive_stealth_keypair(&self, stealth: &StealthAddress) -> Result<Keypair> {
        // Verify ownership first
        if !self.check_stealth_address(stealth)? {
            return Err(KausaError::CryptoError(
                "Stealth address does not belong to this wallet".into()
            ));
        }
        
        // Derive the keypair
        let shared = compute_shared_secret(&self.view_public, &stealth.ephemeral_pubkey);
        let seed = derive_stealth_seed(&self.spend_public, &shared);
        keypair_from_seed(&seed)
    }
    
    /// Legacy function for compatibility - returns seed bytes
    pub fn derive_stealth_privkey(&self, stealth: &StealthAddress) -> Result<[u8; 32]> {
        if !self.check_stealth_address(stealth)? {
            return Err(KausaError::CryptoError(
                "Stealth address does not belong to this wallet".into()
            ));
        }
        
        let shared = compute_shared_secret(&self.view_public, &stealth.ephemeral_pubkey);
        let seed = derive_stealth_seed(&self.spend_public, &shared);
        Ok(seed)
    }
}

impl MetaAddress {
    pub fn encode(&self) -> String {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&self.spend_pubkey);
        data.extend_from_slice(&self.view_pubkey);
        format!("{}{}", META_ADDRESS_PREFIX, bs58::encode(&data).into_string())
    }
    
    pub fn decode(s: &str) -> Result<Self> {
        if !s.starts_with(META_ADDRESS_PREFIX) {
            return Err(KausaError::InvalidMetaAddress("Bad prefix".into()));
        }
        let decoded = bs58::decode(&s[META_ADDRESS_PREFIX.len()..])
            .into_vec()
            .map_err(|e| KausaError::InvalidMetaAddress(e.to_string()))?;
        if decoded.len() != 64 {
            return Err(KausaError::InvalidMetaAddress("Bad length".into()));
        }
        let mut spend = [0u8; 32];
        let mut view = [0u8; 32];
        spend.copy_from_slice(&decoded[..32]);
        view.copy_from_slice(&decoded[32..]);
        Ok(Self { spend_pubkey: spend, view_pubkey: view })
    }
}

/// Create stealth address for receiver's meta-address
/// Returns StealthAddress with valid Solana pubkey that can receive AND be claimed
pub fn create_stealth_address(meta: &MetaAddress) -> Result<StealthAddress> {
    // Generate ephemeral keypair
    let ephemeral_kp = Keypair::new();
    let ephemeral_pubkey = ephemeral_kp.pubkey().to_bytes();
    
    // Compute shared secret (both parties can compute this)
    let shared = compute_shared_secret(&meta.view_pubkey, &ephemeral_pubkey);
    
    // Derive stealth seed
    let seed = derive_stealth_seed(&meta.spend_pubkey, &shared);
    
    // Create stealth keypair from seed
    let stealth_kp = keypair_from_seed(&seed)?;
    
    Ok(StealthAddress {
        pubkey: stealth_kp.pubkey().to_bytes(),
        ephemeral_pubkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keys() {
        let k = StealthKeys::new();
        let m = k.get_meta_address();
        assert_eq!(m.spend_pubkey.len(), 32);
        assert_eq!(m.view_pubkey.len(), 32);
    }

    #[test]
    fn test_encode_decode() {
        let k = StealthKeys::new();
        let enc = k.get_meta_address_string();
        assert!(enc.starts_with(META_ADDRESS_PREFIX));
        let dec = MetaAddress::decode(&enc).unwrap();
        assert_eq!(dec.spend_pubkey, k.get_meta_address().spend_pubkey);
    }

    #[test]
    fn test_stealth_check() {
        let recv = StealthKeys::new();
        let meta = recv.get_meta_address();
        let stealth = create_stealth_address(&meta).unwrap();
        
        // Owner should detect
        assert!(recv.check_stealth_address(&stealth).unwrap());
        
        // Other should NOT detect
        let other = StealthKeys::new();
        assert!(!other.check_stealth_address(&stealth).unwrap());
    }

    #[test]
    fn test_derive_keypair() {
        let recv = StealthKeys::new();
        let meta = recv.get_meta_address();
        let stealth = create_stealth_address(&meta).unwrap();
        
        // Derive keypair
        let derived_kp = recv.derive_stealth_keypair(&stealth).unwrap();
        
        // Derived pubkey should match stealth pubkey!
        assert_eq!(
            derived_kp.pubkey().to_bytes(),
            stealth.pubkey,
            "Derived keypair pubkey must match stealth address"
        );
    }

    #[test]
    fn test_unique_stealth() {
        let recv = StealthKeys::new();
        let meta = recv.get_meta_address();
        let s1 = create_stealth_address(&meta).unwrap();
        let s2 = create_stealth_address(&meta).unwrap();
        
        // Different ephemeral = different stealth
        assert_ne!(s1.pubkey, s2.pubkey);
        assert_ne!(s1.ephemeral_pubkey, s2.ephemeral_pubkey);
        
        // But both belong to receiver
        assert!(recv.check_stealth_address(&s1).unwrap());
        assert!(recv.check_stealth_address(&s2).unwrap());
    }

    #[test]
    fn test_keypair_deterministic() {
        let recv = StealthKeys::new();
        let meta = recv.get_meta_address();
        let stealth = create_stealth_address(&meta).unwrap();
        
        // Derive multiple times
        let kp1 = recv.derive_stealth_keypair(&stealth).unwrap();
        let kp2 = recv.derive_stealth_keypair(&stealth).unwrap();
        
        // Should be same keypair
        assert_eq!(kp1.pubkey(), kp2.pubkey());
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let original = StealthKeys::new();
        let (spend, view) = original.to_bytes();
        
        let restored = StealthKeys::from_bytes(spend, view).unwrap();
        
        assert_eq!(
            original.get_meta_address_string(),
            restored.get_meta_address_string()
        );
    }
}
