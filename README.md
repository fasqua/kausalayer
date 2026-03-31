<div align="center">
  <img src="kausalayer-logo.png" alt="KausaLayer" width="120" />

  # KausaLayer

  **Private transfers on Solana using stealth addresses**

  [Website](https://kausalayer.com) · [Documentation](https://docs.kausalayer.com) · [X (Twitter)](https://x.com/kausalayer)

</div>

---

## Overview

KausaLayer is privacy infrastructure for Solana, powered by the Stealth Diffusion Protocol (SDP). It enables private transfers of SOL and SPL tokens using one-time stealth addresses that are unlinkable to the receiver's public identity.

## Features

- **Stealth Addresses** — Each transfer uses a unique one-time address derived from the receiver's meta-address
- **3-Hop Privacy Routing** — Transfers route through 3 ephemeral wallets before reaching stealth address
- **Private Swap** — Swap SOL to any token via Jupiter, delivered privately
- **Client-Side Keys** — Private keys never leave the user's device
- **Deterministic Derivation** — Receivers can derive stealth keypairs to claim funds
- **Alias Support** — Human-readable addresses (kl_alice) for subscribers
- **Low Fees** — 0.5% protocol fee + minimal Solana transaction fees

## How It Works
```
┌─────────────────────────────────────────────────────────────────┐
│                         PREPARATION                             │
│  Receiver generates stealth keys and shares kl_... meta-address │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                     TRANSFER FLOW (3-Hop)                        │
│  1. Sender requests transfer with recipient's meta-address       │
│  2. Relay generates deposit address + 2 intermediate hops        │
│  3. Sender deposits SOL/tokens to deposit address                │
│  4. TX1: Deposit → Hop1 (ephemeral)                              │
│  5. TX2: Hop1 → Hop2 (ephemeral)                                 │
│  6. TX3: Hop2 → Stealth Address (with ephemeral key memo)        │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                         CLAIM FLOW                               │
│  1. Receiver scans for incoming transfers using view key         │
│  2. Receiver derives stealth keypair client-side                 │
│  3. Receiver signs transaction and claims funds to any wallet    │
└─────────────────────────────────────────────────────────────────┘
```

## Security

- **Ephemeral Keypairs** — All intermediate keys (deposit, hop1, hop2) auto-purged after 24 hours
- **Encryption at Rest** — Keypairs encrypted with AES-256-GCM
- **No Permanent Logs** — Transfer records deleted after claim
- **Trustless Stealth** — Stealth address derived via ECDH, only recipient's view key can detect

## Protocol Details

**Meta-Address Format:**
```
kl_<base58(spend_pubkey || view_pubkey)>
```

**Stealth Address Derivation:**
```
shared_secret = SHA256("KausaLayer_shared_v2" || view_pubkey || ephemeral_pubkey)
stealth_seed  = SHA256("KausaLayer_stealth_v2" || spend_pubkey || shared_secret)
stealth_keypair = Ed25519_Keypair_from_seed(stealth_seed)
```

**Transaction Memo:**
```
SDP:<base58_ephemeral_pubkey>
```

## Quick Start

### Request a Private Transfer
```bash
curl -X POST https://api.kausalayer.com/transfer/request \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "kl_5xYzABC123...",
    "amount": 0.5
  }'
```

### Response
```json
{
  "request_id": "req_1234567890",
  "deposit_address": "ExAmPLeDePo51tAdDrEsS1234567890abcdefghijk",
  "deposit_amount": 0.50255,
  "expires_at": 1710127056,
  "expires_in_seconds": 1800
}
```

## Tech Stack

- **Language:** Rust
- **Blockchain:** Solana
- **Cryptography:** Ed25519, SHA-256, AES-256-GCM

## Links

- [Website](https://kausalayer.com)
- [Documentation](https://docs.kausalayer.com)
- [X (Twitter)](https://x.com/kausalayer)

## License

MIT
