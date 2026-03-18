//! KausaLayer CLI - Private Transfer on Solana

use clap::{Parser, Subcommand};
use kausalayer::Config;
use kausalayer::core::{
    StealthKeys, MetaAddress, create_stealth_address,
    save_wallet, load_wallet, wallet_exists, get_wallet_path,
    Fragmenter, Fragment, lamports_to_sol, sol_to_lamports,
    TransactionBuilder,
};

#[derive(Parser)]
#[command(name = "kausalayer")]
#[command(about = "Private Transfer on Solana - Stealth Diffusion Protocol")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate new stealth wallet and save encrypted
    Setup {
        #[arg(long)]
        no_encrypt: bool,
    },
    
    /// Show your meta-address
    Address,
    
    /// Show your keys (requires password)
    ShowKeys,
    
    /// Test stealth address generation
    TestStealth {
        #[arg(short, long)]
        meta: Option<String>,
    },
    
    /// Test amount fragmentation
    TestFragment {
        #[arg(short, long, default_value = "1.0")]
        amount: f64,
        #[arg(long)]
        instant: bool,
    },
    
    /// Simulate a private transfer (dry run)
    SimulateSend {
        /// Recipient meta-address (kl_xxx)
        #[arg(short, long)]
        to: String,
        /// Amount in SOL
        #[arg(short, long)]
        amount: f64,
    },
}

fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let _config = Config::from_env();
    
    match cli.command {
        Commands::Setup { no_encrypt } => cmd_setup(no_encrypt),
        Commands::Address => cmd_address(),
        Commands::ShowKeys => cmd_show_keys(),
        Commands::TestStealth { meta } => cmd_test_stealth(meta),
        Commands::TestFragment { amount, instant } => cmd_test_fragment(amount, instant),
        Commands::SimulateSend { to, amount } => cmd_simulate_send(to, amount),
    }
}

fn cmd_setup(no_encrypt: bool) {
    println!("🔐 Generating new stealth wallet...\n");
    
    if wallet_exists(None) {
        println!("⚠️  Wallet already exists at {:?}", get_wallet_path().unwrap());
        println!("   Delete it first if you want to create a new one.");
        return;
    }
    
    let keys = StealthKeys::new();
    let meta_address = keys.get_meta_address_string();
    let (spend_bytes, view_bytes) = keys.to_bytes();
    
    if no_encrypt {
        println!("⚠️  WARNING: Keys not saved (--no-encrypt mode)\n");
        println!("📬 Meta-address (share this to receive):");
        println!("   {}\n", meta_address);
        println!("🔑 Spend key (KEEP SECRET):");
        println!("   {}\n", hex::encode(spend_bytes));
        println!("👁️  View key (for scanning):");
        println!("   {}\n", hex::encode(view_bytes));
    } else {
        let password = rpassword::prompt_password("🔒 Enter password to encrypt wallet: ")
            .expect("Failed to read password");
        
        if password.len() < 8 {
            println!("❌ Password must be at least 8 characters!");
            return;
        }
        
        let confirm = rpassword::prompt_password("🔒 Confirm password: ")
            .expect("Failed to read password");
        
        if password != confirm {
            println!("❌ Passwords do not match!");
            return;
        }
        
        match save_wallet(&keys, &password, None) {
            Ok(path) => {
                println!("\n✅ Stealth wallet created and encrypted!\n");
                println!("📁 Saved to: {:?}\n", path);
                println!("📬 Meta-address (share this to receive):");
                println!("   {}\n", meta_address);
                println!("⚠️  Remember your password! It cannot be recovered.");
            }
            Err(e) => println!("❌ Failed to save wallet: {}", e),
        }
    }
}

fn cmd_address() {
    if !wallet_exists(None) {
        println!("❌ No wallet found. Run 'kausalayer setup' first.");
        return;
    }
    
    let password = rpassword::prompt_password("🔒 Enter password: ")
        .expect("Failed to read password");
    
    match load_wallet(&password, None) {
        Ok(keys) => {
            println!("\n📬 Your meta-address:");
            println!("   {}\n", keys.get_meta_address_string());
        }
        Err(e) => println!("❌ Failed to load wallet: {}", e),
    }
}

fn cmd_show_keys() {
    if !wallet_exists(None) {
        println!("❌ No wallet found. Run 'kausalayer setup' first.");
        return;
    }
    
    let password = rpassword::prompt_password("🔒 Enter password: ")
        .expect("Failed to read password");
    
    match load_wallet(&password, None) {
        Ok(keys) => {
            let (spend, view) = keys.to_bytes();
            println!("\n📬 Meta-address:");
            println!("   {}\n", keys.get_meta_address_string());
            println!("🔑 Spend key (KEEP SECRET):");
            println!("   {}\n", hex::encode(spend));
            println!("👁️  View key (for scanning):");
            println!("   {}\n", hex::encode(view));
        }
        Err(e) => println!("❌ Failed to load wallet: {}", e),
    }
}

fn cmd_test_stealth(meta_arg: Option<String>) {
    println!("🧪 Testing stealth address generation...\n");
    
    let (keys, meta_addr) = if let Some(m) = meta_arg {
        let decoded = MetaAddress::decode(&m).expect("Invalid meta-address");
        (None, decoded)
    } else {
        let k = StealthKeys::new();
        let m = k.get_meta_address();
        println!("Generated test wallet:");
        println!("   Meta: {}\n", k.get_meta_address_string());
        (Some(k), m)
    };
    
    println!("Creating 3 stealth addresses...\n");
    for i in 1..=3 {
        let stealth = create_stealth_address(&meta_addr).expect("Failed");
        println!("Stealth #{}: {}", i, bs58::encode(&stealth.pubkey).into_string());
        println!("   Ephemeral R: {}", bs58::encode(&stealth.ephemeral_pubkey).into_string());
        if let Some(ref k) = keys {
            let is_ours = k.check_stealth_address(&stealth).expect("Check failed");
            println!("   Verified: {}", if is_ours { "✅ OURS" } else { "❌ NOT OURS" });
        }
        println!();
    }
    println!("✅ Stealth address test complete!");
}

fn cmd_test_fragment(amount: f64, instant: bool) {
    println!("🧪 Testing amount fragmentation...\n");
    
    let lamports = sol_to_lamports(amount);
    println!("Amount: {} SOL ({} lamports)\n", amount, lamports);
    
    let fragmenter = Fragmenter::default();
    let fragments = if instant {
        fragmenter.fragment_instant(lamports)
    } else {
        fragmenter.fragment(lamports)
    };
    
    match fragments {
        Ok(frags) => {
            println!("Generated {} fragments:\n", frags.len());
            let mut total = 0u64;
            for (i, f) in frags.iter().enumerate() {
                total += f.amount;
                println!("  Fragment #{}: {:>12} lamports ({:>10.6} SOL) | delay: {}ms",
                    i + 1, f.amount, lamports_to_sol(f.amount), f.delay_ms);
            }
            println!("\n────────────────────────────────────────────────");
            println!("  Total:       {:>12} lamports ({:>10.6} SOL)", total, lamports_to_sol(total));
            println!("\n✅ Fragmentation test complete!");
        }
        Err(e) => println!("❌ Fragmentation failed: {}", e),
    }
}

fn cmd_simulate_send(to: String, amount: f64) {
    println!("🚀 Simulating Private Transfer (Dry Run)\n");
    println!("════════════════════════════════════════════════\n");
    
    // 1. Parse recipient meta-address
    let recipient_meta = match MetaAddress::decode(&to) {
        Ok(m) => m,
        Err(e) => {
            println!("❌ Invalid meta-address: {}", e);
            return;
        }
    };
    println!("📬 Recipient: {}", to);
    
    // 2. Calculate amounts
    let config = Config::from_env();
    let builder = TransactionBuilder::new(config.clone());
    let lamports = sol_to_lamports(amount);
    
    let fragmenter = Fragmenter::new(
        config.min_fragments,
        config.max_fragments,
        config.timing_window_ms,
    );
    
    let fragments = match fragmenter.fragment(lamports) {
        Ok(f) => f,
        Err(e) => {
            println!("❌ Fragmentation failed: {}", e);
            return;
        }
    };
    
    // 3. Calculate fees
    let (amt, tx_fee, proto_fee, total) = builder.calculate_total_cost(lamports, fragments.len());
    
    println!("💰 Amount: {} SOL", amount);
    println!("📦 Fragments: {}", fragments.len());
    println!("\n── Fee Breakdown ──────────────────────────────");
    println!("   Transfer amount:  {:>12} lamports ({:.6} SOL)", amt, lamports_to_sol(amt));
    println!("   Transaction fees: {:>12} lamports ({:.6} SOL)", tx_fee, lamports_to_sol(tx_fee));
    println!("   Protocol fee:     {:>12} lamports ({:.6} SOL)", proto_fee, lamports_to_sol(proto_fee));
    println!("   ─────────────────────────────────────────────");
    println!("   TOTAL REQUIRED:   {:>12} lamports ({:.6} SOL)", total, lamports_to_sol(total));
    
    // 4. Generate stealth addresses
    println!("\n── Stealth Addresses ──────────────────────────");
    let mut stealth_addresses = Vec::with_capacity(fragments.len());
    for (i, frag) in fragments.iter().enumerate() {
        let stealth = create_stealth_address(&recipient_meta).expect("Failed");
        println!("   Fragment #{}: {} lamports → {}",
            i + 1, frag.amount, bs58::encode(&stealth.pubkey).into_string());
        stealth_addresses.push(stealth);
    }
    
    // 5. Show timing
    println!("\n── Timing Schedule ────────────────────────────");
    let mut total_time = 0u64;
    for (i, frag) in fragments.iter().enumerate() {
        println!("   T+{:>5}ms: Send fragment #{} ({:.6} SOL)",
            frag.delay_ms, i + 1, lamports_to_sol(frag.amount));
        if frag.delay_ms > total_time {
            total_time = frag.delay_ms;
        }
    }
    
    println!("\n════════════════════════════════════════════════");
    println!("⏱️  Estimated completion: ~{:.1} seconds", (total_time as f64) / 1000.0 + 1.0);
    println!("\n✅ Simulation complete! (No actual transaction sent)");
    println!("\n💡 To actually send, use: kausalayer send --to {} --amount {}", to, amount);
}
