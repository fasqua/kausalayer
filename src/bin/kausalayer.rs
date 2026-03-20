//! KausaLayer AI Agent CLI

use clap::{Parser, Subcommand};
use anyhow::Result;

use kausalayer::agent::commands;
use kausalayer::core::lamports_to_sol;

#[derive(Parser)]
#[command(name = "kausalayer")]
#[command(about = "KausaLayer - Private transfers on Solana", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Setup new wallet
    Setup,
    
    /// Show your meta-address (for receiving)
    Address,
    
    /// Send SOL privately
    Send {
        /// Recipient meta-address (kl_xxx)
        #[arg(long)]
        to: String,
        
        /// Amount in SOL
        #[arg(long)]
        amount: f64,
    },
    
    /// Scan for incoming transfers
    Scan,
    
    /// List pending transfers
    Pending,
    
    /// Claim pending transfers
    Claim {
        /// Claim all pending
        #[arg(long)]
        all: bool,
    },
    
    /// Show balance
    Balance,
    
    /// Check relay status
    Status,
}

fn read_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    std::io::Write::flush(&mut std::io::stdout())?;
    let password = rpassword::read_password()?;
    Ok(password)
}

fn read_password_confirm() -> Result<String> {
    let pass1 = read_password("🔐 Enter password: ")?;
    let pass2 = read_password("🔐 Confirm password: ")?;
    
    if pass1 != pass2 {
        return Err(anyhow::anyhow!("Passwords do not match"));
    }
    
    if pass1.len() < 8 {
        return Err(anyhow::anyhow!("Password must be at least 8 characters"));
    }
    
    Ok(pass1)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Setup => {
            println!("🔐 Setting up new KausaLayer wallet...\n");
            
            let password = read_password_confirm()?;
            
            match commands::cmd_setup(&password) {
                Ok(meta_address) => {
                    println!("\n✅ Wallet created and encrypted!\n");
                    println!("📬 Your meta-address (share this to receive):");
                    println!("   {}\n", meta_address);
                    println!("⚠️  Keep your password safe! It cannot be recovered.");
                }
                Err(e) => {
                    eprintln!("❌ Setup failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Address => {
            let password = read_password("🔐 Enter password: ")?;
            
            match commands::cmd_address(&password) {
                Ok(meta_address) => {
                    println!("\n📬 Your meta-address:");
                    println!("   {}\n", meta_address);
                }
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Send { to, amount } => {
            println!("🚀 Sending {} SOL to {}...\n", amount, &to[..20]);
            
            let password = read_password("🔐 Enter password: ")?;
            
            println!("🧅 Connecting via private network...");
            
            match commands::cmd_send(&password, &to, amount).await {
                Ok(signature) => {
                    println!("\n✅ Sent successfully!\n");
                    println!("📝 Transaction: {}", signature);
                }
                Err(e) => {
                    eprintln!("❌ Send failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Scan => {
            println!("🔍 Scanning for incoming transfers...\n");
            
            let password = read_password("🔐 Enter password: ")?;
            
            match commands::cmd_scan(&password).await {
                Ok(transfers) => {
                    if transfers.is_empty() {
                        println!("No pending transfers found.");
                    } else {
                        println!("✅ Found {} pending transfer(s):\n", transfers.len());
                        
                        let mut total: u64 = 0;
                        for (i, t) in transfers.iter().enumerate() {
                            println!("   {}. {} SOL → {}", 
                                i + 1,
                                lamports_to_sol(t.amount_lamports),
                                &t.stealth_address[..16]
                            );
                            total += t.amount_lamports;
                        }
                        
                        println!("\n   Total pending: {} SOL", lamports_to_sol(total));
                    }
                }
                Err(e) => {
                    eprintln!("❌ Scan failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Pending => {
            match commands::cmd_pending() {
                Ok(transfers) => {
                    if transfers.is_empty() {
                        println!("No pending transfers.");
                    } else {
                        println!("📋 Pending transfers:\n");
                        
                        let mut total: u64 = 0;
                        for (i, t) in transfers.iter().enumerate() {
                            println!("   {}. {} SOL → {}", 
                                i + 1,
                                lamports_to_sol(t.amount_lamports),
                                &t.stealth_address[..16]
                            );
                            total += t.amount_lamports;
                        }
                        
                        println!("\n   Total: {} SOL", lamports_to_sol(total));
                    }
                }
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Claim { all } => {
            if !all {
                eprintln!("Use --all to claim all pending transfers");
                std::process::exit(1);
            }
            
            println!("📤 Claiming all pending transfers...\n");
            
            let password = read_password("🔐 Enter password: ")?;
            
            match commands::cmd_claim_all(&password).await {
                Ok(results) => {
                    println!("\n✅ Claim results:\n");
                    for (addr, sig) in results {
                        println!("   {} → {}", &addr[..16], sig);
                    }
                }
                Err(e) => {
                    eprintln!("❌ Claim failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Balance => {
            let password = read_password("🔐 Enter password: ")?;
            
            match commands::cmd_balance(&password).await {
                Ok((wallet, pending)) => {
                    println!("\n💰 Balance:\n");
                    println!("   Wallet:  {} SOL", lamports_to_sol(wallet));
                    println!("   Pending: {} SOL", lamports_to_sol(pending));
                    println!("   ─────────────────");
                    println!("   Total:   {} SOL", lamports_to_sol(wallet + pending));
                }
                Err(e) => {
                    eprintln!("❌ Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Status => {
            println!("🔍 Checking relay status...\n");
            
            match commands::cmd_status().await {
                Ok(health) => {
                    println!("✅ Relay Status:\n");
                    println!("   Status:  {}", health.status);
                    println!("   Version: {}", health.version);
                    println!("   Wallets: {}", health.wallets_available);
                    println!("   Network: Solana Mainnet");
                }
                Err(e) => {
                    eprintln!("❌ Relay offline: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
    
    Ok(())
}
