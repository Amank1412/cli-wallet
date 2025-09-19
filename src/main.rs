use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::{fs, path::PathBuf};

/// CLI arguments
#[derive(Parser)]
#[command(name = "Rusty Wallet", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new wallet
    Create { name: String },

    /// Show public address of a wallet
    Show { name: String },

    /// List all wallets
    List,

    /// Sign a message with wallet's private key
    Sign { name: String, message: String },
}

/// Wallet file structure
#[derive(Serialize, Deserialize)]
struct WalletFile {
    public: String,
    secret: String,
}

fn wallet_path(name: &str) -> PathBuf {
    PathBuf::from("wallets").join(format!("{}.json", name))
}

/// Save wallet to file
fn save_wallet(name: &str, secret: &SecretKey, pubkey: &PublicKey) {
    let wf = WalletFile {
        public: hex::encode(pubkey.serialize_uncompressed()),
        secret: hex::encode(secret.secret_bytes()),
    };

    fs::create_dir_all("wallets").unwrap();
    fs::write(wallet_path(name), serde_json::to_string_pretty(&wf).unwrap()).unwrap();
    println!(" Wallet '{}' created", name);
}

/// Load wallet from file
fn load_wallet(name: &str) -> WalletFile {
    let data = fs::read_to_string(wallet_path(name)).unwrap();
    serde_json::from_str(&data).unwrap()
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create { name } => {
            let secp = Secp256k1::new();
            let (secret, pubkey) = secp.generate_keypair(&mut OsRng);
            save_wallet(&name, &secret, &pubkey);
        }

        Commands::Show { name } => {
            let wallet = load_wallet(&name);
            println!("Address (Public Key): {}", wallet.public);
        }

        Commands::List => {
            if let Ok(entries) = fs::read_dir("wallets") {
                println!("Wallets:");
                for e in entries {
                    if let Ok(e) = e {
                        println!("- {}", e.path().file_stem().unwrap().to_string_lossy());
                    }
                }
            } else {
                println!("No wallets found.");
            }
        }

        Commands::Sign { name, message } => {
            let wallet = load_wallet(&name);
            let secp = Secp256k1::new();
            let secret_bytes = hex::decode(wallet.secret).unwrap();
            let secret = SecretKey::from_slice(&secret_bytes).unwrap();

            let hash = Sha256::digest(message.as_bytes());
            let msg = Message::from_slice(&hash).unwrap();

            let sig = secp.sign_ecdsa(&msg, &secret);
            println!("Signature: {}", hex::encode(sig.serialize_compact()));
        }
    }
}
