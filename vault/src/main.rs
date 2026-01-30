//! Prosperity Vault Daemon
//! 
//! Secure credential storage for Prosperity AI.
//! Runs as a separate process, communicating via Unix socket.
//!
//! Usage:
//!   prosperity-vault                    # Run daemon
//!   prosperity-vault --socket PATH      # Custom socket path
//!   prosperity-vault --vault PATH       # Custom vault path

use anyhow::Result;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use std::path::PathBuf;

mod crypto;
mod vault;
mod audit;
mod api;

const DEFAULT_SOCKET_PATH: &str = "/run/prosperity/vault.sock";
const DEFAULT_VAULT_PATH: &str = ".prosperity/vault";

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("prosperity_vault=info".parse()?))
        .init();

    // Parse arguments (simple for now)
    let args: Vec<String> = std::env::args().collect();
    
    let socket_path = get_arg(&args, "--socket")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH));
    
    let vault_path = get_arg(&args, "--vault")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .expect("Could not find home directory")
                .join(DEFAULT_VAULT_PATH)
        });

    tracing::info!("Prosperity Vault Daemon starting...");
    tracing::info!("Socket: {:?}", socket_path);
    tracing::info!("Vault: {:?}", vault_path);

    // Initialize sodiumoxide
    sodiumoxide::init().expect("Failed to initialize sodiumoxide");
    
    // Run daemon
    api::run_daemon(socket_path, vault_path).await
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_crypto_roundtrip() {
        sodiumoxide::init().unwrap();
        
        let salt = crypto::generate_salt();
        let master = crypto::derive_master_key("test passphrase", &salt).unwrap();
        let subkey = crypto::derive_subkey(&master, "test-context");
        
        let plaintext = b"Hello, Prosperity!";
        let ciphertext = crypto::encrypt(plaintext, &subkey).unwrap();
        let decrypted = crypto::decrypt(&ciphertext, &subkey).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_vault_full_workflow() {
        sodiumoxide::init().unwrap();
        
        let tmp = TempDir::new().unwrap();
        let vault_path = tmp.path().join("test_vault");
        
        // Create vault
        let mut v = vault::Vault::create(&vault_path, "secure passphrase").unwrap();
        
        // Add entry
        let entry = vault::VaultEntry::new(
            vault::Category::Authentication,
            vault::EntryType::Password,
            "GitHub",
            b"ghp_xxxxxxxxxxxx".to_vec(),
        ).with_username("adam");
        
        let id = v.add_entry(entry).unwrap();
        
        // Lock and reopen
        v.lock();
        drop(v);
        
        let mut v2 = vault::Vault::open(&vault_path).unwrap();
        v2.unlock("secure passphrase").unwrap();
        
        // Retrieve entry
        let retrieved = v2.get_entry(&id).unwrap().unwrap();
        assert_eq!(retrieved.name, "GitHub");
        assert_eq!(retrieved.value, b"ghp_xxxxxxxxxxxx");
    }
}
