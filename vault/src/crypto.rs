//! Core cryptographic operations for Prosperity Vault
//! 
//! Implements:
//! - Argon2id key derivation (256 MiB memory-hard)
//! - HKDF-SHA256 for subkey derivation
//! - XChaCha20-Poly1305 AEAD encryption
//! - Secure memory handling

use anyhow::{anyhow, Result};
use argon2::{Argon2, Algorithm, Version, Params};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::{
    self, Key, Nonce, KEYBYTES, NONCEBYTES,
};
use sodiumoxide::randombytes::randombytes;
use zeroize::Zeroize;

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

// Argon2id parameters (fixed baseline per spec)
pub const ARGON2_MEMORY_KIB: u32 = 262_144; // 256 MiB
pub const ARGON2_ITERATIONS: u32 = 4;
pub const ARGON2_PARALLELISM: u32 = 4;

// Key/nonce sizes
pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = NONCEBYTES; // 24 bytes for XChaCha20

/// Secure key wrapper with auto-zeroing
#[derive(Clone)]
pub struct SecureKey {
    inner: Secret<[u8; KEY_LEN]>,
}

impl SecureKey {
    pub fn new(key: [u8; KEY_LEN]) -> Self {
        Self { inner: Secret::new(key) }
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        self.inner.expose_secret()
    }

    /// Generate random key
    pub fn generate() -> Self {
        let bytes = randombytes(KEY_LEN);
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes);
        Self::new(key)
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // secrecy handles zeroing, but we're explicit
    }
}

/// Generate cryptographically secure random salt
pub fn generate_salt() -> [u8; SALT_LEN] {
    let bytes = randombytes(SALT_LEN);
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes);
    salt
}

/// Generate random nonce for XChaCha20
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let bytes = randombytes(NONCE_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes);
    nonce
}

/// Derive master key from passphrase using Argon2id
/// 
/// This is the expensive operation (~1 second on baseline hardware)
/// that protects against brute-force attacks.
pub fn derive_master_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<SecureKey> {
    // Build Argon2id with our parameters
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LEN),
    ).map_err(|e| anyhow!("Invalid Argon2 params: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|e| anyhow!("Argon2 hashing failed: {}", e))?;

    Ok(SecureKey::new(output))
}

/// Derive subkey from master key using HKDF-SHA256
/// 
/// Context strings isolate keys for different purposes:
/// - "kek" -> Key Encryption Key
/// - "category-FINANCIAL" -> Financial category key
/// - "meta" -> Metadata encryption key
/// - "audit" -> Audit log key
pub fn derive_subkey(master: &SecureKey, context: &str) -> SecureKey {
    let hk = Hkdf::<Sha256>::new(None, master.expose());
    let mut okm = [0u8; KEY_LEN];
    hk.expand(context.as_bytes(), &mut okm)
        .expect("HKDF expand should never fail with 32-byte output");
    SecureKey::new(okm)
}

/// Encrypt plaintext using XChaCha20-Poly1305
/// 
/// Returns: nonce (24 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(plaintext: &[u8], key: &SecureKey) -> Result<Vec<u8>> {
    // Initialize sodiumoxide (safe to call multiple times)
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide"))?;

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes)
        .ok_or_else(|| anyhow!("Invalid nonce"))?;
    
    let key = Key::from_slice(key.expose())
        .ok_or_else(|| anyhow!("Invalid key"))?;

    // Seal: encrypt and authenticate
    let ciphertext = xchacha20poly1305_ietf::seal(plaintext, None, &nonce, &key);

    // Prepend nonce to ciphertext
    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt ciphertext using XChaCha20-Poly1305
/// 
/// Input format: nonce (24 bytes) || ciphertext || tag (16 bytes)
pub fn decrypt(ciphertext: &[u8], key: &SecureKey) -> Result<Vec<u8>> {
    // Initialize sodiumoxide
    sodiumoxide::init().map_err(|_| anyhow!("Failed to initialize sodiumoxide"))?;

    // Minimum size: nonce + tag
    if ciphertext.len() < NONCE_LEN + 16 {
        return Err(anyhow!("Ciphertext too short"));
    }

    let nonce = Nonce::from_slice(&ciphertext[..NONCE_LEN])
        .ok_or_else(|| anyhow!("Invalid nonce in ciphertext"))?;
    
    let key = Key::from_slice(key.expose())
        .ok_or_else(|| anyhow!("Invalid key"))?;

    // Open: decrypt and verify
    xchacha20poly1305_ietf::open(&ciphertext[NONCE_LEN..], None, &nonce, &key)
        .map_err(|_| anyhow!("Decryption failed: invalid key or tampered data"))
}

/// Save data encrypted to file
pub fn save_encrypted(path: &Path, data: &[u8], key: &SecureKey) -> Result<()> {
    let encrypted = encrypt(data, key)?;
    let mut file = File::create(path)?;
    file.write_all(&encrypted)?;
    file.sync_all()?;
    Ok(())
}

/// Load and decrypt data from file
pub fn load_encrypted(path: &Path, key: &SecureKey) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;
    decrypt(&ciphertext, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let salt = generate_salt();
        let key1 = derive_master_key("test passphrase", &salt).unwrap();
        let key2 = derive_master_key("test passphrase", &salt).unwrap();
        let key3 = derive_master_key("different passphrase", &salt).unwrap();

        // Same passphrase + salt = same key
        assert_eq!(key1.expose(), key2.expose());
        // Different passphrase = different key
        assert_ne!(key1.expose(), key3.expose());
    }

    #[test]
    fn test_subkey_derivation() {
        let salt = generate_salt();
        let master = derive_master_key("test", &salt).unwrap();

        let kek = derive_subkey(&master, "kek");
        let meta = derive_subkey(&master, "meta");
        let kek2 = derive_subkey(&master, "kek");

        // Different contexts = different keys
        assert_ne!(kek.expose(), meta.expose());
        // Same context = same key
        assert_eq!(kek.expose(), kek2.expose());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SecureKey::generate();
        let plaintext = b"Hello, Prosperity!";

        let ciphertext = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = SecureKey::generate();
        let key2 = SecureKey::generate();
        let plaintext = b"secret data";

        let ciphertext = encrypt(plaintext, &key1).unwrap();
        let result = decrypt(&ciphertext, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = SecureKey::generate();
        let plaintext = b"secret data";

        let mut ciphertext = encrypt(plaintext, &key).unwrap();
        // Tamper with the data
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt(&ciphertext, &key);
        assert!(result.is_err());
    }
}
