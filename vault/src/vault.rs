//! Vault structure and entry management
//! 
//! Implements:
//! - Category-based encryption (per spec v3)
//! - KEK/DEK key hierarchy
//! - Entry CRUD operations

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{
    self, SecureKey, SALT_LEN,
    derive_master_key, derive_subkey, generate_salt,
    encrypt, decrypt, save_encrypted, load_encrypted,
};

/// Vault data categories (per spec)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Authentication,  // Passwords, API keys, OAuth tokens, TOTP
    Financial,       // Bank accounts, cards, investments
    Identity,        // SSN, passport, government IDs
    Health,          // Medical records, medications, providers
    Personal,        // Secure notes, personal secrets
    Patterns,        // Command shortcuts, learned behaviors, preferences
}

impl Category {
    pub fn all() -> &'static [Category] {
        &[
            Category::Authentication,
            Category::Financial,
            Category::Identity,
            Category::Health,
            Category::Personal,
            Category::Patterns,
        ]
    }

    pub fn context_string(&self) -> &'static str {
        match self {
            Category::Authentication => "category-auth",
            Category::Financial => "category-financial",
            Category::Identity => "category-identity",
            Category::Health => "category-health",
            Category::Personal => "category-personal",
            Category::Patterns => "category-patterns",
        }
    }

    pub fn filename(&self) -> &'static str {
        match self {
            Category::Authentication => "auth.enc",
            Category::Financial => "financial.enc",
            Category::Identity => "identity.enc",
            Category::Health => "health.enc",
            Category::Personal => "personal.enc",
            Category::Patterns => "patterns.enc",
        }
    }
}

/// Entry types within categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    Password,
    ApiKey,
    OAuthToken,
    TotpSeed,
    Card,
    BankAccount,
    Identity,
    SecureNote,
    Certificate,
    RecoveryCode,
    // Pattern types
    Command,      // Learned command shortcuts
    Preference,   // User preferences
    Schedule,     // Time-based patterns
}

/// A single vault entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: Uuid,
    pub category: Category,
    pub entry_type: EntryType,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    #[serde(with = "secret_bytes")]
    pub value: Vec<u8>,  // The actual secret (encrypted at rest)
    pub tags: Vec<String>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub access_count: u32,
}

// Custom serialization for secret bytes
mod secret_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        STANDARD.encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

impl VaultEntry {
    pub fn new(
        category: Category,
        entry_type: EntryType,
        name: impl Into<String>,
        value: impl Into<Vec<u8>>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            category,
            entry_type,
            name: name.into(),
            username: None,
            url: None,
            notes: None,
            value: value.into(),
            tags: Vec::new(),
            created: now,
            modified: now,
            accessed: now,
            access_count: 0,
        }
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
}

/// Category data container
#[derive(Debug, Default, Serialize, Deserialize)]
struct CategoryData {
    entries: Vec<VaultEntry>,
}

/// Vault metadata (partially encrypted)
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultMeta {
    pub version: u32,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub salt: [u8; SALT_LEN],
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub recovery_enabled: bool,
    pub hardware_key_required: bool,
}

impl Default for VaultMeta {
    fn default() -> Self {
        Self {
            version: 1,
            created: Utc::now(),
            modified: Utc::now(),
            salt: generate_salt(),
            kdf_memory_kib: crypto::ARGON2_MEMORY_KIB,
            kdf_iterations: crypto::ARGON2_ITERATIONS,
            kdf_parallelism: crypto::ARGON2_PARALLELISM,
            recovery_enabled: false,
            hardware_key_required: false,
        }
    }
}

/// The main Vault struct
pub struct Vault {
    path: PathBuf,
    meta: VaultMeta,
    master_key: Option<SecureKey>,
    kek: Option<SecureKey>,
    dek: Option<SecureKey>,
    category_keys: HashMap<Category, SecureKey>,
    unlocked_categories: HashMap<Category, CategoryData>,
}

impl Vault {
    /// Create a new vault at the given path
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        
        // Create directory structure
        fs::create_dir_all(&path)?;
        fs::create_dir_all(path.join("categories"))?;
        
        // Generate metadata with fresh salt
        let meta = VaultMeta::default();
        
        // Derive master key
        let master_key = derive_master_key(passphrase, &meta.salt)?;
        
        // Derive KEK and generate DEK
        let kek = derive_subkey(&master_key, "kek");
        let dek = SecureKey::generate();
        
        // Encrypt and save DEK
        let dek_encrypted = encrypt(dek.expose(), &kek)?;
        let mut dek_file = File::create(path.join("dek.enc"))?;
        dek_file.write_all(&dek_encrypted)?;
        
        // Derive category keys
        let mut category_keys = HashMap::new();
        for cat in Category::all() {
            let key = derive_subkey(&master_key, cat.context_string());
            category_keys.insert(*cat, key);
            
            // Create empty category file
            let empty = CategoryData::default();
            let json = serde_json::to_vec(&empty)?;
            save_encrypted(
                &path.join("categories").join(cat.filename()),
                &json,
                category_keys.get(cat).unwrap(),
            )?;
        }
        
        // Save metadata
        let meta_json = serde_json::to_vec_pretty(&meta)?;
        let mut meta_file = File::create(path.join("vault.meta"))?;
        meta_file.write_all(&meta_json)?;
        
        Ok(Self {
            path,
            meta,
            master_key: Some(master_key),
            kek: Some(kek),
            dek: Some(dek),
            category_keys,
            unlocked_categories: HashMap::new(),
        })
    }

    /// Open an existing vault
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        
        // Load metadata
        let mut meta_file = File::open(path.join("vault.meta"))?;
        let mut meta_json = Vec::new();
        meta_file.read_to_end(&mut meta_json)?;
        let meta: VaultMeta = serde_json::from_slice(&meta_json)?;
        
        Ok(Self {
            path,
            meta,
            master_key: None,
            kek: None,
            dek: None,
            category_keys: HashMap::new(),
            unlocked_categories: HashMap::new(),
        })
    }

    /// Unlock the vault with passphrase
    pub fn unlock(&mut self, passphrase: &str) -> Result<()> {
        // Derive master key
        let master_key = derive_master_key(passphrase, &self.meta.salt)?;
        
        // Derive KEK
        let kek = derive_subkey(&master_key, "kek");
        
        // Decrypt DEK
        let dek_path = self.path.join("dek.enc");
        let dek_encrypted = fs::read(&dek_path)?;
        let dek_bytes = decrypt(&dek_encrypted, &kek)?;
        
        if dek_bytes.len() != crypto::KEY_LEN {
            return Err(anyhow!("Invalid DEK length"));
        }
        
        let mut dek_arr = [0u8; crypto::KEY_LEN];
        dek_arr.copy_from_slice(&dek_bytes);
        let dek = SecureKey::new(dek_arr);
        
        // Derive all category keys
        let mut category_keys = HashMap::new();
        for cat in Category::all() {
            let key = derive_subkey(&master_key, cat.context_string());
            category_keys.insert(*cat, key);
        }
        
        self.master_key = Some(master_key);
        self.kek = Some(kek);
        self.dek = Some(dek);
        self.category_keys = category_keys;
        
        Ok(())
    }

    /// Unlock specific categories only (for partial unlock)
    pub fn unlock_categories(&mut self, passphrase: &str, categories: &[Category]) -> Result<()> {
        self.unlock(passphrase)?;
        
        for cat in categories {
            self.load_category(*cat)?;
        }
        
        Ok(())
    }

    /// Check if vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    /// Lock the vault (clear all keys from memory)
    pub fn lock(&mut self) {
        self.master_key = None;
        self.kek = None;
        self.dek = None;
        self.category_keys.clear();
        self.unlocked_categories.clear();
    }

    /// Load a category's entries into memory
    fn load_category(&mut self, category: Category) -> Result<()> {
        let key = self.category_keys.get(&category)
            .ok_or_else(|| anyhow!("Category key not available"))?;
        
        let path = self.path.join("categories").join(category.filename());
        let data = load_encrypted(&path, key)?;
        let cat_data: CategoryData = serde_json::from_slice(&data)?;
        
        self.unlocked_categories.insert(category, cat_data);
        Ok(())
    }

    /// Save a category's entries to disk
    fn save_category(&self, category: Category) -> Result<()> {
        let key = self.category_keys.get(&category)
            .ok_or_else(|| anyhow!("Category key not available"))?;
        
        let cat_data = self.unlocked_categories.get(&category)
            .ok_or_else(|| anyhow!("Category not loaded"))?;
        
        let json = serde_json::to_vec(cat_data)?;
        let path = self.path.join("categories").join(category.filename());
        save_encrypted(&path, &json, key)?;
        
        Ok(())
    }

    /// Add a new entry
    pub fn add_entry(&mut self, entry: VaultEntry) -> Result<Uuid> {
        let category = entry.category;
        let id = entry.id;
        
        // Ensure category is loaded
        if !self.unlocked_categories.contains_key(&category) {
            self.load_category(category)?;
        }
        
        let cat_data = self.unlocked_categories.get_mut(&category)
            .ok_or_else(|| anyhow!("Category not available"))?;
        
        cat_data.entries.push(entry);
        self.save_category(category)?;
        
        Ok(id)
    }

    /// Get an entry by ID
    pub fn get_entry(&mut self, id: &Uuid) -> Result<Option<&VaultEntry>> {
        // First, load all categories we haven't loaded yet
        for cat in Category::all() {
            if !self.unlocked_categories.contains_key(cat) {
                self.load_category(*cat)?;
            }
        }
        
        // Now search all loaded categories
        for cat_data in self.unlocked_categories.values() {
            if let Some(entry) = cat_data.entries.iter().find(|e| &e.id == id) {
                return Ok(Some(entry));
            }
        }
        
        Ok(None)
    }

    /// List entries in a category (metadata only, not values)
    pub fn list_entries(&mut self, category: Category) -> Result<Vec<EntryMetadata>> {
        if !self.unlocked_categories.contains_key(&category) {
            self.load_category(category)?;
        }
        
        let cat_data = self.unlocked_categories.get(&category)
            .ok_or_else(|| anyhow!("Category not available"))?;
        
        Ok(cat_data.entries.iter().map(|e| EntryMetadata {
            id: e.id,
            category: e.category,
            entry_type: e.entry_type,
            name: e.name.clone(),
            username: e.username.clone(),
            url: e.url.clone(),
            tags: e.tags.clone(),
        }).collect())
    }

    /// Delete an entry
    pub fn delete_entry(&mut self, id: &Uuid) -> Result<bool> {
        for cat in Category::all() {
            if !self.unlocked_categories.contains_key(cat) {
                self.load_category(*cat)?;
            }
            
            let cat_data = self.unlocked_categories.get_mut(cat).unwrap();
            if let Some(pos) = cat_data.entries.iter().position(|e| &e.id == id) {
                cat_data.entries.remove(pos);
                self.save_category(*cat)?;
                return Ok(true);
            }
        }
        
        Ok(false)
    }
}

/// Entry metadata (safe to expose, no secret values)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    pub id: Uuid,
    pub category: Category,
    pub entry_type: EntryType,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_vault_create_and_unlock() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test_vault");
        
        // Create vault
        let vault = Vault::create(&path, "test passphrase").unwrap();
        assert!(vault.is_unlocked());
        drop(vault);
        
        // Reopen and unlock
        let mut vault = Vault::open(&path).unwrap();
        assert!(!vault.is_unlocked());
        vault.unlock("test passphrase").unwrap();
        assert!(vault.is_unlocked());
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test_vault");
        
        Vault::create(&path, "correct").unwrap();
        
        let mut vault = Vault::open(&path).unwrap();
        let result = vault.unlock("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_and_get_entry() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test_vault");
        
        let mut vault = Vault::create(&path, "pass").unwrap();
        
        let entry = VaultEntry::new(
            Category::Authentication,
            EntryType::Password,
            "Gmail",
            b"my_secret_password".to_vec(),
        ).with_username("user@gmail.com");
        
        let id = vault.add_entry(entry).unwrap();
        
        // Retrieve
        let retrieved = vault.get_entry(&id).unwrap().unwrap();
        assert_eq!(retrieved.name, "Gmail");
        assert_eq!(retrieved.value, b"my_secret_password");
    }
}
