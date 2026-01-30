//! Audit logging with hash chain integrity
//! 
//! Every vault access is logged with:
//! - Timestamp
//! - What was accessed
//! - Who accessed (agent ID)
//! - Why (purpose string)
//! - Outcome (granted/denied)
//! 
//! Hash chaining ensures tamper detection.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{SecureKey, encrypt, decrypt};
use crate::vault::Category;

/// Type of audit event
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    VaultUnlock,
    VaultLock,
    CategoryUnlock,
    EntryAccess,
    EntryCreate,
    EntryUpdate,
    EntryDelete,
    AuthUse,
    AnomalyDetected,
    AccessDenied,
}

/// A single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    
    // What was accessed
    pub entry_id: Option<Uuid>,
    pub entry_name: Option<String>,
    pub category: Option<Category>,
    
    // Who accessed
    pub agent_id: Option<String>,
    pub origin_chain: Option<Vec<String>>,
    
    // Why
    pub purpose: Option<String>,
    
    // Outcome
    pub granted: bool,
    pub denial_reason: Option<String>,
    
    // For auth operations
    pub target_domain: Option<String>,
    
    // Hash chain
    pub previous_hash: String,
    pub entry_hash: String,
}

impl AuditEntry {
    /// Create a new audit entry
    pub fn new(event_type: AuditEventType, previous_hash: &str) -> Self {
        let mut entry = Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            entry_id: None,
            entry_name: None,
            category: None,
            agent_id: None,
            origin_chain: None,
            purpose: None,
            granted: true,
            denial_reason: None,
            target_domain: None,
            previous_hash: previous_hash.to_string(),
            entry_hash: String::new(),
        };
        entry.compute_hash();
        entry
    }

    /// Compute hash of this entry (including previous hash for chaining)
    fn compute_hash(&mut self) {
        // Serialize entry without the hash field
        let hash_input = format!(
            "{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{:?}|{:?}|{}",
            self.id,
            self.timestamp,
            self.event_type,
            self.entry_id,
            self.entry_name,
            self.category,
            self.agent_id,
            self.origin_chain,
            self.purpose,
            self.granted,
            self.denial_reason,
            self.target_domain,
            self.previous_hash,
        );
        
        let hash = blake3::hash(hash_input.as_bytes());
        self.entry_hash = hash.to_hex().to_string();
    }

    /// Verify this entry's hash is valid
    pub fn verify_hash(&self) -> bool {
        let mut check = self.clone();
        check.entry_hash = String::new();
        check.compute_hash();
        check.entry_hash == self.entry_hash
    }

    // Builder methods
    pub fn with_entry(mut self, id: Uuid, name: impl Into<String>) -> Self {
        self.entry_id = Some(id);
        self.entry_name = Some(name.into());
        self.compute_hash();
        self
    }

    pub fn with_category(mut self, category: Category) -> Self {
        self.category = Some(category);
        self.compute_hash();
        self
    }

    pub fn with_agent(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self.compute_hash();
        self
    }

    pub fn with_origin_chain(mut self, chain: Vec<String>) -> Self {
        self.origin_chain = Some(chain);
        self.compute_hash();
        self
    }

    pub fn with_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self.compute_hash();
        self
    }

    pub fn denied(mut self, reason: impl Into<String>) -> Self {
        self.granted = false;
        self.denial_reason = Some(reason.into());
        self.compute_hash();
        self
    }

    pub fn with_target_domain(mut self, domain: impl Into<String>) -> Self {
        self.target_domain = Some(domain.into());
        self.compute_hash();
        self
    }
}

/// Audit log manager
pub struct AuditLog {
    path: PathBuf,
    key: SecureKey,
    last_hash: String,
}

impl AuditLog {
    /// Genesis hash for new audit logs
    const GENESIS_HASH: &'static str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// Create or open an audit log
    pub fn open(path: impl AsRef<Path>, key: SecureKey) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        
        let last_hash = if path.exists() {
            // Read last entry to get its hash
            Self::read_last_hash(&path, &key)?
        } else {
            Self::GENESIS_HASH.to_string()
        };
        
        Ok(Self { path, key, last_hash })
    }

    /// Read the hash of the last entry in the log
    fn read_last_hash(path: &Path, key: &SecureKey) -> Result<String> {
        let encrypted = fs::read(path)?;
        if encrypted.is_empty() {
            return Ok(Self::GENESIS_HASH.to_string());
        }
        
        let decrypted = decrypt(&encrypted, key)?;
        let content = String::from_utf8(decrypted)?;
        
        // Get last non-empty line
        if let Some(last_line) = content.lines().filter(|l| !l.is_empty()).last() {
            let entry: AuditEntry = serde_json::from_str(last_line)?;
            Ok(entry.entry_hash)
        } else {
            Ok(Self::GENESIS_HASH.to_string())
        }
    }

    /// Append an entry to the log
    pub fn append(&mut self, mut entry: AuditEntry) -> Result<()> {
        // Update previous hash and recompute
        entry.previous_hash = self.last_hash.clone();
        entry.entry_hash = String::new();
        entry.compute_hash();
        
        // Serialize entry
        let line = serde_json::to_string(&entry)? + "\n";
        
        // Read existing content, decrypt, append, re-encrypt
        let mut content = if self.path.exists() {
            let encrypted = fs::read(&self.path)?;
            if encrypted.is_empty() {
                String::new()
            } else {
                String::from_utf8(decrypt(&encrypted, &self.key)?)?
            }
        } else {
            String::new()
        };
        
        content.push_str(&line);
        
        // Re-encrypt and save
        let encrypted = encrypt(content.as_bytes(), &self.key)?;
        fs::write(&self.path, &encrypted)?;
        
        self.last_hash = entry.entry_hash;
        Ok(())
    }

    /// Log a vault unlock event
    pub fn log_unlock(&mut self) -> Result<()> {
        let entry = AuditEntry::new(AuditEventType::VaultUnlock, &self.last_hash);
        self.append(entry)
    }

    /// Log a vault lock event
    pub fn log_lock(&mut self) -> Result<()> {
        let entry = AuditEntry::new(AuditEventType::VaultLock, &self.last_hash);
        self.append(entry)
    }

    /// Log an entry access event
    pub fn log_access(
        &mut self,
        entry_id: Uuid,
        entry_name: &str,
        category: Category,
        agent_id: Option<&str>,
        purpose: Option<&str>,
    ) -> Result<()> {
        let mut entry = AuditEntry::new(AuditEventType::EntryAccess, &self.last_hash)
            .with_entry(entry_id, entry_name)
            .with_category(category);
        
        if let Some(agent) = agent_id {
            entry = entry.with_agent(agent);
        }
        if let Some(p) = purpose {
            entry = entry.with_purpose(p);
        }
        
        self.append(entry)
    }

    /// Log an access denial
    pub fn log_denial(
        &mut self,
        reason: &str,
        agent_id: Option<&str>,
        category: Option<Category>,
    ) -> Result<()> {
        let mut entry = AuditEntry::new(AuditEventType::AccessDenied, &self.last_hash)
            .denied(reason);
        
        if let Some(agent) = agent_id {
            entry = entry.with_agent(agent);
        }
        if let Some(cat) = category {
            entry = entry.with_category(cat);
        }
        
        self.append(entry)
    }

    /// Read all entries
    pub fn read_all(&self) -> Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        
        let encrypted = fs::read(&self.path)?;
        if encrypted.is_empty() {
            return Ok(Vec::new());
        }
        
        let decrypted = decrypt(&encrypted, &self.key)?;
        let content = String::from_utf8(decrypted)?;
        
        let mut entries = Vec::new();
        for line in content.lines() {
            if !line.is_empty() {
                let entry: AuditEntry = serde_json::from_str(line)?;
                entries.push(entry);
            }
        }
        
        Ok(entries)
    }

    /// Verify the entire chain integrity
    pub fn verify_chain(&self) -> Result<bool> {
        let entries = self.read_all()?;
        
        let mut expected_prev = Self::GENESIS_HASH.to_string();
        
        for entry in entries {
            // Check previous hash matches
            if entry.previous_hash != expected_prev {
                return Ok(false);
            }
            
            // Verify entry's own hash
            if !entry.verify_hash() {
                return Ok(false);
            }
            
            expected_prev = entry.entry_hash;
        }
        
        Ok(true)
    }

    /// Get entries from last N hours
    pub fn recent_entries(&self, hours: i64) -> Result<Vec<AuditEntry>> {
        let cutoff = Utc::now() - chrono::Duration::hours(hours);
        let entries = self.read_all()?;
        
        Ok(entries.into_iter()
            .filter(|e| e.timestamp >= cutoff)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::crypto::SecureKey;

    #[test]
    fn test_audit_log_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("audit.enc");
        let key = SecureKey::generate();
        
        let mut log = AuditLog::open(&path, key.clone()).unwrap();
        
        log.log_unlock().unwrap();
        log.log_access(
            Uuid::new_v4(),
            "Gmail",
            Category::Authentication,
            Some("email-agent"),
            Some("send email"),
        ).unwrap();
        log.log_lock().unwrap();
        
        let entries = log.read_all().unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_hash_chain_integrity() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("audit.enc");
        let key = SecureKey::generate();
        
        let mut log = AuditLog::open(&path, key.clone()).unwrap();
        
        log.log_unlock().unwrap();
        log.log_lock().unwrap();
        
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn test_entry_hash_verification() {
        let entry = AuditEntry::new(AuditEventType::VaultUnlock, "genesis");
        assert!(entry.verify_hash());
        
        // Tamper with entry
        let mut tampered = entry.clone();
        tampered.granted = false;
        // Hash should no longer match
        assert!(!tampered.verify_hash());
    }
}
