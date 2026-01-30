//! Unix socket API for vault daemon
//! 
//! Provides JSON-RPC style interface for:
//! - Vault unlock/lock
//! - Entry CRUD
//! - Credential use (without exposing values)

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use uuid::Uuid;

use std::path::Path;
use std::sync::Arc;

use crate::vault::{Category, EntryMetadata, EntryType, Vault, VaultEntry};
use crate::audit::AuditLog;
use crate::crypto::{SecureKey, derive_subkey};

/// API request types
#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    // Vault operations
    Unlock { passphrase: String, categories: Option<Vec<Category>> },
    Lock,
    Status,
    
    // Entry operations
    List { category: Category },
    Get { id: Uuid, agent_id: Option<String>, purpose: Option<String> },
    Create { entry: NewEntryRequest },
    Delete { id: Uuid },
    
    // Auth operations (credential used without returning value)
    UseForAuth { id: Uuid, target_url: String, agent_id: String, purpose: String },
}

/// Request to create a new entry
#[derive(Debug, Deserialize)]
pub struct NewEntryRequest {
    pub category: Category,
    pub entry_type: EntryType,
    pub name: String,
    pub value: String,  // Base64 encoded
    pub username: Option<String>,
    pub url: Option<String>,
}

/// API response types
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok { data: Option<serde_json::Value> },
    Error { message: String },
}

impl Response {
    pub fn ok() -> Self {
        Self::Ok { data: None }
    }

    pub fn ok_with<T: Serialize>(data: T) -> Self {
        Self::Ok { 
            data: Some(serde_json::to_value(data).unwrap_or(serde_json::Value::Null))
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self::Error { message: msg.into() }
    }
}

/// Vault daemon state
pub struct VaultDaemon {
    vault: Option<Vault>,
    audit: Option<AuditLog>,
    vault_path: std::path::PathBuf,
}

impl VaultDaemon {
    pub fn new(vault_path: impl AsRef<Path>) -> Self {
        Self {
            vault: None,
            audit: None,
            vault_path: vault_path.as_ref().to_path_buf(),
        }
    }

    /// Handle a request
    pub async fn handle(&mut self, req: Request) -> Response {
        match req {
            Request::Unlock { passphrase, categories } => {
                self.handle_unlock(&passphrase, categories).await
            }
            Request::Lock => self.handle_lock().await,
            Request::Status => self.handle_status(),
            Request::List { category } => self.handle_list(category).await,
            Request::Get { id, agent_id, purpose } => {
                self.handle_get(id, agent_id, purpose).await
            }
            Request::Create { entry } => self.handle_create(entry).await,
            Request::Delete { id } => self.handle_delete(id).await,
            Request::UseForAuth { id, target_url, agent_id, purpose } => {
                self.handle_use_for_auth(id, target_url, agent_id, purpose).await
            }
        }
    }

    async fn handle_unlock(&mut self, passphrase: &str, categories: Option<Vec<Category>>) -> Response {
        // Try to open existing vault or create new one
        let vault_result = if self.vault_path.exists() {
            let mut vault = match Vault::open(&self.vault_path) {
                Ok(v) => v,
                Err(e) => return Response::error(format!("Failed to open vault: {}", e)),
            };
            
            if let Some(cats) = categories {
                match vault.unlock_categories(passphrase, &cats) {
                    Ok(()) => Ok(vault),
                    Err(e) => Err(e),
                }
            } else {
                match vault.unlock(passphrase) {
                    Ok(()) => Ok(vault),
                    Err(e) => Err(e),
                }
            }
        } else {
            Vault::create(&self.vault_path, passphrase)
        };

        match vault_result {
            Ok(vault) => {
                // Initialize audit log
                let master_key = crate::crypto::derive_master_key(
                    passphrase, 
                    &[0u8; 32] // Would get from vault meta
                ).ok();
                
                if let Some(mk) = master_key {
                    let audit_key = derive_subkey(&mk, "audit");
                    let audit_path = self.vault_path.join("audit.enc");
                    self.audit = AuditLog::open(&audit_path, audit_key).ok();
                    
                    if let Some(ref mut audit) = self.audit {
                        let _ = audit.log_unlock();
                    }
                }
                
                self.vault = Some(vault);
                Response::ok()
            }
            Err(e) => Response::error(format!("Unlock failed: {}", e)),
        }
    }

    async fn handle_lock(&mut self) -> Response {
        if let Some(ref mut vault) = self.vault {
            if let Some(ref mut audit) = self.audit {
                let _ = audit.log_lock();
            }
            vault.lock();
            self.vault = None;
            self.audit = None;
            Response::ok()
        } else {
            Response::error("Vault not unlocked")
        }
    }

    fn handle_status(&self) -> Response {
        #[derive(Serialize)]
        struct Status {
            unlocked: bool,
            vault_exists: bool,
        }
        
        Response::ok_with(Status {
            unlocked: self.vault.as_ref().map(|v| v.is_unlocked()).unwrap_or(false),
            vault_exists: self.vault_path.exists(),
        })
    }

    async fn handle_list(&mut self, category: Category) -> Response {
        let vault = match self.vault.as_mut() {
            Some(v) if v.is_unlocked() => v,
            _ => return Response::error("Vault not unlocked"),
        };

        match vault.list_entries(category) {
            Ok(entries) => Response::ok_with(entries),
            Err(e) => Response::error(format!("List failed: {}", e)),
        }
    }

    async fn handle_get(
        &mut self,
        id: Uuid,
        agent_id: Option<String>,
        purpose: Option<String>,
    ) -> Response {
        let vault = match self.vault.as_mut() {
            Some(v) if v.is_unlocked() => v,
            _ => return Response::error("Vault not unlocked"),
        };

        match vault.get_entry(&id) {
            Ok(Some(entry)) => {
                // Log access
                if let Some(ref mut audit) = self.audit {
                    let _ = audit.log_access(
                        id,
                        &entry.name,
                        entry.category,
                        agent_id.as_deref(),
                        purpose.as_deref(),
                    );
                }
                
                // Return handle (not raw value in production)
                // For now, return full entry
                Response::ok_with(entry)
            }
            Ok(None) => Response::error("Entry not found"),
            Err(e) => Response::error(format!("Get failed: {}", e)),
        }
    }

    async fn handle_create(&mut self, req: NewEntryRequest) -> Response {
        let vault = match self.vault.as_mut() {
            Some(v) if v.is_unlocked() => v,
            _ => return Response::error("Vault not unlocked"),
        };

        // Decode value
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let value = match STANDARD.decode(&req.value) {
            Ok(v) => v,
            Err(e) => return Response::error(format!("Invalid base64 value: {}", e)),
        };

        let mut entry = VaultEntry::new(req.category, req.entry_type, req.name, value);
        if let Some(username) = req.username {
            entry = entry.with_username(username);
        }
        if let Some(url) = req.url {
            entry = entry.with_url(url);
        }

        match vault.add_entry(entry) {
            Ok(id) => Response::ok_with(serde_json::json!({ "id": id })),
            Err(e) => Response::error(format!("Create failed: {}", e)),
        }
    }

    async fn handle_delete(&mut self, id: Uuid) -> Response {
        let vault = match self.vault.as_mut() {
            Some(v) if v.is_unlocked() => v,
            _ => return Response::error("Vault not unlocked"),
        };

        match vault.delete_entry(&id) {
            Ok(true) => Response::ok(),
            Ok(false) => Response::error("Entry not found"),
            Err(e) => Response::error(format!("Delete failed: {}", e)),
        }
    }

    async fn handle_use_for_auth(
        &mut self,
        id: Uuid,
        target_url: String,
        agent_id: String,
        purpose: String,
    ) -> Response {
        // In production, this would:
        // 1. Verify target_url matches entry's associated URL
        // 2. Check certificate pinning
        // 3. Make the HTTP request directly from daemon
        // 4. Return only success/failure (not the credential)
        
        // For now, just validate and return placeholder
        let vault = match self.vault.as_mut() {
            Some(v) if v.is_unlocked() => v,
            _ => return Response::error("Vault not unlocked"),
        };

        match vault.get_entry(&id) {
            Ok(Some(entry)) => {
                // Log the auth use
                if let Some(ref mut audit) = self.audit {
                    let _ = audit.log_access(
                        id,
                        &entry.name,
                        entry.category,
                        Some(&agent_id),
                        Some(&purpose),
                    );
                }
                
                // TODO: Actually perform auth
                // For now, indicate credential would be used
                Response::ok_with(serde_json::json!({
                    "auth_performed": false,
                    "message": "Auth execution not yet implemented",
                    "target": target_url,
                }))
            }
            Ok(None) => Response::error("Entry not found"),
            Err(e) => Response::error(format!("Auth failed: {}", e)),
        }
    }
}

/// Run the vault daemon on a Unix socket
pub async fn run_daemon(socket_path: impl AsRef<Path>, vault_path: impl AsRef<Path>) -> Result<()> {
    let socket_path = socket_path.as_ref();
    
    // Remove existing socket
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    
    // Create parent directory
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    let listener = UnixListener::bind(socket_path)?;
    
    // Set socket permissions (owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    }
    
    tracing::info!("Vault daemon listening on {:?}", socket_path);
    
    let daemon = Arc::new(Mutex::new(VaultDaemon::new(vault_path)));
    
    loop {
        let (stream, _) = listener.accept().await?;
        let daemon = Arc::clone(&daemon);
        
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, daemon).await {
                tracing::error!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(stream: UnixStream, daemon: Arc<Mutex<VaultDaemon>>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // Connection closed
        }
        
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => {
                let mut daemon = daemon.lock().await;
                daemon.handle(req).await
            }
            Err(e) => Response::error(format!("Invalid request: {}", e)),
        };
        
        let response_json = serde_json::to_string(&response)? + "\n";
        writer.write_all(response_json.as_bytes()).await?;
    }
    
    Ok(())
}
