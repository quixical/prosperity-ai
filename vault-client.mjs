/**
 * Prosperity Vault Client
 * 
 * Node.js client for communicating with the Rust vault daemon
 * via Unix socket.
 */

import { createConnection } from "net";
import { promisify } from "util";
import { EventEmitter } from "events";

const SOCKET_PATH = "/run/prosperity/vault.sock";

class VaultClient extends EventEmitter {
  constructor(socketPath = SOCKET_PATH) {
    super();
    this.socketPath = socketPath;
    this.socket = null;
    this.connected = false;
    this.buffer = "";
  }

  /**
   * Connect to the vault daemon
   */
  connect() {
    return new Promise((resolve, reject) => {
      this.socket = createConnection(this.socketPath);

      this.socket.on("connect", () => {
        this.connected = true;
        console.log("🔐 Connected to vault daemon");
        resolve();
      });

      this.socket.on("data", (data) => {
        this.buffer += data.toString();
        // Process complete JSON lines
        const lines = this.buffer.split("\n");
        this.buffer = lines.pop(); // Keep incomplete line in buffer
        for (const line of lines) {
          if (line.trim()) {
            try {
              const response = JSON.parse(line);
              this.emit("response", response);
            } catch (e) {
              console.error("Invalid JSON from vault:", line);
            }
          }
        }
      });

      this.socket.on("error", (err) => {
        this.connected = false;
        if (err.code === "ENOENT") {
          reject(new Error("Vault daemon not running. Start it with: prosperity-vault"));
        } else if (err.code === "ECONNREFUSED") {
          reject(new Error("Vault daemon refused connection"));
        } else {
          reject(err);
        }
      });

      this.socket.on("close", () => {
        this.connected = false;
        this.emit("disconnected");
      });
    });
  }

  /**
   * Disconnect from vault
   */
  disconnect() {
    if (this.socket) {
      this.socket.end();
      this.socket = null;
      this.connected = false;
    }
  }

  /**
   * Send a command and wait for response
   */
  send(command) {
    return new Promise((resolve, reject) => {
      if (!this.connected) {
        reject(new Error("Not connected to vault"));
        return;
      }

      const timeout = setTimeout(() => {
        reject(new Error("Vault request timeout"));
      }, 30000);

      const handler = (response) => {
        clearTimeout(timeout);
        this.removeListener("response", handler);
        resolve(response);
      };

      this.once("response", handler);
      this.socket.write(JSON.stringify(command) + "\n");
    });
  }

  /**
   * Check vault status
   */
  async status() {
    const resp = await this.send({ cmd: "status" });
    if (resp.status === "ok") {
      return resp.data;
    }
    throw new Error(resp.message || "Status check failed");
  }

  /**
   * Unlock the vault with passphrase
   */
  async unlock(passphrase, categories = null) {
    const cmd = { cmd: "unlock", passphrase };
    if (categories) {
      cmd.categories = categories;
    }
    const resp = await this.send(cmd);
    if (resp.status === "ok") {
      return true;
    }
    throw new Error(resp.message || "Unlock failed");
  }

  /**
   * Lock the vault
   */
  async lock() {
    const resp = await this.send({ cmd: "lock" });
    if (resp.status === "ok") {
      return true;
    }
    throw new Error(resp.message || "Lock failed");
  }

  /**
   * List entries in a category
   */
  async list(category) {
    const resp = await this.send({ cmd: "list", category });
    if (resp.status === "ok") {
      return resp.data || [];
    }
    throw new Error(resp.message || "List failed");
  }

  /**
   * Get an entry by ID
   */
  async get(id, agentId = null, purpose = null) {
    const cmd = { cmd: "get", id };
    if (agentId) cmd.agent_id = agentId;
    if (purpose) cmd.purpose = purpose;
    
    const resp = await this.send(cmd);
    if (resp.status === "ok") {
      return resp.data;
    }
    throw new Error(resp.message || "Get failed");
  }

  /**
   * Create a new entry
   */
  async create(entry) {
    // Encode value as base64
    const value = Buffer.from(entry.value).toString("base64");
    
    const resp = await this.send({
      cmd: "create",
      entry: {
        category: entry.category,
        entry_type: entry.entryType || "password",
        name: entry.name,
        value: value,
        username: entry.username || null,
        url: entry.url || null,
      }
    });
    
    if (resp.status === "ok") {
      return resp.data?.id;
    }
    throw new Error(resp.message || "Create failed");
  }

  /**
   * Delete an entry
   */
  async delete(id) {
    const resp = await this.send({ cmd: "delete", id });
    if (resp.status === "ok") {
      return true;
    }
    throw new Error(resp.message || "Delete failed");
  }

  /**
   * Use credential for auth (without exposing value)
   */
  async useForAuth(id, targetUrl, agentId, purpose) {
    const resp = await this.send({
      cmd: "use_for_auth",
      id,
      target_url: targetUrl,
      agent_id: agentId,
      purpose
    });
    if (resp.status === "ok") {
      return resp.data;
    }
    throw new Error(resp.message || "Auth failed");
  }
}

export { VaultClient };
export default VaultClient;
