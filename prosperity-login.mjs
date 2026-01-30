#!/usr/bin/env node
/**
 * Prosperity Login Tool
 * 
 * Logs into websites using credentials from the vault.
 * Uses Playwright for browser automation.
 * 
 * Usage:
 *   node prosperity-login.mjs gmail
 *   node prosperity-login.mjs netflix
 *   node prosperity-login.mjs chase
 */

import { chromium } from 'playwright';
import { createConnection } from "net";
import { readFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const VAULT_SOCKET = "/run/prosperity/vault.sock";
const BROWSER_PROFILE = join(homedir(), ".prosperity", "browser-profile");
const CONFIG_FILE = join(homedir(), "prosperity-ai", "site-configs.json");

// ============== VAULT CONNECTION ==============

let vaultSocket = null;
let vaultBuffer = "";
let vaultResponseResolve = null;
let browserContext = null;

function connectVault() {
  return new Promise((resolve, reject) => {
    vaultSocket = createConnection(VAULT_SOCKET);
    vaultSocket.on("connect", () => resolve());
    vaultSocket.on("data", (data) => {
      vaultBuffer += data.toString();
      const lines = vaultBuffer.split("\n");
      vaultBuffer = lines.pop();
      for (const line of lines) {
        if (line.trim() && vaultResponseResolve) {
          vaultResponseResolve(JSON.parse(line));
          vaultResponseResolve = null;
        }
      }
    });
    vaultSocket.on("error", () => reject(new Error("Vault not running")));
  });
}

function vaultSend(cmd) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Timeout")), 30000);
    vaultResponseResolve = (resp) => {
      clearTimeout(timeout);
      resolve(resp);
    };
    vaultSocket.write(JSON.stringify(cmd) + "\n");
  });
}

async function vaultUnlock(passphrase) {
  const resp = await vaultSend({ cmd: "unlock", passphrase });
  if (resp.status === "ok") return true;
  throw new Error(resp.message);
}

async function vaultList() {
  const resp = await vaultSend({ cmd: "list", category: "authentication" });
  return resp.status === "ok" ? resp.data || [] : [];
}

async function vaultGet(id) {
  const resp = await vaultSend({ 
    cmd: "get", 
    id, 
    agent_id: "prosperity-login",
    purpose: "automated login"
  });
  if (resp.status === "ok") return resp.data;
  throw new Error(resp.message);
}

// ============== SITE CONFIG ==============

function loadSiteConfigs() {
  if (!existsSync(CONFIG_FILE)) {
    console.error("❌ Site configs not found:", CONFIG_FILE);
    process.exit(1);
  }
  return JSON.parse(readFileSync(CONFIG_FILE, "utf-8"));
}

function findSiteConfig(siteName, configs) {
  const lower = siteName.toLowerCase();
  
  // Direct match
  if (configs.sites[lower]) {
    return { key: lower, config: configs.sites[lower] };
  }
  
  // Search by name or domain
  for (const [key, config] of Object.entries(configs.sites)) {
    if (config.name.toLowerCase().includes(lower) ||
        config.domains.some(d => d.includes(lower))) {
      return { key, config };
    }
  }
  
  return null;
}

function findCredential(siteConfig, entries) {
  for (const entry of entries) {
    try {
      const hostname = new URL(entry.url).hostname.replace("www.", "");
      if (siteConfig.config.domains.some(d => hostname.includes(d) || d.includes(hostname))) {
        return entry;
      }
    } catch {}
    
    // Also check by name
    if (entry.name.toLowerCase().includes(siteConfig.key)) {
      return entry;
    }
  }
  return null;
}

// ============== BROWSER AUTOMATION ==============

async function executeSteps(page, steps, values) {
  for (const step of steps) {
    try {
      if (step.fill) {
        const value = step.value
          .replace("{username}", values.username)
          .replace("{password}", values.password);
        
        await page.fill(step.fill, value, { timeout: 10000 });
      }
      
      if (step.click) {
        await page.click(step.click, { timeout: 10000 });
      }
      
      if (step.wait) {
        await page.waitForTimeout(step.wait);
      }
    } catch (e) {
      console.log(`   ⚠️  Step failed: ${e.message}`);
      return false;
    }
  }
  return true;
}

async function login(siteName, passphrase = "test") {
  console.log(`\n🔐 Logging into ${siteName}...\n`);
  
  // Load configs
  const configs = loadSiteConfigs();
  const siteConfig = findSiteConfig(siteName, configs);
  
  if (!siteConfig) {
    console.error(`❌ No config found for: ${siteName}`);
    console.log("\nAvailable sites:");
    Object.keys(configs.sites).forEach(s => console.log(`   - ${s}`));
    return false;
  }
  
  console.log(`📋 Found config: ${siteConfig.config.name}`);
  
  // Connect to vault
  await connectVault();
  await vaultUnlock(passphrase);
  console.log("🔓 Vault unlocked");
  
  // Find credential
  const entries = await vaultList();
  const entry = findCredential(siteConfig, entries);
  
  if (!entry) {
    console.error(`❌ No credential found for ${siteConfig.config.name}`);
    console.log("   Store a password for this site first.");
    vaultSocket.end();
    return false;
  }
  
  console.log(`👤 Found credential: ${entry.username}`);
  
  // Get full entry with password
  const fullEntry = await vaultGet(entry.id);
  const password = Buffer.from(fullEntry.value, "base64").toString();
  
  // Launch browser
  if (!existsSync(BROWSER_PROFILE)) {
    mkdirSync(BROWSER_PROFILE, { recursive: true });
  }
  
  console.log("🌐 Launching browser...");
  
  browserContext = await chromium.launchPersistentContext(BROWSER_PROFILE, {
    headless: false,
    channel: 'chrome',
    args: ['--no-first-run', '--disable-infobars'],
    viewport: null,
    ignoreDefaultArgs: ['--enable-automation']
  });
  
  const page = browserContext.pages()[0] || await browserContext.newPage();
  
  // Navigate and login
  console.log(`📍 Navigating to ${siteConfig.config.login.url}`);
  await page.goto(siteConfig.config.login.url, { waitUntil: 'networkidle', timeout: 30000 });
  
  console.log("🔑 Entering credentials...");
  const success = await executeSteps(page, siteConfig.config.login.steps, {
    username: entry.username,
    password: password
  });
  
  if (success) {
    console.log(`\n✅ Login successful!`);
    console.log("   Browser will stay open. Close it when done.\n");
  } else {
    console.log(`\n⚠️  Login may have failed. Check the browser.\n`);
  }
  
  // Keep browser open, close vault connection
  vaultSocket.end();
  
  // Wait for browser to close
  await new Promise(resolve => {
    browserContext.on('close', resolve);
  });
  
  return success;
}

// ============== MAIN ==============

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    console.log(`
╔═══════════════════════════════════════════════════╗
║   🔑 PROSPERITY LOGIN                             ║
╚═══════════════════════════════════════════════════╝

Usage: node prosperity-login.mjs <site>

Examples:
  node prosperity-login.mjs gmail
  node prosperity-login.mjs netflix
  node prosperity-login.mjs amazon
  node prosperity-login.mjs github

The tool will:
  ✓ Find your stored credential for that site
  ✓ Launch a browser
  ✓ Automatically log you in
  ✓ Keep the browser open for you to use
`);
    process.exit(0);
  }
  
  const siteName = args[0];
  const passphrase = args.includes("--pass") ? args[args.indexOf("--pass") + 1] : "test";
  
  try {
    await login(siteName, passphrase);
  } catch (e) {
    console.error(`\n❌ Error: ${e.message}`);
    if (browserContext) await browserContext.close();
    process.exit(1);
  }
}

main();
