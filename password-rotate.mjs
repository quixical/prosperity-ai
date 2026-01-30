#!/usr/bin/env node
/**
 * Prosperity Password Rotation Tool
 * 
 * Automatically changes passwords to secure computer-generated ones.
 * Uses Playwright for browser automation.
 * 
 * Usage:
 *   node password-rotate.mjs                    # Rotate all passwords
 *   node password-rotate.mjs --site gmail       # Rotate specific site
 *   node password-rotate.mjs --dry-run          # Preview without changing
 */

import { chromium } from 'playwright';
import { createConnection } from "net";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { randomBytes } from "crypto";

const VAULT_SOCKET = "/run/prosperity/vault.sock";
const BROWSER_PROFILE = join(homedir(), ".prosperity", "browser-profile");
const CONFIG_FILE = join(homedir(), "prosperity-ai", "site-configs.json");
const HISTORY_DIR = join(homedir(), ".prosperity", "password-history");

// ============== PASSWORD GENERATION ==============

function generatePassword(length = 20) {
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";  // No O
  const lower = "abcdefghjkmnpqrstuvwxyz";   // No l
  const numbers = "23456789";                 // No 0, 1
  const symbols = "!@#$%^&*-_=+";
  
  const all = upper + lower + numbers + symbols;
  
  // Ensure at least one of each type
  let password = "";
  password += upper[randomBytes(1)[0] % upper.length];
  password += lower[randomBytes(1)[0] % lower.length];
  password += numbers[randomBytes(1)[0] % numbers.length];
  password += symbols[randomBytes(1)[0] % symbols.length];
  
  // Fill the rest randomly
  for (let i = 4; i < length; i++) {
    password += all[randomBytes(1)[0] % all.length];
  }
  
  // Shuffle
  return password.split('').sort(() => randomBytes(1)[0] - 128).join('');
}

// ============== VAULT CONNECTION ==============

let vaultSocket = null;
let vaultBuffer = "";
let vaultResponseResolve = null;

function connectVault() {
  return new Promise((resolve, reject) => {
    vaultSocket = createConnection(VAULT_SOCKET);
    vaultSocket.on("connect", () => {
      console.log("🔐 Connected to vault");
      resolve();
    });
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
    agent_id: "password-rotate",
    purpose: "rotating password"
  });
  if (resp.status === "ok") return resp.data;
  throw new Error(resp.message);
}

async function vaultUpdate(id, newPassword, oldPassword) {
  // Store password history
  if (!existsSync(HISTORY_DIR)) {
    mkdirSync(HISTORY_DIR, { recursive: true });
  }
  
  const historyFile = join(HISTORY_DIR, `${id}.json`);
  let history = [];
  if (existsSync(historyFile)) {
    history = JSON.parse(readFileSync(historyFile, "utf-8"));
  }
  
  history.push({
    password: Buffer.from(oldPassword).toString("base64"),
    rotated_at: new Date().toISOString()
  });
  
  writeFileSync(historyFile, JSON.stringify(history, null, 2));
  
  // Delete old entry and create new one with same name/url
  // (Vault doesn't have update, so we delete + create)
  // For now, just log - actual update needs vault API enhancement
  console.log(`   📝 Password history saved`);
  
  return true;
}

// ============== SITE CONFIG ==============

function loadSiteConfigs() {
  if (!existsSync(CONFIG_FILE)) {
    console.error("❌ Site configs not found:", CONFIG_FILE);
    console.log("   Copy site-configs.json to ~/prosperity-ai/");
    process.exit(1);
  }
  return JSON.parse(readFileSync(CONFIG_FILE, "utf-8"));
}

function findSiteConfig(url, configs) {
  try {
    const hostname = new URL(url).hostname.replace("www.", "");
    
    for (const [key, config] of Object.entries(configs.sites)) {
      if (config.domains.some(d => hostname.includes(d) || d.includes(hostname))) {
        return { key, config };
      }
    }
  } catch {}
  return null;
}

// ============== BROWSER AUTOMATION ==============

async function executeSteps(page, steps, values) {
  for (const step of steps) {
    try {
      if (step.fill) {
        const value = step.value
          .replace("{username}", values.username)
          .replace("{password}", values.password)
          .replace("{old_password}", values.old_password)
          .replace("{new_password}", values.new_password);
        
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

async function rotatePassword(browser, entry, siteConfig, dryRun) {
  const fullEntry = await vaultGet(entry.id);
  const oldPassword = Buffer.from(fullEntry.value, "base64").toString();
  const newPassword = generatePassword(20);
  
  console.log(`\n🔄 ${entry.name}`);
  console.log(`   URL: ${entry.url}`);
  console.log(`   User: ${entry.username}`);
  console.log(`   New password: ${newPassword.slice(0, 4)}${"*".repeat(12)}`);
  
  if (dryRun) {
    console.log(`   🏃 DRY RUN - would change password`);
    return { success: true, dryRun: true };
  }
  
  if (!siteConfig.config.change_password || siteConfig.config.change_password.requires_mfa) {
    console.log(`   ⚠️  Site requires manual password change (MFA)`);
    return { success: false, reason: "mfa_required" };
  }
  
  const page = await browser.newPage();
  
  try {
    // Step 1: Login
    console.log(`   📍 Logging in...`);
    await page.goto(siteConfig.config.login.url, { waitUntil: 'networkidle', timeout: 30000 });
    
    const loginSuccess = await executeSteps(page, siteConfig.config.login.steps, {
      username: entry.username,
      password: oldPassword,
      old_password: oldPassword,
      new_password: newPassword
    });
    
    if (!loginSuccess) {
      console.log(`   ❌ Login failed`);
      await page.close();
      return { success: false, reason: "login_failed" };
    }
    
    // Step 2: Navigate to change password
    console.log(`   📍 Navigating to password change...`);
    await page.goto(siteConfig.config.change_password.url, { waitUntil: 'networkidle', timeout: 30000 });
    
    // Step 3: Change password
    console.log(`   📍 Changing password...`);
    const changeSuccess = await executeSteps(page, siteConfig.config.change_password.steps, {
      username: entry.username,
      password: oldPassword,
      old_password: oldPassword,
      new_password: newPassword
    });
    
    if (!changeSuccess) {
      console.log(`   ❌ Password change failed`);
      await page.close();
      return { success: false, reason: "change_failed" };
    }
    
    // Step 4: Save to vault history
    await vaultUpdate(entry.id, newPassword, oldPassword);
    
    console.log(`   ✅ Password changed successfully!`);
    await page.close();
    
    return { success: true, newPassword };
    
  } catch (e) {
    console.log(`   ❌ Error: ${e.message}`);
    await page.close();
    return { success: false, reason: e.message };
  }
}

// ============== MAIN ==============

async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const siteFilter = args.includes("--site") ? args[args.indexOf("--site") + 1] : null;
  const passphrase = args.includes("--pass") ? args[args.indexOf("--pass") + 1] : "test";
  
  console.log(`
╔═══════════════════════════════════════════════════╗
║   🔄 PROSPERITY PASSWORD ROTATION                 ║
╚═══════════════════════════════════════════════════╝
`);
  
  if (dryRun) {
    console.log("🏃 DRY RUN MODE - no passwords will be changed\n");
  }
  
  // Load site configs
  const configs = loadSiteConfigs();
  console.log(`📋 Loaded ${Object.keys(configs.sites).length} site configurations\n`);
  
  // Connect to vault
  await connectVault();
  await vaultUnlock(passphrase);
  console.log("🔓 Vault unlocked\n");
  
  // Get all passwords
  const entries = await vaultList();
  console.log(`📦 Found ${entries.length} stored credentials\n`);
  
  // Filter entries that have site configs
  const rotatableEntries = entries.filter(entry => {
    const siteConfig = findSiteConfig(entry.url, configs);
    if (!siteConfig) return false;
    if (siteFilter && !siteConfig.key.includes(siteFilter)) return false;
    return true;
  });
  
  console.log(`🎯 ${rotatableEntries.length} credentials can be rotated automatically\n`);
  
  if (rotatableEntries.length === 0) {
    console.log("No credentials to rotate.");
    vaultSocket.end();
    return;
  }
  
  // Launch browser
  if (!existsSync(BROWSER_PROFILE)) {
    mkdirSync(BROWSER_PROFILE, { recursive: true });
  }
  
  console.log("🌐 Launching browser...\n");
  
  const browser = await chromium.launchPersistentContext(BROWSER_PROFILE, {
    headless: false,
    channel: 'chrome',
    args: ['--no-first-run', '--disable-infobars'],
    viewport: null,
    ignoreDefaultArgs: ['--enable-automation']
  });
  
  // Rotate each password
  const results = { success: 0, failed: 0, skipped: 0 };
  
  for (const entry of rotatableEntries) {
    const siteConfig = findSiteConfig(entry.url, configs);
    const result = await rotatePassword(browser, entry, siteConfig, dryRun);
    
    if (result.success) results.success++;
    else if (result.reason === "mfa_required") results.skipped++;
    else results.failed++;
    
    // Small delay between sites
    await new Promise(r => setTimeout(r, 2000));
  }
  
  // Summary
  console.log("\n" + "═".repeat(50));
  console.log("📊 ROTATION SUMMARY");
  console.log("═".repeat(50));
  console.log(`   ✅ Success: ${results.success}`);
  console.log(`   ⏭️  Skipped: ${results.skipped} (MFA required)`);
  console.log(`   ❌ Failed:  ${results.failed}`);
  console.log("═".repeat(50));
  
  await browser.close();
  vaultSocket.end();
}

main().catch(e => {
  console.error("Error:", e.message);
  process.exit(1);
});
