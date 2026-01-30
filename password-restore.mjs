#!/usr/bin/env node
/**
 * Prosperity Password Restore Tool
 * 
 * Restores passwords from backup to Chrome-compatible CSV format.
 * Use this if you need to go back to Chrome's password manager.
 * 
 * Usage:
 *   node password-restore.mjs                     # List available backups
 *   node password-restore.mjs --latest            # Restore latest backup
 *   node password-restore.mjs --file <backup>     # Restore specific backup
 */

import { readFileSync, writeFileSync, readdirSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";

const BACKUP_DIR = join(homedir(), ".prosperity", "backups");
const OUTPUT_DIR = join(homedir(), "Downloads");

function listBackups() {
  if (!existsSync(BACKUP_DIR)) {
    console.log("No backups found.");
    return [];
  }
  
  const files = readdirSync(BACKUP_DIR)
    .filter(f => f.startsWith("import-") && f.endsWith(".json"))
    .sort()
    .reverse();
  
  return files;
}

function loadBackup(filename) {
  const filepath = join(BACKUP_DIR, filename);
  if (!existsSync(filepath)) {
    throw new Error(`Backup not found: ${filepath}`);
  }
  return JSON.parse(readFileSync(filepath, "utf-8"));
}

function restoreToCSV(backup, outputPath) {
  // Chrome CSV format: name,url,username,password
  const lines = ["name,url,username,password"];
  
  for (const entry of backup.entries) {
    const password = Buffer.from(entry.original_password, "base64").toString();
    
    // Escape fields that might contain commas
    const escapedName = entry.name.includes(",") ? `"${entry.name}"` : entry.name;
    const escapedUrl = entry.url.includes(",") ? `"${entry.url}"` : entry.url;
    const escapedUser = entry.username.includes(",") ? `"${entry.username}"` : entry.username;
    const escapedPass = password.includes(",") ? `"${password}"` : password;
    
    lines.push(`${escapedName},${escapedUrl},${escapedUser},${escapedPass}`);
  }
  
  writeFileSync(outputPath, lines.join("\n"));
  return outputPath;
}

async function main() {
  const args = process.argv.slice(2);
  
  console.log(`
╔═══════════════════════════════════════════════════╗
║   🔙 PROSPERITY PASSWORD RESTORE                  ║
╚═══════════════════════════════════════════════════╝
`);
  
  // List backups
  const backups = listBackups();
  
  if (backups.length === 0) {
    console.log("❌ No backups found in", BACKUP_DIR);
    console.log("   Run password-import.mjs first to create a backup.");
    return;
  }
  
  // If no args, just list backups
  if (args.length === 0) {
    console.log("📦 Available backups:\n");
    backups.forEach((b, i) => {
      const backup = loadBackup(b);
      console.log(`   ${i + 1}. ${b}`);
      console.log(`      Imported: ${backup.imported_at}`);
      console.log(`      Entries:  ${backup.count}`);
      console.log(`      Source:   ${backup.source}`);
      console.log("");
    });
    
    console.log("To restore, run:");
    console.log("   node password-restore.mjs --latest");
    console.log("   node password-restore.mjs --file <backup-filename>");
    return;
  }
  
  // Determine which backup to restore
  let backupFile;
  
  if (args.includes("--latest")) {
    backupFile = backups[0];
  } else if (args.includes("--file")) {
    backupFile = args[args.indexOf("--file") + 1];
  } else {
    console.log("Usage:");
    console.log("   node password-restore.mjs                  # List backups");
    console.log("   node password-restore.mjs --latest         # Restore latest");
    console.log("   node password-restore.mjs --file <name>    # Restore specific");
    return;
  }
  
  console.log(`📂 Loading backup: ${backupFile}\n`);
  
  const backup = loadBackup(backupFile);
  
  console.log(`   Imported at: ${backup.imported_at}`);
  console.log(`   Entries:     ${backup.count}`);
  console.log(`   Source:      ${backup.source}`);
  console.log("");
  
  // Create restore CSV
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const outputPath = join(OUTPUT_DIR, `restored-passwords-${timestamp}.csv`);
  
  restoreToCSV(backup, outputPath);
  
  console.log("✅ Passwords restored!\n");
  console.log(`📄 Output: ${outputPath}\n`);
  console.log("To import back into Chrome:");
  console.log("   1. Open Chrome → Settings → Passwords");
  console.log("   2. Click ⋮ → Import passwords");
  console.log("   3. Select the restored CSV file");
  console.log("");
  console.log("⚠️  Delete the CSV after importing:");
  console.log(`   rm "${outputPath}"`);
}

main().catch(e => {
  console.error("Error:", e.message);
  process.exit(1);
});
