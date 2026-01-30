#!/usr/bin/env node
/**
 * Prosperity AI - Voice Assistant v4
 * 
 * Architecture:
 *   HER (PersonaPlex-style) - What user sees and hears
 *   CLAUDE - Behind the scenes, toggle to reveal
 * 
 * Keys:
 *   SPACE = record
 *   S = stop speech  
 *   D = toggle Claude details
 *   Q = quit
 */

import { spawn, execSync } from "child_process";
import { readFileSync, unlinkSync, existsSync } from "fs";
import { tmpdir, homedir } from "os";
import { join } from "path";
import { createConnection } from "net";

const WHISPER = "/home/quixical/.prosperity-venv/bin/whisper";
const VOICE = "en-US-AriaNeural";
const SESSION_ID = "voice-session";
const VAULT_SOCKET = "/run/prosperity/vault.sock";

let recording = false;
let processing = false;
let recorder = null;
let ttsProcess = null;
let audioFile = "";
let lastKeyTime = 0;
let showDetails = false;  // D toggle state
let lastClaudeResponse = "";  // Store for toggle

// Vault state
let vaultSocket = null;
let vaultConnected = false;
let vaultUnlocked = false;
let vaultBuffer = "";
let vaultResponseResolve = null;

// ============== STALL PHRASES ==============

const STALL_PHRASES = {
  thinking: [
    "Hmm, let me think about that...",
    "Okay, give me just a sec...",
    "Good question, let me work on that...",
  ],
  searching: [
    "Let me check on that...",
    "One moment...",
    "Looking into it...",
  ],
  writing: [
    "Alright, working on it...",
    "Let me put something together...",
    "On it...",
  ],
  vault: [
    "Let me pull that up...",
    "Checking the vault...",
  ],
  complex: [
    "Hmm, I want to get this right...",
    "Let me figure this out...",
  ]
};

function getStallPhrase(type = "thinking") {
  const phrases = STALL_PHRASES[type] || STALL_PHRASES.thinking;
  return phrases[Math.floor(Math.random() * phrases.length)];
}

// ============== VAULT CLIENT ==============

function connectVault() {
  return new Promise((resolve) => {
    vaultSocket = createConnection(VAULT_SOCKET);
    
    vaultSocket.on("connect", () => {
      vaultConnected = true;
      resolve();
    });
    
    vaultSocket.on("data", (data) => {
      vaultBuffer += data.toString();
      const lines = vaultBuffer.split("\n");
      vaultBuffer = lines.pop();
      for (const line of lines) {
        if (line.trim() && vaultResponseResolve) {
          try {
            vaultResponseResolve(JSON.parse(line));
            vaultResponseResolve = null;
          } catch (e) {}
        }
      }
    });
    
    vaultSocket.on("error", () => {
      vaultConnected = false;
      resolve();
    });
    
    vaultSocket.on("close", () => {
      vaultConnected = false;
    });
  });
}

function vaultSend(cmd) {
  return new Promise((resolve, reject) => {
    if (!vaultConnected) return reject(new Error("Not connected"));
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
  if (resp.status === "ok") {
    vaultUnlocked = true;
    return true;
  }
  throw new Error(resp.message);
}

async function vaultLock() {
  const resp = await vaultSend({ cmd: "lock" });
  vaultUnlocked = false;
  return resp.status === "ok";
}

async function vaultList(category = "authentication") {
  const resp = await vaultSend({ cmd: "list", category });
  return resp.status === "ok" ? resp.data || [] : [];
}

async function vaultGet(id) {
  const resp = await vaultSend({ 
    cmd: "get", 
    id, 
    agent_id: "prosperity-voice",
    purpose: "user voice request"
  });
  if (resp.status === "ok") return resp.data;
  throw new Error(resp.message);
}

// ============== BROWSER ==============

function openBrowser(url) {
  if (!url.startsWith("http")) url = "https://" + url;
  try {
    execSync(`xdg-open "${url}" &`, { stdio: 'ignore' });
    return true;
  } catch (e) {
    return false;
  }
}

// ============== COMMAND ROUTER ==============

function classifyCommand(text) {
  const lower = text.toLowerCase();
  
  // Remove wake words/names first
  const cleaned = lower
    .replace(/^(hey|hi|hello|okay|ok)\s+(prosperity|assistant|computer)[,.]?\s*/i, "")
    .replace(/^(prosperity|assistant|computer)[,.]?\s*/i, "")
    .trim();
  
  // Local commands (fast) - check cleaned text
  if (cleaned.match(/(?:open|go to|launch)\s+\w+/)) return { type: "local", category: "browser" };
  
  // Vault commands - expanded patterns
  if (cleaned.match(/password/i) && cleaned.match(/(list|how many|count|show|all)/i)) return { type: "local", category: "vault_list" };
  if (cleaned.match(/(lock|close).*vault/i)) return { type: "local", category: "vault" };
  if (cleaned.match(/(unlock|open).*vault/i)) return { type: "local", category: "vault" };
  if (cleaned.match(/(get|show|what('?s| is)|find).*password.*for/i)) return { type: "local", category: "vault_get" };
  
  // Time
  if (cleaned.match(/what time|what's the time/)) return { type: "local", category: "time" };
  
  // Greetings - ONLY if the whole message is basically just a greeting
  if (cleaned.match(/^(hi|hello|hey|good morning|good afternoon|good evening|what'?s up|how are you)[.!?]?$/i)) {
    return { type: "local", category: "greeting" };
  }
  
  // Claude commands (complex)
  if (cleaned.includes("write") || cleaned.includes("draft") || cleaned.includes("email")) return { type: "claude", category: "writing" };
  if (cleaned.includes("analyze") || cleaned.includes("explain") || cleaned.includes("help me")) return { type: "claude", category: "thinking" };
  if (cleaned.includes("search") || cleaned.includes("find") || cleaned.includes("look up")) return { type: "claude", category: "searching" };
  
  // Default to Claude for unknown
  return { type: "claude", category: "thinking" };
}

// ============== LOCAL COMMAND HANDLING ==============

async function handleLocalCommand(text) {
  const lower = text.toLowerCase();
  
  // Remove wake words/names first
  const cleaned = lower
    .replace(/^(hey|hi|hello|okay|ok)\s+(prosperity|assistant|computer)[,.]?\s*/i, "")
    .replace(/^(prosperity|assistant|computer)[,.]?\s*/i, "")
    .trim();
  
  // Browser
  const browserMatch = cleaned.match(/(?:open|go to|launch)\s+(\w+)/);
  if (browserMatch) {
    const site = browserMatch[1];
    const urls = {
      youtube: "youtube.com", google: "google.com", gmail: "gmail.com",
      instagram: "instagram.com", facebook: "facebook.com", twitter: "twitter.com",
      amazon: "amazon.com", netflix: "netflix.com", reddit: "reddit.com",
      github: "github.com", linkedin: "linkedin.com", spotify: "spotify.com",
      twitch: "twitch.tv", chase: "chase.com",
    };
    
    if (urls[site]) {
      openBrowser(urls[site]);
      return { 
        her: `Opening ${site}.`,
        claude: `[browser] xdg-open https://${urls[site]}`
      };
    }
  }
  
  // Greetings - only if cleaned text is basically just a greeting
  if (cleaned.match(/^(hi|hello|hey|what'?s up|how are you)[.!?]?$/i)) {
    const greetings = ["Hey!", "Hi there!", "Hello!", "Hey, what's up?"];
    return {
      her: greetings[Math.floor(Math.random() * greetings.length)],
      claude: "[greeting] Responded to user greeting"
    };
  }
  
  if (cleaned.match(/^good morning[.!?]?$/i)) {
    return { her: "Good morning! What can I help you with?", claude: "[greeting] morning" };
  }
  
  if (cleaned.match(/^good afternoon[.!?]?$/i)) {
    return { her: "Good afternoon! What do you need?", claude: "[greeting] afternoon" };
  }
  
  if (cleaned.match(/^good evening[.!?]?$/i)) {
    return { her: "Good evening! How can I help?", claude: "[greeting] evening" };
  }
  
  // Time
  if (cleaned.match(/what time|what's the time/)) {
    const now = new Date();
    const time = now.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
    return {
      her: `It's ${time}.`,
      claude: `[time] ${now.toISOString()}`
    };
  }
  
  // Vault: get specific password (check BEFORE list - more specific first!)
  if (cleaned.match(/password/i) && cleaned.match(/for\s+(.+)/i)) {
    if (!vaultConnected || !vaultUnlocked) {
      return { her: "The vault isn't unlocked.", claude: "[vault] Status: locked" };
    }
    const match = cleaned.match(/for\s+(.+?)(?:\s+please)?\.?$/i);
    const searchTerm = match[1].trim().toLowerCase();
    const entries = await vaultList("authentication");
    
    // Search in name, url, AND username
    const entry = entries.find(e => {
      const name = (e.name || "").toLowerCase();
      const url = (e.url || "").toLowerCase();
      const username = (e.username || "").toLowerCase();
      
      return name.includes(searchTerm) || 
             url.includes(searchTerm) || 
             username.includes(searchTerm) ||
             searchTerm.includes(name.split("@")[0]) ||  // "earnest" matches "earnestconstruction@..."
             name.split("@")[0].includes(searchTerm.replace(/\s+/g, "")); // "terminally deficient" matches "terminallydeficient"
    });
    
    if (entry) {
      const full = await vaultGet(entry.id);
      const password = Buffer.from(full.value, "base64").toString();
      return { 
        her: `Found it. The password for ${entry.name} is on your screen.`,
        claude: `[vault] get ${entry.id}\n🔑 ${entry.name}\n   User: ${entry.username}\n   Pass: ${password}`
      };
    }
    return { 
      her: `I couldn't find a password matching ${searchTerm}.`,
      claude: `[vault] search "${searchTerm}" - not found`
    };
  }
  
  // Vault: list/count passwords (general - after specific)
  if (cleaned.match(/password/i) && cleaned.match(/(list|how many|count|all|have)/i) && !cleaned.match(/for\s+\w+/i)) {
    if (!vaultConnected || !vaultUnlocked) {
      return { her: "The vault isn't unlocked.", claude: "[vault] Status: locked" };
    }
    const entries = await vaultList("authentication");
    const count = entries.length;
    const sample = entries.slice(0, 5).map(e => e.name).join(", ");
    return { 
      her: `You have ${count} passwords.`,
      claude: `[vault] list authentication\nFound ${count} entries\nSample: ${sample}`
    };
  }
  
  // Vault: lock/unlock
  if (cleaned.match(/(lock|close).*vault/i)) {
    if (!vaultConnected) {
      return { her: "The vault isn't connected.", claude: "[vault] Not connected" };
    }
    await vaultLock();
    return { her: "Vault locked.", claude: "[vault] lock - success" };
  }
  
  if (cleaned.match(/(unlock|open).*vault/i)) {
    if (!vaultConnected) {
      return { her: "The vault isn't connected.", claude: "[vault] Not connected" };
    }
    try {
      await vaultUnlock("test");
      return { her: "Vault unlocked.", claude: "[vault] unlock - success" };
    } catch (e) {
      return { her: "Couldn't unlock the vault.", claude: `[vault] unlock - failed: ${e.message}` };
    }
  }
  
  return null;
}

// ============== CLAUDE HANDLING ==============

async function askClaude(question) {
  return new Promise((resolve) => {
    let response = "";
    
    const p = spawn("node", [
      "prosperity.mjs", 
      "agent", 
      "--local",
      "--session-id", SESSION_ID,
      "--message", question
    ], {
      cwd: "/home/quixical/prosperity-ai",
      stdio: ["ignore", "pipe", "pipe"]
    });
    
    p.stdout.on("data", (d) => response += d.toString());
    p.stderr.on("data", (d) => response += d.toString());
    
    p.on("close", () => {
      // Clean ANSI codes
      let clean = response
        .replace(/\x1b\[[0-9;]*m/g, "")
        .replace(/^.*?🦞.*?\n/gm, "")
        .trim();
      
      const lines = clean.split("\n");
      if (lines[0] && lines[0].includes("Moltbot")) lines.shift();
      clean = lines.join("\n").trim();
      
      resolve(clean || "Done.");
    });
    
    p.on("error", () => resolve("Something went wrong."));
    
    setTimeout(() => { 
      p.kill(); 
      resolve("Request timed out."); 
    }, 120000);
  });
}

function summarizeForHer(claudeResponse) {
  // Create a brief, natural summary of Claude's response
  const lines = claudeResponse.split("\n").filter(l => l.trim());
  
  // If it's short, just clean it up
  if (claudeResponse.length < 100) {
    // Remove technical stuff
    let clean = claudeResponse
      .replace(/\[.*?\]/g, "")
      .replace(/```[\s\S]*?```/g, "")
      .replace(/\$\s+\S+/g, "")
      .trim();
    return clean || "Done.";
  }
  
  // For longer responses, create a summary
  if (claudeResponse.includes("error") || claudeResponse.includes("Error")) {
    return "There was an issue. Check the details.";
  }
  
  if (claudeResponse.includes("Done") || claudeResponse.includes("success")) {
    return "Done.";
  }
  
  // Default brief response
  return "Done. The details are on screen if you need them.";
}

// ============== TTS ==============

async function speak(text) {
  if (!text || text.length < 2) return;
  
  const mp3 = join(tmpdir(), `tts-${Date.now()}.mp3`);
  
  try {
    const edgeTts = await import("node-edge-tts");
    const tts = new edgeTts.EdgeTTS({ voice: VOICE });
    await tts.ttsPromise(text, mp3);
    
    if (existsSync(mp3)) {
      ttsProcess = spawn("ffplay", ["-nodisp", "-autoexit", mp3], { stdio: 'ignore' });
      await new Promise(resolve => {
        ttsProcess.on("close", resolve);
        ttsProcess.on("error", resolve);
      });
      ttsProcess = null;
      try { unlinkSync(mp3); } catch {}
    }
  } catch (e) {}
}

function stopSpeech() {
  if (ttsProcess) {
    ttsProcess.kill();
    ttsProcess = null;
  }
}

// ============== TRANSCRIBE ==============

async function transcribe(file) {
  return new Promise((resolve) => {
    const out = tmpdir();
    const p = spawn(WHISPER, [
      file, "--model", "tiny", "--language", "en",
      "--output_format", "txt", "--output_dir", out
    ], { stdio: ["ignore", "pipe", "pipe"] });

    p.on("close", () => {
      try {
        const base = file.split("/").pop().replace(".wav", "");
        const txtFile = join(out, base + ".txt");
        if (existsSync(txtFile)) {
          const txt = readFileSync(txtFile, "utf-8").trim();
          try { unlinkSync(txtFile); } catch {}
          resolve(txt);
        } else {
          resolve("");
        }
      } catch {
        resolve("");
      }
    });
    p.on("error", () => resolve(""));
  });
}

// ============== DISPLAY ==============

function clearScreen() {
  process.stdout.write("\x1B[2J\x1B[H");
}

function displayResponse(her, claude) {
  lastClaudeResponse = claude;
  
  console.log("═══════════════════════════════════════════════════════════");
  console.log("🎙️  " + her);
  console.log("═══════════════════════════════════════════════════════════");
  
  if (showDetails && claude) {
    console.log("");
    console.log("┌─ Claude ─────────────────────────────────────────────────┐");
    const lines = claude.split("\n");
    lines.forEach(line => {
      console.log("│ " + line.substring(0, 56).padEnd(56) + " │");
    });
    console.log("└──────────────────────────────────────────────────────────┘");
  }
  console.log("");
}

function toggleDetails() {
  showDetails = !showDetails;
  if (lastClaudeResponse) {
    console.log("");
    if (showDetails) {
      console.log("┌─ Claude ─────────────────────────────────────────────────┐");
      const lines = lastClaudeResponse.split("\n");
      lines.forEach(line => {
        console.log("│ " + line.substring(0, 56).padEnd(56) + " │");
      });
      console.log("└──────────────────────────────────────────────────────────┘");
    } else {
      console.log("  [Details hidden]");
    }
    console.log("");
    showPrompt();
  }
}

// ============== RECORDING ==============

function startRec() {
  if (recording || processing) return;
  
  recording = true;
  audioFile = join(tmpdir(), `voice-${Date.now()}.wav`);
  console.log("\n🔴 Recording...\n");

  recorder = spawn("arecord", ["-f", "cd", "-t", "wav", "-r", "16000", "-c", "1", audioFile], {
    stdio: ["ignore", "ignore", "ignore"]
  });
  recorder.on("error", () => { recording = false; });
}

async function stopRec() {
  if (!recording) return;
  recording = false;

  if (recorder) {
    recorder.kill("SIGINT");
    recorder = null;
  }

  processing = true;
  await new Promise(r => setTimeout(r, 300));

  if (!existsSync(audioFile)) {
    processing = false;
    showPrompt();
    return;
  }

  console.log("📝 Transcribing...\n");
  const text = await transcribe(audioFile);
  try { unlinkSync(audioFile); } catch {}

  if (!text) {
    console.log("⚠️  No speech detected.\n");
    processing = false;
    showPrompt();
    return;
  }

  console.log(`💬 You: "${text}"\n`);
  
  // Classify the command
  const classification = classifyCommand(text);
  
  let her, claude;
  
  if (classification.type === "local") {
    // Handle locally (fast)
    const result = await handleLocalCommand(text);
    if (result) {
      her = result.her;
      claude = result.claude;
    } else {
      // Fallback to Claude if local handler returned null
      classification.type = "claude";
    }
  }
  
  if (classification.type === "claude") {
    // Stall while Claude thinks
    const stallPhrase = getStallPhrase(classification.category);
    console.log(`🎙️  "${stallPhrase}"\n`);
    
    // Speak stall phrase without waiting
    speak(stallPhrase);
    
    // Get Claude's response
    console.log("🤔 Thinking...\n");
    claude = await askClaude(text);
    
    // Wait for stall phrase to finish
    await new Promise(r => setTimeout(r, 500));
    
    // Summarize for her
    her = summarizeForHer(claude);
  }
  
  // Display
  displayResponse(her, claude);
  
  // Speak her response
  console.log(`🔊 Speaking...\n`);
  await speak(her);

  processing = false;
  showPrompt();
}

function showPrompt() {
  const vaultStatus = vaultConnected ? (vaultUnlocked ? "🔓" : "🔒") : "⚠️";
  const detailsStatus = showDetails ? "👁️" : "  ";
  console.log("────────────────────────────────────────────────────────────");
  console.log(`  SPACE = talk  |  S = stop  |  D = details ${detailsStatus}  |  Q = quit  |  ${vaultStatus}`);
  console.log("────────────────────────────────────────────────────────────\n");
}

// ============== MAIN ==============

async function main() {
  console.log("\n╔══════════════════════════════════════════════════════════╗");
  console.log("║   🎤 PROSPERITY AI v4                                    ║");
  console.log("║   Her voice. Claude's brain. Your control.               ║");
  console.log("╚══════════════════════════════════════════════════════════╝\n");

  await connectVault();
  
  if (vaultConnected) {
    try {
      await vaultUnlock("test");
      console.log("🔐 Vault connected and unlocked");
    } catch (e) {
      console.log("🔐 Vault connected (locked)");
    }
  } else {
    console.log("⚠️  Vault not running");
  }
  
  console.log("");
  showPrompt();

  if (process.stdin.isTTY) process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");

  process.stdin.on("data", async (key) => {
    const now = Date.now();
    if (now - lastKeyTime < 300) return;
    lastKeyTime = now;

    // S = stop speech
    if (key === "s" || key === "S") {
      stopSpeech();
      console.log("🔇 Stopped\n");
      showPrompt();
      return;
    }

    // D = toggle details
    if (key === "d" || key === "D") {
      toggleDetails();
      return;
    }

    // Q = quit
    if (key === "q" || key === "Q" || key === "\u0003") {
      console.log("\n👋 Goodbye!\n");
      stopSpeech();
      if (recorder) recorder.kill();
      if (vaultSocket) vaultSocket.end();
      process.stdin.setRawMode(false);
      process.exit(0);
    }

    // SPACE = record
    if (key === " ") {
      if (processing) return;
      if (!recording) {
        startRec();
      } else {
        await stopRec();
      }
    }
  });
}

main().catch(e => { console.error("Error:", e.message); process.exit(1); });
