# Prosperity AI

**Your AI. Your Data. Your Control.**

Prosperity AI is a personal AI system designed to give you genuine digital autonomy. Unlike cloud-dependent assistants that harvest your data, Prosperity runs locally, encrypts everything with keys only you hold, and works toward a single goal: **helping you digitally disappear while remaining fully functional in the modern world.**

---

## The Vision

The internet has become a surveillance machine. Every password you reuse is a liability. Every account linked to your real email is a data point. Every "free" service sells your attention and identity.

**Prosperity AI exists to reverse this.**

We're building toward a future where:
- Your passwords are unique, computer-generated, and impossible to guess
- Your credentials are encrypted with military-grade cryptography that only YOU can unlock
- Your AI assistant works FOR you, not for advertisers
- Your digital footprint shrinks instead of grows
- Your identity is protected by default, not exposed by default

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      VOICE INTERFACE                         │
│              (Natural conversation, local processing)        │
│    "Hey Prosperity, how many passwords do I have?"          │
└─────────────────────────┬───────────────────────────────────┘
                          │
        ┌─────────────────┴─────────────────┐
        │                                   │
        ▼                                   ▼
┌───────────────────┐             ┌───────────────────────────┐
│   LOCAL ROUTING   │             │      CLOUD BRAIN          │
│                   │             │      (Claude API)         │
│ • Open websites   │             │                           │
│ • Vault commands  │             │ • Complex reasoning       │
│ • Time/greetings  │             │ • Writing assistance      │
│ • Cached patterns │             │ • Analysis tasks          │
│                   │             │ • First-time commands     │
│   ⚡ <200ms       │             │   🧠 2-3 seconds          │
└───────────────────┘             └───────────────────────────┘
        │                                   │
        └─────────────────┬─────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    PROSPERITY VAULT                          │
│           (Argon2id + XChaCha20-Poly1305 encryption)        │
│                                                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │Authentication│ │  Financial  │ │   Health    │            │
│  │  Passwords   │ │   Accounts  │ │   Records   │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │   Identity   │ │   Personal  │ │   Patterns  │            │
│  │  Documents   │ │    Notes    │ │   (Cache)   │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
│                                                              │
│  • Zero-knowledge: We never see your data                   │
│  • Local-first: Vault runs on YOUR machine                  │
│  • Audited access: Every read is logged                     │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  BROWSER AUTOMATION                          │
│                    (Playwright)                              │
│                                                              │
│  • Auto-login with vault credentials                        │
│  • Password rotation (change to secure passwords)           │
│  • No extensions, no manual clicking                        │
│  • Dedicated browser profile (isolated)                     │
└─────────────────────────────────────────────────────────────┘
```

---

## The Shield: Password Protection System

**The problem:** You have 276 passwords. Most people reuse the same 3-5 passwords everywhere. One breach = all accounts compromised.

**The solution:** Prosperity's Shield automatically:

1. **Imports** your existing passwords from Chrome/Edge
2. **Backs up** everything (encrypted) before touching anything
3. **Rotates** each password to a unique 20+ character randomly generated password
4. **Stores** the new passwords in your encrypted vault
5. **Logs you in** automatically when needed

You never type passwords again. You never reuse passwords again. You never know what your passwords are - and that's the point.

### Shield Components

| Tool | Purpose |
|------|---------|
| `password-import.mjs` | Import from Chrome/Edge CSV into vault |
| `password-rotate.mjs` | Change passwords to secure generated ones |
| `password-restore.mjs` | Emergency restore to Chrome format |
| `prosperity-login.mjs` | Auto-login to any configured site |
| `site-configs.json` | Login/change selectors for major sites |

---

## Roadmap: Digital Disappearance

### Phase 1: Foundation ✅
- [x] Secure vault with category encryption
- [x] Voice interface with natural conversation
- [x] Password import from browsers
- [x] Basic browser automation

### Phase 2: The Shield (Current)
- [x] Password rotation system
- [x] Site configuration framework
- [ ] Automated password change for top 50 sites
- [ ] Password strength audit
- [ ] Breach monitoring integration

### Phase 3: Identity Protection
- [ ] Email alias generation (hide real email)
- [ ] Phone number masking
- [ ] Address forwarding service integration
- [ ] Data broker removal automation

### Phase 4: Financial Privacy
- [ ] Virtual card generation
- [ ] Subscription tracking
- [ ] Automated cancellation of unused services
- [ ] Privacy-focused payment routing

### Phase 5: Complete Autonomy
- [ ] Self-hosted AI inference (no cloud dependency)
- [ ] Encrypted sync across devices
- [ ] Dead man's switch (data destruction on trigger)
- [ ] Identity verification without revealing identity

---

## Philosophy

1. **Local-first**: Your data lives on YOUR hardware
2. **Zero-knowledge**: We can't see your data even if we wanted to
3. **Auditable**: Every access is logged, you control the logs
4. **Reversible**: Full backups before any destructive action
5. **Progressive**: Works today, improves toward full autonomy

---

## Quick Start

```bash
# Terminal 1: Start the vault
sudo mkdir -p /run/prosperity && sudo chown $USER:$USER /run/prosperity
cd ~/prosperity-vault && ./target/release/prosperity-vault

# Terminal 2: Start voice assistant
cd ~/prosperity-ai && node prosperity-voice-v4.mjs
```

**Voice commands:**
- "How many passwords do I have?"
- "Open YouTube"
- "What's the password for Gmail?"
- "Lock the vault"

**Keyboard:**
- `SPACE` = record
- `S` = stop speech
- `D` = toggle Claude details
- `Q` = quit

---

## Security Model

See [VAULT_SPEC_v3_FINAL.md](./docs/VAULT_SPEC_v3_FINAL.md) for the complete cryptographic specification.

**Summary:**
- Master passphrase → Argon2id (memory-hard) → Key Encryption Key
- KEK encrypts per-category Data Encryption Keys
- DEKs encrypt actual entries with XChaCha20-Poly1305
- Audit log tracks every access with timestamps and purpose

---

## License

MIT License - Use it, modify it, own it.

---

## Contributing

This is built for people who value their privacy. If that's you, contributions welcome.

**Priority areas:**
- Site configurations for password rotation
- Data broker removal scripts
- Privacy-focused service integrations

---

*"The best way to keep a secret is to not have one. The second best way is to encrypt it with keys only you control."*
