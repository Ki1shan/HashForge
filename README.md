# 🔐 HashForge

![Python](https://img.shields.io/badge/python-3.8+-blue)
![GUI](https://img.shields.io/badge/interface-tkinter%20GUI-green)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Hashes](https://img.shields.io/badge/hash%20types-60+-orange)
![Mutations](https://img.shields.io/badge/mutation%20rules-12-red)

> A dual-panel GUI tool for hash cracking and hash generation — supporting 60+ hash types, 12 mutation rules, salt handling, real-time detection, and multi-algorithm hash generation.

---

## ⚠️ Disclaimer

This tool is intended **ONLY** for:

- Authorized penetration testing and CTF challenges
- Password recovery on systems you own or have explicit permission to test
- Security research and educational purposes
- Cybersecurity training environments

**Do NOT use against systems or accounts without explicit written permission.**

---

## Overview

HashForge is a Python GUI tool built with tkinter, split into two resizable panels:

- **Cracking Panel** — dictionary attack with real-time hash type detection, mutation rules, salt support, progress tracking, and stop control
- **Generation Panel** — compute hashes of any plaintext across all supported algorithms simultaneously, with show/hide password toggle

All cracking operations run in background threads — the GUI stays fully responsive during attacks.

---

## Features

### 🔨 Hash Cracking
- Dictionary attack using any wordlist file
- **Real-time hash type detection** as you type — auto-detects on `KeyRelease`
- 60+ hash type patterns with regex-based identification
- Manual hash type selection via dropdown for ambiguous hashes (e.g. MD5 vs NTLM vs MD4 — all 32 chars)
- Salt support — prepended to candidate before hashing
- 12 mutation rules — generates password variants per wordlist entry
- Progress bar with attempt counter
- Stop button — gracefully halts cracking mid-wordlist
- Background threading — UI never freezes

### 🔑 Hash Generation
- Enter any plaintext password
- Show/hide password toggle
- Generates all supported algorithm hashes simultaneously
- Clean formatted output — `ALGORITHM : hash_value`
- Includes Base64 and Base32 encoding alongside cryptographic hashes

---

## Supported Hash Types (60+)

### Cryptographic Hashes
| Algorithm | Output Length |
|-----------|--------------|
| MD5 | 32 chars |
| SHA1 | 40 chars |
| SHA224 | 56 chars |
| SHA256 | 64 chars |
| SHA384 | 96 chars |
| SHA512 | 128 chars |
| SHA3-224 | 56 chars |
| SHA3-256 | 64 chars |
| SHA3-384 | 96 chars |
| SHA3-512 | 128 chars |
| BLAKE2b | 128 chars |
| BLAKE2s | 64 chars |
| RIPEMD160 | 40 chars |
| WHIRLPOOL | 128 chars |

### Windows / AD Hashes
| Algorithm | Notes |
|-----------|-------|
| NTLM | MD4 of UTF-16LE encoded password |
| NTLMv2 | Challenge-response variant |
| LM | Legacy LAN Manager hash |
| MD4 | Base of NTLM |

### Unix / Linux Hashes
| Algorithm | Format |
|-----------|--------|
| MD5-Crypt | `$1$salt$hash` |
| SHA256-Crypt | `$5$salt$hash` |
| SHA512-Crypt | `$6$salt$hash` |
| DESCrypt | 13-char DES |
| bcrypt | `$2b$rounds$hash` |
| ARGON2 | `$argon2id$...` |
| SCRYPT | `$scrypt$...` |

### Database Hashes
| System | Notes |
|--------|-------|
| MySQL | 40-char SHA1 variant |
| MSSQL | 40-char hex |
| PostgreSQL | 40-char hex |
| Oracle | 16-char hex |

### Network / Device Hashes
| System | Notes |
|--------|-------|
| WPA | Wi-Fi password hash |
| Cisco-Type7 | Cisco IOS obfuscation |
| Cisco-PMD5 | Cisco MD5 password |
| Juniper | 64-char hex |
| HTTP-Digest | 32-char MD5 |
| NT-CHALLENGE | 16-char hex |

### Encodings & Others
Base64, Base32, Base16, URL-Encoded, PBKDF2-HMAC-SHA256, PBKDF2-HMAC-SHA1, GOST, HAVAL-128/160/192/224/256, TIGER128/160/192, MDC2, CRC32, CRC64, ADLER32, BLAKE3, UUID, SAP-B, SAP-G, RACF, DNSSEC, SALESFORCE, MEDIAWIKI and more.

---

## Mutation Rules (12)

| Rule | Effect | Example Input → Output |
|------|--------|----------------------|
| `None` | No mutation | `password` → `password` |
| `Lowercase` | All lowercase | `Password` → `password` |
| `Uppercase` | All uppercase | `password` → `PASSWORD` |
| `Capitalize` | First letter capital | `password` → `Password` |
| `Reverse` | Reversed string | `password` → `drowssap` |
| `Leet` | Leet speak substitution | `password` → `p@ssw0rd` |
| `Duplicate` | Word repeated twice | `pass` → `passpass` |
| `Title Case` | Each word capitalized | `password` → `Password` |
| `Swap Case` | Inverts case | `Password` → `pASSWORD` |
| `Add Numbers` | Appends 0-9 | `password` → `password0`...`password9` |
| `Add Special` | Appends `!@#$%^&*` | `password` → `password!` etc. |
| `Year Append` | Appends 1990-2029 | `password` → `password2024` etc. |

---

## Installation

```bash
git clone https://github.com/Ki1shan/HashForge.git
cd HashForge
python hashforge.py
```

> No external dependencies required. Uses Python's built-in `tkinter`, `hashlib`, `base64`, `hmac`, `threading`, and `re` modules only.

---

## Usage

### Hash Cracking
1. Paste target hash into the **Hash** field
2. Hash type auto-detected as you type — shown in blue below the field
3. Override via dropdown if needed (especially for ambiguous 32-char hashes)
4. Optionally enter a **Salt** value
5. Select a **Mutation Rule**
6. Click **Browse** to select your wordlist
7. Click **Start Cracking**
8. Use **Stop** to halt mid-wordlist at any time

### Hash Generation
1. Enter plaintext password in the **Generation Panel**
2. Toggle **Show** to reveal/hide the password
3. Click **Generate Hashes**
4. All algorithm outputs displayed simultaneously for easy copying

---

## GUI Layout

```
┌──────────────────────────────────────────────────────────────────┐
│                          HashForge                               │
├───────────────────────────────────┬──────────────────────────────┤
│         CRACKING PANEL            │      GENERATION PANEL        │
│                                   │                              │
│  Hash: [____________________]     │  Password: [________] [Show] │
│  Detected: SHA256, BLAKE2s        │                              │
│                                   │  [Generate Hashes]           │
│  Type:      [Auto Detect ▼]       │                              │
│  Salt:      [________]            │  MD5    : 5f4dcc3b5aa...     │
│  Mutations: [Leet      ▼]         │  SHA1   : 5baa61e4c9b...     │
│                                   │  SHA256 : 5e884898da2...     │
│  Wordlist: [/path/list]  [Browse] │  SHA512 : b109f3bbbc2...     │
│  [████████░░] 4200 attempts       │  NTLM   : 8846f7eaee8...     │
│  Status: Running...               │  BLAKE2b: a665a45920...      │
│                                   │  Base64 : cGFzc3dvcmQ=       │
│  [Start Cracking]  [Stop]         │  ...                         │
│                                   │                              │
│  Results:                         │                              │
│  *** PASSWORD FOUND! ***          │                              │
│  Password: letmein                │                              │
│  Attempts: 4271                   │                              │
└───────────────────────────────────┴──────────────────────────────┘
```

---

## Use Cases

- **CTF challenges** — identify unknown hash types and crack instantly
- **Penetration testing** — dictionary attack against hashes from `/etc/shadow`, NTDS.dit, database dumps
- **Security awareness** — demonstrate how fast weak passwords are cracked
- **Hash identification** — auto-detect unknown hash formats across 60+ patterns
- **Hash generation** — quickly generate reference hashes for testing and verification

---

## Author

**Kishan N**
Offensive Security Engineer | Tool Developer

Built HashForge as a practical, GUI-based alternative to command-line hash tools — combining cracking, identification, and generation in one clean dual-panel interface.

---

## License

MIT License — see `LICENSE` file for details.

---

*A hash is only as strong as the password behind it.*
