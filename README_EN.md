# 🔐 keychain_decrypt

Offline decryption tool for macOS `login.keychain-db` files, written in pure Rust.

Extracts the **Chrome Safe Storage** password from a keychain database without using Apple's Security.framework — useful for cross-platform forensics, backup recovery, and security research.

## ✨ Features

- **Pure Rust** — no C dependencies, no macOS SDK required
- **Offline decryption** — operates directly on `.keychain-db` binary files
- **Full key hierarchy** — PBKDF2 → DB Key → KeyBlob → SSGP, fully implemented
- **Minimal binary** — release build with LTO, strip, and `opt-level = "z"`

## 🔑 How It Works

```
  User Password
       │
       ▼
  ┌──────────────────────┐
  │  PBKDF2-HMAC-SHA1    │  1000 iterations
  │  + salt from DBBlob  │
  └──────────┬───────────┘
             │
             ▼
        Master Key (24B)
             │
             ▼
  ┌──────────────────────┐
  │  3DES-CBC decrypt    │  IV from DBBlob
  │  DBBlob ciphertext   │
  └──────────┬───────────┘
             │
             ▼
         DB Key (24B)
             │
             ▼
  ┌──────────────────────┐
  │  Two-pass 3DES-CBC   │  magicCmsIV → reverse → record IV
  │  KeyBlob decrypt     │
  └──────────┬───────────┘
             │
             ▼
       Record Key (24B)
             │
             ▼
  ┌──────────────────────┐
  │  3DES-CBC decrypt    │  IV from SSGP header
  │  SSGP ciphertext     │
  └──────────┬───────────┘
             │
             ▼
      Plaintext Password
```

## 📦 Prerequisites

- Rust 1.56+ (edition 2021)
- Access to a `login.keychain-db` file (requires Full Disk Access on macOS)
- The keychain's login password

## 🚀 Usage

### Build

```bash
# Debug build
cargo build

# Optimized release build
cargo build --release
```

### Run

```bash
keychain_decrypt --keychain <path-to-keychain> --password <keychain-password>
```

**Example:**

```bash
./target/release/keychain_decrypt \
  --keychain ~/Library/Keychains/login.keychain-db \
  --password "my_login_password"
```

**Output:**

```
[*] Read keychain file: 273624 bytes
[*] Keychain signature: "kych", schema at 0x38
[*] Found 5 tables
[*] Built table map (5 entries)
[*] DBBlob: magic=0xFADE0711, salt=..., iv=...
[*] Derived master key (PBKDF2): ...
[*] Decrypted DB key: ...
[*] Found 3 symmetric key records
[*] Decrypted 3 key blobs
[*] Found 1 'Chrome Safe Storage' entries
[+] Chrome Safe Storage password (plaintext):
    <decrypted_password>
[+] Hex: ...
[+] Length: 16 bytes
```

## 📁 Project Structure

```
keychain_decrypt/
├── Cargo.toml          # Dependencies & release profile
└── src/
    ├── main.rs         # CLI entry point & orchestration
    ├── crypto.rs       # PBKDF2, 3DES-CBC, key hierarchy decryption
    ├── parser.rs       # Binary format parser (headers, tables, blobs)
    └── error.rs        # Unified error types
```

| Module     | Responsibility                                                       |
|------------|----------------------------------------------------------------------|
| `main`     | Argument parsing, high-level decrypt flow, output formatting         |
| `crypto`   | `derive_master_key`, `decrypt_db_key`, `decrypt_key_blob`, `decrypt_ssgp` |
| `parser`   | Big-endian readers, header/schema/table/DBBlob/SSGP parsing         |
| `error`    | `KeychainError` enum with `Display` and `From<io::Error>`           |

## 🔧 Dependencies

| Crate    | Version | Purpose                        |
|----------|---------|--------------------------------|
| `des`    | 0.8     | Triple DES (3DES / DES-EDE3)   |
| `cbc`    | 0.1     | CBC block cipher mode           |
| `pbkdf2` | 0.12    | PBKDF2 key derivation           |
| `hmac`   | 0.12    | HMAC for PBKDF2                 |
| `sha1`   | 0.10    | SHA-1 hash for PBKDF2-HMAC-SHA1|
| `cipher` | 0.4     | Block cipher traits             |
| `hex`    | 0.4     | Hex encoding for debug output   |

## ⚠️ Disclaimer

This tool is intended for **legitimate security research, forensics, and personal backup recovery only**. Unauthorized access to others' keychain data may violate applicable laws. Use responsibly.

## 📄 License

MIT
