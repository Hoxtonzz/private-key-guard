# 🔐 Private Key Guard

A secure and lightweight GUI tool for encrypting and decrypting private keys using AES-256-GCM. Built in Rust with [egui](https://github.com/emilk/egui) and powered by [ring](https://github.com/briansmith/ring) cryptography.

## 💡 Motivation
When transmitting private keys via chat apps, email, or cloud services, there's a risk that plaintext content may be intercepted or logged by servers. To prevent this, Private Key Guard was built as a simple yet effective way to encrypt private keys before sending them over untrusted networks, and to decrypt them securely on the receiving end.

## ✨ Features

- AES-256-GCM encryption/decryption with PBKDF2 key derivation
- Secure random salt and nonce for every encryption
- Drag-and-drop file selection (supports `.pem`, `.key`, etc.)
- key-based encryption
- Clean cross-platform GUI interface
- Rust-native and dependency-light

## 📷 Screenshots

<img width="796" height="614" alt="image" src="https://github.com/user-attachments/assets/499570ef-c7c9-4534-a5c6-d99aa1f2da6b" />


## 🛡️ Security

- Uses `ring::aead::AES_256_GCM` for authenticated encryption
- Keys are derived using `PBKDF2-HMAC-SHA256` with a 100,000 iteration count
- Salt and Nonce are randomly generated using system secure RNG
- Encrypted data is encoded in Base64URL (no padding) for easy copy-paste or transport

> ⚠️ Never reuse the same password + salt + nonce combination across encryptions.

## 🔧 Installation

### Prerequisites

- Rust >= 1.70 (stable)
- Cargo

### Build from source

```bash
git clone https://github.com/yourusername/private-key-guard.git
cd private-key-guard
cargo build --release
