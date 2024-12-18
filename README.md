# Secure File Encryptor

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: AES-256-GCM](https://img.shields.io/badge/Security-AES--256--GCM-blue.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![Key Derivation: Argon2](https://img.shields.io/badge/Key_Derivation-Argon2-green.svg)](https://en.wikipedia.org/wiki/Argon2)

A secure command-line tool for file encryption and decryption using AES-256-GCM with Argon2 key derivation.

## Features

- 🔐 AES-256-GCM encryption
- 🗝️ Argon2 password hashing
- 🔄 HKDF key derivation
- ✅ File integrity verification
- 📝 Detailed error messages

## Installation

```bash
cargo install secure-file-encryptor
```

## Usage

Encrypt a file:
```bash
secure-file-encryptor --file secret.txt --password mysecretpassword --encrypt
```

Decrypt a file:
```bash
secure-file-encryptor --file secret.txt.encrypted --password mysecretpassword
```

## Security Features

- Uses AES-256-GCM for authenticated encryption
- Argon2 for secure password hashing
- Unique salt for each encryption
- File integrity verification
- Secure random nonce generation

## License

MIT License