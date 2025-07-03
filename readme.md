# 🥷 TAMAL-STEGO

**TAMAL-STEGO** is a modern, command-line steganography utility for hiding files inside images with **strong encryption** — including **post-quantum cryptography (Kyber)**. Built entirely in Python, it supports both classic and quantum-secure algorithms and works on Linux, Windows, and macOS.

> 🔐 Developed by **Tamal Bag**  
> 📧 Email: [tamalbag107@gmail.com](mailto:tamalbag107@gmail.com)

---

## ✨ Features

- ✅ Hide any file inside PNG, BMP, or TIFF images
- ✅ Supports authenticated encryption (Fernet, AES-GCM)
- ✅ 🛡️ Supports **Post-Quantum Kyber (Kyber768 + AES-256-GCM)** via `pqcrypto-lite`
- ✅ Modular architecture with support for LSB steganography
- ✅ Command-line interface (CLI) — lightweight, portable
- ✅ Cross-platform: Windows, Linux, macOS

---

## 🔐 Supported Algorithms

| Type           | Engine       | Description                                          |
|----------------|--------------|------------------------------------------------------|
| Steganography  | `lsb`        | Least-significant bit embedding in RGB channels     |
| Encryption     | `fernet`     | AES-128-GCM via password                            |
| Encryption     | `aesgcm`     | AES-256-GCM with scrypt password key derivation     |
| Encryption     | `kyber`      | Post-quantum Kyber768 + AES-256-GCM hybrid (Linux)  |

---

## 🧠 Why It’s Special

- 💡 Uses **post-quantum Kyber KEM** to secure the symmetric key (via `pqcrypto-lite`)
- 🔐 All encryption is AEAD (authenticated encryption with associated data)
- 🧵 Modular: you can plug in other stego or crypto engines
- 📦 Single-file script — no compilation or external binaries required

---

## 📦 Installation

### ✅ Dependencies (Python 3.6+)

#### Windows:
```powershell
python -m pip install pillow cryptography
