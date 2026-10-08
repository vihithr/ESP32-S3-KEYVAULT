# 🔐 KeyVault USB —— ESP32-S3 Hardware-Level Air-Gapped Password & Secret Vault

[English](README_EN.md) | [中文](README.md)

KeyVault is a **completely offline, highly redundant, and zero-trust hardware password & secret vault** powered by the native USB-OTG peripheral of the ESP32-S3 microcontroller.

With just a single Type-C cable plugged into any PC, Mac, Linux, or mobile phone, KeyVault automatically establishes a point-to-point high-speed virtual network (USB RNDIS). Users can manage credentials, SSH keys, API tokens, and encrypted notes directly through a sleek, modern responsive Web interface with zero software installation.

---

## 🌟 Key Features & Architectural Highlights

### 1. 🗄️ Massive Storage Capacity (1,536 Encrypted Secret Slots)
- **High-Density Storage**: Supports **1,024 account credentials** + **512 custom key-value pairs** (1,536 secret records in total).
- **Expanded Partitions**: Dual partitions with **512 KB** each (1 MB total redundancy pool), with ample room for tens of thousands of writes and NVS log-structured wear leveling.

### 2. 🗜️ Deterministic Two-Tier Lossless Compression (TLV + 7-bit Bit-Packing)
- **Compact TLV Binary Layout**: Strips verbose JSON field names (`name`, `user`, `pass`, etc.), dramatically shrinking flash footprint.
- **7-bit ASCII Bitstream Packing**: For alphanumeric characters and common password symbols (ASCII `0x20` to `0x7E`), packs every 8 7-bit characters into 7 continuous physical bytes, cutting storage usage by **12.5%**.
- **Compress-then-Encrypt (Side-Channel Immune)**: Compression takes place in isolated memory strictly before encryption. Ciphertext length scales linearly and deterministically with character count, rendering CRIME / BREACH style length-leakage side-channel attacks impossible.
- **Seamless Backward Compatibility**: Automatically recognizes legacy JSON ciphertexts and upgrades them to compact TLV format upon the next write.

### 3. 🛡️ Active-Mirror Dual Zones & Flash Self-Healing Monitor
- **Active-Mirror Dual Zones**: `vault` (`0xD000`) and `vault2` (`0x8D000`) act as mutual real-time mirrors. Each entry maintains an independent 12-byte Nonce, AES-GCM authentication tag, and CRC32 integrity checksum.
- **Bit-Flip / Power-Cut Self-Healing**: If a CRC error or decryption anomaly is detected in either partition during reads, KeyVault automatically pulls the valid record from the opposite mirror and executes an **instant, transparent self-healing repair write**.
- **Flash Endurance & Safe Read-Only Mode**: Continuously tracks cumulative NVS writes, slot utilization, and self-healing occurrences. In the extreme event that both zones experience hardware failures, KeyVault immediately locks into **Safe Read-Only Mode**, preventing write corruption while remaining fully exportable.

### 4. 🔒 Zero-Config End-to-End Encryption (HTTP Zero-Config E2EE)
- **Solves the Browser "Red Screen" Dilemma**: Bypasses the need for importing private Root CAs or enduring HTTPS insecure warnings on private intranet IPs (e.g. `192.168.7.1`).
- **Pure Native JS Cryptographic Engine**: Built-in pure JavaScript implementation of **RFC 7748 X25519 (ECDH)**, **SHA-256**, and **AES-256-GCM (with full GHASH authentication)** using modern `BigInt`. Operates independently of restricted `window.crypto.subtle` contexts, running out of the box on all browsers.
- **Ephemeral Key Exchange (PFS)**: On every session initiation, both client and ESP32-S3 generate ephemeral X25519 keypairs to derive a transient 256-bit session key. All request payloads and responses are encrypted and authenticated via on-chip hardware AES-256-GCM. Packet sniffers capture only high-entropy ciphertexts.

### 5. 🔌 Pure Single RNDIS Virtual NIC & Zero Radio Frequency (RF) Exposure
- **Single RNDIS Driver Mode**: Eliminates routing conflicts caused by multi-interface network cards. Plug-and-play host configuration assigns `192.168.7.2` via the onboard DHCP server.
- **Zero RF by Default**: Wi-Fi and Bluetooth radios are completely powered down by default, producing zero wireless electromagnetic footprint.
- **Physical Button 2FA Authorization**: Critical operations (initial setup, login/unlock) require pressing the physical **BOOT** button on the ESP32-S3 board, thwarting remote brute-force and injection attacks.

---

## 📐 Hardware & Boot Modes

The ESP32-S3 shares physical pins (`GPIO19: D-`, `GPIO20: D+`) between USB-Serial/JTAG and USB-OTG. KeyVault manages these modes through an automated software state machine:

1. **Default Mode (USB Offline NIC Mode)**:
   - Enters native USB RNDIS network mode automatically after a 3-second startup buffer. Access via browser: `http://192.168.7.1`.
2. **Debug / Flashing Protection Mode**:
   - Short-press the onboard **BOOT** button (`GPIO0`) within the 3-second startup window to stay permanently in USB-Serial/JTAG mode with LED blinking, ready for PlatformIO firmware flashing or serial log monitoring.
3. **Emergency Wi-Fi Recovery Mode**:
   - Long-press the onboard **BOOT** button for **10 seconds** at any time to launch the emergency recovery hotspot (SSID: `KeyVault-Recovery`, Password: `vault2024`, IP: `http://192.168.4.1`).

---

## 🚀 Quick Start & One-Click Flashing

### Method 1: Using the Automated Script (Recommended for Windows)
Run the automated flashing script in PowerShell from the repository root:
```powershell
.\flash.ps1
```
The script will automatically detect the download port, upload the partition table and firmware, and verify network connectivity.

> 💡 **Button Instruction**: When prompted, press and hold the board's **[BOOT]** button, tap the **[RESET]** button once, and release **[BOOT]** to enter ROM download mode.

### Method 2: Standard PlatformIO Build & Flash
```powershell
# 1. Compile firmware and web assets
pio run

# 2. Flash firmware to ESP32-S3
pio run -t upload

# 3. Monitor live serial logs
pio device monitor
```

---

## 🗃️ Flash Partition Table (4 MB Flash)

```csv
# Name,   Type, SubType, Offset,   Size,     Flags
nvs,      data, nvs,     0x9000,   0x4000,
vault,    data, nvs,     0xD000,   0x80000,  # 512KB Primary Vault (1024 Creds + 512 KV)
vault2,   data, nvs,     0x8D000,  0x80000,  # 512KB Redundant Mirror Vault
factory,  app,  factory, 0x110000, 0x1D0000, # 1.81MB Factory Firmware (64KB aligned)
```

---

## 🌐 REST API Overview

| Method | Path | Description | Authentication |
| :--- | :--- | :--- | :--- |
| **GET** | `/api/status` | Query setup status and USB link state | None |
| **POST** | `/api/e2ee/handshake` | Ephemeral X25519 session key negotiation | None |
| **GET** | `/api/health` | Query storage health score, self-heal counts, and write stats | None (touch keepalive with Token) |
| **GET** | `/api/usb` | Query USB active protocol and assigned IP | None (touch keepalive with Token) |
| **POST** | `/api/setup` | Initialize master password (requires physical button 2FA) | None |
| **POST** | `/api/login` | Unlock vault with master password (requires physical button 2FA) | None |
| **POST** | `/api/lock` | Emergency lock and immediately purge session keys in RAM | None (safe fallback) |
| **GET** | `/api/creds` | Retrieve credential summary list | `X-Token` |
| **POST** | `/api/creds` | Add a new credential | `X-Token` |
| **GET** | `/api/cred/<id>` | Retrieve full credential with plaintext password | `X-Token` |
| **POST** | `/api/cred/update` | Update an existing credential | `X-Token` |
| **POST** | `/api/cred/delete` | Delete a credential | `X-Token` |
| **GET** | `/api/kv` | Retrieve list of all custom key names | `X-Token` |
| **POST** | `/api/kv` | Write or update a custom key-value pair | `X-Token` |
| **GET** | `/api/kv/<key>` | Retrieve full value of a custom key | `X-Token` |
| **POST** | `/api/kv/delete` | Delete a custom key | `X-Token` |
| **POST** | `/api/generate` | High-entropy physical TRNG password generator | None |
| **POST** | `/api/chpwd` | Change master password with full-database re-encryption | `X-Token` |
| **POST** | `/api/export` | Export encrypted AES backup (`.kvbk`) | `X-Token` |
| **POST** | `/api/import` | Import encrypted backup and restore | `X-Token` |
| **POST** | `/api/reset` | Factory wipe and erase all secret partitions | `X-Token` |
| **POST** | `/api/reboot` | Restart the device | `X-Token` |

> **Note**: All API requests carrying the `X-E2EE-Session` header are transparently encrypted and decrypted using AES-256-GCM.

---

## 📁 Repository Structure

```
ESP32-S3-KEYVAULT/
├── partitions.csv            # 512KB dual-zone redundant partition table
├── platformio.ini            # PlatformIO build configuration
├── flash.ps1                 # One-click smart flashing & diagnostics script
├── LICENSE                   # MIT License
├── README.md                 # Documentation (Chinese)
├── README_EN.md              # Documentation (English)
├── tools/
│   └── gen_web_content.py    # Zero-loss Web-to-C code generator
└── src/
    ├── main.c                # HTTP server routes, event loop & E2EE pipeline
    ├── keyvault.h / c        # 1536 entries, 7-bit compression & dual-zone healing
    ├── e2ee.h / c            # RFC 7748 X25519 & hardware AES-256-GCM cryptography
    ├── rndis.h / c           # Native RNDIS USB device class driver
    ├── usb_net.h / c         # Network adapter, DHCP server & IP stack
    ├── usb_desc.h / c        # USB hardware descriptors & string tables
    ├── json_util.h / c       # Lightweight JSON parser & escaping utility
    ├── web_content.h / c     # Embedded Web UI read-only byte arrays
    └── index.html            # Responsive dark-theme Web UI with pure JS crypto engine
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE). Feel free to use, audit, and contribute!
