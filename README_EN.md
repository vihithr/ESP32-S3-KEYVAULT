# 🔐 KEYVAULT-ESP32 —— Offline Hardware Key & Credential Vault

[English](README_EN.md) | [中文](README.md)

**KEYVAULT-ESP32** is an **offline hardware password and credential management device** powered by the native USB-OTG peripheral of the ESP32-S3 microcontroller.

Connected to any PC, Mac, Linux, or mobile device via a standard Type-C cable, the device provides driverless access via USB RNDIS (virtual network) and USB HID keyboard emulation. Users can securely manage credentials, API tokens, SSH keys, and encrypted notes directly in any modern browser without installing proprietary desktop clients or browser extensions, and inject passwords into target forms via physical keystroke emulation.

---

## 🛠️ Key Features & Security Architecture

### 1. 🗄️ Storage Capacity & Partition Planning
- **Multi-Slot Capacity**: Stores up to **1,024 account credentials** + **512 custom key-value pairs** (1,536 total entries).
- **Partition Allocation**: Dedicated 512 KB Flash for each zone (1 MB total pool), utilizing log-structured NVS wear-leveling to distribute Flash write cycles evenly.

### 2. 🗜️ Compact Encoding & Storage Optimization
- **TLV Binary Layout**: Compact Type-Length-Value encoding replaces verbose JSON keys, reducing storage overhead.
- **7-bit ASCII Bit-Packing**: Compresses standard alphanumeric characters and common symbols (ASCII `0x20` to `0x7E`) by packing eight 7-bit characters into seven physical bytes.
- **Compress-then-Encrypt**: Compression is performed in isolated memory prior to encryption. Deterministic padding mitigates length-leakage risks.
- **Smooth Format Migration**: Automatically parses legacy records and transparently updates them to the compact layout upon the next write.

### 3. 🛡️ Dual-Zone Mirroring & Storage Integrity
- **Active-Mirror Dual Zones**: Two independent NVS partitions (`vault` and `vault2`) mirror each other. Each entry carries an independent Nonce, AES-GCM authentication tag, and CRC32 checksum.
- **Integrity Check & Self-Healing**: If corrupted data or an invalid checksum is encountered on one partition, the system attempts to restore the valid entry from the opposite mirror and write it back.
- **Endurance Tracking & Read-Only Fallback**: Monitors write cycles, slot utilization, and repair counts. If an extreme double-partition fault occurs, the device falls back to a **Safe Read-Only Mode** to prevent corruption while permitting backup export.

### 4. 🔒 Application-Layer End-to-End Encryption (E2EE)
- **Eliminating Certificate Warnings**: Avoids browser insecure warnings on local intranet IPs (such as `192.168.7.1`) caused by lack of recognized CA root certificates.
- **Native JS Cryptographic Suite**: Built with pure JavaScript implementations of **RFC 7748 X25519 (ECDH)**, **SHA-256**, and **AES-256-GCM**, functioning independently of restricted Web Crypto contexts across major browsers.
- **Forward-Secure Ephemeral Sessions**: Both client and microcontroller generate transient X25519 keypairs upon each session start to derive a 256-bit session key. All payloads are encrypted and authenticated with AES-GCM at the application layer, ensuring sensitive data is not exposed in cleartext over the wire.

### 5. ⌨️ USB HID Hardware Auto-Typing
- **Composite Driver-Free Design**: Implements standard USB HID keyboard emulation alongside RNDIS, requiring no host driver installation.
- **30-Second Single-Shot Arming**: Clicking the keyboard icon arms the device for 30 seconds; the decrypted credential is temporarily staged in volatile RAM with a visible countdown.
- **Physical Button Trigger**: Focus the target input box (lock screen, terminal, or login form) and press the onboard **BOOT** button. The device simulates hardware keystrokes to type the password character-by-character.
- **Safety Constraints & Sanitization**:
  - **No Enter Key**: Stops immediately after the password characters, preventing unintended form submission.
  - **Bypasses Operating System Clipboard**: Credentials never touch the host clipboard, reducing exposure to clipboard monitoring tools.
  - **Immediate Memory Zeroing**: Upon typing completion or arming timeout, `vault_secure_zero` wipes the staging buffer in volatile RAM.

### 6. 🔘 Physical 2FA Button Confirmation & Offline Operation
- **Physical Confirmation on Credential Retrieval**: Viewing or copying credentials triggers a 15-second hardware wait state. **The user must physically press the onboard BOOT button** before cleartext is returned, limiting unauthorized background scraping.
- **Disabled Radios by Default**: Wi-Fi and Bluetooth radios remain off by default to minimize wireless attack vectors.
- **No Cleartext Master Password on Disk**: Only salt values and cryptographic hash verifiers are stored in Flash. Verification occurs in RAM and temporary buffers are wiped immediately afterwards.

---

## 🛡️ Threat Model & Security Boundaries

Any practical security system must be constructed upon explicit threat assumptions. The primary defensive goal of KEYVAULT-ESP32 is: **To protect against the vast majority of automated network attacks and host malware in everyday computing environments at minimal cost and high portability, rendering bulk vault exfiltration unfeasible.**

### 1. In-Scope Defended Attack Scenarios
- **Background Malware & Automated Bulk Scraping**:
  Even if the host machine harbors malicious background processes, any attempt to decrypt and retrieve credentials triggers a hardware-suspended state requiring physical interaction. Automated malware cannot silently dump the vault without physical human presence.
- **Operating System Clipboard Hijacking & Sniffing**:
  Using USB HID hardware keystroke emulation (Auto-Type), credentials are typed directly into the active focus window, completely bypassing host OS clipboard mechanisms and neutralizing clipboard-hooking tools.
- **Cleartext Network Sniffing & Unauthorized Transport Interception**:
  Application-layer X25519 ephemeral key agreement and AES-256-GCM encryption guarantee that only high-entropy ciphertexts traverse the USB virtual network channel.
- **Non-Interactive Online Brute-Forcing**:
  Login authentication also requires physical button confirmation, halting automated online dictionary attacks at the very first attempt.

### 2. Cryptographic Trade-offs: PBKDF2 Iterations vs Password Entropy
- **Engineering Justification for 30,000 PBKDF2 Iterations**:
  On a 240 MHz ESP32-S3, 30k iterations take approximately 80–150 ms. This guarantees smooth, responsive unlocking without triggering FreeRTOS task watchdogs (Task WDT).
- **Linear Delay vs Exponential Search Space**:
  KDF iteration count provides a **linear work factor**, whereas **the entropy of the master password (length and character pool) provides an exponential barrier**. A 12+ character high-entropy password spans a search space of $\sim 10^{22}$, making offline brute-forcing mathematically infeasible.
- **Prerequisites for Offline Attacks**:
  Offline cracking requires extraordinary preconditions: the attacker must physically possess the hardware, possess the tools and skill to desolder or dump Flash contents, and reverse-engineer the private storage layout. Furthermore, when ESP32-S3 hardware **Flash Encryption (AES-XTS) and eFuse blowing** are enabled, raw Flash reads yield only pseudo-random noise.

### 3. Explicit Security Boundaries & Non-Goals (Out of Scope)
Firmware and microcontrollers cannot defend against attacks that violate their physical and logical trust boundaries:
- **Fully Compromised Endpoint (Host Rootkits & Keyloggers)**:
  If the host OS is controlled by a kernel-level rootkit or driver-level keylogger, the hardware prevents dumping the whole database, but cannot prevent the currently typed single credential from being captured by the host OS (a problem addressed by public-key schemes like FIDO2 / Passkey).
- **Phishing Attacks**:
  If a user manually injects credentials into a fraudulent website, hardware keystrokes cannot verify the domain name due to the lack of origin-binding in traditional passwords.
- **Physical Coercion & Social Engineering (OPSEC)**：
  Should the master password be divulged through coercion (e.g. the classic "\$5 wrench attack") or shoulder surfing, protection belongs to physical operational security (OPSEC).
- **Lab-Grade Physical & Silicon-Level Attacks**:
  Techniques such as Focused Ion Beam (FIB), Differential Power Analysis (DPA), and laser fault injection require dedicated Secure Elements (SE) with active physical tamper meshes (e.g. ATECC608A).

---

## 📐 Hardware & Boot Modes

The ESP32-S3 multiplexes its physical pins (`GPIO19: D-`, `GPIO20: D+`) between USB-Serial/JTAG and USB-OTG. The firmware manages transitions via an internal state machine:

1. **Default Mode (USB Offline NIC Mode)**:
   - Enters USB virtual network mode automatically after a 3-second boot buffer. Access via browser at: `http://192.168.7.1`.
2. **Flashing / Debug Mode**:
   - Short-press the onboard **BOOT** button (`GPIO0`) within the 3-second startup buffer to stay in USB-Serial/JTAG mode with the LED blinking, suitable for firmware flashing or reading serial logs.
3. **Emergency Wi-Fi Mode**:
   - Long-press the onboard **BOOT** button for **10 seconds** at runtime to start a temporary recovery hotspot (SSID: `KeyVault-Recovery`, Password: `vault2024`, IP: `http://192.168.4.1`).

---

## 🚀 Quick Start & Firmware Flashing

### Method 1: Precompiled Release Flashing (Recommended)
Download and extract `ESP32-S3-KEYVAULT-vX.X.X-release.zip` from GitHub Releases:
- **🖥️ Graphical Flashing GUI (Recommended)**: Double-click `flash_gui.bat` to launch the GUI flasher. It automatically detects Python/Conda/venv environments, scans serial ports, and provides one-click flashing, full chip erase, and a built-in serial monitor.
- **⌨️ Command Line Utility**: Double-click `flash.bat` and enter your COM port (e.g. `COM3`) to flash via CLI.

### Method 2: Building from Source (PlatformIO)
```powershell
# 1. Generate embedded web assets and compile firmware
python tools/gen_web_content.py
pio run

# 2. Upload firmware to device
pio run -t upload

# 3. Open serial monitor
pio device monitor
```

### Method 3: esptool Command Line
```bash
esptool.py --chip esp32s3 -p <COM_PORT> -b 921600 write_flash \
  0x0 flashtool/firmware/bootloader.bin \
  0x8000 flashtool/firmware/partitions.bin \
  0x10000 flashtool/firmware/firmware.bin
```

---

## 🗃️ Flash Partition Layout (4 MB Flash)

```csv
# Name,   Type, SubType, Offset,   Size,     Flags
nvs,      data, nvs,     0x9000,   0x4000,
vault,    data, nvs,     0xD000,   0x80000,  # 512KB Primary Vault (1024 Creds + 512 KV)
vault2,   data, nvs,     0x8D000,  0x80000,  # 512KB Redundant Mirror Vault
factory,  app,  factory, 0x110000, 0x1D0000, # 1.81MB Factory Firmware (64KB aligned)
```

---

## 🌐 REST API Overview

| Method | Path | Description | Auth |
| :--- | :--- | :--- | :--- |
| **GET** | `/api/status` | Query initialization and connection state | None |
| **POST** | `/api/e2ee/handshake` | Ephemeral X25519 session key negotiation | None |
| **GET** | `/api/health` | Query dual-zone health and write statistics | None |
| **GET** | `/api/usb` | Query USB active protocol and assigned IP | None |
| **POST** | `/api/setup` | Initialize master password (requires physical button 2FA) | None |
| **POST** | `/api/login` | Unlock vault with master password (requires physical button 2FA) | None |
| **POST** | `/api/lock` | Lock and immediately clear session keys in RAM | None |
| **GET** | `/api/creds` | Retrieve credential summary list | `X-Token` |
| **POST** | `/api/creds` | Add a new credential | `X-Token` |
| **GET** | `/api/cred/<id>` | Retrieve credential details (requires physical button 2FA) | `X-Token` |
| **POST** | `/api/cred/update` | Update an existing credential | `X-Token` |
| **POST** | `/api/cred/delete` | Delete a credential | `X-Token` |
| **GET** | `/api/kv` | Retrieve list of custom keys | `X-Token` |
| **POST** | `/api/kv` | Create or update a custom key-value pair | `X-Token` |
| **GET** | `/api/kv/<key>` | Retrieve key-value contents (requires physical button 2FA) | `X-Token` |
| **POST** | `/api/kv/delete` | Delete a custom key | `X-Token` |
| **POST** | `/api/hid/arm` | Arm single-shot HID auto-typing | `X-Token` |
| **POST** | `/api/hid/disarm` | Disarm HID state and wipe staging buffer | `X-Token` |
| **GET** | `/api/hid/status` | Query HID arming status and remaining duration | `X-Token` |
| **POST** | `/api/generate` | Generate random password using on-chip TRNG | None |
| **POST** | `/api/chpwd` | Change master password with re-encryption | `X-Token` |
| **POST** | `/api/export` | Export encrypted AES backup (`.kvbk`) | `X-Token` |
| **POST** | `/api/import` | Import and restore encrypted backup | `X-Token` |
| **POST** | `/api/reset` | Wipe data and perform factory reset | `X-Token` |
| **POST** | `/api/reboot` | Restart the device | `X-Token` |

> When accompanied by the `X-E2EE-Session` header, API payloads are encrypted and authenticated using AES-256-GCM.

---

## 📁 Repository Structure

```
KEYVAULT-ESP32/
├── partitions.csv            # 512KB dual-zone redundant partition table
├── platformio.ini            # PlatformIO build configuration
├── flash.ps1                 # Flashing script
├── LICENSE                   # MIT License
├── README.md                 # Documentation (Chinese)
├── README_EN.md              # Documentation (English)
├── flashtool/                # Precompiled binaries & GUI flashing toolkit
│   ├── esp32_flash_gui.py    # GUI Flasher (port scan / flash / erase / monitor)
│   ├── esp32_flasher.py      # Flashing engine (auto-detects Conda / venv / Python)
│   ├── flash_gui.bat         # One-click GUI launcher (auto environment adaptation)
│   ├── flash.bat             # Minimalist command-line batch script
│   ├── create_package.py     # Automated build, sync & distribution packaging script
│   ├── requirements.txt      # Dependencies (esptool, pyserial)
│   └── firmware/             # Precompiled binaries (bootloader/partitions/firmware)
├── tools/
│   └── gen_web_content.py    # Web-to-C code generator
└── src/
    ├── main.c                # Main loop, HTTP routing & event coordination
    ├── keyvault.h / c        # 1,536 entries, 7-bit packing & dual-zone healing
    ├── e2ee.h / c            # X25519 key exchange & AES-256-GCM encryption
    ├── usb_hid.h / c         # USB HID keyboard simulation & arming engine
    ├── rndis.h / c           # RNDIS virtual network device driver
    ├── usb_net.h / c         # Network adapter, DHCP server & IP stack
    ├── usb_desc.h / c        # USB composite descriptors & endpoints
    ├── json_util.h / c       # Lightweight JSON parser
    ├── web_content.h / c     # Embedded Web UI read-only byte arrays
    └── index.html            # Responsive Web UI (bilingual with pure JS crypto engine)
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
