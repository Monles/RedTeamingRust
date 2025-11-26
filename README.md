# RedTeamingRust

Educational Rust implementations of offensive security techniques for authorised penetration testing and security research.

## Overview

This repository contains professionally developed proof-of-concept (PoC) payloads and offensive security tools written in Rust. All code is intended for educational purposes, authorised security testing, and defensive security research.

## Project Structure

```text
RedTeamingRust/
├── src/
│   ├── evasion_payload/      # Sandbox evasion techniques
│   └── apc_injection/         # APC injection demonstration
├── docs/
│   └── wiki/
│       ├── Evasion-Payload.md       # Sandbox evasion documentation
│       └── Payload-Generation.md    # Professional payload generation guide
└── README.md
```

## Techniques Implemented

### 1. Sandbox Evasion ([src/evasion_payload/](src/evasion_payload/))

Implementation of common sandbox detection and evasion techniques:

- **API Hammering** - Intensive file I/O operations to stress test sandboxes
- **CPU-Intensive Prime Calculation** - Detect time-accelerated analysis environments

**Features**:

- Progress tracking and status reporting
- Configurable iteration counts
- Comprehensive error handling
- Detailed inline documentation

**Build & Run**:

```bash
cd src/evasion_payload
cargo build --release
cargo run --release
```

**Documentation**: [docs/wiki/Evasion-Payload.md](docs/wiki/Evasion-Payload.md)

**References**: Based on [RustRedOps/API-Hammering](https://github.com/joaoviictorti/RustRedOps/blob/main/API-Hammering/src/main.rs)

---

### 2. APC Injection ([src/apc_injection/](src/apc_injection/))

Professional implementation of Asynchronous Procedure Call (APC) injection technique for Windows.

**Technique Overview**:

1. Creates a thread in an alertable wait state
2. Allocates memory for shellcode with RW permissions
3. Copies shellcode into allocated memory
4. Changes memory permissions to RX (Read+Execute)
5. Queues an APC to execute the shellcode
6. Resumes the thread to trigger execution

**Features**:

- Step-by-step execution logging
- Proper error handling with Windows API Results
- Comprehensive safety documentation
- Multiple payload loading methods (file, embedded, network)
- Modular payload loader architecture

**Build & Run** (Windows only):

```bash
cd src/apc_injection
cargo build --release
cargo run --release
```

**MITRE ATT&CK**: T1055.004 - Process Injection: Asynchronous Procedure Call

**References**: Based on [RustRedOps/APC-Injection](https://github.com/joaoviictorti/RustRedOps/blob/main/APC-Injection/Local/src/main.rs)

---

## Documentation

### Comprehensive Guides

1. **[Evasion Payload Guide](docs/wiki/Evasion-Payload.md)**
   - Detailed technique analysis
   - Performance characteristics
   - Detection and mitigation strategies
   - Defence recommendations

2. **[Payload Generation Guide](docs/wiki/Payload-Generation.md)**
   - Professional payload generation methods
   - Why to avoid hardcoded payloads
   - Multiple loading strategies (file, network, embedded, registry)
   - Encryption and obfuscation techniques
   - Build system integration
   - Complete working examples

### Key Topics Covered

**Payload Generation Tools**:

- Metasploit Framework (msfvenom)
- Custom shellcode development (Assembly, pwntools)
- Donut (EXE/DLL to shellcode conversion)
- C2 frameworks (Cobalt Strike, Sliver, Mythic)

**Loading Methods**:

- File-based loading (encrypted and plain)
- Embedded resources (compile-time inclusion)
- Environment variables (base64 encoded)
- Network staging (HTTP/HTTPS)
- Registry storage (Windows)
- Steganography (LSB in images)

**Encryption Techniques**:

- XOR obfuscation
- AES-256 encryption
- ChaCha20 stream cipher

---

## Quick Start

### Prerequisites

**For All Projects**:

- Rust 1.70+ (`rustup install stable`)
- Cargo package manager

**For APC Injection** (Windows-specific):

- Windows 10/11 or Windows Server
- Visual Studio Build Tools (for linking)

### Building All Projects

```bash
# Build evasion payload
cd src/evasion_payload
cargo build --release

# Build APC injection (Windows only)
cd ../apc_injection
cargo build --release
```

### Running Examples

**Sandbox Evasion**:

```bash
cd src/evasion_payload
cargo run --release
```

**APC Injection** (Windows):

```bash
cd src/apc_injection
cargo run --release
```

---

## Project Features

### Code Quality

- ✅ Comprehensive inline documentation
- ✅ Proper error handling with Result types
- ✅ Safety documentation for unsafe operations
- ✅ Professional code structure and organisation
- ✅ British English spelling throughout
- ✅ MITRE ATT&CK technique references

### Build Optimisations

All projects use aggressive release optimisations:

```toml
[profile.release]
opt-level = 3        # Maximum optimisation
lto = true           # Link-time optimisation
codegen-units = 1    # Single codegen unit for better optimisation
strip = true         # Strip debug symbols
```

---

## Educational Use Cases

This repository is designed for:

- ✅ **Authorised Penetration Testing** - With written permission from target organisations
- ✅ **Security Research** - Understanding offensive techniques in controlled environments
- ✅ **Malware Analysis** - Defensive research and threat intelligence
- ✅ **Red Team Operations** - Authorised security assessments
- ✅ **CTF Competitions** - Capture the Flag and security training exercises
- ✅ **Academic Study** - Educational purposes in cybersecurity courses

---

## Legal and Ethical Considerations

### ⚠️ Important Notice

**This code is provided for educational and authorised security research only.**

### Authorised Use

- ✅ Penetration testing with written permission
- ✅ Security research in isolated lab environments
- ✅ Educational purposes in academic settings
- ✅ Defensive security research and malware analysis
- ✅ CTF competitions and security training

### Prohibited Use

- ❌ Unauthorised access to computer systems
- ❌ Deployment against production systems without permission
- ❌ Malicious software development or distribution
- ❌ Bypassing security controls for illegal purposes
- ❌ Any activity violating local, state, or federal laws

### Disclaimer

The authors and contributors of this project:

- Do not condone illegal or unauthorised use
- Accept no responsibility for misuse of this code
- Provide this material for educational purposes only
- Recommend consulting legal counsel before use in security testing

---

## Contributing

Contributions that enhance the educational value of this project are welcome:

1. **Additional Techniques** - Implement new offensive security techniques
2. **Documentation** - Improve guides, add examples, enhance explanations
3. **Detection Methods** - Add defensive strategies and detection signatures
4. **Code Quality** - Refactoring, optimisations, error handling improvements
5. **Cross-Platform** - Extend support for Linux, macOS where applicable

### Contribution Guidelines

- Maintain educational focus and proper documentation
- Include MITRE ATT&CK references where applicable
- Add comprehensive inline comments
- Provide detection and mitigation strategies
- Follow Rust best practices and safety guidelines

---

## Technical Architecture

### Evasion Payload

**Language**: Rust (cross-platform)
**Dependencies**: `rand = "0.8"`
**Techniques**: API Hammering, CPU-intensive computation
**OPSEC Level**: Basic (obvious detection patterns for educational purposes)

### APC Injection

**Language**: Rust with Windows FFI
**Dependencies**: `windows = "0.58"`
**Platform**: Windows only
**Technique**: Local APC injection with alertable threads
**MITRE**: T1055.004

---

## References and Attribution

### Primary Sources

- **RustRedOps**: <https://github.com/joaoviictorti/RustRedOps>
  Main inspiration for techniques implemented in this repository

### Additional Resources

**Frameworks**:

- [Metasploit Framework](https://www.metasploit.com/) - Payload generation
- [Cobalt Strike](https://www.cobaltstrike.com/) - Advanced C2 framework
- [Sliver](https://github.com/BishopFox/sliver) - Open-source C2

**Analysis Tools**:

- [Cuckoo Sandbox](https://cuckoosandbox.org/) - Automated malware analysis
- [CAPE Sandbox](https://capesandbox.com/) - Malware configuration extraction
- [ANY.RUN](https://any.run/) - Interactive online sandbox

**Documentation**:

- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary tactics and techniques
- [Rust Security Book](https://doc.rust-lang.org/book/) - Rust programming fundamentals

---

## Roadmap

### Planned Features

- [ ] Process Injection techniques (Process Hollowing, Thread Hijacking)
- [ ] Encryption and obfuscation methods
- [ ] Anti-debugging techniques
- [ ] Syscall direct invocation
- [ ] AMSI/ETW bypass demonstrations
- [ ] Reflective DLL loading
- [ ] Linux-specific techniques

### Documentation Improvements

- [ ] Video tutorials and demonstrations
- [ ] Detection signatures (YARA, Sigma rules)
- [ ] Blue team response guides
- [ ] Architecture diagrams
- [ ] Performance benchmarking results

---

## Support and Community

For questions, discussions, or educational inquiries:

1. Review the comprehensive [documentation](docs/wiki/)
2. Study the [RustRedOps project](https://github.com/joaoviictorti/RustRedOps)
3. Consult security research communities and forums
4. Engage with authorised security training programmes

---

## Licence

This project is part of an educational security research initiative. All code is provided for educational purposes under the understanding that users will:

- Obtain proper authorisation before testing
- Use tools responsibly and ethically
- Comply with all applicable laws and regulations
- Not engage in malicious activities

---

## Version Information

**Current Version**: 0.1.0
**Last Updated**: 2025-11-26
**Rust Version**: 1.70+
**Status**: Active Development

---

## Acknowledgements

Special thanks to:

- **João Victor** ([@joaoviictorti](https://github.com/joaoviictorti)) - For the excellent RustRedOps project that inspired this work
- **The Rust Community** - For creating a memory-safe systems programming language
- **Security Researchers** - For advancing the field of offensive security research

---

**⚠️ Remember: With great power comes great responsibility. Use these tools ethically and legally.**
