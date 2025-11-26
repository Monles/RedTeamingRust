# Sandbox Evasion Payload

## Overview

The Sandbox Evasion Payload is an educational Rust implementation of common sandbox detection and evasion techniques used in red team operations and malware analysis research. This project demonstrates how adversaries may attempt to detect or evade automated analysis environments.

## Purpose

This payload is designed for:

- **Educational purposes** - Understanding how sandbox evasion works
- **Authorised security testing** - Testing detection capabilities of security tools
- **Malware research** - Studying evasion techniques in a controlled environment
- **Red team operations** - Authorised penetration testing scenarios

## Techniques Implemented

### 1. API Hammering

**Function**: `api_hammering(iterations: usize)`

API Hammering is a technique that performs rapid, intensive file I/O operations to:

- Stress test sandbox environments with limited resources
- Detect virtualised or emulated file systems with performance anomalies
- Generate noise to mask malicious activity
- Exhaust monitoring resources in analysis environments

#### How It Works

```rust
fn api_hammering(iterations: usize) -> io::Result<()>
```

The function performs the following operations in a loop:

1. **File Creation**: Creates a temporary file in the system temp directory
2. **Random Data Generation**: Generates ~1MB (0xFFFFF bytes) of random data using `rand::thread_rng()`
3. **Write Operation**: Writes the random buffer to the file
4. **Read Operation**: Reads the entire file back into memory
5. **Cleanup**: Removes the temporary file after all iterations

**Key Parameters**:

- `iterations`: Number of write/read cycles (default: 2000)
- `size`: Buffer size in bytes (0xFFFFF ≈ 1MB)

**Detection Indicators**:

- Sandboxes may timeout or terminate the process
- Virtual machines might show abnormal I/O performance
- File system monitors may generate excessive logs

#### Technical Details

- **Temp Directory**: Uses `std::env::temp_dir()` for cross-platform compatibility
- **Error Handling**: Returns `io::Result<()>` for proper error propagation
- **Progress Tracking**: Prints progress every 500 iterations
- **Cleanup**: Ensures temporary file is removed after execution

---

### 2. CPU-Intensive Prime Calculation

**Function**: `calc_primes(iterations: usize)`

This technique performs computationally expensive operations to:

- Detect time-accelerated analysis environments
- Evade sandboxes with execution time limits
- Measure CPU performance to identify virtualisation
- Create delays without using obvious sleep functions

#### How It Works

```rust
fn calc_primes(iterations: usize)
```

The function calculates prime numbers using a brute-force algorithm:

1. **Prime Search**: Iterates through integers starting from 2
2. **Primality Test**: Checks each number by testing divisibility by all smaller numbers
3. **Counter**: Tracks the number of primes found
4. **Progress Reporting**: Displays progress and last prime found

**Key Features**:

- `#[no_mangle]`: Prevents name mangling for easier reverse engineering detection
- `#[inline(never)]`: Prevents compiler optimisations that would reduce execution time
- Intentionally inefficient algorithm (O(n²) complexity)

**Detection Indicators**:

- Time-accelerated sandboxes will show inconsistent timing
- Resource-limited environments may timeout
- High CPU usage may trigger monitoring alerts

#### Technical Details

**Primality Test Algorithm**:

```rust
fn is_prime(n: usize) -> bool {
    if n < 2 {
        return false;
    }
    (2..n).all(|j| n % j != 0)
}
```

This is intentionally inefficient (checking all divisors up to n) to maximise CPU usage.

---

## Architecture

### Project Structure

```
evasion_payload/
├── Cargo.toml           # Project configuration and dependencies
├── src/
│   └── main.rs          # Main payload implementation
└── docs/
    └── wiki/
        └── Evasion-Payload.md  # This documentation
```

### Dependencies

```toml
[dependencies]
rand = "0.8"  # Cryptographically secure random number generation
```

### Build Configuration

The project uses aggressive optimisation for release builds:

```toml
[profile.release]
opt-level = 3        # Maximum optimisation
lto = true           # Link-time optimisation
codegen-units = 1    # Single codegen unit for better optimisation
strip = true         # Strip debug symbols
```

---

## Usage

### Building the Payload

**Development Build**:

```bash
cd evasion_payload
cargo build
```

**Optimised Release Build**:

```bash
cargo build --release
```

The release binary will be located at:

```
target/release/evasion_payload
```

### Running the Payload

**Development Mode**:

```bash
cargo run
```

**Release Mode**:

```bash
cargo run --release
```

**Direct Execution**:

```bash
./target/release/evasion_payload
```

### Expected Output

```
[+] Evasion Payload Starting
[+] ========================

[+] Starting API hammering (File I/O stress)...
[*] API hammering progress: 500/2000
[*] API hammering progress: 1000/2000
[*] API hammering progress: 1500/2000
[*] API hammering progress: 2000/2000
[✓] API hammering completed successfully

[+] Starting CPU-intensive prime calculation...
[*] Prime calculation progress: 500/2000 (last prime: 3571)
[*] Prime calculation progress: 1000/2000 (last prime: 7919)
[*] Prime calculation progress: 1500/2000 (last prime: 12553)
[*] Prime calculation progress: 2000/2000 (last prime: 17389)
[*] Prime calculation complete. Last prime found: 17389
[✓] Prime calculation completed

[+] All evasion techniques executed successfully
```

---

## Performance Characteristics

### Execution Time

**Typical Execution Times** (on bare metal):

- API Hammering (2000 iterations): ~30-60 seconds
- Prime Calculation (2000 primes): ~5-10 seconds
- **Total Runtime**: ~35-70 seconds

### Resource Usage

**API Hammering**:

- **Disk I/O**: ~2GB written, ~2GB read (1MB × 2000 iterations)
- **Memory**: ~1MB peak (buffer size)
- **CPU**: Low to moderate

**Prime Calculation**:

- **CPU**: Very high (100% single-core usage)
- **Memory**: Minimal (<1KB)
- **Disk I/O**: None

### Detection in Sandboxes

Sandboxes may exhibit:

- Significantly faster execution (time acceleration)
- Timeouts or forced termination
- Reduced I/O performance
- Different timing ratios between techniques

---

## Evasion Analysis

### How Sandboxes May Detect This Payload

1. **Behavioural Analysis**:
   - Unusual file I/O patterns
   - High CPU usage without network activity
   - No interaction with system resources

2. **Static Analysis**:
   - Function names like `api_hammering` and `calc_primes`
   - `#[no_mangle]` attributes
   - Obvious evasion patterns in code

3. **Resource Monitoring**:
   - Excessive temporary file creation
   - Sustained high CPU usage
   - Large amounts of random data generation

### How This Payload Detects Sandboxes

The payload doesn't explicitly report sandbox detection, but behaviours that may indicate a sandbox:

1. **Extremely Fast Execution**:
   - Time-accelerated sandboxes may complete in <1 second
   - Indicates clock manipulation

2. **Early Termination**:
   - Sandbox timeout mechanisms may kill the process
   - Indicates resource or time limits

3. **Performance Anomalies**:
   - Unusual I/O speeds (too fast or too slow)
   - Indicates virtualised or emulated storage

4. **Error Conditions**:
   - Failed file operations
   - Permission errors in restricted environments

---

## Limitations

### Current Limitations

1. **No Explicit Detection**: The payload doesn't return sandbox detection results
2. **Obvious Indicators**: Function names and code structure are easily identified
3. **Single-threaded**: Doesn't leverage multiple CPU cores
4. **Predictable Behavior**: Always uses same iterations and file patterns
5. **No Obfuscation**: Code is clear and well-documented

### Potential Improvements

These are documented for educational awareness only:

1. **Randomisation**: Variable iteration counts and file sizes
2. **Multiple Techniques**: Network checks, system information gathering
3. **Timing Analysis**: Explicit measurement of execution time anomalies
4. **Environment Checks**: Hardware fingerprinting, debugger detection
5. **Obfuscation**: String encoding, control flow flattening

---

## Defense and Detection

### For Defenders

**Detection Strategies**:

1. **Monitor File I/O Patterns**:

   ```bash
   # Linux: Monitor file creation in /tmp
   inotifywait -m /tmp
   ```

2. **CPU Usage Alerts**:
   - Alert on sustained high CPU usage with no network activity
   - Monitor for processes with unusual computation patterns

3. **Behavioural Analysis**:
   - Flag processes that perform intensive operations without clear purpose
   - Detect repetitive file I/O to temp directories

4. **Static Analysis**:
   - Scan for known evasion function signatures
   - Identify `#[no_mangle]` and `#[inline(never)]` patterns
   - Look for references to `temp_dir()` combined with loops

**Mitigation Strategies**:

1. **Resource Limits**:

   ```bash
   # Linux: Limit CPU and I/O using cgroups
   systemd-run --scope -p CPUQuota=50% ./evasion_payload
   ```

2. **Enhanced Sandboxing**:
   - Use realistic timing (avoid time acceleration)
   - Implement resource limits that don't trigger obvious failures
   - Emulate realistic file I/O performance

3. **Machine Learning**:
   - Train models to identify evasion patterns
   - Detect anomalous behaviour combinations

---

## References

### Source Attribution

This implementation is based on techniques from the RustRedOps project:

- **Repository**: [joaoviictorti/RustRedOps](https://github.com/joaoviictorti/RustRedOps)
- **Specific Reference**: [API-Hammering/src/main.rs](https://github.com/joaoviictorti/RustRedOps/blob/main/API-Hammering/src/main.rs)

### Additional Resources

**Academic Papers**:

- "The Art of Software Security Assessment" - Analysing evasion techniques
- "Practical Malware Analysis" - Understanding sandbox evasion behaviour

**Tools**:

- [Cuckoo Sandbox](https://cuckoosandbox.org/) - Open-source automated malware analysis
- [CAPE Sandbox](https://capesandbox.com/) - Malware configuration and payload extraction
- [ANY.RUN](https://any.run/) - Interactive online malware analysis

**Related Techniques**:

- Sleep acceleration detection
- Hardware breakpoint detection
- Debugger detection
- VM artifact detection
- Timing-based checks

---

## Legal and Ethical Considerations

### Authorised Use Only

This code is provided for **educational and authorised security research only**. Usage must comply with:

- **Authorised penetration testing** with written permission
- **Security research** in controlled environments
- **Educational purposes** in academic settings
- **Malware analysis** and defensive research
- **CTF competitions** and security training

### Prohibited Uses

- Unauthorised access to computer systems
- Deployment against production systems without permission
- Malicious software development or distribution
- Bypassing security controls for illegal purposes
- Any activity violating local, state, or federal laws

### Disclaimer

The authors and contributors of this project:

- Do not condone illegal or unauthorised use
- Accept no responsibility for misuse of this code
- Provide this material for educational purposes only
- Recommend consulting legal counsel before use in security testing

---

## Contributing

Contributions that enhance the educational value of this project are welcome:

1. Additional evasion technique implementations
2. Improved documentation and analysis
3. Detection and mitigation strategies
4. Performance optimisations
5. Cross-platform compatibility improvements

---

## License

This project is part of an educational security research initiative. Refer to the main repository license for terms and conditions.

---

**Last Updated**: 2025-11-26
**Version**: 0.1.0
