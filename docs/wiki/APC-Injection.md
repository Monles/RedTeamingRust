# APC Injection — Process Injection via Asynchronous Procedure Calls

## Overview

Asynchronous Procedure Call (APC) injection is a sophisticated process injection technique that allows adversaries to execute malicious code by queuing APCs (Asynchronous Procedure Calls) to target threads. This technique exploits Windows' built-in APC mechanism, which enables functions to be executed asynchronously within a specific thread's context.

**MITRE ATT&CK Mapping:** [T1055.004 — Process Injection: Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004/)

---

## What is an Asynchronous Procedure Call (APC)?

### Definition

An APC is a function that is executed asynchronously within the context of a specific thread. When an APC is queued to a thread, it is added to that thread's APC queue. When the thread is scheduled to run and enters an **alertable state**, it checks its APC queue for pending APCs and executes them before continuing with normal execution.

### APC Queue Execution Flow

```
Thread Running → Check APC Queue → Execute Pending APCs → Resume Thread Execution
                 (when alertable)
```

### Two Types of APCs

#### 1. **Kernel APCs**

- Executed in **kernel-mode context** with kernel-level privileges
- Can directly access and modify kernel structures
- Typically requires kernel-mode driver or privilege escalation
- More powerful but harder to implement from user-mode

#### 2. **User APCs**

- Executed in **user-mode context** with user-level privileges
- Cannot directly access kernel structures
- More common target for user-mode injection
- Suitable for injecting into running user processes

---

## How APC Injection Works

### Attack Lifecycle (5-Step Process)

Based on the MITRE ATT&CK framework and Picus Security research:

#### Step 1: Process and Thread Handle Acquisition

- Attacker obtains a handle to the **target process** using `OpenProcess` with required access rights:
  - `PROCESS_VM_OPERATION` — Allocate/free memory
  - `PROCESS_VM_WRITE` — Write to process memory
  - `PROCESS_QUERY_INFORMATION` — Query process information
- Attacker identifies and opens a handle to a **target thread** using `OpenThread` with:
  - `THREAD_SET_CONTEXT` — Modify thread context (for APCs)
  - `THREAD_SUSPEND_RESUME` — Suspend/resume thread (optional)

```rust
// Pseudo-code
let hprocess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, target_pid)?;
let hthread = OpenThread(THREAD_SET_CONTEXT, false, target_tid)?;
```

#### Step 2: Memory Allocation in Target Process

- Allocator uses `VirtualAllocEx` to allocate memory in the target process's address space
- Initial memory permissions: `PAGE_READWRITE` (for writing shellcode)
- Memory layout:

  ```
  [Allocated Memory]
  ├── Shellcode
  ├── Stack space for function execution
  └── Return address
  ```

```rust
// Pseudo-code
let addr = VirtualAllocEx(
    hprocess,
    None,
    shellcode_size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);
```

#### Step 3: Writing Shellcode

- Attacker writes malicious shellcode into the allocated memory using `WriteProcessMemory`
- Shellcode can be:
  - Raw machine code (x64 assembly)
  - Injected DLL payload
  - Obfuscated/encrypted code
  - Reflective DLL injection payload

```rust
// Pseudo-code
WriteProcessMemory(hprocess, addr, shellcode.as_ptr(), shellcode.len(), &mut written);
```

#### Step 4: Memory Protection Change

- Change memory permissions from `PAGE_READWRITE` to `PAGE_EXECUTE_READ` using `VirtualProtectEx`
- This prevents further modification while enabling code execution
- Marks memory as executable, triggering code integrity checks

```rust
// Pseudo-code
let mut old_protect = PAGE_PROTECTION_FLAGS(0);
VirtualProtectEx(hprocess, addr, shellcode_size, PAGE_EXECUTE_READ, &mut old_protect);
```

#### Step 5: APC Queueing and Triggering

- Queue APC using `QueueUserAPC` to point to the shellcode address
- The APC points to the shellcode in allocated memory
- Force thread into **alertable state** by calling functions like:
  - `SleepEx` with `bAlertable=true`
  - `WaitForSingleObjectEx` with `bAlertable=true`
  - `SignalObjectAndWait` with `bAlertable=true`
- When thread becomes alertable, queued APC executes automatically

```rust
// Pseudo-code
QueueUserAPC(Some(shellcode_func_pointer), hthread, 0);
ResumeThread(hthread); // or trigger alertable state via SleepEx
```

---

## Implementation Approaches in Rust

### Folder Structure

```
src/apc_injection/
├── unsafe/                  # Original unsafe APC injection (shellcode execution)
├── option_b/               # DLL payload + loader (safer alternative)
├── option_c/               # IPC payload + loader (safest alternative)
├── remote_process_apc/     # Remote process APC injection demo
├── user_apc/               # User-mode APC injection concept
├── kernel_apc/             # Kernel-mode APC injection info
├── Cargo.toml              # Workspace configuration
└── README.md               # Build and run instructions
```

### 1. **Remote Process APC Injection** (`remote_process_apc/`)

Injects shellcode into a **remote (target) process** via APC:

- Opens target process handle
- Allocates memory in target process
- Writes shellcode to remote memory
- Queues APC to remote thread
- Forces thread into alertable state

**Key Functions:**

- `OpenProcess()` — Get target process handle
- `VirtualAllocEx()` — Allocate memory in target
- `WriteProcessMemory()` — Write shellcode to target
- `QueueUserAPC()` — Queue APC routine
- `OpenThread()` / `CreateRemoteThread()` — Target specific thread

**Use Case:** Cross-process code injection while maintaining stealth.

### 2. **User-Mode APC Injection** (`user_apc/`)

Demonstrates user-mode APC concepts and workflow:

- User APCs execute in user-mode context
- Requires thread handle with appropriate rights
- Target thread must enter alertable state
- Limited to user-level privileges

**Key Functions:**

- `OpenThread()` — Get thread handle
- `QueueUserAPC()` — Queue APC to thread
- `SleepEx(..., true)` — Enter alertable state

**Use Case:** Lightweight injection within privilege constraints.

### 3. **Kernel-Mode APC Injection** (`kernel_apc/`)

Information and conceptual overview of kernel APCs:

- Kernel APCs execute with kernel privileges
- Typically requires kernel-mode driver
- Can target any thread or system thread
- More powerful but complex to implement

**Challenges:**

- Requires kernel driver (`.sys` file)
- Needs system privileges
- High detection risk
- Complex implementation

**Use Case:** Privilege escalation, accessing protected processes.

### 4. **Safe Alternatives** (`option_b/`, `option_c/`)

- **Option B (DLL Loader):** Uses `rundll32.exe` to invoke DLL exports—avoids raw shellcode execution
- **Option C (IPC):** Safe child process communication via stdio—entirely in user-mode, portable

---

## Detection and Evasion

### Detection Indicators

**Behavioral:**

- Process creating threads and allocating memory
- Memory permission changes (RW → RX)
- Unexpected thread alertable state changes
- APC queue monitoring

**Forensic:**

- Shellcode in process memory
- Anomalous thread stack traces
- Memory region with execute permissions

**EDR/AV:**

- API call monitoring (VirtualAllocEx, WriteProcessMemory, QueueUserAPC)
- Memory scanning for known shellcode patterns
- Behavioral analysis of thread state changes

### Evasion Techniques

1. **Shellcode Obfuscation** — Encrypt/encode shellcode to evade pattern detection
2. **API Masking** — Use direct syscalls instead of Windows API
3. **Thread Hijacking** — Target existing alertable threads instead of creating new ones
4. **Timing Evasion** — Delay injection to avoid behavioral detection windows
5. **Process Spoofing** — Mimic legitimate application behavior
6. **DLL Side-Loading** — Use APC to load legitimate-looking but malicious DLL

---

## Real-World Examples

### PythonRatLoader & XWORM Malware (2024)

**Attack Vector:** APC injection to deploy XWORM malware

**Techniques Used:**

1. Created `notepad.exe` process (process hollowing preparation)
2. Injected payload before thread execution started
3. Used APC to execute malicious code
4. Obfuscated Python code for injection logic

**Decryption Pattern:**

```python
key = 'evr8pl5K'.encode('ascii')
shellcode = rc4_decrypt(key, encrypted_data)
# Queue APC with decrypted shellcode
```

---

## Defensive Measures

### System Administrator Mitigations

1. **Disable APC mechanisms** — Group Policy (limited effectiveness)
2. **Kernel Patch Guard (KPG)** — Protect kernel structures on Win 10+
3. **Code Integrity Enforcement** — Windows Defender Device Guard
4. **Privilege Restrictions** — Limit token privileges
5. **EDR Deployment** — Monitor process creation, memory changes, thread behavior

### Developer Best Practices

1. **Validate Thread Handles** — Only necessary threads
2. **Monitor Memory Access** — Alert on suspicious allocations
3. **Audit APC Usage** — Log all QueueUserAPC calls
4. **Integrity Checks** — Verify memory regions haven't been tampered

---

## References

- **MITRE ATT&CK Framework:** [T1055.004 — Process Injection: Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004/)
- **Picus Security Blog:** [T1055.004 - Asynchronous Procedure Call](https://www.picussecurity.com/resource/blog/t1055-004-asynchronous-procedure-call)
- **Microsoft Windows API Documentation:** [QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
- **Cofense Research:** [PythonRatLoader: The Proprietor of XWorm](https://cofense.com/blog/pythonratloader-the-proprietor-of-xworm-and-friends)

---

## Disclaimer

This documentation and code examples are for **educational and authorized security research purposes only**. Unauthorized injection of code into processes is illegal and unethical. Always ensure you have explicit written permission before testing these techniques on any system.
