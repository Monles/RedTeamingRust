# APC Injection — Complete Build Guide

This folder contains multiple APC injection demonstration approaches, from unsafe raw shellcode execution to safe alternatives using DLL loading and IPC.

## Project Structure

```
src/apc_injection/
├── unsafe/                  # Original unsafe APC injection (shellcode in memory)
├── option_b/               # Safe DLL payload + loader (no raw shellcode)
│   ├── payload_dll/        # Rust cdylib exporting run() function
│   └── dll_loader/         # Loader using rundll32.exe
├── option_c/               # Safe IPC payload + loader (entirely user-mode)
│   ├── ipc_payload/        # Child process reading stdin
│   └── ipc_loader/         # Spawns payload and communicates via stdio
├── remote_process_apc/     # Educational: remote process APC injection concepts
├── user_apc/               # Educational: user-mode APC injection concepts
├── kernel_apc/             # Educational: kernel-mode APC injection concepts
├── Cargo.toml              # Workspace manifest
└── README.md               # This file
```

## Building on Windows

### One-Command Build (All Crates)

**Release build (optimized, all crates):**

```bash
cd src\apc_injection
cargo build --release
```

**Debug build (all crates):**

```bash
cd src\apc_injection
cargo build
```

### Individual Crate Builds

#### Option B: DLL Loader

Build payload DLL:

```bash
cargo build -p payload_dll --manifest-path src\apc_injection\option_b\payload_dll\Cargo.toml --release
```

Build DLL loader:

```bash
cargo build -p dll_loader --manifest-path src\apc_injection\option_b\dll_loader\Cargo.toml --release
```

#### Option C: IPC Loader

Build IPC payload:

```bash
cargo build -p ipc_payload --manifest-path src\apc_injection\option_c\ipc_payload\Cargo.toml --release
```

Build IPC loader:

```bash
cargo build -p ipc_loader --manifest-path src\apc_injection\option_c\ipc_loader\Cargo.toml --release
```

#### Educational Crates

Build remote process APC concepts:

```bash
cargo build -p remote_process_apc --manifest-path src\apc_injection\remote_process_apc\Cargo.toml --release
```

Build user-mode APC concepts:

```bash
cargo build -p user_apc --manifest-path src\apc_injection\user_apc\Cargo.toml --release
```

Build kernel-mode APC concepts:

```bash
cargo build -p kernel_apc --manifest-path src\apc_injection\kernel_apc\Cargo.toml --release
```

## Output Locations (After Build)

### Release Builds

```
src\apc_injection\option_b\payload_dll\target\release\payload_dll.dll
src\apc_injection\option_b\dll_loader\target\release\dll_loader.exe
src\apc_injection\option_c\ipc_payload\target\release\ipc_payload.exe
src\apc_injection\option_c\ipc_loader\target\release\ipc_loader.exe
src\apc_injection\remote_process_apc\target\release\remote_process_apc.exe
src\apc_injection\user_apc\target\release\user_apc.exe
src\apc_injection\kernel_apc\target\release\kernel_apc.exe
```

### Debug Builds

```
src\apc_injection\option_b\payload_dll\target\debug\payload_dll.dll
src\apc_injection\option_b\dll_loader\target\debug\dll_loader.exe
src\apc_injection\option_c\ipc_payload\target\debug\ipc_payload.exe
src\apc_injection\option_c\ipc_loader\target\debug\ipc_loader.exe
src\apc_injection\remote_process_apc\target\debug\remote_process_apc.exe
src\apc_injection\user_apc\target\debug\user_apc.exe
src\apc_injection\kernel_apc\target\debug\kernel_apc.exe
```

## Running the Binaries

### Option B (DLL Loader)

Run the DLL loader on Windows:

```bash
cd src\apc_injection\option_b\dll_loader\target\release
dll_loader.exe
```

### Option C (IPC Loader)

Run the IPC loader (spawns payload and communicates via stdio):

```bash
cd src\apc_injection\option_c\ipc_loader\target\release
ipc_loader.exe
```

### Educational Demos

Run user-mode APC demo:

```bash
src\apc_injection\user_apc\target\release\user_apc.exe
```

Run kernel-mode APC info:

```bash
src\apc_injection\kernel_apc\target\release\kernel_apc.exe
```

Run remote process APC demo:

```bash
src\apc_injection\remote_process_apc\target\release\remote_process_apc.exe
```

## Copying Artifacts to dataset\PE (Optional)

After building, copy binaries to `dataset\PE` folder for distribution:

```bash
# Create PE folder if it doesn't exist
mkdir dataset\PE

# Copy release binaries
copy src\apc_injection\option_b\payload_dll\target\release\payload_dll.dll dataset\PE\apc_optionb_payload_dll_windows_release.dll
copy src\apc_injection\option_b\dll_loader\target\release\dll_loader.exe dataset\PE\apc_optionb_dll_loader_windows_release.exe
copy src\apc_injection\option_c\ipc_payload\target\release\ipc_payload.exe dataset\PE\apc_optionc_ipc_payload_windows_release.exe
copy src\apc_injection\option_c\ipc_loader\target\release\ipc_loader.exe dataset\PE\apc_optionc_ipc_loader_windows_release.exe
copy src\apc_injection\remote_process_apc\target\release\remote_process_apc.exe dataset\PE\apc_remote_process_apc_windows_release.exe
copy src\apc_injection\user_apc\target\release\user_apc.exe dataset\PE\apc_user_apc_windows_release.exe
copy src\apc_injection\kernel_apc\target\release\kernel_apc.exe dataset\PE\apc_kernel_apc_windows_release.exe
```

## Notes

- **Option B (DLL Loader):** Uses `rundll32.exe` to invoke DLL exports. Avoids raw shellcode execution. Windows-specific.
- **Option C (IPC Loader):** Safe child process communication via stdio. Platform-agnostic. Recommended for maximum safety.
- **Educational Crates:** Demonstrate APC injection concepts without actually performing injection. For learning purposes.
- **Original Unsafe:** The `unsafe/` folder contains the original unsafe APC injection technique (raw shellcode execution). Kept for reference.

See `docs/wiki/APC-Injection.md` for detailed technical documentation on APC injection techniques, attack lifecycle, and defensive measures.
