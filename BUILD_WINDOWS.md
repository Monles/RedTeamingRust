# Building on Windows

This guide explains how to build the Option B and Option C payloads natively on Windows (much faster than cross-compilation).

## Prerequisites

On Windows, install:

1. **Rust** — <https://rustup.rs/> (includes `cargo`)
2. **Git** (optional, for cloning)

## Building Release Binaries

From the repository root on Windows, run:

```bash
# Build all Option B and Option C crates (release)
cargo build --manifest-path src/apc_injection/option_b/payload_dll/Cargo.toml --release
cargo build --manifest-path src/apc_injection/option_b/dll_loader/Cargo.toml --release
cargo build --manifest-path src/apc_injection/option_c/ipc_payload/Cargo.toml --release
cargo build --manifest-path src/apc_injection/option_c/ipc_loader/Cargo.toml --release
```

## Building Debug Binaries

```bash
# Build all Option B and Option C crates (debug)
cargo build --manifest-path src/apc_injection/option_b/payload_dll/Cargo.toml
cargo build --manifest-path src/apc_injection/option_b/dll_loader/Cargo.toml
cargo build --manifest-path src/apc_injection/option_c/ipc_payload/Cargo.toml
cargo build --manifest-path src/apc_injection/option_c/ipc_loader/Cargo.toml
```

## Output Locations

After building, the binaries will be at:

**Release:**

- `src/apc_injection/option_b/payload_dll/target/release/payload_dll.dll`
- `src/apc_injection/option_b/dll_loader/target/release/dll_loader.exe`
- `src/apc_injection/option_c/ipc_payload/target/release/ipc_payload.exe`
- `src/apc_injection/option_c/ipc_loader/target/release/ipc_loader.exe`

**Debug:**

- `src/apc_injection/option_b/payload_dll/target/debug/payload_dll.dll`
- `src/apc_injection/option_b/dll_loader/target/debug/dll_loader.exe`
- `src/apc_injection/option_c/ipc_payload/target/debug/ipc_payload.exe`
- `src/apc_injection/option_c/ipc_loader/target/debug/ipc_loader.exe`

## Copying to dataset/PE (Optional)

After building, copy binaries into `dataset/PE/` with descriptive names:

```bash
# Example (adjust paths and names as needed)
copy src\apc_injection\option_b\payload_dll\target\release\payload_dll.dll dataset\PE\apc_optionb_payload_dll_windows_x86_64_release.dll
copy src\apc_injection\option_b\dll_loader\target\release\dll_loader.exe dataset\PE\apc_optionb_dll_loader_windows_x86_64_release.exe
copy src\apc_injection\option_c\ipc_payload\target\release\ipc_payload.exe dataset\PE\apc_optionc_ipc_payload_windows_x86_64_release.exe
copy src\apc_injection\option_c\ipc_loader\target\release\ipc_loader.exe dataset\PE\apc_optionc_ipc_loader_windows_x86_64_release.exe
```

## Running the Binaries

### Option B (DLL Loader)

On Windows, the `dll_loader` executable uses `rundll32.exe` to invoke the `run` export from `payload_dll.dll`:

```bash
# Make sure payload_dll.dll is built and in the same directory or in PATH
cd src/apc_injection/option_b/dll_loader/target/release
.\dll_loader.exe
```

### Option C (IPC Payload + Loader)

The IPC approach spawns a child process and communicates via stdin/stdout:

```bash
# Build both crates first, then run the loader
cd src/apc_injection/option_c/ipc_loader/target/release
.\ipc_loader.exe
```

The loader will spawn `ipc_payload.exe` and send it a message.

## Notes

- Both approaches avoid raw `unsafe` shellcode execution (the original APC injection).
- Option B uses DLL loading (platform-specific to Windows).
- Option C is platform-agnostic and uses safe IPC (recommended for maximum portability and safety).
