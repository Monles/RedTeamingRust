ApC Injection — Option B (DLL) and Option C (IPC)
=================================================

This folder contains two demonstration approaches that avoid raw `unsafe` shellcode execution in the injector.

Option B — DLL payload + loader

- `option_b/payload_dll` — Rust `cdylib` that exports a `run` function. The payload is implemented in Rust (no C).
- `option_b/dll_loader` — Loader that invokes the DLL. On Windows this example uses `rundll32.exe` to call the exported `run` symbol.

Build & run (Windows):

```bash
# From repository root
cargo build -p payload_dll --manifest-path src/apc_injection/option_b/payload_dll/Cargo.toml --release
cargo run -p dll_loader --manifest-path src/apc_injection/option_b/dll_loader/Cargo.toml --release
```

Option C — Safe IPC (recommended if you want no `unsafe` at all)

- `option_c/ipc_payload` — Simple child process that reads stdin and performs payload actions.
- `option_c/ipc_loader` — Spawns the payload and communicates via stdio.

Build & run (all platforms):

```bash
# Build both
cargo build --manifest-path src/apc_injection/option_c/ipc_payload/Cargo.toml --release
cargo build --manifest-path src/apc_injection/option_c/ipc_loader/Cargo.toml --release

# Run loader (it will spawn the payload)
cargo run --manifest-path src/apc_injection/option_c/ipc_loader/Cargo.toml --release
```

Notes

- The original APC injection technique (executing raw shellcode in memory) inherently requires `unsafe` and low-level OS calls. These demos avoid that technique and instead show safer alternatives.
- `rundll32` expects particular DLL export signatures; the `payload_dll` here is a minimal demo and may need adjustments for production.
