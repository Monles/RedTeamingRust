The code was referenced from
<https://github.com/joaoviictorti/RustRedOps/blob/main/AMSI/README.md>

# List of Rust idioms

## 1. **RAII (Resource Acquisition Is Initialization)**

- Used with `PAGE_PROTECTION_FLAGS` and memory protection through automatic cleanup
- The `Result<()>` return type ensures proper error propagation
- Memory handles are managed through Windows-rs abstractions

## 2. **`unsafe` Block Isolation**

- The entire `main` body is wrapped in a single `unsafe` block, isolating all unsafe operations
- Demonstrates explicit boundary between safe and unsafe code

## 3. **Type-Safe C String Literals (`c"..."` syntax)**

- `let name = c"AmsiScanBuffer";` uses the modern C string literal syntax (Rust 1.77+)
- Provides compile-time null-termination guarantee without runtime overhead

## 4. **Error Handling with `?` Operator**

- Extensively used throughout: `LoadLibraryA(s!("AMSI"))?`, `VirtualProtect(...)?`
- Enables concise error propagation in fallible operations

## 5. **Pattern Matching with `if let`**

- `if let Some(x) = bytes.windows(pattern.len()).position(...)` handles optional values idiomatically
- Avoids explicit `match` when only the `Some` case matters

## 6. **Iterator Methods and Functional Chains**

- `bytes.windows(pattern.len()).position(|window| window == pattern)`
- Uses iterator adapters for efficient pattern searching without manual loops

## 7. **Slice Pattern Matching**

- `let pattern = [0xC3, 0xCC, 0xCC];` defines a byte pattern as an array
- `window == pattern` compares slices directly

## 8. **Raw Pointer Manipulation**

- Explicit casting: `as *const u8`, `as *mut c_void`, `as *mut u8`
- Demonstrates low-level systems programming capability

## 9. **Option Combinators**

- `bytes.get(i + 1).copied().unwrap_or(0)` chains Option methods
- Provides safe access with fallback value

## 10. **Zero-Sized Unit Type `()`**

- `Result<()>` indicates success/failure without a return value
- Idiomatic for side-effect functions

## 11. **Early Return Pattern**

- `if p_patch_address.is_null() { return Err(...); }` validates state before proceeding
- Guards against invalid conditions early

## 12. **Mutable Variable for Out Parameters**

- `let mut old_protect = PAGE_PROTECTION_FLAGS(0);` prepares for FFI out-parameter
- `&mut old_protect` passes mutable reference to Windows API

## 13. **Reverse Iteration**

- `for i in (0..x).rev()` searches backwards through the buffer
- Uses range adapters for direction control

## 14. **Array Indexing with Bounds Checking**

- `bytes.get(target_index)` uses safe indexing method
- `bytes[i]` uses direct indexing where bounds are known

## 15. **Turbofish-Free Type Inference**

- The compiler infers types without explicit annotations (`::<>`)
- Demonstrates Rust's powerful type inference

---

# Analysis of the code

## Summary of this code

This code implements an **AMSI (Antimalware Scan Interface) bypass** by patching the `AmsiScanBuffer` function in memory. It's a security research/red team tool that disables Windows' antimalware scanning capability by modifying runtime behavior of the AMSI library.

### Break down the functionalities of the code step by step

1. **Library Loading**
   - Loads `AMSI.dll` dynamically using `LoadLibraryA`
   - Retrieves the address of `AmsiScanBuffer` function using `GetProcAddress`

2. **Pattern Recognition**
   - Searches for a specific byte pattern `[0xC3, 0xCC, 0xCC]` (ret + two int3 instructions)
   - This pattern helps locate a specific code region in the function

3. **Backwards Scanning**
   - From the found pattern, scans backwards to find a `je` (0x74) conditional jump instruction
   - Verifies the jump leads to a `mov eax, imm32` (0xB8) instruction
   - This identifies the critical branching logic in AMSI's scanning routine

4. **Memory Protection Modification**
   - Uses `VirtualProtect` to change memory permissions to `PAGE_EXECUTE_READWRITE`
   - Allows modification of normally read-only executable code

5. **Opcode Patching**
   - Replaces the `je` (0x74 - "jump if equal") instruction with `jne` (0x75 - "jump if not equal")
   - This inverts the conditional logic, causing AMSI scans to always return "clean"

6. **Protection Restoration**
   - Restores original memory protection flags
   - Maintains stealth by leaving memory permissions in expected state

**Security Context**: This technique is commonly used in offensive security to bypass endpoint detection. The code demonstrates advanced Windows internals knowledge, including function prologue analysis, runtime patching, and memory protection manipulation.
