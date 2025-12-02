//! # User-Mode APC Injection
//!
//! This module demonstrates APC injection in user-mode context.
//! User APCs are executed in the context of a user-mode process (not kernel-mode).
//!
//! Key differences from kernel APCs:
//! - Executed with user-level privileges
//! - Cannot directly access kernel structures
//! - Suitable for injecting into running user processes
//!
//! Injection steps:
//! 1. Find or enumerate threads in target process
//! 2. Allocate and write shellcode to process memory
//! 3. Use QueueUserAPC to queue the APC to a specific thread
//! 4. Force thread into alertable state (e.g., via SleepEx)
//! 5. APC executes when thread becomes alertable

use windows::core::Result;
use windows::Win32::System::Threading::{OpenThread, QueueUserAPC, SleepEx, THREAD_SET_CONTEXT};

/// Queues a user APC to execute shellcode
pub fn queue_user_apc(tid: u32, shellcode: &[u8]) -> Result<()> {
    println!("[*] Queueing user APC...");
    println!("[*] Target TID: {}", tid);
    println!("[*] Shellcode size: {} bytes", shellcode.len());

    // Open thread handle
    let _hthread = unsafe { OpenThread(THREAD_SET_CONTEXT, false, tid) }?;
    println!("[+] Thread handle obtained");

    // Queue APC (in real scenario, shellcode would be executed via APC callback)
    println!("[*] User APC would be queued to thread");
    println!("[+] APC will execute when thread enters alertable state");

    Ok(())
}

/// Puts current thread into alertable state
pub fn enter_alertable_state() {
    println!("[*] Entering alertable state...");
    println!("[*] Thread can now execute queued user APCs");

    // In real scenario:
    // unsafe { SleepEx(std::u32::MAX, true); }
    // This would put thread in alertable wait state
}

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║      User-Mode APC Injection Technique Demo                ║");
    println!("║              Educational Use Only                          ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    println!("[*] User-mode APC injection characteristics:");
    println!("    - Executed in user-level context");
    println!("    - Works within process privileges");
    println!("    - Requires thread handle with THREAD_SET_CONTEXT");
    println!("    - Target thread must enter alertable state");
    println!();
    println!("[*] Attack flow:");
    println!("    1. Find target thread in process");
    println!("    2. Allocate memory for shellcode");
    println!("    3. Queue APC via QueueUserAPC");
    println!("    4. Wait for thread to enter alertable state");
    println!("    5. Shellcode executes in thread context");

    Ok(())
}
