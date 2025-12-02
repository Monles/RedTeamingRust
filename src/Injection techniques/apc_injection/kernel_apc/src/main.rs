//! # Kernel-Mode APC Injection
//!
//! This module documents kernel-mode APC injection concepts.
//! Kernel APCs are executed in kernel-mode context with kernel-level privileges.
//!
//! Key characteristics:
//! - Executed with kernel-level privileges
//! - Can directly access kernel structures
//! - Difficult to implement from user-mode without driver support
//! - Typically requires a kernel-mode driver
//! - Can target system threads or threads in any process
//!
//! Note: Direct kernel APC injection from user-mode is limited without kernel support.
//! This module demonstrates the conceptual approach and differences.

use windows::core::Result;

/// Kernel APC injection concepts
pub fn kernel_apc_info() {
    println!("[*] Kernel APC Injection Information:");
    println!();
    println!("[*] Types of Kernel APCs:");
    println!("    1. SpecialUserApc - Executed in target thread's user-mode context");
    println!("    2. SystemApc - Executed in kernel-mode context");
    println!("    3. ControlledApc - Advanced control over execution");
    println!();
    println!("[*] Advantages:");
    println!("    - Execute with kernel privileges");
    println!("    - Can target system threads");
    println!("    - Bypass user-mode security controls");
    println!();
    println!("[*] Challenges:");
    println!("    - Requires kernel-mode driver or exploits");
    println!("    - Complex implementation");
    println!("    - Heavily monitored by EDR/AV");
    println!();
    println!("[*] Attack vector:");
    println!("    1. Load kernel driver or exploit kernel vulnerability");
    println!("    2. Use driver to queue kernel APC");
    println!("    3. Execute malicious code with kernel privileges");
    println!("    4. Evade detection by manipulating kernel structures");
}

fn main() -> Result<()> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║      Kernel-Mode APC Injection Information                 ║");
    println!("║              Educational Use Only                          ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    kernel_apc_info();

    println!();
    println!("[!] Note: Kernel APC injection typically requires:");
    println!("    - Kernel-mode driver");
    println!("    - System privileges");
    println!("    - Kernel API access");
    println!();
    println!("[*] For user-mode alternatives, see:");
    println!("    - remote_process_apc: Cross-process injection");
    println!("    - user_apc: User-mode thread injection");

    Ok(())
}
