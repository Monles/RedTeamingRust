//! # Sandbox Evasion Payload
//!
//! This module implements common sandbox evasion techniques for educational and
//! security research purposes.
//!
//! ## References
//!
//! Based on techniques from the RustRedOps project:
//! - <https://github.com/joaoviictorti/RustRedOps/blob/main/API-Hammering/src/main.rs>
//!
//! ## Techniques Implemented
//!
//! 1. **API Hammering** - Rapid file I/O operations to stress test sandboxes
//! 2. **CPU-Intensive Computation** - Prime number calculation to detect time-accelerated environments

use rand::{thread_rng, Rng};
use std::fs::{remove_file, File};
use std::io::{self, Read, Write};

/// This function simulates "API hammering" by rapidly creating a file in the system's temp directory,
/// writing a large buffer of random bytes to it, and reading it back. This is done repeatedly
/// to increase system noise or potentially evade sandbox analysis.
///
/// # References
///
/// Technique adapted from: <https://github.com/joaoviictorti/RustRedOps/blob/main/API-Hammering/src/main.rs>
///
/// # Parameters
///
/// * `iterations` - The number of I/O iterations to perform.
///
/// # Returns
///
/// * `Ok(())` on success.
/// * `Err(io::Error)` if any file operation fails.
fn api_hammering(iterations: usize) -> io::Result<()> {
    let dir = std::env::temp_dir();
    let path = dir.as_path().join("file.tmp");
    let size = 0xFFFFF; // ~1MB of data

    for i in 0..iterations {
        // Create the file and write random data
        let mut file = File::create(&path)?;
        let mut rng = thread_rng();
        let data: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
        file.write_all(&data)?;

        // Read written data back
        let mut file = File::open(&path)?;
        let mut buffer = vec![0; size];
        file.read_exact(&mut buffer)?;

        if (i + 1) % 500 == 0 {
            println!("[*] API hammering progress: {}/{}", i + 1, iterations);
        }
    }

    // Cleanup
    remove_file(path)?;

    Ok(())
}

/// Calculates a sequence of prime numbers using brute-force method.
///
/// This function simulates heavy CPU-bound computation by iterating through integers
/// and checking primality using division tests. Useful for stress testing or generating
/// delays in execution to evade time-accelerated sandbox environments.
///
/// # References
///
/// Technique adapted from: <https://github.com/joaoviictorti/RustRedOps>
///
/// # Parameters
///
/// * `iterations` - Number of prime numbers to find.
#[no_mangle]
#[inline(never)]
fn calc_primes(iterations: usize) {
    let mut prime = 2;
    let mut count = 0;
    let mut last_prime = 2;

    while count < iterations {
        if is_prime(prime) {
            count += 1;
            last_prime = prime;

            if count % 500 == 0 {
                println!(
                    "[*] Prime calculation progress: {}/{} (last prime: {})",
                    count, iterations, last_prime
                );
            }
        }
        prime += 1;
    }

    println!(
        "[*] Prime calculation complete. Last prime found: {}",
        last_prime
    );
}

/// Helper function to check if a number is prime.
///
/// # Parameters
///
/// * `n` - The number to check for primality.
///
/// # Returns
///
/// * `true` if the number is prime, `false` otherwise.
#[inline(never)]
fn is_prime(n: usize) -> bool {
    if n < 2 {
        return false;
    }
    (2..n).all(|j| n % j != 0)
}

fn main() {
    println!("[+] Evasion Payload Starting");
    println!("[+] ========================\n");

    // First evasion technique: API hammering
    println!("[+] Starting API hammering (File I/O stress)...");
    match api_hammering(2000) {
        Ok(_) => println!("[✓] API hammering completed successfully\n"),
        Err(e) => {
            eprintln!("[!] Error during API hammering: {}", e);
            std::process::exit(1);
        }
    }

    // Second evasion technique: CPU-intensive computation
    println!("[+] Starting CPU-intensive prime calculation...");
    calc_primes(2000);
    println!("[✓] Prime calculation completed\n");

    println!("[+] All evasion techniques executed successfully");
}
