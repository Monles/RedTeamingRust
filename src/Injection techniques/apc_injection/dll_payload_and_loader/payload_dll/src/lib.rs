// Minimal Rust cdylib payload. This exports a `run` function that a loader
// can invoke. No `unsafe` or C code required in this crate.

#[cfg(windows)]
#[no_mangle]
pub extern "C" fn run() {
    // On Windows, attempt to spawn Notepad as a demonstrative payload.
    // This uses only Rust's std APIs and no unsafe code.
    let _ = std::process::Command::new("notepad.exe").spawn();
}

#[cfg(not(windows))]
#[no_mangle]
pub extern "C" fn run() {
    // On non-Windows platforms just print a message.
    println!("[payload_dll] run called");
}
