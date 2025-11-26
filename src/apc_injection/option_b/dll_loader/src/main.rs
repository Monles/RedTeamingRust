use std::process::Command;
use std::path::PathBuf;

fn dll_path() -> PathBuf {
    // Default location where `cargo build --release` will place the cdylib on Windows.
    // Adjust as needed for your build layout.
    #[cfg(windows)]
    {
        PathBuf::from("target/release/payload_dll.dll")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("target/release/libpayload_dll.dylib")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("target/release/libpayload_dll.so")
    }
}

fn main() -> anyhow::Result<()> {
    let dll = dll_path();
    if !dll.exists() {
        eprintln!("DLL not found at {:?}. Build `payload_dll` first.", dll);
        std::process::exit(1);
    }

    // On Windows we can use `rundll32.exe` to invoke an exported function by name.
    // This avoids writing any `unsafe` or C code in the loader – it merely spawns
    // an external process to call into the DLL. Note: `rundll32` expects a
    // specific signature for the exported function; behavior may vary.
    #[cfg(windows)]
    {
        let dll_arg = format!("{},run", dll.to_string_lossy());
        let status = Command::new("rundll32.exe").arg(dll_arg).status()?;
        println!("rundll32 exit: {:?}", status);
    }

    #[cfg(not(windows))]
    {
        println!("On non-Windows platforms, loading a Windows DLL is not applicable.");
        println!("Built payload is at: {:?}", dll);
    }

    Ok(())
}
