use anyhow::Result;
use std::io::Write;
use std::process::{Command, Stdio};

fn main() -> Result<()> {
    // Path to the payload binary produced by building `ipc_payload`.
    let payload = std::path::Path::new("target/release/ipc_payload");
    if cfg!(windows) {
        // On Windows binaries have .exe extension
        let p = payload.with_extension("exe");
        run_payload(&p)?;
    } else {
        run_payload(payload)?;
    }
    Ok(())
}

fn run_payload(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        eprintln!("Payload not found at {:?}. Build `ipc_payload` first.", path);
        std::process::exit(1);
    }

    let mut child = Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    // Send a message to the payload
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "Hello from ipc_loader")?;
    }

    // Read response
    let output = child.wait_with_output()?;
    println!("Payload stdout:\n{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}
