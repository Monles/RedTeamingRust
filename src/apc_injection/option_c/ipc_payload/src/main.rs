use std::io::{self, Read};

fn main() -> anyhow::Result<()> {
    // Simple payload that reads a message from stdin and responds on stdout.
    // No unsafe or C code required.
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    println!("[ipc_payload] Received: {}", buf.trim());

    // Demonstrative action: on Windows attempt to spawn notepad (best-effort).
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("notepad.exe").spawn();
    }

    Ok(())
}
