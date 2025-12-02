use std::ffi::c_void;
use std::ptr::null_mut;
use std::slice::from_raw_parts;
use windows::core::{s, Error, Result, HSTRING, PCSTR};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{
    VirtualQuery, MEMORY_BASIC_INFORMATION,
};

fn main() -> Result<()> {
    let function_name = c"GetSystemTimeAsFileTime";

    unsafe {
        // Opcode we're searching for (0xC3 -> 'ret')
        let search_opcode = 0xC3u8;

        // Load the kernel32.dll library
        let h_module = LoadLibraryA(s!("kernel32"))?;

        // Retrieve the address of the target function
        let address = GetProcAddress(h_module, PCSTR(function_name.as_ptr().cast()))
            .ok_or_else(|| Error::from_win32())? as *const u8;

        println!("Analyzing function: GetSystemTimeAsFileTime");
        println!("Function address: {:p}", address);

        // Pattern to search for: common function prologue
        let pattern = [0x48, 0x89, 0x5C]; // mov [rsp+offset], rbx
        let mut analysis_address = null_mut();
        let bytes = from_raw_parts(address as *const u8, 0x100 as usize);

        // Search for the pattern within the buffer
        if let Some(x) = bytes
            .windows(pattern.len())
            .position(|window| window == pattern)
        {
            println!("Found prologue pattern at offset: 0x{:X}", x);

            // Forward scan to find return instruction
            for i in x..bytes.len() {
                if bytes[i] == search_opcode {
                    let prev_byte = bytes.get(i.saturating_sub(1)).copied().unwrap_or(0);

                    // Confirm this is a standalone return (not part of another instruction)
                    if prev_byte != 0xFF && prev_byte != 0xC2 {
                        analysis_address = (address.add(i)) as *mut c_void;
                        println!("Found return instruction at offset: 0x{:X}", i);
                        break;
                    }
                }
            }
        }

        if analysis_address.is_null() {
            println!("Pattern not found - function may have different structure");
            return Err(Error::from_win32());
        }

        // Query memory information (read-only operation)
        let mut mem_info = MEMORY_BASIC_INFORMATION::default();
        VirtualQuery(
            Some(analysis_address),
            &mut mem_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        // Display memory protection information
        println!("\nMemory Analysis:");
        println!("  Base address: {:p}", mem_info.BaseAddress);
        println!("  Region size: 0x{:X} bytes", mem_info.RegionSize);
        println!("  Protection flags: 0x{:X}", mem_info.Protect.0);
        println!("  State: 0x{:X}", mem_info.State.0);

        // Analyze first 16 bytes of function
        println!("\nFunction bytecode (first 16 bytes):");
        for (i, byte) in bytes.iter().take(16).enumerate() {
            if i % 8 == 0 {
                print!("  {:04X}: ", i);
            }
            print!("{:02X} ", byte);
            if i % 8 == 7 {
                println!();
            }
        }
        println!();

        // Count instruction patterns (educational analysis)
        let mut ret_count = 0;
        let mut call_count = 0;
        let mut jmp_count = 0;

        for i in 0..bytes.len() {
            match bytes[i] {
                0xC3 | 0xC2 => ret_count += 1, // ret instructions
                0xE8 => call_count += 1,       // call instruction
                0xEB | 0xE9 => jmp_count += 1, // jmp instructions
                _ => {}
            }
        }

        println!("Instruction Statistics:");
        println!("  Return instructions: {}", ret_count);
        println!("  Call instructions: {}", call_count);
        println!("  Jump instructions: {}", jmp_count);
    }

    Ok(())
}
