# APC Injection DLL Loader - Testing Guide

## Overview

This directory contains binaries that demonstrate DLL-based payload loading using `rundll32.exe`. The payload DLL spawns Notepad.exe when executed.

## Files

- `dll_loader_windows_x86_64_release.exe` - Release build of the DLL loader
- `dll_loader_windows_x86_64_debug.exe` - Debug build of the DLL loader
- `payload_dll_windows_x86_64_release.dll` - Release payload DLL (spawns Notepad)
- `payload_dll_windows_x86_64_debug.dll` - Debug payload DLL (spawns Notepad)
- `test_apc_injection.bat` - Automated test script (Batch)
- `test_apc_injection.ps1` - Automated test script (PowerShell)

## What the Code Does

### Payload DLL
The DLL exports a `run()` function that executes:
```rust
std::process::Command::new("notepad.exe").spawn()
```

### Loader
The loader uses Windows `rundll32.exe` to invoke the DLL's exported function:
```rust
Command::new("rundll32.exe").arg("payload_dll.dll,run").status()
```

## Quick Test

### Option 1: Automated Test (Recommended)

**Using Batch Script:**
```cmd
test_apc_injection.bat
```

**Using PowerShell:**
```powershell
powershell -ExecutionPolicy Bypass -File test_apc_injection.ps1
```

### Option 2: Manual Test

```cmd
# Create directory structure
mkdir target\release
copy payload_dll_windows_x86_64_release.dll target\release\payload_dll.dll

# Run the loader
dll_loader_windows_x86_64_release.exe

# Check if Notepad launched
tasklist | findstr notepad
```

### Option 3: Direct DLL Test

```cmd
rundll32.exe payload_dll_windows_x86_64_release.dll,run
```

## Expected Behavior

1. ✅ Loader starts
2. ✅ `rundll32.exe` is spawned
3. ✅ DLL is loaded by `rundll32.exe`
4. ✅ DLL's `run()` function is called
5. ✅ **Notepad.exe launches** (SUCCESS INDICATOR)

## Success Criteria

**You will see:**
- A new Notepad window opens
- Console output: `rundll32 exit: ExitStatus(ExitCode(0))`
- Notepad process visible in Task Manager

## Verification Methods

### 1. Visual Verification
- ✅ Notepad window appears

### 2. Process List Check
```cmd
tasklist | findstr /i "notepad"
```
Expected output:
```
notepad.exe                  12345 Console                 1      5,432 K
```

### 3. Process Monitor (Advanced)
1. Download Process Monitor from Sysinternals
2. Filter: `Process Name is dll_loader_windows_x86_64_release.exe`
3. Run loader
4. Look for:
   - Process Create: `rundll32.exe`
   - Load Image: `payload_dll_windows_x86_64_release.dll`
   - Process Create: `notepad.exe`

### 4. Event Viewer
- Windows Logs → Security
- Event ID 4688 (Process Creation)
- Look for `notepad.exe` creation

## Troubleshooting

### Error: "DLL not found"
**Solution:** Ensure the DLL is in `target/release/payload_dll.dll` relative to the loader:
```cmd
mkdir target\release
copy payload_dll_windows_x86_64_release.dll target\release\payload_dll.dll
```

### Error: "Access Denied" or AV blocks execution
**Solution:** This is educational malware simulation code. Add exclusion to Windows Defender:
- Windows Security → Virus & threat protection → Exclusions
- Add folder: `C:\Users\y279-wang\Documents\RedTeamingRust`

### Notepad doesn't launch
**Possible causes:**
1. Windows Defender blocked execution
2. DLL not in expected location
3. `rundll32.exe` restricted by policy
4. Check loader exit code for errors

## Technical Details

### Why rundll32?

This implementation uses `rundll32.exe` instead of direct APC injection APIs to:
- Avoid writing `unsafe` Rust code
- Demonstrate safe, high-level DLL loading
- Provide educational example without low-level Windows API calls

### Architecture

```
dll_loader.exe
    └─→ spawns: rundll32.exe payload_dll.dll,run
           └─→ loads: payload_dll.dll
                 └─→ calls: run() function
                       └─→ spawns: notepad.exe ✓
```

### Memory Permissions

The loader doesn't directly manipulate memory permissions. Windows handles DLL loading automatically through:
- `LoadLibrary()` (called by rundll32)
- Automatic RX permissions for .text section
- Automatic RW permissions for .data section

## Educational Notes

**MITRE ATT&CK Mapping:**
- T1055.001 - Process Injection: Dynamic-link Library Injection
- T1218.011 - System Binary Proxy Execution: Rundll32

**Detection Opportunities:**
- Monitoring `rundll32.exe` execution with uncommon DLLs
- Tracking process creation chains
- DLL load events from unexpected locations

## Safety

⚠️ **WARNING:** This is educational red team code. Only run in:
- Isolated VMs
- Lab environments
- With proper authorization
- For security research/testing purposes

## Cleanup

Remove test artifacts:
```cmd
# Kill Notepad processes
taskkill /IM notepad.exe /F

# Remove directory structure (optional)
rmdir /s /q target
```

## Support

For issues or questions:
- Check the source code in `src/apc_injection/dll_payload_and_loader/`
- Review build logs
- Verify Windows API availability on target system
