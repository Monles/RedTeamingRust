## AMSI in Rust Malware Context

**AMSI (Antimalware Scan Interface)** is a Windows security feature that allows applications to request scanning of:

- PowerShell scripts
- VBScript/JScript
- In-memory buffers
- Downloaded files

Rust malware commonly targets AMSI because bypassing it enables:

1. Undetected shellcode execution
2. PowerShell script execution without scanning
3. Memory-based payload deployment

---

## AMSI Bypass Patterns

### Phase 1: AMSI-Specific Sample Collection

**Priority Samples from RustRedOps:**

```
AMSI-related techniques:
├── patch_amsi (PRIMARY - your code example)
├── patch_etw (related telemetry bypass)
├── ntdll_unhooking (similar memory patching)
├── api_hammering (evasion pre-bypass)
└── iat_obfuscation (hides AMSI API usage)
```

### Phase 2: AMSI Bypass Pattern Analysis

**2.1 Common AMSI Bypass Techniques in Rust**

Based on your code and RustRedOps, here are the expected patterns:

| **Pattern Type** | **Technical Detail** | **Rust Implementation** |
|------------------|---------------------|------------------------|
| **Memory Patching** | Modify `AmsiScanBuffer` function in memory | `VirtualProtect` + direct byte writes |
| **Function Hooking** | Redirect AMSI calls to dummy functions | IAT modification or inline hooks |
| **DLL Unloading** | Force unload `amsi.dll` from process | `FreeLibrary` after initial load |
| **Context Corruption** | Corrupt `AMSI_CONTEXT` structure | Null pointer or invalid handle injection |

**2.2 Reverse Engineering Focus**

Create `amsi_pattern_analyzer.py` for Binary Ninja:

```python
import binaryninja as bn
from pathlib import Path
import json

def detect_amsi_patterns(bv):
    """Detect AMSI bypass patterns in Rust binaries"""
    patterns = {
        "memory_patching": False,
        "api_hammering": False,
        "string_obfuscation": False,
        "pattern_search": False,
        "details": []
    }
    
    # Pattern 1: Memory Patching Signature
    # Look for VirtualProtect → memory write → VirtualProtect sequence
    for func in bv.functions:
        virtual_protect_calls = []
        memory_writes = []
        
        for block in func.mlil:
            for instr in block:
                # Detect VirtualProtect calls
                if instr.operation == bn.MediumLevelILOperation.MLIL_CALL:
                    target = instr.dest
                    if "VirtualProtect" in str(target):
                        virtual_protect_calls.append(instr.address)
                
                # Detect memory writes (store operations)
                elif instr.operation == bn.MediumLevelILOperation.MLIL_STORE:
                    memory_writes.append(instr.address)
        
        # Check for pattern: VirtualProtect → write → VirtualProtect
        if len(virtual_protect_calls) >= 2 and len(memory_writes) > 0:
            patterns["memory_patching"] = True
            patterns["details"].append({
                "type": "memory_patching",
                "function": func.name,
                "virtual_protect_calls": [hex(addr) for addr in virtual_protect_calls],
                "memory_writes_between": len(memory_writes)
            })
    
    # Pattern 2: AMSI String/API References
    amsi_strings = []
    for string in bv.strings:
        if "amsi" in string.value.lower() or "amsiscanbuffer" in string.value.lower():
            amsi_strings.append({
                "value": string.value,
                "address": hex(string.start),
                "refs": [hex(ref.address) for ref in bv.get_code_refs(string.start)]
            })
    
    if amsi_strings:
        patterns["details"].append({
            "type": "amsi_references",
            "strings": amsi_strings
        })
    
    # Pattern 3: Byte Pattern Search (0xC3, 0xCC, 0xCC)
    # This is your specific implementation
    for func in bv.functions:
        for block in func.hlil:
            # Look for array comparisons with specific byte patterns
            instr_str = str(block)
            if "0xc3" in instr_str.lower() and "0xcc" in instr_str.lower():
                patterns["pattern_search"] = True
                patterns["details"].append({
                    "type": "byte_pattern_search",
                    "function": func.name,
                    "pattern": "[0xC3, 0xCC, 0xCC]",
                    "address": hex(block.address)
                })
    
    # Pattern 4: Conditional Jump Modification (0x74 -> 0x75)
    # je (0x74) converted to jne (0x75)
    for func in bv.functions:
        for block in func.llil:
            # Look for immediate value 0x74 or 0x75 being used
            for instr in block:
                if instr.operation == bn.LowLevelILOperation.LLIL_SET_REG:
                    if "0x75" in str(instr) or "0x74" in str(instr):
                        patterns["details"].append({
                            "type": "conditional_jump_patch",
                            "instruction": str(instr),
                            "address": hex(instr.address)
                        })
    
    return patterns

# Main analysis loop
results = {}
binary_dir = Path("./binaries")

for binary_path in binary_dir.glob("*.exe"):
    print(f"[*] Analysing {binary_path.name}...")
    bv = bn.open_view(str(binary_path))
    
    if bv:
        results[binary_path.name] = detect_amsi_patterns(bv)
        bv.file.close()
        print(f"[+] Completed {binary_path.name}")

# Save results
with open("amsi_patterns.json", "w") as f:
    json.dump(results, indent=2, fp=f)

print("[*] Analysis complete. Results saved to amsi_patterns.json")
```

### Phase 3: YARA Rules for AMSI Bypass Detection

**3.1 Generic AMSI Bypass Detection**

```yara
rule Rust_AMSI_Memory_Patch {
    meta:
        description = "Detects Rust AMSI bypass via memory patching"
        author = "Your Research"
        severity = "high"
        
    strings:
        // Rust panic strings (confirms Rust binary)
        $rust1 = "panicked at" ascii
        $rust2 = "src\\libcore" ascii
        
        // AMSI.dll loading
        $amsi_dll = "AMSI" wide ascii nocase
        $amsi_func = "AmsiScanBuffer" ascii
        
        // VirtualProtect imports
        $vp = "VirtualProtect" ascii
        
        // Byte pattern search signature (0xC3, 0xCC, 0xCC)
        $pattern = { C3 CC CC }
        
        // Conditional jump opcodes
        $je_opcode = { 74 ?? }  // je with any offset
        $jne_opcode = { 75 ?? } // jne with any offset
        
        // Memory protection constants
        $page_execute_readwrite = { 40 00 00 00 } // PAGE_EXECUTE_READWRITE (0x40)
        
    condition:
        uint16(0) == 0x5A4D and // PE header
        filesize < 5MB and
        ($rust1 or $rust2) and
        $amsi_dll and
        $vp and
        #pattern > 2 and // Multiple instances of ret + int3 + int3
        ($je_opcode and $jne_opcode) // Both conditional jumps present
}

rule Rust_AMSI_Bypass_Detailed {
    meta:
        description = "Specific pattern from your PoC code"
        
    strings:
        // Your exact implementation pattern
        $load_amsi = { 48 8D [2-4] 41 ?? E8 } // LoadLibraryA("AMSI")
        $get_proc = { 48 8D [2-4] 48 ?? E8 } // GetProcAddress
        
        // Pattern search loop
        $pattern_search = { C3 CC CC }
        
        // Reverse loop (searching backwards for 0x74)
        $reverse_scan = { 74 ?? B8 } // je + offset + mov eax pattern
        
        // Patch write (mov byte ptr, 0x75)
        $patch_write = { C6 ?? 75 }
        
    condition:
        uint16(0) == 0x5A4D and
        all of them
}
```

### Phase 4: Expected Top 3 AMSI Patterns

Based on your code and common Rust implementations:

**Pattern 1: VirtualProtect Memory Patching** ✅ (Your code)

```
Characteristics:
├── LoadLibraryA("AMSI") 
├── GetProcAddress for target function
├── Byte pattern search in function prologue
├── VirtualProtect(PAGE_EXECUTE_READWRITE)
├── Direct memory write (0x74 → 0x75)
└── VirtualProtect restore
```

**Pattern 2: AmsiScanBuffer Return Value Modification**

```
Common alternative approach:
├── Locate AmsiScanBuffer function
├── Find function epilogue/return
├── Patch to always return S_OK (0x0)
└── Bypass all AMSI checks
```

**Pattern 3: AMSI Context Corruption**

```
Less common but stealthier:
├── Obtain AMSI context handle
├── Corrupt context structure
├── AMSI fails gracefully
└── No obvious patching detected
```

### Phase 5: Binary Ninja Scripting Workflow

**Quick Analysis Script:**

```bash
# 1. Extract all AMSI-related samples
mkdir amsi_samples
cp RustRedOps/patch_amsi/target/release/*.exe amsi_samples/
cp RustRedOps/patch_etw/target/release/*.exe amsi_samples/

# 2. Run Binary Ninja analysis
python3 amsi_pattern_analyzer.py

# 3. Generate report
python3 -c "
import json
with open('amsi_patterns.json') as f:
    data = json.load(f)
    
for binary, patterns in data.items():
    print(f'\n{binary}:')
    print(f'  Memory Patching: {patterns[\"memory_patching\"]}')
    print(f'  Pattern Search: {patterns[\"pattern_search\"]}')
    print(f'  Details: {len(patterns[\"details\"])} findings')
"
```

---

## Research Deliverables

- **Comparative table**: Rust vs C/C++ AMSI bypass implementations
- **Binary signatures**: Rust-specific compilation artifacts in AMSI bypasses

**Key Finding to Highlight:**
Rust's ownership system and Result/Option types create **unique stack frame patterns** during error handling in AMSI bypass code that don't exist in C/C++ equivalents - this is your differentiation factor.
