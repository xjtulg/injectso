# InjectSO - ELF Symbol Resolution & Process Injection Toolkit

A C-based educational toolkit for learning ELF file injection, process tracing, and symbol resolution using ptrace system calls.

> **For educational and research purposes only** - Do not use for malicious software development or illegal activities

## Features

- **ELF File Parsing** - Complete parsing of ELF headers, program headers, and dynamic segments
- **Symbol Table Parsing** - Parse dynamic symbol tables and string tables (STT_FUNC symbols)
- **link_map Traversal** - Walk the dynamic linker's link_map chain to discover all loaded shared libraries
- **DT_DEBUG Resolution** - Retrieve link_map via DT_DEBUG -> r_debug -> r_map, with GOT[1] fallback
- **PLT Relocation Search** - Search PLT relocations (JMPREL) for undefined symbols
- **Relative Address Handling** - Detect and handle both absolute and relative d_ptr values in dynamic sections
- **PIE Support** - Correctly compute load_bias for both ET_EXEC and ET_DYN (PIE) executables
- **Multi-Target Search** - Search multiple function symbols simultaneously across all loaded libraries
- **Process Tracing** - Attach/detach with register save/restore via ptrace
- **Makefile Build System** - Debug/release modes, demo target, and example test program

## Building

### Prerequisites

- GCC compiler
- Make utility
- Linux/Android environment with ptrace support

### Quick Start

```bash
# Build and run demo
make demo

# Or build manually
make
```

### Build Commands

```bash
make all      # Build injector and example program (default)
make debug    # Debug build with symbols
make release  # Optimized build
make clean    # Clean build artifacts
make help     # Show all commands
```

### Manual Build

```bash
gcc -Wall -Wextra -std=c99 -O2 -o injector injector.c elf_io.c proc_trace.c
```

## Usage

```bash
# Basic usage
./injector <pid>

# Quick demo with test program
make demo
```

### How It Works

The injector performs symbol resolution in 3 steps:

1. **Step 1: Attach** - Attach to target process via ptrace, save registers
2. **Step 2: Get link_map** - Parse ELF headers, find PT_DYNAMIC, retrieve link_map via DT_DEBUG -> r_debug -> r_map (falls back to GOT[1] if DT_DEBUG unavailable)
3. **Step 3: Search symbols** - Walk the link_map chain, searching each library's DT_SYMTAB for defined functions and DT_JMPREL (PLT) for undefined symbols

### Finding Target PIDs

```bash
# Find PID by name
pgrep process_name

# Quick demo
./injector $(pgrep test_program)
```

## Architecture

### Core Components

| File | Description |
|------|-------------|
| **injector.c** | Entry point - orchestrates attach, link_map retrieval, and symbol search |
| **elf_io.c** | ELF parsing, link_map retrieval (DT_DEBUG + GOT fallback), symbol resolution (symtab + PLT) |
| **proc_trace.c** | ptrace wrapper - attach/detach, register save/restore, memory read/write, function call |
| **elf_io.h** | Defines `elf_info` and `dynamic_info` structs, ELFW macros |
| **proc_trace.h** | ptrace function declarations |
| **example/test_program.c** | Long-running test target with multiple findable symbols |

### Data Structures

- **`elf_info`** - Stores ELF base address, program header address, dynamic section address and size
- **`dynamic_info`** - Contains runtime addresses and sizes of symtab, strtab, reldyn, relplt, rela

### Data Flow

1. Attach to target process and save register state
2. Read executable name from `/proc/[pid]/status`
3. Find ELF base (offset-0 segment) from `/proc/[pid]/maps`
4. Parse ELF header -> find PT_LOAD (for load_bias) and PT_DYNAMIC
5. Walk dynamic section to find DT_DEBUG -> r_debug -> r_map (or fallback to DT_PLTGOT -> GOT[1])
6. Read link_map chain head
7. For each target symbol, iterate link_map chain:
   - Parse DT_SYMTAB/DT_STRTAB from each library's dynamic section
   - Search symtab for defined STT_FUNC symbols
   - Search PLT relocations (JMPREL) for undefined symbols
8. Restore registers and detach

## Sample Output

```
ELF Symbol Resolution Tool
============================
Target PID: 12345

[*] Step 1: Attaching to process

[*] Step 2: Getting link_map from GOT
Module name is: test_program
Module base is: 0x5626a4d3f000
ELF type: 3 (ET_DYN/PIE)
ph offset:0x40 phnum:13
load_bias: 0x5626a4d3f000
dyn_addr	 0x5626a4d41d90 memsz:496
r_debug at	 0x7f884849e2e0
lm->l_addr	 0x5626a4d3f000
lm->l_prev	 (nil)  lm->l_next	 0x7f88484a02d0

[*] Step 3: Searching for symbols across all loaded libraries

--- Searching for: puts ---
Searching for [puts] in  (base: 0x5626a4d3f000)
addr of symtab: 0x5626a4d3f3c8
addr of strtab: 0x5626a4d3f520
...
--> Next library: /lib/x86_64-linux-gnu/libc.so.6
Searching for [puts] in /lib/x86_64-linux-gnu/libc.so.6 (base: 0x7f8846200000)
[OK] Found puts at 0x7f8846280ed0
[OK] 'puts' resolved at: 0x7f8846280ed0

--- Searching for: malloc ---
...
[OK] 'malloc' resolved at: 0x7f88462a0070

--- Searching for: free ---
...
[OK] 'free' resolved at: 0x7f88462a1250

[OK] Symbol resolution complete
[*] Detached from process 12345
```

## Security

This tool requires elevated privileges and accesses process memory directly:

### Permissions Required

- Appropriate permissions to attach to target processes
- May need to run with `sudo` on modern Linux systems

### Ptrace Configuration

Modern Linux systems restrict ptrace access:

```bash
# Temporary: disable restrictions
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Or run with sudo
sudo ./injector <PID>
```

⚠️ **Warning:** Only use on systems you own for educational purposes.

## Limitations

- Function symbols only (STT_FUNC)
- 64-bit ELF binaries on Linux/Android
- Symbol table scan capped at 1000 entries per library, link_map depth capped at 256
- Hash table lookup (DT_HASH/DT_GNU_HASH) not implemented - uses linear scan
- Requires ptrace permissions

## Contributing

Educational project. Contributions welcome for:
- DT_GNU_HASH / DT_HASH based symbol lookup
- Additional symbol types (STT_OBJECT, etc.)
- Cross-platform compatibility

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.