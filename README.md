# InjectSO - ELF Symbol Resolution & Process Injection Toolkit 🚀

A C-based educational toolkit for learning ELF file injection, process tracing, and symbol resolution using ptrace system calls.

> ⚠️ **For educational and research purposes only** - Do not use for malicious software development or illegal activities

## Features

- **🔍 ELF File Parsing** - Complete parsing of ELF headers, program headers, and dynamic segments
- **📚 Symbol Table Parsing** - Parse dynamic symbol tables and string tables, supporting multiple symbol types
- **🔗 Shared Library Scanning** - Automatically discover all shared libraries loaded by a process
- **⚡ Process Injection** - Safe ptrace operations to attach to target processes
- **🎯 Multi-Target Search** - Support for searching multiple function symbols simultaneously
- **📊 Detailed Reporting** - Generate detailed memory layout and symbol information reports
- **🛡️ Error Handling** - Graceful error handling without crashes or hangs
- **🎨 User-Friendly** - Clear output with rich emoji indicators
- **🏗️ Modern Build** - Complete Makefile build system with debug/release modes

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

The injector performs comprehensive symbol resolution:

1. **Process Attachment** - Attaches to target process using ptrace
2. **ELF Analysis** - Parses executable headers and dynamic sections
3. **Symbol Discovery** - Searches for functions in main executable and all loaded libraries
4. **Memory Mapping** - Traverses link_map structures to find shared libraries
5. **Detailed Reporting** - Provides step-by-step output with addresses and metadata

### Finding Target PIDs

```bash
# Find PID by name
pgrep process_name

# Quick demo
cd example && make run && cd ..
./injector $(pgrep test_program)
```

## Architecture

### Core Components

- **injector.c** - Main entry point and orchestration
- **proc_trace.c** - Low-level ptrace operations
- **elf_io.c** - ELF parsing and symbol resolution

### Data Flow

1. Attach to target process and preserve register state
2. Extract executable information from `/proc/[pid]/`
3. Parse ELF headers and dynamic sections
4. Discover shared libraries via link_map traversal
5. Search symbol tables across all modules
6. Report findings and restore process state

## Sample Output

```
🚀 ELF Symbol Resolution Tool
============================
Target PID: 12345

📍 Step 1: Attaching to process
📍 Step 2: Analyzing main executable
Module name is: test_program
Module base is: 0x55e8a5ac000

📍 Step 3: Finding symbols in main executable
🔍 Searching for target function: demo_function_target
✅ Found 'demo_function_target' at address: 0x55e8a5ad123

📍 Step 4: Scanning shared libraries
Found library: /lib/x86_64-linux-gnu/libc.so.6 @ 0x7f884628000
Found library: /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 @ 0x7f88483f000
Found 2 shared libraries

📍 Step 5: Analyzing shared libraries
📚 Analyzing library 1: /lib/x86_64-linux-gnu/libc.so.6
🔍 Searching for symbols in /lib/x86_64-linux-gnu/libc.so.6
✅ Found 'puts' at address: 0x7f8847e4a640

🎉 Injection analysis complete!
✅ Successfully analyzed:
   • Main executable symbols
   • 2 shared libraries
   • Function addresses and metadata
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
- Hash table optimization not implemented
- Requires ptrace permissions

## Contributing

Educational project. Contributions welcome for:
- Enhanced error handling
- Additional symbol types
- Performance optimizations
- Cross-platform compatibility

## License

Educational use only. Ensure appropriate permissions before use.