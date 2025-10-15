# InjectSO - ELF Symbol Resolution & Process Injection Toolkit 🚀

A C-based toolkit for learning and researching ELF file injection, process tracing, and symbol resolution. This project demonstrates low-level process manipulation using ptrace system calls.

> ⚠️ **For educational and research purposes only** - Do not use for malicious software development or illegal activities

## Overview

InjectSO is a C-based educational tool that allows you to:
- Attach to running processes using ptrace
- Parse ELF headers and extract dynamic linking information
- Walk through loaded shared libraries via link_map structures
- Search for multiple symbols across all loaded modules
- Read and write memory in target process address space
- Demonstrate comprehensive symbol resolution capabilities

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

### Quick Build

```bash
# Build all components (injector + example program)
make all

# Or simply run (all is the default target)
make
```

### Build Options

```bash
# Run complete demonstration
make demo

# Debug build (with debug symbols)
make debug

# Release build (optimized version)
make release

# Clean build files
make clean

# Show project information
make info

# Show all available commands
make help
```

### Build Target Descriptions

- **`make all`** - Build main program and example program (default)
- **`make example`** - Build only the example program
- **`make debug`** - Debug build with debug information and extra output
- **`make release`** - Optimized build with debug info stripped
- **`make demo`** - Automatically run complete demonstration workflow
- **`make clean`** - Clean all build artifacts
- **`make info`** - Display project build information

### Manual Build

If you prefer not to use make:

```bash
# Standard build with warnings and optimizations
gcc -Wall -Wextra -std=c99 -O2 -o injector injector.c elf_io.c proc_trace.c

# Build with debug info
gcc -Wall -Wextra -std=c99 -g -o injector injector.c elf_io.c proc_trace.c

# Build example program
gcc -Wall -Wextra -std=c99 -O2 -o example/test_program example/test_program.c
```

## Usage

The injector requires a target process ID (PID):

```bash
# Basic usage
./injector <pid>

# Example
./injector 1234
```

### What the Injector Does

The injector performs comprehensive symbol resolution:

1. **Main Executable Analysis**: Searches for multiple target functions:
   - `demo_function_target` - Primary demonstration function
   - Standard library functions: `puts`, `printf`, `malloc`, `free`, `strlen`, `strcpy`

2. **Shared Library Scanning**: Automatically discovers and analyzes all loaded shared libraries
3. **Symbol Resolution**: Uses both symbol tables and PLT (Procedure Linkage Table) for comprehensive symbol finding
4. **Detailed Reporting**: Provides step-by-step output of the analysis process

### Finding Target PIDs

You can find process PIDs using standard Linux tools:

```bash
# Find PID by process name
pgrep process_name

# List all processes
ps aux

# Find specific process
ps aux | grep firefox

# Quick demo - use the included test program
cd example && make run && cd ..
./injector $(pgrep test_program)
```

## Architecture

### Core Components

1. **injector.c** - Main entry point
   - Process attachment/detachment with register preservation
   - Orchestrates the comprehensive symbol resolution process
   - Searches for multiple target functions for demonstration
   - Enhanced shared library analysis capabilities

2. **proc_trace.c** - Low-level ptrace operations
   - `ptrace_attach()`: Attach to process and save registers
   - `ptrace_detach()`: Restore registers and detach cleanly
   - `ptrace_read()`/`ptrace_write()`: Memory operations with error handling
   - `ptrace_readstr()`: Safe string reading from target process

3. **elf_io.c** - ELF parsing and symbol resolution
   - `get_linkmap()`: Extract and create link_map for main executable
   - `find_symbol()`: Comprehensive symbol search across symbol tables and PLT
   - `get_dyninfo()`: Parse dynamic section with address validation
   - `find_shared_libraries()`: Auto-discover loaded shared libraries from /proc/pid/maps
   - Enhanced error handling and validation for all operations

### Data Flow

1. Attach to target process and preserve register state
2. Extract executable name from `/proc/[pid]/status`
3. Find ELF base address from `/proc/[pid]/maps`
4. Parse ELF headers to locate dynamic section
5. Create link_map for main executable and discover shared libraries
6. For each module (main executable + shared libraries):
   - Parse dynamic section for symbol/PLT tables
   - Search for target functions in symbol table
   - If not found, search PLT relocations
   - Validate addresses and report findings
7. Restore process state and detach cleanly

## 📊 Sample Output

### Complete Analysis Output
```
🚀 ELF Symbol Resolution Tool
============================
Target PID: 12345

📍 Step 1: Attaching to process
📍 Step 2: Analyzing main executable
Module name is: test_program
Module base is: 0x55e8a5ac000
Magic: 7f 45 4c 46
Type: 3 (0x3)

📍 Step 3: Finding symbols in main executable
🔍 Searching for target function: demo_function_target
✅ Found 'demo_function_target' at address: 0x55e8a5ad123

📍 Step 4: Scanning shared libraries
=== Scanning shared libraries ===
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

### Symbol Discovery Output
```
addr of symtab: 0x7ffff7dd5f40 (raw d_ptr=0x1e5f40, base=0x55e8a5ac000)
addr of strtab: 0x7ffff7e06a60 (raw d_ptr=0x206a60, base=0x55e8a5ac000)
size of dymsym: 245

🔍 Scanning 245 symbols in symbol table...
  [0] Found FUNC symbol: '_init' at 0x55e8a5ad000 (type=0)
  [1] Found FUNC symbol: 'demo_function_target' at 0x55e8a5ad123 (type=2)
  [2] Found FUNC symbol: 'puts@plt' at 0x55e8a5ac200 (type=2)
✅ Found demo_function_target at 0x55e8a5ad123 (value: 0x123)
```

## Security Considerations

This tool requires elevated privileges and accesses process memory directly:
- Requires appropriate permissions to attach to target processes
- Modifies target process state temporarily
- Should only be used for educational purposes on systems you own
- May trigger security monitoring tools

### Ptrace Permissions

Modern Linux systems restrict ptrace access for security. To use the injector:

1. **Recommended: Run with sudo**
   ```bash
   sudo ./injector <PID>
   ```

2. **Alternative: Temporarily disable restrictions**
   ```bash
   echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
   ```

3. **Permanent configuration**
   - Add `kernel.yama.ptrace_scope = 0` to `/etc/sysctl.d/10-ptrace.conf`
   - Run `sudo sysctl -p /etc/sysctl.d/10-ptrace.conf`

⚠️ **Warning:** Modifying ptrace scope reduces system security. Only do this on development systems.

## Limitations

- Currently only searches for function symbols (STT_FUNC)
- Hash table optimization (DT_HASH/DT_GNU_HASH) not implemented for performance
- Limited to 64-bit ELF binaries on Linux/Android
- Requires appropriate ptrace permissions (may need sudo)
- Symbol search is limited to prevent infinite loops (safety limits in place)

## Contributing

This is an educational project. Contributions for:
- Better error handling and validation
- Support for additional symbol types
- Hash table optimization (DT_HASH/DT_GNU_HASH)
- Cross-platform compatibility
- Enhanced symbol resolution features
- Performance improvements

are welcome.

## Quick Demo

The easiest way to see the injector in action is to use the built-in demo:

```bash
# Build everything and run automatic demonstration
make demo
```

This will:
1. Build the injector and example program
2. Start the example program in the background
3. Automatically detect its PID
4. Run the injector to demonstrate symbol resolution
5. Clean up everything

## Manual Testing

### Step-by-Step Example

1. **Build the project:**
   ```bash
   make                    # Build injector and example program
   ```

2. **Start the test program:**
   ```bash
   cd example
   make run               # Start test program in background
   ./test_program &       # Alternative method
   ```

3. **Get the PID:**
   ```bash
   pgrep test_program     # Get the PID of test program
   # Output will show: Process ID: 12345
   ```

4. **Run the injector:**
   ```bash
   cd ..
   ./injector 12345       # Use the actual PID
   # Or with sudo if needed:
   sudo ./injector 12345
   ```

5. **Expected output:**
   The injector will discover functions like:
   - `demo_function_target` - Primary demonstration function
   - `test_function_1`, `test_function_2`, `test_function_3`
   - `memory_test_function`, `string_test_function`
   - Standard library functions: `puts`, `printf`, `malloc`, `free`

6. **Cleanup:**
   ```bash
   cd example
   make stop              # Stop test program
   # Or kill manually:
   pkill test_program
   ```

### Example Test Program Features

The test program (`example/test_program.c`) includes:
- **Demonstration Functions**: `demo_function_target`, `symbol_lookup_demo`
- **Test Functions**: Various functions with different characteristics
- **Memory Operations**: `malloc`/`free` usage for testing
- **String Operations**: String manipulation and output
- **Math Functions**: Mathematical calculations
- **Time Functions**: Time-related operations
- **Signal Handling**: Graceful shutdown on Ctrl+C
- **Main Loop**: Periodic function calls for continuous testing

The program is designed to create a rich symbol table for the injector to discover, making it perfect for testing and demonstration purposes.

## License

Educational use only. Please ensure you have appropriate permissions before using this tool on any system.