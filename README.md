# InjectSO - ELF Symbol Resolution & Process Injection Toolkit 🚀

一个用于学习和研究ELF文件注入、进程追踪和符号解析的C语言工具包。这个项目演示了使用ptrace系统调用进行底层进程操作。

> ⚠️ **仅用于教育和研究目的** - 请勿用于恶意软件开发或非法活动

## Overview

InjectSO is a C-based educational tool that allows you to:
- Attach to running processes using ptrace
- Parse ELF headers and extract dynamic linking information
- Walk through loaded shared libraries via link_map structures
- Search for multiple symbols across all loaded modules
- Read and write memory in target process address space
- Demonstrate comprehensive symbol resolution capabilities

## ✨ 特性

- **🔍 ELF文件解析** - 完整解析ELF头部、程序头和动态段
- **📚 符号表解析** - 解析动态符号表和字符串表，支持多种符号类型
- **🔗 共享库扫描** - 自动发现进程加载的所有共享库
- **⚡ 进程注入** - 安全的ptrace操作，附加到目标进程
- **🎯 多目标搜索** - 支持同时搜索多个函数符号
- **📊 详细报告** - 生成详细的内存布局和符号信息报告
- **🛡️ 错误处理** - 优雅的错误处理，不会崩溃或挂起
- **🎨 用户友好** - 清晰的输出和丰富的表情符号
- **🏗️ 现代构建** - 完整的Makefile构建系统，支持debug/release模式

## Building

### Prerequisites

- GCC compiler
- Make utility
- Linux/Android environment with ptrace support

### Quick Build

```bash
# 构建所有组件（injector + example program）
make all

# 或者简单运行（all是默认目标）
make
```

### 构建选项

```bash
# 运行完整演示
make demo

# Debug构建（包含调试符号）
make debug

# Release构建（优化版本）
make release

# 清理构建文件
make clean

# 查看项目信息
make info

# 查看所有可用命令
make help
```

### 构建目标说明

- **`make all`** - 构建主程序和示例程序（默认）
- **`make example`** - 仅构建示例程序
- **`make debug`** - Debug构建，包含调试信息和额外输出
- **`make release`** - 优化构建，去除调试信息
- **`make demo`** - 自动运行完整演示流程
- **`make clean`** - 清理所有构建产物
- **`make info`** - 显示项目构建信息

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

## 📊 输出示例

### 完整分析输出
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

### 符号发现输出
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