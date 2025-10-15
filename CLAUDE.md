# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a C-based ELF injection and process tracing toolkit for learning about shared object injection on Android and Linux platforms. The project demonstrates low-level process manipulation using ptrace.

## Code Architecture

The codebase is organized into several modules:

### Core Components
- **injector.c/main()**: Entry point that orchestrates the injection process
  - Attaches to target process via PID
  - Retrieves link_map structure
  - Searches for symbols (currently hardcoded to find "puts")
  - Detaches cleanly

- **proc_trace.c**: Low-level ptrace operations wrapper
  - `ptrace_attach()`: Attach to process and save registers
  - `ptrace_detach()`: Restore registers and detach
  - `ptrace_read()`/`ptrace_write()`: Memory read/write operations
  - `ptrace_readstr()`: Read null-terminated strings from target process
  - `ptrace_call()`: Execute functions in target process space

- **elf_io.c**: ELF parsing and symbol resolution
  - `get_linkmap()`: Extract link_map from target process's GOT
  - `find_symbol()`: Recursively search symbol tables across all loaded libraries
  - `get_dyninfo()`: Parse dynamic section for symbol/relayout tables
  - `findELFbase()`: Locate module base address from /proc/pid/maps
  - `findExeName()`: Extract executable name from /proc/pid/status

### Data Structures
- `elf_info`: Stores ELF header, program header, and dynamic section addresses
- `dynamic_info`: Contains addresses and sizes of dynamic linking tables (symtab, strtab, relplt, etc.)
- Uses system `struct link_map` for traversing loaded libraries

## Build System

No formal build system exists. Compile manually with gcc:

```bash
gcc -o injector injector.c elf_io.c proc_trace.c
```

**Note**: Build tools (gcc, make) are not installed in the current environment. Install build-essential package first.

## Usage

The injector requires a target PID:

```bash
./injector <pid>
```

Example:
```bash
./injector 1234
```

## Key Implementation Details

### Process Tracing Flow
1. Attach to target process with `PTRACE_ATTACH`
2. Wait for process to stop (`WUNTRACED`)
3. Extract ELF base from `/proc/pid/maps`
4. Parse ELF headers to find dynamic section
5. Locate link_map through GOT entry
6. Recursively walk link_map chain to find symbols
7. Restore registers and detach

### Symbol Resolution
- Parses DT_SYMTAB, DT_STRTAB from dynamic section
- Traverses all loaded libraries via link_map->l_next
- Currently only searches for STT_FUNC type symbols
- Hash table optimization (DT_HASH/DT_GNU_HASH) noted but not implemented

### Memory Access
- Uses `PTRACE_PEEKTEXT`/`PTRACE_POKETEXT` for word-aligned access
- String reading handles word boundaries and null termination
- Stack manipulation via `ptrace_push()` for function calls

## Development Notes

- Code includes extensive debug output showing symbol addresses and table locations
- Error handling is basic but functional
- Memory allocation needs verification (malloc without null checks in some places)
- The symbol search is recursive across all loaded libraries
- Currently hardcoded to search for "puts" symbol as demonstration