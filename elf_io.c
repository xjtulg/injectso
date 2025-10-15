#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include "elf_io.h"

int findExeName(pid_t pid, char* name)
{
    char status[256] = {0};
    char line[1024] = {0};

    sprintf(status, "/proc/%d/status", pid);

    FILE* fp = fopen(status, "r");
    if(NULL == fp) {
        printf("open %s err\n", status);
        return -1;
    }

    while(fgets(line, 1024, fp)) {
        if(strstr(line, "Name:")) {
            strcpy(name, line+sizeof("Name:"));
            break;
        }
    }

    if(name[0] == '\0') {
        return -1;
    } else {
        return 0;
    }
}

ElfW(Addr) findELFbase(pid_t pid, const char* module)
{
    char maps[256] = {0};
    char line[1024] = {0};
    ElfW(Addr) base = 0;

    sprintf(maps, "/proc/%d/maps", pid);
    FILE* fp = fopen(maps, "r");
    if (NULL == fp) {
        printf("open %s err\n", maps);
        return 0;
    }

    // Find the first segment of the module (contains ELF header)
    // This is typically the r--p segment, not r-xp
    while(fgets(line, 1024, fp)) {
        if(strstr(line, module)) {
            // Check if this is the first segment (lowest address)
            ElfW(Addr) addr = strtoul(line, NULL, 16);
            if (base == 0 || addr < base) {
                base = addr;
            }
        }
    }

    fclose(fp);

    return base;
}

int get_dyninfo(pid_t pid, struct link_map *lm, dynamic_info *dyninfo)
{
    ElfW(Dyn) dyn = {0};
    unsigned long dyn_addr;

    dyn_addr = (unsigned long)lm->l_ld;

    ptrace_read(pid, dyn_addr, &dyn, sizeof(ElfW(Dyn)));
    while(dyn.d_tag != DT_NULL) {
        switch(dyn.d_tag) {
            case DT_SYMTAB:
                // For main executable (ET_EXEC), d_ptr is already a virtual address
                // For shared libraries (ET_DYN), d_ptr is relative and needs base offset
                // We can detect this by checking if d_ptr is already in the expected range
                if (dyn.d_un.d_ptr > 0x100000000) {  // Likely already a virtual address
                    dyninfo->symtab = dyn.d_un.d_ptr;
                } else {  // Need to add base address
                    dyninfo->symtab = lm->l_addr + dyn.d_un.d_ptr;
                }
                printf("addr of symtab: %p (raw d_ptr=0x%lx, base=0x%lx)\n",
                       (void*)dyninfo->symtab, (unsigned long)dyn.d_un.d_ptr, (unsigned long)lm->l_addr);
                break;
            case DT_STRTAB:
                // Same logic for string table
                if (dyn.d_un.d_ptr > 0x100000000) {  // Likely already a virtual address
                    dyninfo->strtab = dyn.d_un.d_ptr;
                } else {  // Need to add base address
                    dyninfo->strtab = lm->l_addr + dyn.d_un.d_ptr;
                }
                printf("addr of strtab: %p (raw d_ptr=0x%lx, base=0x%lx)\n",
                       (void*)dyninfo->strtab, (unsigned long)dyn.d_un.d_ptr, (unsigned long)lm->l_addr);
                break;
            //TODO:don't know how to find symbol by hash or gnu_hash
            case DT_HASH:
                break;
            case DT_GNU_HASH:
                break;
            case DT_REL:
                if (dyn.d_un.d_ptr > 0x100000000) {  // Likely already a virtual address
                    dyninfo->reldyn = dyn.d_un.d_ptr;
                } else {  // Need to add base address
                    dyninfo->reldyn = lm->l_addr + dyn.d_un.d_ptr;
                }
                printf("addr of reldyn: %p\n", (void*)dyninfo->reldyn);
                break;

            case DT_RELSZ:
                dyninfo->reldynsz = dyn.d_un.d_val / sizeof(ElfW(Rel));
                printf("size of reldyn: %ld\n", dyninfo->reldynsz);
                break;

            case DT_JMPREL:
                if (dyn.d_un.d_ptr > 0x100000000) {  // Likely already a virtual address
                    dyninfo->relplt = dyn.d_un.d_ptr;
                } else {  // Need to add base address
                    dyninfo->relplt = lm->l_addr + dyn.d_un.d_ptr;
                }
                printf("addr of relplt: %p (raw d_ptr=0x%lx, base=0x%lx)\n",
                       (void*)dyninfo->relplt, (unsigned long)dyn.d_un.d_ptr, (unsigned long)lm->l_addr);
                break;

            case DT_PLTRELSZ:
                dyninfo->relpltsz = dyn.d_un.d_val / sizeof(ElfW(Rela));
                printf("size of relplt: %ld\n", dyninfo->relpltsz);
                break;

            case DT_RELA:
                if (dyn.d_un.d_ptr > 0x100000000) {  // Likely already a virtual address
                    dyninfo->rela = dyn.d_un.d_ptr;
                } else {  // Need to add base address
                    dyninfo->rela = lm->l_addr + dyn.d_un.d_ptr;
                }
                printf("addr of rela:%p\n", (void*)dyninfo->rela);
                break;

            case DT_RELASZ:
                dyninfo->relasz = dyn.d_un.d_val/ sizeof(ElfW(Rela));
                printf("size of rela:%ld\n", dyninfo->relasz);
                break;
        }

        ptrace_read(pid, dyn_addr += sizeof(ElfW(Dyn)), &dyn, sizeof(ElfW(Dyn)));
    }

    dyninfo->symsize = (dyninfo->strtab - dyninfo->symtab)/sizeof(ElfW(Sym));
    printf("size of dymsym: %ld\n", dyninfo->symsize);

    return 0;
}

/*****************************************************************************
 Prototype    : ElfW
 Description  : Find
 Input        : pid_t pid,struct link_map *lm,const elf_info *elfinfo,
                      const char * sym_name
 Output       : ElfW(Sym)
 Return Value :
 Calls        :
 Called By    :

  History        :
  1.Date         : 2015/9/13
    Author       : Justin Liu
    Modification : Created function

*****************************************************************************/
ElfW(Addr) find_symbol(pid_t pid,struct link_map *lm, const char * sym_name)
{
    ElfW(Sym) sym = {0};
    struct link_map map = {0};
    dynamic_info dyninfo = {0};
    char *name = NULL;
    int i = 0;

    printf("Searching for [%s] in %s (base: %p)\n", sym_name,
           (char*)lm->l_name, (void*)lm->l_addr);

    //get dynamic table info from lm
    get_dyninfo(pid, lm, &dyninfo);

    // For shared libraries, the dynamic section addresses might be absolute
    // For the main executable, they are relative to the base address
    // Let's try to validate the addresses first
    if (dyninfo.symtab == 0 || dyninfo.strtab == 0) {
        printf("⚠️  Invalid dynamic section addresses in %s\n", (char*)lm->l_name);
        goto next_library;
    }

    // Try to verify if we can read from the dynamic section
    // Test multiple entries to find a non-NULL one, since first entry is often NULL
    int valid_symbols_found = 0;
    for (int test_idx = 0; test_idx < 5 && test_idx < dyninfo.symsize; test_idx++) {
        ElfW(Sym) test_sym = {0};
        ptrace_read(pid, dyninfo.symtab + test_idx * sizeof(ElfW(Sym)), &test_sym, sizeof(ElfW(Sym)));
        // A valid symbol table should have at least one non-zero entry
        if (test_sym.st_name != 0 || test_sym.st_info != 0 || test_sym.st_value != 0 || test_sym.st_size != 0) {
            valid_symbols_found++;
        }
    }

    if (valid_symbols_found == 0 && dyninfo.symsize > 0) {
        printf("⚠️  Cannot read valid symbols from table at %p in %s (symsize=%ld)\n",
               (void*)dyninfo.symtab, (char*)lm->l_name, dyninfo.symsize);
        goto next_library;
    }

    // First try to find symbol in the symbol table (for defined functions)
    printf("🔍 Scanning %ld symbols in symbol table...\n", dyninfo.symsize);
    for (i=0; i<dyninfo.symsize && i < 1000; i++) {  // Limit to prevent infinite loops
        ptrace_read(pid, dyninfo.symtab + i * sizeof(ElfW(Sym)), &sym,
                    sizeof(ElfW(Sym)));

        if (sym.st_name == 0) {
            continue;  // Skip empty symbol names
        }

        name = ptrace_readstr(pid, dyninfo.strtab + sym.st_name);

        // Debug: Show first few function symbols
        if (i < 5 && ELFW(ST_TYPE)(sym.st_info) == STT_FUNC) {
            printf("  [%d] Found FUNC symbol: '%s' at 0x%lx (type=%d)\n",
                   i, name ? name : "(null)", (unsigned long)sym.st_value, ELFW(ST_TYPE)(sym.st_info));
        }

        if (ELFW(ST_TYPE)(sym.st_info) != STT_FUNC) {
            if (name) free(name);
            continue;
        }

        if (name && strcmp(name, sym_name) == 0) {
            if (sym.st_value != 0) {
                // Defined function in this module
                printf("✅ Found %s at %p (value: 0x%lx)\n",
                       name, (void*)(lm->l_addr + sym.st_value), (unsigned long)sym.st_value);
                free(name);
                return lm->l_addr + sym.st_value;
            } else {
                // Undefined function - will be handled by PLT search
                printf("🔍 Found undefined %s in symbol table, checking PLT...\n", name);
            }
        }

        if (name) {
            free(name);
        }
    }

    // If symbol not found in symbol table, try PLT relocations (for undefined symbols)
    if (dyninfo.relplt != 0 && dyninfo.relpltsz > 0) {
        // Try to verify if we can read from the PLT
        // Test multiple entries since first one might be NULL
        int valid_rela_found = 0;
        for (int test_idx = 0; test_idx < 3 && test_idx < dyninfo.relpltsz; test_idx++) {
            ElfW(Rela) test_rela = {0};
            ptrace_read(pid, dyninfo.relplt + test_idx * sizeof(ElfW(Rela)), &test_rela, sizeof(ElfW(Rela)));
            if (test_rela.r_offset != 0 || test_rela.r_info != 0) {
                valid_rela_found++;
                break;
            }
        }

        if (valid_rela_found > 0) {
            for(i=0; i<dyninfo.relpltsz && i < 100; i++) {  // Limit to prevent infinite loops
                ElfW(Rela) rela = {0};
                ptrace_read(pid, dyninfo.relplt + i * sizeof(ElfW(Rela)), &rela,
                            sizeof(ElfW(Rela)));

                if(ELF64_R_SYM(rela.r_info)) {
                    ElfW(Sym) rel_sym = {0};
                    if (ELF64_R_SYM(rela.r_info) < (unsigned long)dyninfo.symsize) {
                        ptrace_read(pid, dyninfo.symtab + ELF64_R_SYM(rela.r_info) *
                                    sizeof(ElfW(Sym)), &rel_sym,
                                    sizeof(ElfW(Sym)));

                        if (rel_sym.st_name != 0) {
                            name = ptrace_readstr(pid, dyninfo.strtab + rel_sym.st_name);
                            if (name && strcmp(name, sym_name) == 0) {
                                printf("✅ Found %s via PLT at address: %p\n",
                                       name, (void*)(lm->l_addr + rela.r_offset));
                                free(name);
                                return lm->l_addr + rela.r_offset;
                            }
                            if (name) {
                                free(name);
                            }
                        }
                    }
                }
            }
        } else {
            printf("⚠️  Cannot read PLT at %p in %s\n",
                   (void*)dyninfo.relplt, (char*)lm->l_name);
        }
    }

next_library:
    // Recursively search in next library if this one doesn't contain the symbol
    if(lm->l_next != NULL) {
        ptrace_read(pid, (unsigned long)lm->l_next, &map, sizeof(struct link_map));
        name = ptrace_readstr(pid, (unsigned long)map.l_name);
        if (name && strlen(name) > 0) {
            printf("-->Searching in next library: %s\n", name);
            free(name);
            return find_symbol(pid, &map, sym_name);
        }
        if (name) free(name);
    }
    return 0;
}

struct link_map * get_linkmap(pid_t pid, elf_info *elfinfo)
{
    ElfW(Ehdr) ehdr = {0};
    ElfW(Phdr) phdr = {0};
    int i = 0;
    ElfW(Addr) phdr_addr = 0;
    char module[256] = {0};
    int ret = 0;

    struct link_map *map = (struct link_map *)
                           malloc(sizeof(struct link_map));

    //initialize the memory of local variable
    memset(map, 0, sizeof(struct link_map));

    if (0 != findExeName(pid, module)) {
        printf("can't find name of exe\n");
        ret = -1;
        goto done;
    }
    printf("Module name is:%s \n", module);
    elfinfo->base = findELFbase(pid, module);
    printf("Module base is:%p \n", (void*)elfinfo->base);
    if (0 == elfinfo->base) {
        ret = -1;
        goto done;
    }

    ptrace_read(pid, elfinfo->base, &ehdr, sizeof(ElfW(Ehdr)));

    // Debug: Check ELF magic and type
    printf("ELF header read from address %p\n", (void*)elfinfo->base);
    printf("Magic: %02x %02x %02x %02x\n",
           (unsigned char)ehdr.e_ident[0], (unsigned char)ehdr.e_ident[1],
           (unsigned char)ehdr.e_ident[2], (unsigned char)ehdr.e_ident[3]);
    printf("Type: %d (0x%x)\n", ehdr.e_type, ehdr.e_type);

    if(ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
        printf("pid:%d is not a valid executable process, type=%d.\n", pid, ehdr.e_type);
        printf("Expected ET_EXEC (%d) or ET_DYN (%d)\n", ET_EXEC, ET_DYN);
        ret = -1;
        goto done;
    }
    printf("ph offset:0x%x phnum:%d\n", (int)ehdr.e_phoff, ehdr.e_phnum);

    phdr_addr = elfinfo->phdr_addr = elfinfo->base + ehdr.e_phoff;
    printf("phdr_addr\t %p\n", (void *)elfinfo->phdr_addr);

    for (i = 0; i < ehdr.e_phnum; i++) {
        phdr_addr = elfinfo->phdr_addr + i*sizeof(ElfW(Phdr));
        ptrace_read(pid, phdr_addr, &phdr,sizeof(ElfW(Phdr)));

        if (phdr.p_type == PT_DYNAMIC) {
            elfinfo->dyn_addr = elfinfo->base + phdr.p_vaddr;
            elfinfo->dyn_memsz = phdr.p_memsz;
            printf("dyn_addr\t %p memsz:%lu dyncount:%lu\n", (void
                    *)elfinfo->dyn_addr, elfinfo->dyn_memsz,
                   elfinfo->dyn_memsz/sizeof(ElfW(Dyn)));
            break;
        }
    }

    if (0 == elfinfo->dyn_addr) {
        printf("can't find addr of dynamic section.");
        ret = -1;
        goto done;
    }

    // Create a fake link_map for the main executable
    map->l_addr = elfinfo->base;
    map->l_name = strdup(module);
    map->l_ld = (Elf64_Dyn *)elfinfo->dyn_addr;
    map->l_next = 0;
    map->l_prev = 0;

    printf("Created link_map for main executable:\n");
    printf("lm->l_addr\t %p \n", (void *)map->l_addr);
    printf("lm->l_name\t %s \n", (char *)map->l_name);
    printf("lm->l_ld\t\t %p \n", (void *)map->l_ld);

done:
    if(ret != 0) {
        free(map);
        return NULL;
    }
    return map;
}

// Find shared libraries from /proc/pid/maps and create link_map entries for them
int find_shared_libraries(pid_t pid, struct link_map **libs, int max_libs)
{
    char maps_path[256];
    char line[1024];
    int lib_count = 0;
    FILE *fp;

    sprintf(maps_path, "/proc/%d/maps", pid);
    fp = fopen(maps_path, "r");
    if (!fp) {
        printf("Cannot open %s\n", maps_path);
        return 0;
    }

    printf("\n=== Scanning shared libraries ===\n");
    while (fgets(line, sizeof(line), fp) && lib_count < max_libs) {
        // Look for shared libraries (.so files)
        if (strstr(line, ".so") && strstr(line, "r-xp")) {
            // Extract the full path from the line
            char *start = strchr(line, '/');
            if (start) {
                char *end = strstr(start, ".so");
                if (end) {
                    // Find the end of the .so filename
                    end += 3; // Move past ".so"
                    while (*end && *end != ' ' && *end != '\n') end++;

                    // Extract the full path
                    size_t path_len = end - start;
                    char *full_path = malloc(path_len + 1);
                    strncpy(full_path, start, path_len);
                    full_path[path_len] = '\0';

                    // Parse base address
                    unsigned long base = strtoul(line, NULL, 16);

                    // Create link_map entry
                    libs[lib_count] = malloc(sizeof(struct link_map));
                    libs[lib_count]->l_addr = base;
                    libs[lib_count]->l_name = full_path;
                    libs[lib_count]->l_ld = 0;  // Will be found later
                    libs[lib_count]->l_next = 0;
                    libs[lib_count]->l_prev = 0;

                    printf("Found library: %s @ %p\n", full_path, (void*)base);
                    lib_count++;
                }
            }
        }
    }
    fclose(fp);
    printf("Found %d shared libraries\n", lib_count);
    printf("===============================\n\n");

    return lib_count;
}



