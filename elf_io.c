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

    snprintf(status, sizeof(status), "/proc/%d/status", pid);

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

    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE* fp = fopen(maps, "r");
    if (NULL == fp) {
        printf("open %s err\n", maps);
        return 0;
    }

    // Find the segment with file offset 0 for this module (contains ELF header)
    while(fgets(line, 1024, fp)) {
        if(strstr(line, module)) {
            // Parse: addr-end perms offset ...
            // The ELF header is in the segment with file offset 0
            unsigned long addr_val, end_val, offset_val;
            char perms[8];
            if (sscanf(line, "%lx-%lx %4s %lx", &addr_val, &end_val, perms, &offset_val) == 4) {
                if (offset_val == 0) {
                    base = addr_val;
                    break;
                }
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

    // For most loaded objects, ld.so adjusts d_ptr to absolute addresses in memory.
    // However, some objects (like linux-vdso) keep d_ptr as relative offsets.
    // Detect this: if d_ptr < l_addr, it's a relative offset needing l_addr added.
    ptrace_read(pid, dyn_addr, &dyn, sizeof(ElfW(Dyn)));
    while(dyn.d_tag != DT_NULL) {
        switch(dyn.d_tag) {
            case DT_SYMTAB:
                dyninfo->symtab = dyn.d_un.d_ptr < lm->l_addr
                    ? lm->l_addr + dyn.d_un.d_ptr : dyn.d_un.d_ptr;
                printf("addr of symtab: %p\n", (void*)dyninfo->symtab);
                break;
            case DT_STRTAB:
                dyninfo->strtab = dyn.d_un.d_ptr < lm->l_addr
                    ? lm->l_addr + dyn.d_un.d_ptr : dyn.d_un.d_ptr;
                printf("addr of strtab: %p\n", (void*)dyninfo->strtab);
                break;
            case DT_HASH:
                break;
            case DT_GNU_HASH:
                break;
            case DT_REL:
                dyninfo->reldyn = dyn.d_un.d_ptr < lm->l_addr
                    ? lm->l_addr + dyn.d_un.d_ptr : dyn.d_un.d_ptr;
                printf("addr of reldyn: %p\n", (void*)dyninfo->reldyn);
                break;

            case DT_RELSZ:
                dyninfo->reldynsz = dyn.d_un.d_val / sizeof(ElfW(Rel));
                printf("size of reldyn: %ld\n", dyninfo->reldynsz);
                break;

            case DT_JMPREL:
                dyninfo->relplt = dyn.d_un.d_ptr < lm->l_addr
                    ? lm->l_addr + dyn.d_un.d_ptr : dyn.d_un.d_ptr;
                printf("addr of relplt: %p\n", (void*)dyninfo->relplt);
                break;

            case DT_PLTRELSZ:
                dyninfo->relpltsz = dyn.d_un.d_val / sizeof(ElfW(Rela));
                printf("size of relplt: %ld\n", dyninfo->relpltsz);
                break;

            case DT_RELA:
                dyninfo->rela = dyn.d_un.d_ptr < lm->l_addr
                    ? lm->l_addr + dyn.d_un.d_ptr : dyn.d_un.d_ptr;
                printf("addr of rela: %p\n", (void*)dyninfo->rela);
                break;

            case DT_RELASZ:
                dyninfo->relasz = dyn.d_un.d_val / sizeof(ElfW(Rela));
                printf("size of rela: %ld\n", dyninfo->relasz);
                break;
        }

        ptrace_read(pid, dyn_addr += sizeof(ElfW(Dyn)), &dyn, sizeof(ElfW(Dyn)));
    }

    dyninfo->symsize = (dyninfo->strtab - dyninfo->symtab) / sizeof(ElfW(Sym));
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
ElfW(Addr) find_symbol(pid_t pid, struct link_map *lm, const char *sym_name)
{
    ElfW(Sym) sym = {0};
    struct link_map current = *lm;
    dynamic_info dyninfo = {0};
    char *name = NULL;
    int i = 0;
    int depth = 0;
    const int MAX_DEPTH = 256;

    while (depth < MAX_DEPTH) {
        memset(&dyninfo, 0, sizeof(dyninfo));

        name = ptrace_readstr(pid, (unsigned long)current.l_name);
        printf("Searching for [%s] in %s (base: %p)\n", sym_name,
               name ? name : "(unknown)", (void*)current.l_addr);
        if (name) free(name);

        get_dyninfo(pid, &current, &dyninfo);

        if (dyninfo.symtab == 0 || dyninfo.strtab == 0) {
            printf("[WARN] Invalid dynamic section addresses\n");
            goto next_library;
        }

        // Search symbol table for defined functions
        printf("Scanning %ld symbols...\n", dyninfo.symsize);
        for (i = 0; i < dyninfo.symsize && i < 1000; i++) {
            ptrace_read(pid, dyninfo.symtab + i * sizeof(ElfW(Sym)), &sym,
                        sizeof(ElfW(Sym)));

            if (sym.st_name == 0)
                continue;

            if (ELFW(ST_TYPE)(sym.st_info) != STT_FUNC)
                continue;

            name = ptrace_readstr(pid, dyninfo.strtab + sym.st_name);

            if (name && strcmp(name, sym_name) == 0) {
                if (sym.st_value != 0) {
                    printf("[OK] Found %s at %p\n",
                           name, (void*)(current.l_addr + sym.st_value));
                    free(name);
                    return current.l_addr + sym.st_value;
                } else {
                    printf("Found undefined %s, checking PLT...\n", name);
                }
            }

            if (name) free(name);
        }

        // Search PLT relocations for undefined symbols
        if (dyninfo.relplt != 0 && dyninfo.relpltsz > 0) {
            for (i = 0; i < dyninfo.relpltsz && i < 100; i++) {
                ElfW(Rela) rela = {0};
                ptrace_read(pid, dyninfo.relplt + i * sizeof(ElfW(Rela)), &rela,
                            sizeof(ElfW(Rela)));

                unsigned long sym_idx = ELFW(R_SYM)(rela.r_info);
                if (sym_idx == 0 || sym_idx >= (unsigned long)dyninfo.symsize)
                    continue;

                ElfW(Sym) rel_sym = {0};
                ptrace_read(pid, dyninfo.symtab + sym_idx * sizeof(ElfW(Sym)),
                            &rel_sym, sizeof(ElfW(Sym)));

                if (rel_sym.st_name == 0)
                    continue;

                name = ptrace_readstr(pid, dyninfo.strtab + rel_sym.st_name);
                if (name && strcmp(name, sym_name) == 0) {
                    printf("[OK] Found %s via PLT at address: %p\n",
                           name, (void*)(current.l_addr + rela.r_offset));
                    free(name);
                    return current.l_addr + rela.r_offset;
                }
                if (name) free(name);
            }
        }

next_library:
        // Move to next library in link_map chain (iterative, not recursive)
        if (current.l_next == NULL)
            break;

        ptrace_read(pid, (unsigned long)current.l_next, &current, sizeof(struct link_map));
        name = ptrace_readstr(pid, (unsigned long)current.l_name);
        if (name && strlen(name) > 0) {
            printf("--> Next library: %s\n", name);
        }
        if (name) free(name);
        depth++;
    }

    return 0;
}

struct link_map * get_linkmap(pid_t pid, elf_info *elfinfo)
{
    ElfW(Ehdr) ehdr = {0};
    ElfW(Phdr) phdr = {0};
    ElfW(Dyn) dyn = {0};
    int i = 0;
    ElfW(Addr) phdr_addr = 0;
    ElfW(Addr) got = 0;
    ElfW(Addr) map_addr = 0;
    ElfW(Addr) load_bias = 0;
    char module[256] = {0};
    int ret = 0;

    struct link_map *map = (struct link_map *)
                           malloc(sizeof(struct link_map));

    memset(map, 0, sizeof(struct link_map));

    if (0 != findExeName(pid, module)) {
        printf("can't find name of exe\n");
        ret = -1;
        goto done;
    }
    printf("Module name is: %s\n", module);
    elfinfo->base = findELFbase(pid, module);
    printf("Module base is: %p\n", (void*)elfinfo->base);
    if (0 == elfinfo->base) {
        ret = -1;
        goto done;
    }

    ptrace_read(pid, elfinfo->base, &ehdr, sizeof(ElfW(Ehdr)));

    if(ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
        printf("pid:%d is not a valid executable process, type=%d.\n", pid, ehdr.e_type);
        ret = -1;
        goto done;
    }
    printf("ELF type: %d (%s)\n", ehdr.e_type,
           ehdr.e_type == ET_EXEC ? "ET_EXEC" : "ET_DYN/PIE");
    printf("ph offset:0x%x phnum:%d\n", (int)ehdr.e_phoff, ehdr.e_phnum);

    phdr_addr = elfinfo->phdr_addr = elfinfo->base + ehdr.e_phoff;

    // Single pass: find first PT_LOAD (for load bias) and PT_DYNAMIC
    ElfW(Addr) preferred_base = 0;
    int found_load = 0;
    for (i = 0; i < ehdr.e_phnum; i++) {
        phdr_addr = elfinfo->phdr_addr + i * sizeof(ElfW(Phdr));
        ptrace_read(pid, phdr_addr, &phdr, sizeof(ElfW(Phdr)));

        if (phdr.p_type == PT_LOAD && !found_load) {
            preferred_base = phdr.p_vaddr;
            found_load = 1;
        }
    }

    // load_bias: 0 for non-PIE (ET_EXEC), base for PIE (ET_DYN with preferred_base=0)
    load_bias = elfinfo->base - preferred_base;
    printf("load_bias: %p\n", (void*)load_bias);

    // Find PT_DYNAMIC and compute its runtime address using load_bias
    for (i = 0; i < ehdr.e_phnum; i++) {
        phdr_addr = elfinfo->phdr_addr + i * sizeof(ElfW(Phdr));
        ptrace_read(pid, phdr_addr, &phdr, sizeof(ElfW(Phdr)));

        if (phdr.p_type == PT_DYNAMIC) {
            elfinfo->dyn_addr = load_bias + phdr.p_vaddr;
            elfinfo->dyn_memsz = phdr.p_memsz;
            printf("dyn_addr\t %p memsz:%lu\n",
                   (void*)elfinfo->dyn_addr, elfinfo->dyn_memsz);
            break;
        }
    }

    if (0 == elfinfo->dyn_addr) {
        printf("can't find addr of dynamic section.\n");
        ret = -1;
        goto done;
    }

    // Find link_map via DT_DEBUG -> r_debug -> r_map
    // This works with both lazy binding and BIND_NOW (full RELRO)
    ElfW(Addr) debug_addr = 0;
    ptrace_read(pid, elfinfo->dyn_addr, &dyn, sizeof(ElfW(Dyn)));
    i = 0;
    while(dyn.d_tag != DT_NULL) {
        if (dyn.d_tag == DT_DEBUG) {
            debug_addr = dyn.d_un.d_ptr;
            break;
        }
        i++;
        ptrace_read(pid, elfinfo->dyn_addr + i * sizeof(ElfW(Dyn)),
                    &dyn, sizeof(ElfW(Dyn)));
    }

    if (debug_addr == 0) {
        // Fallback: try GOT[1] (works only without BIND_NOW)
        printf("[WARN] DT_DEBUG not found, trying GOT[1] fallback\n");
        ptrace_read(pid, elfinfo->dyn_addr, &dyn, sizeof(ElfW(Dyn)));
        i = 0;
        while(dyn.d_tag != DT_NULL) {
            if (dyn.d_tag == DT_PLTGOT) break;
            i++;
            ptrace_read(pid, elfinfo->dyn_addr + i * sizeof(ElfW(Dyn)),
                        &dyn, sizeof(ElfW(Dyn)));
        }
        if (dyn.d_tag == DT_PLTGOT) {
            got = dyn.d_un.d_ptr;
            got += sizeof(ElfW(Addr));
            ptrace_read(pid, got, &map_addr, sizeof(ElfW(Addr)));
        }
    } else {
        // Read r_debug structure to get r_map (the link_map chain head)
        printf("r_debug at\t %p\n", (void*)debug_addr);
        struct r_debug rdebug = {0};
        ptrace_read(pid, debug_addr, &rdebug, sizeof(struct r_debug));
        map_addr = (ElfW(Addr))rdebug.r_map;
    }

    if (map_addr == 0) {
        printf("link_map not found\n");
        ret = -1;
        goto done;
    }

    // Read the link_map from the dynamic linker's chain
    ptrace_read(pid, map_addr, map, sizeof(struct link_map));

    printf("lm->l_addr\t %p\n", (void*)map->l_addr);
    printf("lm->l_prev\t %p  lm->l_next\t %p\n",
           (void*)map->l_prev, (void*)map->l_next);

done:
    if(ret != 0) {
        free(map);
        return NULL;
    }
    return map;
}

// Find shared libraries from /proc/pid/maps (fallback when GOT chain unavailable)
int find_shared_libraries(pid_t pid, struct link_map **libs, int max_libs)
{
    char maps_path[256];
    char line[1024];
    int lib_count = 0;
    FILE *fp;

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    fp = fopen(maps_path, "r");
    if (!fp) {
        printf("Cannot open %s\n", maps_path);
        return 0;
    }

    printf("\n=== Scanning shared libraries ===\n");
    while (fgets(line, sizeof(line), fp) && lib_count < max_libs) {
        if (!strstr(line, ".so"))
            continue;

        // Parse: addr-end perms offset dev inode path
        unsigned long addr_val, end_val, offset_val;
        char perms[8];
        if (sscanf(line, "%lx-%lx %4s %lx", &addr_val, &end_val, perms, &offset_val) != 4)
            continue;

        // Only use the segment with file offset 0 (contains ELF header)
        if (offset_val != 0)
            continue;

        char *start = strchr(line, '/');
        if (!start)
            continue;

        char *end = strstr(start, ".so");
        if (!end)
            continue;

        // Find the end of the .so filename
        end += 3;
        while (*end && *end != ' ' && *end != '\n') end++;

        size_t path_len = end - start;
        char *full_path = malloc(path_len + 1);
        strncpy(full_path, start, path_len);
        full_path[path_len] = '\0';

        // Deduplicate: skip if we already have this library
        int duplicate = 0;
        for (int j = 0; j < lib_count; j++) {
            if (strcmp((char*)libs[j]->l_name, full_path) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) {
            free(full_path);
            continue;
        }

        // Use the offset-0 segment address as the base (contains ELF header)
        libs[lib_count] = malloc(sizeof(struct link_map));
        libs[lib_count]->l_addr = addr_val;
        libs[lib_count]->l_name = full_path;
        libs[lib_count]->l_ld = 0;
        libs[lib_count]->l_next = 0;
        libs[lib_count]->l_prev = 0;

        printf("Found library: %s @ %p\n", full_path, (void*)addr_val);
        lib_count++;
    }
    fclose(fp);
    printf("Found %d shared libraries\n", lib_count);
    printf("===============================\n\n");

    return lib_count;
}

