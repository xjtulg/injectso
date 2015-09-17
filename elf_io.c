#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    ElfW(Addr) base = NULL;

    sprintf(maps, "/proc/%d/maps", pid);
    FILE* fp = fopen(maps, "r");
    if (NULL == fp) {
        printf("open %s err\n", maps);
        return 0;
    }

    while(fgets(line, 1024, fp)) {
        if(strstr(line, "r-xp") && strstr(line, module)) {
            base = strtoul(line, NULL, 16);
            break;
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
                dyninfo->symtab = lm->l_addr + dyn.d_un.d_ptr;
                printf("addr of symtab: %p\n", (void*)dyninfo->symtab);
                break;
            case DT_STRTAB:
                dyninfo->strtab = lm->l_addr + dyn.d_un.d_ptr;
                printf("addr of strtab: %p\n", (void*)dyninfo->strtab);
                break;
            //TODO:don't know how to find symbol by hash or gnu_hash
            case DT_HASH:
                break;
            case DT_GNU_HASH:
                break;
            case DT_REL:
                dyninfo->reldyn = lm->l_addr + dyn.d_un.d_ptr;
                printf("addr of reldyn: %p\n", (void*)dyninfo->reldyn);
                break;

            case DT_RELSZ:
                dyninfo->reldynsz = dyn.d_un.d_val / sizeof(ElfW(Rel));
                printf("size of reldyn: %ld\n", dyninfo->reldynsz);
                break;

            case DT_JMPREL:
                dyninfo->relplt = lm->l_addr + dyn.d_un.d_ptr;
                printf("addr of relplt: %p\n", (void*)dyninfo->relplt);
                break;

            case DT_PLTRELSZ:
                dyninfo->relpltsz = dyn.d_un.d_val / sizeof(ElfW(Rela));
                printf("size of relplt: %ld\n", dyninfo->relpltsz);
                break;

            case DT_RELA:
                dyninfo->rela = lm->l_addr + dyn.d_un.d_ptr;
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
    ElfW(Rela) rela = {0};
    struct link_map map = {0};
    dynamic_info dyninfo = {0};
    char *name = NULL;
    ElfW(Addr) addr = 0;
    int i = 0;


    //get dynamic table info from lm
    get_dyninfo(pid, lm, &dyninfo);


    for(i=0; i<dyninfo.relpltsz; i++) {
        ptrace_read(pid, dyninfo.relplt+ i * sizeof(ElfW(Rela)), &rela,
                    sizeof(ElfW(Rela)));

        if(ELF64_R_SYM(rela.r_info)) {
            ptrace_read(pid, dyninfo.symtab+ ELF64_R_SYM(rela.r_info) *
                        sizeof(ElfW(Sym)), &sym,
                        sizeof(ElfW(Sym)));
            if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) {
                continue;
            }
            name = ptrace_readstr(pid, dyninfo.strtab + sym.st_name);
            printf("walk on symbol:%s addr: %p\n", name, (void*)(lm->l_addr +
                    rela.r_offset));
            free(name);
        }

        if(0) {
            addr = lm->l_addr + sym.st_value;
            return addr;
        }

    }

    if(lm->l_next != NULL) {
        ptrace_read(pid, (unsigned long)lm->l_next, &map, sizeof(struct link_map));
        name = ptrace_readstr(pid, (unsigned long)map.l_name);
        printf("Finding symbol [%s] in %s\n", sym_name, name);
        free(name);
        return find_symbol(pid, &map, sym_name);
    }
    return 0;
}

struct link_map * get_linkmap(pid_t pid, elf_info *elfinfo)
{
    ElfW(Ehdr) ehdr = {{0}};
    ElfW(Phdr) phdr = {0};
    ElfW(Dyn)  dyn =  {0};
    int i = 0;
    ElfW(Addr) phdr_addr = 0;
    ElfW(Addr) got = 0;
    ElfW(Addr) map_addr = 0;
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
    if(ehdr.e_type != ET_EXEC) {
        printf("pid:%d is not a execute process, type=%d.\n", pid, ehdr.e_type);
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
            elfinfo->dyn_addr = phdr.p_vaddr;
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

    ptrace_read(pid, elfinfo->dyn_addr, &dyn, sizeof(ElfW(Dyn)));
    i = 0;
    while(dyn.d_tag != DT_NULL) {
        if (dyn.d_tag == DT_PLTGOT ) {
            break;
        }
        i++;
        ptrace_read(pid, elfinfo->dyn_addr + i * sizeof(ElfW(Dyn)), &dyn, sizeof(ElfW(Dyn)));
    }

    if (dyn.d_tag != DT_PLTGOT) {
        printf("can't find PLTGOT\n");
        ret = -1;
        goto done;
    }

    got = dyn.d_un.d_ptr;
    printf("GOT\t\t %p\n", (void *)got);
    got += sizeof(ElfW(Addr));

    ptrace_read(pid, got, &map_addr, sizeof(ElfW(Addr)));

    ptrace_read(pid, map_addr, map, sizeof(struct link_map));

    printf("lm->l_addr\t %p \n", (void *)map->l_addr);

    printf("lm-prev:%p lm->next:%p\n",(void*)map->l_prev, (void*)map->l_next);

done:
    if(ret != 0) {
        free(map);
        return NULL;
    }
    return map;
}



