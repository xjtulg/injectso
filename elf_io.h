/******************************************************************************

  Copyright (C), 2001-2013, Unknown Tech. Co., Ltd.

 ******************************************************************************
  File Name     : elf_io.h
  Version       : Initial Draft
  Author        : Justin Liu
  Created       : 2015/9/11
  Last Modified :
  Description   : Get ELF file info from other process
  Function List :
  History       :
  1.Date        : 2015/9/11
    Author      : Justin Liu
    Modification: Created file

******************************************************************************/
#ifndef _ELF_IO
#define _ELF_IO
#include <link.h>
#include "proc_trace.h"


#define ELFW(type)	_ELFW (ELF, __ELF_NATIVE_CLASS, type)
#define _ELFW(e,w,t)	_ELFW_1 (e, w, _##t)
#define _ELFW_1(e,w,t)	e##w##t

typedef struct elf_info_t {
    //ELF head info
    ElfW(Addr) base;

    ElfW(Addr) phdr_addr;
    ElfW(Addr) dyn_addr;
    ElfW(Xword) dyn_memsz;



} elf_info;

typedef struct dynamic_info_t {
    //dynamic table info
    ElfW(Addr) symtab;
    ElfW(Addr) strtab;
    long    symsize;
    ElfW(Addr) reldyn;
    long    reldynsz;
    ElfW(Addr) relplt;
    long    relpltsz;
    ElfW(Addr) rela;
    long    relasz;
} dynamic_info;


extern struct link_map * get_linkmap(pid_t pid, elf_info *elfinfo);
extern ElfW(Addr) find_symbol(pid_t pid,struct link_map *lm, const char *
                              sym_name);
extern int find_shared_libraries(pid_t pid, struct link_map **libs, int max_libs);
#endif
