/******************************************************************************

  Copyright (C), 2001-2013, Unknown Tech. Co., Ltd.

 ******************************************************************************
  File Name     : proc_trace.h
  Version       : Initial Draft
  Author        : Justin Liu
  Created       : 2015/9/11
  Last Modified :
  Description   : Trace processs to get ELF infomation or hook function
  Function List :
  History       :
  1.Date        : 2015/9/11
    Author      : Justin Liu
    Modification: Created file

******************************************************************************/
#ifndef _PROC_TRACE
#define _PROC_TRACE
#include <sys/user.h>

extern void ptrace_attach(pid_t pid, struct user_regs_struct *oldregs);

extern void ptrace_cont(pid_t pid);

extern void ptrace_detach(pid_t pid, struct user_regs_struct *oldregs);

extern void ptrace_write(pid_t pid, unsigned long addr, void *vptr, int len);

extern void ptrace_read(pid_t pid, unsigned long addr, void *vptr, int len);

extern char * ptrace_readstr(pid_t pid, unsigned long addr);

extern void ptrace_call(pid_t pid, unsigned long addr);

#endif