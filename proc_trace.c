/******************************************************************************

  Copyright (C), 2001-2013, Unknown Tech. Co., Ltd.

 ******************************************************************************
  File Name     : proc_trace.c
  Version       : Initial Draft
  Author        : Justin Liu
  Created       : 2015/9/11
  Last Modified :
  Description   : Trace processs to get ELF infomation or hook function
  Function List :
              ptrace_attach
              ptrace_call
              ptrace_cont
              ptrace_detach
              ptrace_push
              ptrace_read
              ptrace_readreg
              ptrace_readstr
              ptrace_write
              ptrace_writereg
  History       :
  1.Date        : 2015/9/11
    Author      : Justin Liu
    Modification: Created file

******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "proc_trace.h"


static void ptrace_readreg(pid_t pid, struct user_regs_struct *regs)
{
    if(ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
        printf("*** ptrace_readreg error ***\n");
    }

}

static void ptrace_writereg(pid_t pid, struct user_regs_struct *regs)
{
    if(ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
        printf("*** ptrace_writereg error ***\n");
    }
}

static void * ptrace_push(pid_t pid, void *paddr, int size)
{
    unsigned long rsp = 0;
    struct user_regs_struct regs = {0};

    ptrace_readreg(pid, &regs);
    rsp = regs.rsp;
    rsp -= size;
    rsp = rsp - rsp % sizeof(rsp);
    regs.rsp = rsp;

    ptrace_writereg(pid, &regs);

    ptrace_write(pid, rsp, paddr, size);

    return (void *)rsp;
}

void ptrace_attach(pid_t pid, struct user_regs_struct *oldregs)
{
    if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace_attach");
        exit(-1);
    }

    waitpid(pid, NULL, WUNTRACED);

    ptrace_readreg(pid, oldregs);
}


void ptrace_cont(pid_t pid)
{
    int stat;

    if(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        perror("ptrace_cont");
        exit(-1);
    }

    while(!WIFSTOPPED(stat)) {
        waitpid(pid, &stat, WNOHANG);
    }
}


void ptrace_detach(pid_t pid, struct user_regs_struct *oldregs)
{
    ptrace_writereg(pid, oldregs);

    if(ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        perror("ptrace_detach");
        exit(-1);
    }
}

void ptrace_write(pid_t pid, unsigned long addr, void *vptr, int len)
{
    int count = 0;
    long word = 0;

    count = 0;

    while(count < len) {
        memcpy(&word, vptr + count, sizeof(word));
        word = ptrace(PTRACE_POKETEXT, pid, addr + count, word);
        count += sizeof(word);

        if(errno != 0) {
            printf("ptrace_write failed\t %ld\n", addr + count);
        }
    }
}


void ptrace_read(pid_t pid, unsigned long addr, void *vptr, int len)
{
    int i = 0,count = 0;
    long word = 0;
    unsigned long *ptr = (unsigned long *)vptr;


    while (count < len) {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
        count += sizeof(word);
        ptr[i++] = word;
    }
}

char * ptrace_readstr(pid_t pid, unsigned long addr)
{
    char *str = (char *) malloc(1024);
    memset(str, 0, 1024);
    int i = 0,j = 0,count = 0;
    long word = 0;
    char *pa = NULL;

    i = count = 0;
    pa = (char *)&word;

    while(i <= 1000) {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
        count += sizeof(word);
        for (j=0; j<sizeof(word); j++) {
            if (pa[j] == '\0') {
                str[i] = '\0';
                return str;
            } else {
                str[i++] = pa[j];
            }
        }
    }

    return str;
}


void ptrace_call(pid_t pid, unsigned long addr)
{
    void *pc = NULL;
    struct user_regs_struct regs;
    int stat;


    pc = (void *) 0x41414140;
    (void)ptrace_push(pid, &pc, sizeof(pc));

    ptrace_readreg(pid, &regs);
    regs.rip = addr;
    ptrace_writereg(pid, &regs);

    ptrace_cont(pid);

    while(!WIFSIGNALED(stat)) {
        waitpid(pid, &stat, WNOHANG);
    }
}


