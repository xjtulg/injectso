#include <stdio.h>
#include <stdlib.h>
#include "elf_io.h"
#include "injector.h"

struct user_regs_struct regs;
elf_info elfinfo;



int main(int argc, char* argv[])
{
    struct link_map * lm = NULL;

    pid_t pid = 0;
    if(argc != 2) {
        printf("for example:att [pid]\n");
        return -1;
    }

    pid = (pid_t)atoi(argv[1]);

    printf("begin to attach pid:%d\n", pid);

    ptrace_attach(pid, &regs);

    lm = get_linkmap(pid, &elfinfo);

    if (NULL == lm)
    {
        goto done;
    }

    find_symbol(pid, lm, "puts");
done:
    ptrace_detach(pid, &regs);

    return 0;
}


