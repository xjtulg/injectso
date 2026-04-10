#include <stdio.h>
#include <stdlib.h>
#include "elf_io.h"
#include "injector.h"

struct user_regs_struct regs;
elf_info elfinfo;

int main(int argc, char *argv[])
{
    struct link_map *lm = NULL;

    pid_t pid = 0;
    if (argc != 2) {
        printf("Usage: ./injector [pid]\n");
        printf("Example: ./injector 1234\n");
        return -1;
    }

    pid = (pid_t)atoi(argv[1]);

    printf("ELF Symbol Resolution Tool\n");
    printf("============================\n");
    printf("Target PID: %d\n\n", pid);

    printf("[*] Step 1: Attaching to process\n");
    ptrace_attach(pid, &regs);

    printf("\n[*] Step 2: Getting link_map from GOT\n");
    lm = get_linkmap(pid, &elfinfo);

    if (NULL == lm) {
        printf("[ERR] Failed to get link_map\n");
        goto done;
    }

    printf("\n[*] Step 3: Searching for symbols across all loaded libraries\n");

    // find_symbol traverses the entire link_map chain (main exe + all shared libs)
    const char *target_functions[] = {
        "puts",
        "malloc",
        "free",
    };
    int num_targets = sizeof(target_functions) / sizeof(target_functions[0]);

    for (int i = 0; i < num_targets; i++) {
        printf("\n--- Searching for: %s ---\n", target_functions[i]);
        ElfW(Addr) found_addr = find_symbol(pid, lm, target_functions[i]);
        if (found_addr != 0) {
            printf("[OK] '%s' resolved at: %p\n", target_functions[i], (void*)found_addr);
        } else {
            printf("[WARN] '%s' not found\n", target_functions[i]);
        }
    }

    printf("\n[OK] Symbol resolution complete\n");

done:
    ptrace_detach(pid, &regs);

    if (lm)
        free(lm);

    printf("[*] Detached from process %d\n", pid);
    return 0;
}


