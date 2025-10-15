#include <stdio.h>
#include <stdlib.h>
#include "elf_io.h"
#include "injector.h"

struct user_regs_struct regs;
elf_info elfinfo;



int main(int argc, char* argv[])
{
    struct link_map * lm = NULL;
    struct link_map *libs[32];  // Support up to 32 libraries
    int lib_count = 0;
    int i = 0;

    pid_t pid = 0;
    if(argc != 2) {
        printf("Usage: ./injector [pid]\n");
        printf("Example: ./injector 1234\n");
        return -1;
    }

    pid = (pid_t)atoi(argv[1]);

    printf("🚀 ELF Symbol Resolution Tool\n");
    printf("============================\n");
    printf("Target PID: %d\n", pid);
    printf("\n📍 Step 1: Attaching to process\n");

    ptrace_attach(pid, &regs);

    printf("\n📍 Step 2: Analyzing main executable\n");
    lm = get_linkmap(pid, &elfinfo);

    if (NULL == lm)
    {
        printf("❌ Failed to get link_map for main executable\n");
        goto done;
    }

    printf("\n📍 Step 3: Finding symbols in main executable\n");

    // Try to find multiple functions - focus on library functions in main executable
    const char* target_functions[] = {
        "demo_function_target",  // Function defined in main executable
        "puts",                  // Standard library function
        "printf",                // Standard library function
        "malloc",                // Standard library function
        "free",                  // Standard library function
        "strlen",                // Standard library function
        "strcpy"                 // Standard library function
    };
    int num_targets = sizeof(target_functions) / sizeof(target_functions[0]);
    int found_any = 0;

    for (int func_idx = 0; func_idx < num_targets; func_idx++) {
        printf("🔍 Searching for target function: %s\n", target_functions[func_idx]);
        ElfW(Addr) found_addr = find_symbol(pid, lm, target_functions[func_idx]);
        if (found_addr != 0) {
            printf("✅ Found '%s' at address: %p\n", target_functions[func_idx], (void*)found_addr);
            found_any = 1;
            if (func_idx == 0) break; // Found our primary target
        } else {
            printf("⚠️  '%s' not found in main executable\n", target_functions[func_idx]);
        }
    }

    if (!found_any) {
        printf("❌ No target functions found in main executable\n");
    }

    printf("\n📍 Step 4: Scanning shared libraries\n");
    lib_count = find_shared_libraries(pid, libs, 32);

    if (lib_count > 0) {
        printf("\n📍 Step 5: Analyzing shared libraries\n");
        for (i = 0; i < lib_count; i++) {
            printf("\n📚 Analyzing library %d: %s\n", i+1, (char*)libs[i]->l_name);

              // Try to find dynamic section for this library
            ElfW(Ehdr) ehdr;
            ptrace_read(pid, libs[i]->l_addr, &ehdr, sizeof(ElfW(Ehdr)));

            if (ehdr.e_ident[0] == 0x7f && ehdr.e_ident[1] == 'E' &&
                ehdr.e_ident[2] == 'L' && ehdr.e_ident[3] == 'F') {

                // Find dynamic section
                ElfW(Phdr) phdr;
                ElfW(Addr) dyn_addr = 0;
                int j;

                for (j = 0; j < ehdr.e_phnum && j < 20; j++) {  // Limit to prevent infinite loops
                    ElfW(Addr) phdr_addr = libs[i]->l_addr + ehdr.e_phoff + j * sizeof(ElfW(Phdr));
                    ptrace_read(pid, phdr_addr, &phdr, sizeof(ElfW(Phdr)));
                    if (phdr.p_type == PT_DYNAMIC) {
                        dyn_addr = libs[i]->l_addr + phdr.p_vaddr;
                        libs[i]->l_ld = (Elf64_Dyn *)dyn_addr;
                        break;
                    }
                }

                if (dyn_addr != 0) {
                    printf("🔍 Searching for symbols in %s\n", (char*)libs[i]->l_name);

                    // Look for standard library functions in shared libraries
                    for (int lib_func_idx = 0; lib_func_idx < 2; lib_func_idx++) {
                        const char* lib_targets[] = {"puts", "printf"};
                        ElfW(Addr) lib_found_addr = find_symbol(pid, libs[i], lib_targets[lib_func_idx]);
                        if (lib_found_addr != 0) {
                            printf("✅ Found '%s' at address: %p\n", lib_targets[lib_func_idx], (void*)lib_found_addr);
                            break; // Found one, that's enough for demo
                        }
                    }
                } else {
                    printf("⚠️  Could not find dynamic section in %s\n", (char*)libs[i]->l_name);
                }
            } else {
                printf("⚠️  %s is not a valid ELF file\n", (char*)libs[i]->l_name);
            }
        }
    }

    printf("\n🎉 Injection analysis complete!\n");
    printf("===============================\n");
    printf("✅ Successfully analyzed:\n");
    printf("   • Main executable symbols\n");
    printf("   • %d shared libraries\n", lib_count);
    printf("   • Function addresses and metadata\n");

done:
    ptrace_detach(pid, &regs);

    // Cleanup
    if (lm) {
        if (lm->l_name) free((char*)lm->l_name);
        free(lm);
    }
    for (i = 0; i < lib_count; i++) {
        if (libs[i]) {
            if (libs[i]->l_name) free((char*)libs[i]->l_name);
            free(libs[i]);
        }
    }

    printf("\n👋 Injector detached successfully\n");
    return 0;
}


