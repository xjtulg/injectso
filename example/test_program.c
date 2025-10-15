#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>

volatile sig_atomic_t keep_running = 1;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down gracefully...\n", sig);
    keep_running = 0;
}

// Additional test functions specifically for injector demonstration
// These are designed to be easily findable symbols

__attribute__((used)) __attribute__((noinline))
void demo_function_target(void) {
    puts("✅ Found demo_function_target - this is the target function!");
}

__attribute__((used)) __attribute__((noinline))
void symbol_lookup_demo(const char* func_name) {
    printf("🎯 Symbol lookup demo: %s was found!\n", func_name);
}

__attribute__((used)) __attribute__((noinline))
int demo_math_function(int x, int y) {
    return x * y + 42;
}

__attribute__((used)) __attribute__((noinline))
void* demo_memory_function(size_t size) {
    void* ptr = malloc(size);
    if (ptr) {
        printf("📝 Allocated %zu bytes at %p\n", size, ptr);
    }
    return ptr;
}

// Explicit puts function to ensure it's in symbol table
__attribute__((used)) __attribute__((noinline))
void explicit_puts_call(void) {
    puts("📢 This is an explicit puts() call for symbol lookup");
}

// Test functions that can be found by the injector
void test_function_1(void) {
    puts("This is test_function_1");
}

void test_function_2(void) {
    printf("This is test_function_2 with PID: %d\n", getpid());
}

void test_function_3(const char* message) {
    char* buffer = malloc(256);
    if (buffer) {
        strcpy(buffer, "test_function_3: ");
        strcat(buffer, message);
        puts(buffer);
        free(buffer);
    }
}

void memory_test_function(void) {
    int* ptr = malloc(sizeof(int) * 10);
    if (ptr) {
        for (int i = 0; i < 10; i++) {
            ptr[i] = i * i;
        }
        printf("Memory test: sum of squares = %d\n", ptr[0] + ptr[1] + ptr[2]);
        free(ptr);
    }
}

void string_test_function(void) {
    const char* messages[] = {
        "Hello from string_test_function",
        "This function tests string operations",
        "It should be visible in the symbol table"
    };

    for (int i = 0; i < 3; i++) {
        puts(messages[i]);
    }
}

void math_test_function(void) {
    double result = 0.0;
    for (int i = 1; i <= 10; i++) {
        result += 1.0 / i;
    }
    printf("Math test: harmonic sum = %.6f\n", result);
}

void time_test_function(void) {
    time_t now = time(NULL);
    printf("Current time: %s", ctime(&now));
}

// Main loop function
void main_loop(void) {
    int counter = 0;
    time_t start_time = time(NULL);

    while (keep_running) {
        if (counter % 5 == 0) {
            printf("Main loop: iteration %d, running for %ld seconds\n",
                   counter, time(NULL) - start_time);
        }

        // Call various test functions periodically
        switch (counter % 12) {
            case 0:
                test_function_1();
                break;
            case 2:
                test_function_2();
                break;
            case 4:
                test_function_3("Periodic call from main loop");
                break;
            case 6:
                memory_test_function();
                break;
            case 7:
                string_test_function();
                break;
            case 8:
                demo_function_target();
                break;
            case 9:
                explicit_puts_call();
                break;
            case 10:
                symbol_lookup_demo("periodic demo");
                break;
            case 11:
                void* ptr = demo_memory_function(64);
                if (ptr) free(ptr);
                break;
        }

        if (counter % 10 == 0) {
            math_test_function();
            time_test_function();
        }

        counter++;
        sleep(2); // Wait 2 seconds between iterations
    }
}

int main(void) {
    printf("=== InjectSO Test Program ===\n");
    printf("Process ID: %d\n", getpid());
    printf("This program creates various functions for testing the injector.\n");
    printf("Run: ./injector %d\n", getpid());
    printf("Press Ctrl+C to stop the program.\n");
    printf("=============================\n\n");

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Call all test functions once at startup
    printf("Calling all test functions once at startup:\n");
    test_function_1();
    test_function_2();
    test_function_3("Startup call");
    memory_test_function();
    string_test_function();
    math_test_function();
    time_test_function();

    // Call demonstration functions
    printf("\n🎯 Calling demonstration functions for injector:\n");
    demo_function_target();
    symbol_lookup_demo("demo_function_target");
    explicit_puts_call();
    void* test_ptr = demo_memory_function(128);
    if (test_ptr) free(test_ptr);
    int result = demo_math_function(10, 20);
    printf("🧮 Math test result: %d\n", result);

    printf("\nStarting main loop...\n");

    // Enter main loop
    main_loop();

    printf("Test program exiting gracefully.\n");
    return 0;
}