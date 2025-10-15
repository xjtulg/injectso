# Makefile for injectso project
# ELF injection and process tracing toolkit
# Updated for enhanced symbol resolution capabilities

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS =

# Source files
SOURCES = injector.c elf_io.c proc_trace.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = injector

# Example program
EXAMPLE_DIR = example
EXAMPLE_TARGET = $(EXAMPLE_DIR)/test_program
EXAMPLE_SOURCES = $(EXAMPLE_DIR)/test_program.c

# Default target
all: $(TARGET) example

# Build the main injector
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "✅ Injector built successfully!"

# Build example program
example: $(EXAMPLE_TARGET)

$(EXAMPLE_TARGET): $(EXAMPLE_SOURCES)
	$(CC) $(CFLAGS) $< -o $@
	@echo "✅ Example program built successfully!"

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Debug build with additional flags
debug: CFLAGS += -g -DDEBUG -Wno-int-conversion -Wno-implicit-function-declaration
debug: $(TARGET) example
	@echo "🐛 Debug build complete!"

# Release build with optimizations
release: CFLAGS += -O3 -DNDEBUG -s
release: clean $(TARGET) example
	@echo "🚀 Release build complete!"

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET) $(EXAMPLE_TARGET)
	@echo "🧹 Clean complete!"

# Deep clean (including backups and temporary files)
distclean: clean
	rm -f *~ *.bak core *.core
	@echo "🧹 Deep clean complete!"

# Quick test - builds and runs a demo
demo: $(TARGET) $(EXAMPLE_TARGET)
	@echo "🎬 Starting injector demo..."
	@echo "1. Starting example program..."
	@cd $(EXAMPLE_DIR) && timeout 30s ./$(notdir $(EXAMPLE_TARGET)) &
	@sleep 2
	@echo "2. Getting PID of example program..."
	@PID=$$(pgrep test_program | head -1); \
	if [ -n "$$PID" ]; then \
		echo "3. Running injector on PID $$PID..."; \
		echo "   (This will demonstrate full ELF symbol resolution)"; \
		./$(TARGET) $$PID; \
		echo "4. Demo complete!"; \
		echo "   Stopping example program..."; \
		kill $$PID 2>/dev/null || true; \
		sleep 1; \
	else \
		echo "❌ Could not find test_program process"; \
	fi


# Show project information
info:
	@echo "📊 InjectSO Project Information"
	@echo "=============================="
	@echo "Target: $(TARGET)"
	@echo "Sources: $(SOURCES)"
	@echo "Example: $(EXAMPLE_TARGET)"
	@echo "Compiler: $(CC) $(CFLAGS)"
	@echo "Linker: $(CC) $(LDFLAGS)"
	@echo "Build date: $$(date)"
	@echo "Git commit: $$(git rev-parse HEAD 2>/dev/null || echo 'N/A')"


# Comprehensive help
help:
	@echo "🚀 InjectSO Makefile Targets"
	@echo "============================="
	@echo ""
	@echo "🔨 Build Targets:"
	@echo "  all          - Build injector and example (default)"
	@echo "  example      - Build only the example program"
	@echo "  debug        - Build with debug symbols and warnings disabled"
	@echo "  release      - Optimized release build"
	@echo ""
	@echo "🧹 Cleanup Targets:"
	@echo "  clean        - Remove build artifacts"
	@echo "  distclean    - Deep clean including backup files"
	@echo ""
	@echo "🎬 Testing & Demo:"
	@echo "  demo         - Run a complete demonstration"
	@echo ""
	@echo "ℹ️  Information:"
	@echo "  info         - Show project information"
	@echo ""
	@echo "  help         - Show this help message"

# Phony targets
.PHONY: all example debug release clean distclean demo info help