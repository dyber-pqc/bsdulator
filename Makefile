# BSDulator - FreeBSD Compatibility Layer for Linux
# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11
CFLAGS += -I$(INCDIR) -I$(SRCDIR)
LDFLAGS = 

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = .

# Source files
SRCS = $(SRCDIR)/main.c \
       $(SRCDIR)/interceptor/interceptor.c \
       $(SRCDIR)/syscall/syscall_table.c \
       $(SRCDIR)/loader/elf_loader.c \
       $(SRCDIR)/abi/abi_translate.c \
       $(SRCDIR)/runtime/freebsd_runtime.c \
       $(SRCDIR)/jail/jail.c

# Object files
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Target
TARGET = $(BINDIR)/bsdulator

# Default target
all: CFLAGS += -O2
all: $(TARGET)

# Debug build
debug: CFLAGS += -g3 -O0 -DDEBUG -fsanitize=address -fsanitize=undefined
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: $(TARGET)

# Verbose build (enable all logging)
verbose: CFLAGS += -O2 -DBSD_VERBOSE
verbose: $(TARGET)

# Link
$(TARGET): $(OBJS)
	@echo "  LINK    $@"
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Compile
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@echo "  CC      $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Dependencies
$(OBJDIR)/main.o: $(SRCDIR)/main.c $(INCDIR)/bsdulator.h
$(OBJDIR)/interceptor/interceptor.o: $(SRCDIR)/interceptor/interceptor.c $(INCDIR)/bsdulator.h $(INCDIR)/bsdulator/interceptor.h
$(OBJDIR)/syscall/syscall_table.o: $(SRCDIR)/syscall/syscall_table.c $(INCDIR)/bsdulator.h $(INCDIR)/bsdulator/syscall.h $(INCDIR)/bsdulator/jail.h $(SRCDIR)/runtime/freebsd_runtime.h
$(OBJDIR)/loader/elf_loader.o: $(SRCDIR)/loader/elf_loader.c $(INCDIR)/bsdulator.h $(INCDIR)/bsdulator/loader.h
$(OBJDIR)/abi/abi_translate.o: $(SRCDIR)/abi/abi_translate.c $(INCDIR)/bsdulator.h $(INCDIR)/bsdulator/abi.h
$(OBJDIR)/runtime/freebsd_runtime.o: $(SRCDIR)/runtime/freebsd_runtime.c $(SRCDIR)/runtime/freebsd_runtime.h $(INCDIR)/bsdulator.h
$(OBJDIR)/jail/jail.o: $(SRCDIR)/jail/jail.c $(INCDIR)/bsdulator.h $(INCDIR)/bsdulator/jail.h

# Clean
clean:
	@echo "  CLEAN"
	@rm -rf $(OBJDIR) $(TARGET)

# Install
install: $(TARGET)
	@echo "  INSTALL $(TARGET) -> /usr/local/bin/"
	@install -m 755 $(TARGET) /usr/local/bin/

# Uninstall
uninstall:
	@echo "  UNINSTALL /usr/local/bin/bsdulator"
	@rm -f /usr/local/bin/bsdulator

# Run tests
test: $(TARGET)
	@echo "Running tests..."
	@./tests/run_tests.sh

# Setup FreeBSD root filesystem
setup-freebsd:
	@echo "Setting up FreeBSD root filesystem..."
	@./scripts/setup_freebsd_root.sh

# Help
help:
	@echo "BSDulator - FreeBSD Compatibility Layer for Linux"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build optimized release (default)"
	@echo "  debug         - Build with debug symbols and sanitizers"
	@echo "  verbose       - Build with verbose logging"
	@echo "  clean         - Remove build artifacts"
	@echo "  install       - Install to /usr/local/bin"
	@echo "  uninstall     - Remove from /usr/local/bin"
	@echo "  test          - Run test suite"
	@echo "  setup-freebsd - Download FreeBSD base system"
	@echo "  help          - Show this help"

.PHONY: all debug verbose clean install uninstall test setup-freebsd help
