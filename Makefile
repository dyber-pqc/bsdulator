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

# BSDulator source files
SRCS = $(SRCDIR)/main.c \
       $(SRCDIR)/interceptor/interceptor.c \
       $(SRCDIR)/syscall/syscall_table.c \
       $(SRCDIR)/syscall/netlink_emul.c \
       $(SRCDIR)/loader/elf_loader.c \
       $(SRCDIR)/abi/abi_translate.c \
       $(SRCDIR)/runtime/freebsd_runtime.c \
       $(SRCDIR)/jail/jail.c

# BSDulator object files
OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Lochs CLI source files
LOCHS_SRCS = $(SRCDIR)/lochs/lochs_main.c \
             $(SRCDIR)/lochs/lochs_commands.c \
             $(SRCDIR)/lochs/lochs_images.c \
             $(SRCDIR)/lochs/lochs_compose.c \
             $(SRCDIR)/lochs/lochfile_parser.c \
             $(SRCDIR)/lochs/lochs_network.c \
             $(SRCDIR)/lochs/lochs_storage.c \
             $(SRCDIR)/lochs/lochs_zfs.c

# Lochs CLI object files
LOCHS_OBJS = $(LOCHS_SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Targets
TARGET = $(BINDIR)/bsdulator
LOCHS_TARGET = $(BINDIR)/lochs

# Default target - build both
all: CFLAGS += -O2
all: $(TARGET) $(LOCHS_TARGET)

# Debug build
debug: CFLAGS += -g3 -O0 -DDEBUG -fsanitize=address -fsanitize=undefined
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: $(TARGET) $(LOCHS_TARGET)

# Verbose build (enable all logging)
verbose: CFLAGS += -O2 -DBSD_VERBOSE
verbose: $(TARGET) $(LOCHS_TARGET)

# Link BSDulator
$(TARGET): $(OBJS)
	@echo "  LINK    $@"
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Link Lochs CLI
$(LOCHS_TARGET): $(LOCHS_OBJS)
	@echo "  LINK    $@"
	@$(CC) $(LOCHS_OBJS) -o $@ $(LDFLAGS)

# Compile
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	@echo "  CC      $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Dependencies - BSDulator
$(OBJDIR)/main.o: $(SRCDIR)/main.c $(INCDIR)/bsdulator.h
$(OBJDIR)/interceptor/interceptor.o: $(SRCDIR)/interceptor/interceptor.c $(INCDIR)/bsdulator.h $(INCDIR)/bsdulator/interceptor.h
$(OBJDIR)/syscall/syscall_table.o: $(SRCDIR)/syscall/syscall_table.c $(INCDIR)/bsdulator.h $(INCDIR)/bsdulator/syscall.h $(INCDIR)/bsdulator/jail.h $(SRCDIR)/runtime/freebsd_runtime.h
$(OBJDIR)/syscall/netlink_emul.o: $(SRCDIR)/syscall/netlink_emul.c $(INCDIR)/bsdulator.h $(INCDIR)/bsdulator/netlink.h
$(OBJDIR)/loader/elf_loader.o: $(SRCDIR)/loader/elf_loader.c $(INCDIR)/bsdulator.h $(INCDIR)/bsdulator/loader.h
$(OBJDIR)/abi/abi_translate.o: $(SRCDIR)/abi/abi_translate.c $(INCDIR)/bsdulator.h $(INCDIR)/bsdulator/abi.h
$(OBJDIR)/runtime/freebsd_runtime.o: $(SRCDIR)/runtime/freebsd_runtime.c $(SRCDIR)/runtime/freebsd_runtime.h $(INCDIR)/bsdulator.h
$(OBJDIR)/jail/jail.o: $(SRCDIR)/jail/jail.c $(INCDIR)/bsdulator.h $(INCDIR)/bsdulator/jail.h

# Dependencies - Lochs CLI
$(OBJDIR)/lochs/lochs_main.o: $(SRCDIR)/lochs/lochs_main.c $(INCDIR)/bsdulator/lochs.h
$(OBJDIR)/lochs/lochs_commands.o: $(SRCDIR)/lochs/lochs_commands.c $(INCDIR)/bsdulator/lochs.h $(SRCDIR)/lochs/lochs_compose.h
$(OBJDIR)/lochs/lochs_images.o: $(SRCDIR)/lochs/lochs_images.c $(INCDIR)/bsdulator/lochs.h
$(OBJDIR)/lochs/lochs_compose.o: $(SRCDIR)/lochs/lochs_compose.c $(SRCDIR)/lochs/lochs_compose.h $(INCDIR)/bsdulator/lochs.h
$(OBJDIR)/lochs/lochfile_parser.o: $(SRCDIR)/lochs/lochfile_parser.c $(INCDIR)/bsdulator/lochs.h
$(OBJDIR)/lochs/lochs_network.o: $(SRCDIR)/lochs/lochs_network.c $(INCDIR)/bsdulator/lochs.h
$(OBJDIR)/lochs/lochs_storage.o: $(SRCDIR)/lochs/lochs_storage.c $(INCDIR)/bsdulator/lochs.h
$(OBJDIR)/lochs/lochs_zfs.o: $(SRCDIR)/lochs/lochs_zfs.c $(INCDIR)/bsdulator/lochs.h

# Clean
clean:
	@echo "  CLEAN"
	@rm -rf $(OBJDIR) $(TARGET) $(LOCHS_TARGET)

# Install
install: $(TARGET) $(LOCHS_TARGET)
	@echo "  INSTALL $(TARGET) -> /usr/local/bin/"
	@install -m 755 $(TARGET) /usr/local/bin/
	@echo "  INSTALL $(LOCHS_TARGET) -> /usr/local/bin/"
	@install -m 755 $(LOCHS_TARGET) /usr/local/bin/

# Uninstall
uninstall:
	@echo "  UNINSTALL /usr/local/bin/bsdulator"
	@rm -f /usr/local/bin/bsdulator
	@echo "  UNINSTALL /usr/local/bin/lochs"
	@rm -f /usr/local/bin/lochs

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
	@echo "Lochs.dev - FreeBSD jail management CLI"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build bsdulator and lochs (default)"
	@echo "  debug         - Build with debug symbols and sanitizers"
	@echo "  verbose       - Build with verbose logging"
	@echo "  clean         - Remove build artifacts"
	@echo "  install       - Install to /usr/local/bin"
	@echo "  uninstall     - Remove from /usr/local/bin"
	@echo "  test          - Run test suite"
	@echo "  setup-freebsd - Download FreeBSD base system"
	@echo "  help          - Show this help"

.PHONY: all debug verbose clean install uninstall test setup-freebsd help
