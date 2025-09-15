# Compiler Settings
CC = gcc
# Incluye includes y cflags de pkg-config en CPPFLAGS (no en CFLAGS)
CPPFLAGS += -Iinclude $(shell pkg-config --cflags libbpf libcurl)
CFLAGS   += -Wall -MMD -Wunused-but-set-variable
LDLIBS   += $(shell pkg-config --libs libbpf libcurl) -ldl

SRCDIR=src
OBJDIR=build
BINDIR=bin
EXE=$(BINDIR)/rootisnaked
TESTS_DIR=tests
INCLUDE_DIR=include

# Source Files
SOURCES=$(wildcard $(SRCDIR)/*.c)
OBJ=$(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SOURCES))
DEPFILES=$(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.d, $(SOURCES))

# eBPF Program
BPF_SOURCE=$(SRCDIR)/kernel/rootisnaked.bpf.c
BPF_OBJ=$(OBJDIR)/rootisnaked.bpf.o

# Compiler settings
LINTER := clang-tidy
FORMATTER := clang-format

# Detect architecture automatically
ARCH := $(shell uname -m)

# Map architecture to BPF target names
ifeq ($(ARCH),x86_64)
    ARCH_BPF = x86
else ifeq ($(ARCH),aarch64)
    ARCH_BPF = arm64
else ifeq ($(ARCH),armv7l)
    ARCH_BPF = arm
else
    $(error Unsupported architecture: $(ARCH))
endif

# Targets
all: format $(BPF_OBJ) $(EXE)

# Compile Executable (link)
$(EXE): $(OBJ)
	@mkdir -p $(BINDIR)
	$(CC) $(OBJ) $(LDLIBS) -o $@

# Compile Object Files
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Compile eBPF Object File
$(BPF_OBJ): $(BPF_SOURCE)
	@mkdir -p $(OBJDIR)
	clang -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH_BPF) -I$(INCLUDE_DIR)/ -c $< -o $@

# Include dependency files
-include $(DEPFILES)

# Run formatter on source and header files
format:
	@$(FORMATTER) -i $(SRCDIR)/*.c $(INCLUDE_DIR)/*.h

# Run linter on source and header files
lint:
	@$(LINTER) --config-file=.clang-tidy $(SRCDIR)/*.c $(INCLUDE_DIR)/*.h -- $(CPPFLAGS) $(CFLAGS)

gen-vmlinux: ## Generate vmlinux.h
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

# Clean up
clean:
	rm -rf $(OBJDIR) $(BINDIR)

build: $(BPF_OBJ) $(EXE) ## Build all

