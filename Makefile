# ----------------------------------------------------------------------
#  Compiler configuration
# ----------------------------------------------------------------------
CC        := gcc
CPPFLAGS  += -Iinclude $(shell pkg-config --cflags libbpf libcurl)
CFLAGS    += -Wall -MMD -Wunused-but-set-variable
LDLIBS    += $(shell pkg-config --libs libbpf libcurl) -ldl

# ----------------------------------------------------------------------
#  Parallel build
# ----------------------------------------------------------------------
# Use all available CPU cores on the machine when invoking make.
# If the NPROC variable is defined (for example in CI), it is respected;
# otherwise, it is determined at runtime using `nproc`.
MAKEFLAGS += -j$(if $(NPROC),$(NPROC),$(shell nproc))

# ----------------------------------------------------------------------
#  Directory layout
# ----------------------------------------------------------------------
SRCDIR      := src
KERNDIR     := $(SRCDIR)/kernel
OBJDIR      := build
BINDIR      := bin
INCLUDE_DIR := include

# ----------------------------------------------------------------------
#  Architecture detection for BPF
# ----------------------------------------------------------------------
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    ARCH_BPF = x86
else ifeq ($(ARCH),aarch64)
    ARCH_BPF = arm64
else ifeq ($(ARCH),armv7l)
    ARCH_BPF = arm
else
    $(error Unsupported architecture: $(ARCH))
endif

# ----------------------------------------------------------------------
#  Source / object lists
# ----------------------------------------------------------------------
SOURCES   := $(wildcard $(SRCDIR)/*.c)
OBJ       := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
DEPFILES  := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.d,$(SOURCES))

# All eBPF sources in src/kernel
BPF_SRCS := $(wildcard $(KERNDIR)/*.bpf.c)
BPF_OBJS := $(patsubst $(KERNDIR)/%.bpf.c,$(OBJDIR)/%.bpf.o,$(BPF_SRCS))

# Final executable
EXE := $(BINDIR)/rootisnaked

# ----------------------------------------------------------------------
#  Tools for lint/format
# ----------------------------------------------------------------------
LINTER    := clang-tidy
FORMATTER := clang-format

# ----------------------------------------------------------------------
#  Primary targets
# ----------------------------------------------------------------------
.PHONY: all format lint gen-vmlinux clean build

all: $(BPF_OBJS) $(EXE)

# Compile user-space executable
$(EXE): $(OBJ) | $(BPF_OBJS)
	@mkdir -p $(BINDIR)
	$(CC) $(OBJ) $(LDLIBS) -o $@

# Compile normal C objects (user-space)
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Compile each eBPF object
$(OBJDIR)/%.bpf.o: $(KERNDIR)/%.bpf.c | $(INCLUDE_DIR)/vmlinux.h
	@mkdir -p $(OBJDIR)
	clang -O2 -g -target bpf \
	      -D__TARGET_ARCH_$(ARCH_BPF) \
	      -I$(INCLUDE_DIR) \
	      -c $< -o $@

# ----------------------------------------------------------------------
#  Helper / maintenance targets
# ----------------------------------------------------------------------
format:
	@$(FORMATTER) -i $(SRCDIR)/*.c $(INCLUDE_DIR)/*.h

lint:
	@$(LINTER) --config-file=.clang-tidy $(SRCDIR)/*.c $(INCLUDE_DIR)/*.h -- $(CPPFLAGS) $(CFLAGS)

# Generate vmlinux.h (BTF)
gen-vmlinux:
	@mkdir -p $(INCLUDE_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(INCLUDE_DIR)/vmlinux.h

clean:
	rm -rf $(OBJDIR) $(BINDIR)

compile-commands: clean
	bear -- make

build: clean all

# ----------------------------------------------------------------------
#  Include generated dependency files
# ----------------------------------------------------------------------
-include $(DEPFILES)
