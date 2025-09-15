# ----------------------------------------------------------------------
#  Compiler configuration
# ----------------------------------------------------------------------
CC        := gcc                         # user‑space compiler (can be clang)
CPPFLAGS  += -Iinclude $(shell pkg-config --cflags libbpf libcurl)
CFLAGS    += -Wall -MMD -Wunused-but-set-variable
LDLIBS    += $(shell pkg-config --libs libbpf libcurl) -ldl

# ----------------------------------------------------------------------
#  Directory layout
# ----------------------------------------------------------------------
SRCDIR    := src
KERNDIR   := $(SRCDIR)/kernel            # eBPF source directory
OBJDIR    := build
BINDIR    := bin
INCLUDE_DIR := include

# ----------------------------------------------------------------------
#  Architecture detection (for BPF target)
# ----------------------------------------------------------------------
ARCH      := $(shell uname -m)
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
# User‑space (normal) sources
SOURCES   := $(wildcard $(SRCDIR)/*.c)
OBJ       := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
DEPFILES  := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.d,$(SOURCES))

# eBPF sources (any *.bpf.c under $(KERNDIR))
BPF_SRCS  := $(wildcard $(KERNDIR)/*.bpf.c)
BPF_OBJS  := $(patsubst $(KERNDIR)/%.bpf.c,$(OBJDIR)/%.bpf.o,$(BPF_SRCS))

# Final executable
EXE       := $(BINDIR)/rootisnaked

# ----------------------------------------------------------------------
#  Tools for lint/format
# ----------------------------------------------------------------------
LINTER    := clang-tidy
FORMATTER := clang-format

# ----------------------------------------------------------------------
#  Primary targets
# ----------------------------------------------------------------------
.PHONY: all format lint gen-vmlinux clean build

all: $(EXE)               # default target builds everything

# Build the user‑space binary; order‑only prerequisite ensures eBPF objects are fresh
$(EXE): $(OBJ) | $(BPF_OBJS)
	@mkdir -p $(BINDIR)
	$(CC) $(OBJ) $(LDLIBS) -o $@

# ----------------------------------------------------------------------
#  Pattern rule for normal C objects (user‑space)
# ----------------------------------------------------------------------
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# ----------------------------------------------------------------------
#  Pattern rule for eBPF objects (one per *.bpf.c)
# ----------------------------------------------------------------------
$(OBJDIR)/%.bpf.o: $(KERNDIR)/%.bpf.c $(INCLUDE_DIR)/vmlinux.h
	@mkdir -p $(OBJDIR)
	$(CC) -O2 -g -target bpf \
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

# Generate vmlinux.h (BTF) – optional, but many eBPF programs need it
gen-vmlinux:
	@mkdir -p $(INCLUDE_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(INCLUDE_DIR)/vmlinux.h

clean:
	rm -rf $(OBJDIR) $(BINDIR)

# Alias that forces a full rebuild (useful for CI)
build: clean all

# ----------------------------------------------------------------------
#  Include generated dependency files for normal C objects
# ----------------------------------------------------------------------
-include $(DEPFILES)