# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Copyright (c) 2024 jdLu
#
# A generic Makefile for building multiple libbpf-based BPF applications.

# List of applications to build. Add new application names here.
APPS = run_bench_with_bpf mysql_monitor

# Default tools and paths. Can be overridden from the command line.
# (e.g., `make BPFTOOL=/path/to/bpftool`)
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# Adjust this path to your libbpf source location if it's not in a standard place.
# For this project, we assume it's in a relative path.
# If you have libbpf installed system-wide, you might not need this.
LIBBPF_SRC ?= ../libbpf/src
LIBBPF_OBJ ?= $(LIBBPF_SRC)/libbpf.a

# Common flags
CFLAGS = -g -Wall
INCLUDES = -I. -I/usr/include -I/usr/include/bpf
LDFLAGS = -lbpf -lelf -lz

# vmlinux.h is required for BPF CO-RE.
# Ensure it's available. You can generate it with:
# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
VMLINUX_H = vmlinux.h

.PHONY: all
all: $(VMLINUX_H) $(APPS)

.PHONY: clean
clean:
	rm -f $(APPS)
	rm -f *.o
	rm -f *.skel.h
	rm -f *.bpf.o

# Generate vmlinux.h if it doesn't exist.
# This is a helper, you might need to run it manually if it fails.
$(VMLINUX_H):
	@if [ ! -f "$(VMLINUX_H)" ]; then \
		echo "WARN: vmlinux.h not found. Attempting to generate it with bpftool."; \
		echo "WARN: This may require sudo or root privileges."; \
		set -x; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H); \
	fi

# --- Generic Build Rules ---

# Rule to compile a BPF C file to a BPF object file.
%.bpf.o: %.bpf.c $(VMLINUX_H)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $< -o $@

# Rule to generate a BPF skeleton header from a BPF object file.
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Rule to compile a user-space C file to an object file.
%.o: %.c %.skel.h
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Rule to link the user-space object file and libbpf to create the final executable.
$(APPS): %: %.o %.bpf.o
	$(CLANG) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# --- End of Generic Rules ---
