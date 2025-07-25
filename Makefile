# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Copyright (c) 2024 jdLu
#
# A robust, generic Makefile for building multiple libbpf-based BPF applications.

# List of applications to build. Add new application names here.
APPS = run_bench_with_bpf mysql_monitor

# Default tools and paths.
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
LIBBPF_OBJ ?= -lbpf # Link against installed libbpf

# Common flags
CFLAGS = -g -Wall
INCLUDES = -I.
LDFLAGS = $(LIBBPF_OBJ) -lelf -lz

# vmlinux.h is required for BPF CO-RE.
VMLINUX_H = vmlinux.h

# Generate lists of files from the APPS variable
BPF_OBJS = $(addsuffix .bpf.o, $(APPS))
USR_OBJS = $(addsuffix .o, $(APPS))
SKEL_HDRS = $(addsuffix .skel.h, $(APPS))

.PHONY: all
all: $(VMLINUX_H) $(APPS)

.PHONY: clean
clean:
	rm -f $(APPS) $(BPF_OBJS) $(USR_OBJS) $(SKEL_HDRS)

# Helper to generate vmlinux.h if it's missing.
# May require root privileges.
$(VMLINUX_H):
	@if [ ! -f "$(VMLINUX_H)" ]; then \
		echo "WARN: $(VMLINUX_H) not found. Attempting to generate..."; \
		set -x; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H); \
	fi

# --- Build Rules ---

# Final linking step for each application.
# Depends on the user-space object file and the BPF object file.
$(APPS): %: %.o %.bpf.o
	$(CLANG) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to compile user-space C files.
# This now correctly depends on the skeleton header.
$(USR_OBJS): %.o: %.c %.skel.h
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Rule to generate skeleton headers from BPF object files.
$(SKEL_HDRS): %.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Rule to compile BPF C files into BPF object files.
$(BPF_OBJS): %.bpf.o: %.bpf.c $(VMLINUX_H)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $< -o $@