# Makefile strictly following the user's specified toolchain and structure.

# Toolchain configuration from user's original Makefile
BPFTOOL := /home/jdLu/bpftool
CLANG := clang
GCC := gcc

# BPF compilation flags from user's original Makefile
# Added -I. to find vmlinux.h in the current directory
BPF_CFLAGS := -O2 -g -fno-builtin -target bpf -D__TARGET_ARCH_x86 \
              -I/home/jdLu/Diploma/linux-5.15.19/tool/lib/ -I.

# User-space compilation flags from user's original Makefile
USR_CFLAGS := -g -O2 -Wall -I.
USR_LDFLAGS := -lbpf -lelf -lz

.PHONY: all clean run_bench_with_bpf mysql_monitor

# Default target builds all specified applications
all: run_bench_with_bpf mysql_monitor

# --- Build recipe for mysql_monitor ---
# This target explicitly defines the build steps in the correct order.
mysql_monitor: mysql_monitor.bpf.c mysql_monitor.c vmlinux.h
	@echo "--- Building mysql_monitor ---"
	@echo "  [BPF]    CC      mysql_monitor.bpf.c"
	@$(CLANG) $(BPF_CFLAGS) -c mysql_monitor.bpf.c -o mysql_monitor.bpf.o
	@echo "  [SKEL]   GEN     mysql_monitor.skel.h"
	@$(BPFTOOL) gen skeleton mysql_monitor.bpf.o > mysql_monitor.skel.h
	@echo "  [USR]    CC      mysql_monitor.c"
	@$(GCC) $(USR_CFLAGS) -o mysql_monitor mysql_monitor.c $(USR_LDFLAGS)
	@echo "Build complete: ./mysql_monitor"

# --- Build recipe for run_bench_with_bpf ---
# This target explicitly defines the build steps in the correct order.
run_bench_with_bpf: run_bench_with_bpf.bpf.c run_bench_with_bpf.c vmlinux.h
	@echo "--- Building run_bench_with_bpf ---"
	@echo "  [BPF]    CC      run_bench_with_bpf.bpf.c"
	@$(CLANG) $(BPF_CFLAGS) -c run_bench_with_bpf.bpf.c -o run_bench_with_bpf.bpf.o
	@echo "  [SKEL]   GEN     run_bench_with_bpf.skel.h"
	@$(BPFTOOL) gen skeleton run_bench_with_bpf.bpf.o > run_bench_with_bpf.skel.h
	@echo "  [USR]    CC      run_bench_with_bpf.c"
	@$(GCC) $(USR_CFLAGS) -o run_bench_with_bpf run_bench_with_bpf.c $(USR_LDFLAGS)
	@echo "Build complete: ./run_bench_with_bpf"

# --- Clean Rule ---
clean:
	@echo "  [CLEAN]  Cleaning generated files"
	@rm -f run_bench_with_bpf mysql_monitor
	@rm -f *.bpf.o *.skel.h
	@rm -f *.o
