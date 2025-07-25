#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 jdLu
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import ctypes as ct
import time
import argparse
import csv
import sys

# BPF C Code for kernel instrumentation
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

#define MAX_FILENAME_LEN 256

// Data structure to hold event information, passed from kernel to user space
struct data_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 offset;
    u64 nr_to_read; // Number of pages to read ahead
    char filename[MAX_FILENAME_LEN];
};

// BPF map to send data to user space via a performance buffer
BPF_PERF_OUTPUT(events);

// kprobe attached to the kernel function __do_page_cache_readahead
int trace_readahead(struct pt_regs *ctx, struct file *file, unsigned long offset, unsigned long nr_to_read) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Filter for 'mysqld' processes in the kernel to reduce overhead
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    char target_comm[] = "mysqld";
    for (int i = 0; i < sizeof(target_comm) -1; ++i) {
        if (comm[i] != target_comm[i]) {
            return 0; // Not a mysqld process, exit
        }
    }

    data.ts = bpf_ktime_get_ns();
    data.pid = pid;
    data.offset = offset;
    data.nr_to_read = nr_to_read;
    bpf_probe_read_kernel_str(&data.comm, sizeof(data.comm), comm);

    if (file != NULL && file->f_path.dentry != NULL && file->f_path.dentry->d_name.name != NULL) {
        bpf_probe_read_str(&data.filename, sizeof(data.filename), file->f_path.dentry->d_name.name);
    } else {
        const char unknown[] = "[unknown]";
        __builtin_memcpy(data.filename, unknown, sizeof(unknown));
    }

    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}
"""

# Python data structure corresponding to the C struct
class Data(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 256),
        ("offset", ct.c_ulonglong),
        ("nr_to_read", ct.c_ulonglong),
    ]

# Globals for output handling
csv_writer = None
output_file = None

def print_event(cpu, data, size):
    """
    Callback function to process events from the BPF perf buffer.
    It prints to stdout or writes to a CSV file based on user arguments.
    """
    event = ct.cast(data, ct.POINTER(Data)).contents
    
    try:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        pid = event.pid
        comm = event.comm.decode('utf-8')
        filename = event.filename.decode('utf-8')
        pages = event.nr_to_read
        offset = event.offset

        if csv_writer:
            csv_writer.writerow([timestamp, pid, comm, filename, pages, offset])
        else:
            print(f"[{timestamp}] PID: {pid:<6} COMM: {comm:<16} FILE: {filename:<30} PAGES: {pages:<5} OFFSET: {offset}")

    except UnicodeDecodeError:
        # Ignore events with non-UTF8 comm or filename
        pass

def main():
    """
    Main function to parse arguments, set up BPF, and poll for events.
    """
    global csv_writer, output_file

    parser = argparse.ArgumentParser(
        description="Monitor MySQL page cache readahead I/O using eBPF.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Path to a CSV file to save the output.\nIf not provided, prints to standard output."
    )
    args = parser.parse_args()

    if args.output:
        try:
            output_file = open(args.output, 'w', newline='')
            csv_writer = csv.writer(output_file)
            # Write CSV header
            csv_writer.writerow(['Timestamp', 'PID', 'Command', 'File', 'Pages', 'Offset'])
            print(f"Capturing data... Saving to {args.output}. Press Ctrl+C to stop.")
        except IOError as e:
            print(f"Error: Could not open file {args.output} for writing: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Starting MySQL readahead monitor...")
        print("Waiting for readahead events from 'mysqld' processes. Press Ctrl+C to exit.")
        print("-" * 110)
        print(f"{'TIMESTAMP':<21} {'PID':<6} {'COMM':<16} {'FILE':<30} {'PAGES':<5} {'OFFSET'}")
        print("-" * 110)

    # Initialize BPF
    b = BPF(text=bpf_text)
    try:
        b.attach_kprobe(event="__do_page_cache_readahead", fn_name="trace_readahead")
    except Exception as e:
        print(f"Error attaching kprobe: {e}", file=sys.stderr)
        print("Please ensure you are running with root privileges and that your kernel headers are installed.", file=sys.stderr)
        sys.exit(1)

    # Set up perf buffer
    b["events"].open_perf_buffer(print_event)

    # Poll for events
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nDetaching kprobe and exiting.")
            break
    
    # Clean up
    if output_file:
        output_file.close()

if __name__ == "__main__":
    main()