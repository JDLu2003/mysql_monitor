// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 jdLu
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define TARGET_COMM "mysqld"

// Data structure to hold event information
struct event {
	__u64 ts;
	__u32 pid;
	__u64 offset;
	__u64 nr_to_read;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

// Perf event map to send data to user space
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// kprobe attached to the kernel function __do_page_cache_readahead
SEC("kprobe/__do_page_cache_readahead")
int BPF_KPROBE(__do_page_cache_readahead, struct file *file, unsigned long offset,
	       unsigned long nr_to_read)
{
	struct event event = {};
	const char *filename;
	struct dentry *dentry;

	// Filter for target process name
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	for (int i = 0; i < sizeof(TARGET_COMM) - 1; ++i) {
		if (event.comm[i] != TARGET_COMM[i]) {
			return 0; // Not the target process, exit
		}
	}

	// Populate event data
	event.ts = bpf_ktime_get_ns();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.offset = offset;
	event.nr_to_read = nr_to_read;

	// Get filename
	dentry = BPF_CORE_READ(file, f_path.dentry);
	filename = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_str(&event.filename, sizeof(event.filename), filename);

	// Submit the event to user space
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
