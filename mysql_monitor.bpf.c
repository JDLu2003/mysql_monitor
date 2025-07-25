// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 jdLu
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define HOOK_POINT_LEN 32
#define TARGET_COMM "mysqld"

// Updated event structure with a field to identify the hook point
struct event {
	__u64 ts;
	__u32 pid;
	__u64 req_size; // Requested readahead size
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	char hook_point[HOOK_POINT_LEN];
};

// Perf event map to send data to user space
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Common logic for handling readahead probes
static __always_inline int
process_ra_event(void *ctx, struct file_ra_state *ra, size_t req_size,
		 const char *hook_name)
{
	struct event event = {};
	const char *filename;
	struct file *file;
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
	event.req_size = req_size;
	bpf_probe_read_str(&event.hook_point, sizeof(event.hook_point),
			   hook_name);

	// Get filename from file_ra_state -> file -> dentry
	file = BPF_CORE_READ(ra, file);
	dentry = BPF_CORE_READ(file, f_path.dentry);
	filename = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_str(&event.filename, sizeof(event.filename), filename);

	// Submit the event to user space
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

	return 0;
}

// kprobe for synchronous readahead
SEC("kprobe/page_cache_sync_ra")
int BPF_KPROBE(page_cache_sync_ra, struct file_ra_state *ra, size_t req_size)
{
	return process_ra_event(ctx, ra, req_size, "sync_ra");
}

// kprobe for asynchronous readahead
SEC("kprobe/page_cache_async_ra")
int BPF_KPROBE(page_cache_async_ra, struct file_ra_state *ra, size_t req_size)
{
	return process_ra_event(ctx, ra, req_size, "async_ra");
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";