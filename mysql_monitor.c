// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 jdLu
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "mysql_monitor.skel.h"

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Data structure to hold event information (must match the BPF struct)
struct event {
	__u64 ts;
	__u32 pid;
	__u64 offset;
	__u64 nr_to_read;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

static volatile bool exiting = false;
static FILE *output_f = NULL;
static bool verbose = false;

// Libbpf logging callback
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

// Signal handler for graceful exit
static void sig_handler(int sig)
{
	exiting = true;
}

// Perf buffer event handler
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	char ts[32];
	time_t t;
	struct tm *tm;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

	if (output_f) {
		fprintf(output_f, "%s,%u,%s,%s,%llu,%llu\n", ts, e->pid,
			e->comm, e->filename, e->nr_to_read, e->offset);
	} else {
		printf("%-20s %-7u %-16s %-30s %-7llu %-10llu\n", ts,
		       e->pid, e->comm, e->filename, e->nr_to_read,
		       e->offset);
	}
}

static void print_usage(const char *prog)
{
	printf("USAGE: %s [-o FILE] [-v]\n", prog);
	printf("  -o FILE  Path to a CSV file to save the output\n");
	printf("  -v       Verbose debug output\n");
	printf("  -h       Show this help message\n");
}

int main(int argc, char **argv)
{
	struct mysql_monitor_bpf *skel;
	struct perf_buffer *pb = NULL;
	char *output_file = NULL;
	int err, opt;

	// Parse command-line arguments using getopt
	while ((opt = getopt(argc, argv, "o:vh")) != -1) {
		switch (opt) {
		case 'o':
			output_file = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	// Set up libbpf logging
	libbpf_set_print(libbpf_print_fn);

	// Open, load, and verify BPF application
	skel = mysql_monitor_bpf__open();
	if (!skel) {
		fprintf(stderr, "Error: Failed to open BPF skeleton\n");
		return 1;
	}

	err = mysql_monitor_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Error: Failed to load BPF skeleton\n");
		goto cleanup;
	}

	err = mysql_monitor_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Error: Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	// Set up signal handler
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Open output file if specified
	if (output_file) {
		output_f = fopen(output_file, "w");
		if (!output_f) {
			fprintf(stderr, "Error: Failed to open output file %s\n",
				output_file);
			err = 1;
			goto cleanup;
		}
		// Write CSV header
		fprintf(output_f,
			"Timestamp,PID,Command,File,Pages,Offset\n");
		printf("Capturing data... Saving to %s. Press Ctrl+C to stop.\n",
		       output_file);
	} else {
		// Print table header
		printf("%-20s %-7s %-16s %-30s %-7s %-10s\n", "TIMESTAMP",
		       "PID", "COMMAND", "FILE", "PAGES", "OFFSET");
	}

	// Set up perf buffer polling
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event,
			      NULL, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Error: Failed to create perf buffer\n");
		goto cleanup;
	}

	// Main event loop
	while (!exiting) {
		err = perf_buffer__poll(pb, 100); // 100ms timeout
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	perf_buffer__free(pb);
	mysql_monitor_bpf__destroy(skel);
	if (output_f)
		fclose(output_f);
	return -err;
}