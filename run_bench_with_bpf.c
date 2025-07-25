#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "run_bench_with_bpf.skel.h"

typedef char stringkey[64];
typedef __u32 u32;

int main(int argc, char **argv) {

    struct timespec start_time, end_time;

    // clear all cache
    int ret = system("sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'");

    if (ret == -1) {
        fprintf(stderr, "Failed to clear all cache\n");
    } else {
        fprintf(stderr, "Succeessfil cleared all caches\n");
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args ...]\n", argv[0]);
        return 1;
    }

    struct run_bench_with_bpf_bpf *skel;
    int err;
    skel = run_bench_with_bpf_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    err = run_bench_with_bpf_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }
    err = run_bench_with_bpf_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        goto cleanup;
    }

    if (child == 0) {
        // 子进程：执行测试命令
        execvp(argv[1], &argv[1]);
        perror("execvp");
        exit(127);
    }

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // 父进程：将子进程 pid 写入 bpf map
    stringkey keys[10] = {"pid", "read", "write", "mmap", "sync_ra", "async_ra", "sync_accessed", "async_accessed", "page_fault_user", "page_cache_ra_unbounded"};
    u32 zero = 0;
    bpf_map__update_elem(skel->maps.bench_map, &keys[0], sizeof(keys[0]), &child, sizeof(child), BPF_ANY);
    for (int i = 1; i < 10; i++) {
        bpf_map__update_elem(skel->maps.bench_map, &keys[i], sizeof(keys[i]), &zero, sizeof(zero), BPF_ANY);
    }

    printf("Running '%s' (pid=%d), monitoring...\n", argv[1], child);
    int status;
    while (1) {
        // sleep(1);
        // u32 val;
        // printf("==== stats ====\n");
        // for (int j = 1; j < 10; j++) {
        //     if (bpf_map__lookup_elem(skel->maps.bench_map, &keys[j], sizeof(keys[j]), &val, sizeof(val), BPF_ANY) == 0) {
        //         printf("%s count = %u\n", keys[j], val);
        //     }
        // }
        // 检查子进程是否结束
        pid_t w = waitpid(child, &status, 0);
        if (w == child) {
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            double period_time = (end_time.tv_sec - start_time.tv_sec) * 1e6 +
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e3;
            printf("============================================\nTotal execution time: %.6f micro seconds\n============================================\n", period_time);
            printf("Child process exited.\n");
            break;
        }
    }

cleanup:
    run_bench_with_bpf_bpf__destroy(skel);
    return 0;
} 