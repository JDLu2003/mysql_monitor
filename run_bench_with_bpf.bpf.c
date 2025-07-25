#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u32 u32;
typedef char stringkey[64];

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    stringkey *key;
    __type(value, u32);
} bench_map SEC(".maps");


static __always_inline int check_pid() {
    stringkey key = "pid";
    u32 mypid = bpf_get_current_pid_tgid();
    u32 *val = bpf_map_lookup_elem(&bench_map, &key);
    if (val && *val == mypid)
        return 1;
    return 0;
}

SEC("ksyscall/read")
int trace_read(struct pt_regs *ctx) {
    if (!check_pid())
        return 0;
    bpf_printk("[BPF] enter read hook, pid=%d", bpf_get_current_pid_tgid() >> 32);
    stringkey key = "read";
    u32 *v = bpf_map_lookup_elem(&bench_map, &key);
    if (v)
        (*v)++;
    return 0;
}

SEC("ksyscall/write")
int trace_write(struct pt_regs *ctx) {
    if (!check_pid())
        return 0;
    bpf_printk("[BPF] enter write hook, pid=%d", bpf_get_current_pid_tgid() >> 32);
    stringkey key = "write";
    u32 *v = bpf_map_lookup_elem(&bench_map, &key);
    if (v)
        (*v)++;
    return 0;
}

SEC("ksyscall/mmap")
int trace_mmap(struct pt_regs *ctx) {
    if (!check_pid())
        return 0;
    bpf_printk("[BPF] enter mmap hook, pid=%d", bpf_get_current_pid_tgid() >> 32);
    stringkey key = "mmap";
    u32 *v = bpf_map_lookup_elem(&bench_map, &key);
    if (v)
        (*v)++;
    return 0;
}

SEC("kprobe/page_cache_sync_ra")
int trace_page_cache_sync_ra(struct pt_regs *ctx) {
    if (!check_pid())
        return 0;
    bpf_printk("[BPF] enter page_cache_sync_ra hook, pid=%d", bpf_get_current_pid_tgid() >> 32);
    stringkey key = "sync_ra";
    u32 flag = 1;
    bpf_map_update_elem(&bench_map, &key, &flag, BPF_ANY);
    return 0;
}

SEC("kretprobe/page_cache_sync_ra")
int trace_page_cache_sync_ra_exit(struct pt_regs *ctx) {
    if (!check_pid())
        return 0;
    bpf_printk("[BPF] enter page_cache_sync_ra_exit hook, pid=%d", bpf_get_current_pid_tgid() >> 32);
    stringkey key = "sync_ra";
    u32 flag = 0;
    bpf_map_update_elem(&bench_map, &key, &flag, BPF_ANY);
    return 0;
}

SEC("kprobe/page_cache_async_ra")
int trace_page_cache_async_ra(struct pt_regs *ctx) {
    if (!check_pid())
        return 0;
    bpf_printk("[BPF] enter page_cache_async_ra hook, pid=%d", bpf_get_current_pid_tgid() >> 32);
    stringkey key = "async_ra";
    u32 flag = 1;
    bpf_map_update_elem(&bench_map, &key, &flag, BPF_ANY);
    return 0;
}

SEC("kretprobe/page_cache_async_ra")
int trace_page_cache_async_ra_exit(struct pt_regs *ctx) {
    if (!check_pid())
        return 0;
    bpf_printk("[BPF] enter page_cache_async_ra_exit hook, pid=%d", bpf_get_current_pid_tgid() >> 32);
    stringkey key = "async_ra";
    u32 flag = 0;
    bpf_map_update_elem(&bench_map, &key, &flag, BPF_ANY);
    return 0;
}

SEC("kprobe/add_to_page_cache_lru")
int trace_add_to_page_cache_lru(struct pt_regs *ctx) {
    if (!check_pid())
        return 0;
    bpf_printk("[BPF] enter add_to_page_cache_lru hook, pid=%d", bpf_get_current_pid_tgid() >> 32);
    stringkey key_sync = "sync_ra";
    u32 *v_sync = bpf_map_lookup_elem(&bench_map, &key_sync);
    if (v_sync && *v_sync == 1) {
        stringkey key = "sync_accessed";
        u32 *v = bpf_map_lookup_elem(&bench_map, &key);
        if (v) {
            (*v)++;
        }
    }
    stringkey key_async = "async_ra";
    u32 *v_async = bpf_map_lookup_elem(&bench_map, &key_async);
    if (v_async && *v_async == 1) {
        stringkey key = "async_accessed";
        u32 *v = bpf_map_lookup_elem(&bench_map, &key);
        if (v) {
            (*v)++;
        }
    }
    return 0;
}

// 使用 kprobe 方式追踪 handle_mm_fault
SEC("kprobe/handle_mm_fault")
int handle_user_pf(struct pt_regs *ctx) {
    if (!check_pid())
        return 0;
    bpf_printk("[BPF] enter handle_mm_fault hook, pid=%d", bpf_get_current_pid_tgid() >> 32);
    stringkey key = "page_fault_user";
    u32 *v = bpf_map_lookup_elem(&bench_map, &key);
    if (v)
        (*v)++;
    unsigned long addr = PT_REGS_PARM2(ctx);
    bpf_printk("[PF] pid=%d addr=0x%lx", bpf_get_current_pid_tgid() >> 32, addr);
    return 0;
}

SEC("kprobe/invalidate_mapping_pages")
int trace_invalidate_mapping_pages(struct pt_regs *ctx) {
    u64 mapping = (u64)PT_REGS_PARM1(ctx);
    u64 start = PT_REGS_PARM2(ctx);
    u64 end = PT_REGS_PARM3(ctx);
    bpf_printk("invalidate_mapping_pages: mapping=%p, start=%llu, end=%llu", (void*)mapping, start, end);
    return 0;
}

SEC("kprobe/page_cache_ra_unbounded")
int trace_page_cache_ra_unbounded(struct pt_regs *ctx) {
    // struct readahead_control *ractl = (struct readahead_control *)PT_REGS_PARM1(ctx);
    unsigned long nr_to_read = PT_REGS_PARM2(ctx);
    unsigned long lookahead_size = PT_REGS_PARM3(ctx);
    bpf_printk("page_cache_ra_unbounded: nr_to_read=%lu, lookahead_size=%lu", nr_to_read, lookahead_size);
    stringkey key = "page_cache_ra_unbounded";
    u32 *v = bpf_map_lookup_elem(&bench_map, &key);
    if (v) {
        (*v)++;
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
