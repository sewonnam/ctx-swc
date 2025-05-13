#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "swc.h"

#define MAX_ENTRIES 10240

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct data);
} datas SEC(".maps");

static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
    int err;
    struct data *d;
    u32 pid;

    pid = BPF_CORE_READ(next, pid);
    d = bpf_map_lookup_elem(&datas, &pid);
    if (!d) {
        struct data init;
        bpf_probe_read_kernel_str(&init.comm, sizeof(init.comm), next->comm);
        init.count = 1;
        bpf_map_update_elem(&datas, &pid, &init, BPF_NOEXIST);
        return 0;
    }

    d->count++;

    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    return handle_switch(preempt, prev, next);
}

char LICENSE[] SEC("license") = "GPL";
