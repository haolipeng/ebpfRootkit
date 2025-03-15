#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

// 定义 BPF map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB 的缓冲区
} events SEC(".maps");

//定义tracepoint处理函数

SEC("tracepoint/syscalls/sys_enter_getdents64")
int handle_getdents64(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    
    // 从 ringbuf 预留空间
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }
    
    // 填充事件数据
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // 提交事件
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_getdents64_exit(struct trace_event_raw_sys_exit *ctx) {
    bpf_printk("getdents64 exited\n");
    return 0;
}







