#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

//全局变量区
volatile int target_ppid = 0;

// 映射表 存储dents 缓冲区的地址
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} map_buffs SEC(".maps");

// RingBuffer to send events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB 的缓冲区
} rb SEC(".maps");

//定义tracepoint处理函数
// 函数原型：int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
SEC("tracepoint/syscalls/sys_enter_getdents64")
int handle_getdents64_enter(struct trace_event_raw_sys_enter *ctx) {
    size_t pid_tgid = bpf_get_current_pid_tgid();
    if(target_ppid != 0) {
        //检查是否是目标进程的子进程
        struct task_struct* task = (struct task_struct*)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if(ppid != target_ppid) {
            return 0;
        }
    }

    int pid = pid_tgid >> 32;
    unsigned int fd = ctx->args[0];
    unsigned int buff_count = ctx->args[2];
    bpf_printk("getdents64 called with pid: %d, fd: %d, buff_count: %d\n", pid, fd, buff_count);

    // 将参数存储到map中,供退出函数使用
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];

    // 将缓冲区地址存储到map中
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_getdents64_exit(struct trace_event_raw_sys_exit *ctx) {
    bpf_printk("getdents64 exited\n");
    return 0;
}







