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

// 定义 ringbuf 回调函数
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("PID: %u, UID: %u, COMM: %s\n", e->pid, e->uid, e->comm);
    return 0;
}

int main(int argc, char *argv[]) {
    struct rootkit_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    /* Setup common tasks*/
    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    };

    /* Open BPF application */
    skel = rootkit_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = rootkit_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Setup maps for tail calls */
    //TODO: continue here at 2025-03-18,come on, you can do it!
    //int index = 1;
    //int prog_fd = bpf_program__fd(skel->progs.handle_getdents64_enter);

    /* Attach tracepoint handler */
    err = rootkit_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output\n");

    /* Poll events */
    while (1) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
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
    ring_buffer__free(rb);
    rootkit_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}