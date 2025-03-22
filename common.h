#ifndef __COMMON_H
#define __COMMON_H
#include <stdbool.h>

// 定义事件结构体
struct event {
    int pid;
    int uid;
    char comm[16];
    bool success;
};

// 可以在这里添加其他共享的常量或结构体
#define MAX_ENTRIES 1024
#define TASK_COMM_LEN 16

#define PROG_01 1
#define PROG_02 2

#endif /* __COMMON_H */ 