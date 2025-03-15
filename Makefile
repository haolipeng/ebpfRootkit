# 编译器和标志
CLANG ?= clang
CC ?= gcc
CFLAGS ?= -g -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# libbpf 相关路径
LIBBPF_SRC = ./libbpf/src
LIBBPF_OBJ = $(LIBBPF_SRC)/libbpf.a
LIBBPF_HEADERS = ./libbpf/include

# 编译标志
CFLAGS += -I$(LIBBPF_HEADERS) -I$(LIBBPF_SRC) -I./vmlinux
LDFLAGS = -L$(LIBBPF_SRC) -lbpf -lelf -lz

# 目标文件
BPF_TARGETS = rootkit.bpf.o
USER_TARGETS = rootkit

# 首先编译 libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch])
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1

# 编译 BPF 程序
%.bpf.o: %.bpf.c common.h
	$(CLANG) $(CFLAGS) -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		$(LIBBPF_CFLAGS) \
		-c $< -o $@
	# 删除或注释掉下面这行
	# llvm-strip -g $@

# 生成骨架头文件
%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

# 编译用户态程序
$(USER_TARGETS): rootkit.c rootkit.skel.h common.h $(LIBBPF_OBJ)
	$(CC) $(CFLAGS) -o $@ rootkit.c $(LIBBPF_OBJ) $(LDFLAGS)

# 默认目标
all: $(BPF_TARGETS) $(USER_TARGETS)

# 清理目标
clean:
	$(MAKE) -C $(LIBBPF_SRC) clean
	rm -f $(BPF_TARGETS) $(USER_TARGETS) *.skel.h

.PHONY: clean all 