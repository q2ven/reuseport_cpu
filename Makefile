BPFTOOL=bpftool
CC=gcc
ARCH=$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

all: reuseport_cpu

reuseport_cpu: reuseport_cpu.c reuseport_cpu.skel.h
	$(CC) -lbpf reuseport_cpu.c reuseport_cpu.skel.h -o reuseport_cpu

reuseport_cpu.skel.h: reuseport_cpu_bpf.o
	$(BPFTOOL) gen skeleton reuseport_cpu_bpf.o > reuseport_cpu.skel.h

reuseport_cpu_bpf.o: reuseport_cpu.bpf.c vmlinux.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c reuseport_cpu.bpf.c -o reuseport_cpu_bpf.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm reuseport_cpu reuseport_cpu.skel.h reuseport_cpu_bpf.o vmlinux.h
