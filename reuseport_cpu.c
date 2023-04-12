// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "reuseport_cpu.skel.h"

#define PORT_START	10000

struct worker {
	struct reuseport_cpu_bpf *skel;
	int cpu;
	int fd;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int set_affinity(int cpu)
{
	cpu_set_t cpu_set;
	int err;

	CPU_ZERO(&cpu_set);
	CPU_SET(cpu, &cpu_set);

	err = sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);
	if (err)
		fprintf(stderr, "CPU[%02d]: Failed to set CPU affinity\n", cpu);

	return err;
}

static int create_socket(int cpu, int port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	int fd, err;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		fprintf(stderr, "CPU[%02d]: Failed to create a socket\n", cpu);
		return -1;
	}

	err = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int));
	if (err) {
		fprintf(stderr, "CPU[%02d]: Failed to set SO_REUSEPORT\n", cpu);
		goto close;
	}

	addr.sin_port = htons(port);

	err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (err) {
		fprintf(stderr, "CPU[%02d]: Failed to bind a socket\n", cpu);
		goto close;
	}

	return fd;

close:
	close(fd);

	return err;
}

static int update_reuseport_map(struct worker *worker)
{
	int map_fd, err;

	map_fd = bpf_map__fd(worker->skel->maps.reuseport_map);

	err = bpf_map_update_elem(map_fd, &worker->cpu, &worker->fd, BPF_NOEXIST);
	if (err)
		fprintf(stderr, "CPU[%02d]: Failed to update BPF map", worker->cpu);

	return err;
}

struct worker *setup_worker(struct reuseport_cpu_bpf *skel, int cpu)
{
	struct worker *worker;
	int err;

	/* Bind process on a single CPU */
	err = set_affinity(cpu);
	if (err)
		goto err;

	worker = malloc(sizeof(struct worker));
	if (!worker) {
		fprintf(stderr, "CPU[%02d]: Failed to allocate memory\n", cpu);
		goto err;
	}

	/* Listen on port PORT_START */
	worker->fd = create_socket(cpu, PORT_START);
	if (worker->fd < 0)
		goto free;

	worker->skel = skel;
	worker->cpu = cpu;

	/* Update BPF map like: map[cpu_id] = socket_fd */
	err = update_reuseport_map(worker);
	if (err)
		goto close;

	return worker;

close:
	close(worker->fd);
free:
	free(worker);
err:
	return NULL;
}

static void teardown_worker(struct worker *worker)
{
	close(worker->fd);
	free(worker);
}

static int run_worker(struct reuseport_cpu_bpf *skel, int cpu)
{
	struct sockaddr_in addr;
	struct worker *worker;
	socklen_t addrlen;
	char buf[1024];
	int err;

	worker = setup_worker(skel, cpu);
	if (!worker)
		return -1;

	while (1) {
		err = recvfrom(worker->fd, buf, 1024, 0, (struct sockaddr *)&addr, &addrlen);
		if (err < 0)
			break;

		fprintf(stdout, "CPU[%02d]: Received data: %s\n", worker->cpu, buf);
	}

	teardown_worker(worker);

	return 0;
}

static int run_workers(struct reuseport_cpu_bpf *skel)
{
	int nr_cpu, i;
	pid_t pid;

	nr_cpu = libbpf_num_possible_cpus();

	for (i = 0; i < nr_cpu; i++) {
		pid = fork();

		if (pid < 0) {
			fprintf(stderr, "Failed to create %dth child\n", i);
			nr_cpu = i;
			break;
		}

		if (pid == 0)
			return run_worker(skel, i);
	}

	return nr_cpu;
}

static int wait_workers(int nr_worker)
{
	int i, wstatus;

	for (i = 0; i < nr_worker; i++)
		wait(&wstatus);
}

static int attach_reuseport_prog(struct reuseport_cpu_bpf *skel)
{
	int fd, prog_fd, err;

	/* We do not insert this socket into BPF map, but we use
	 * this socket to attach BPF prog to sockets listening on
	 * port 10000.  We can close this socket if there is alive
	 * socket, but we keep it open to avoid checking that.
	 */
	fd = create_socket(-1, PORT_START);
	if (fd < 0)
		return -1;

	prog_fd = bpf_program__fd(skel->progs.migrate_reuseport);

	err = setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd));
	if (err) {
		fprintf(stderr, "Failed to attach BPF prog\n");
		close(fd);
		return err;
	}

	return fd;
}

int main(int argc, char **argv)
{
	struct reuseport_cpu_bpf *skel;
	int err, nr_worker, fd;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = reuseport_cpu_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return -1;
	}

	/* Load & verify BPF programs */
	err = reuseport_cpu_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Run workers on each CPU */
	nr_worker = run_workers(skel);
	if (!nr_worker)
		goto cleanup;

	/* Attach BPF program to reuseport group */
	fd = attach_reuseport_prog(skel);
	if (fd < 0)
		goto cleanup;

	wait_workers(nr_worker);

	close(fd);

cleanup:
	reuseport_cpu_bpf__destroy(skel);

	return err;
}
