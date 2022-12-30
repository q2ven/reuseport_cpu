// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, 256);
	__type(key, int);
	__type(value, int);
} reuseport_map SEC(".maps");

SEC("sk_reuseport/migrate")
int migrate_reuseport(struct sk_reuseport_md *reuse_md)
{
	int cpu = bpf_get_smp_processor_id();
	int err;

	err = bpf_sk_select_reuseport(reuse_md, &reuseport_map, &cpu, 0);

	bpf_printk("err: %d, cpu: %d", err, cpu);

	return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
