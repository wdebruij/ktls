/*
 * Copyright (C) 2020 Google LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/bpf.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

char _license[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") sock_map = {
	.type = BPF_MAP_TYPE_SOCKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 2,
};

struct bpf_map_def SEC("maps") sock_map_tx = {
	.type = BPF_MAP_TYPE_SOCKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1,
};

SEC("prog_parser")
int _prog_parser(struct __sk_buff *skb)
{
	char debug_msg[] = "[_,_] prog_parser called\n";
	long headlen = skb->data_end - skb->data;
	void *data, *data_end;
	char *d;

	if (bpf_skb_pull_data(skb, skb->len))
		return SK_DROP;

	data = (void *)(long) skb->data;
	data_end = (void *)(long) skb->data_end;
	d = data;

	if (data_end >= data + 1) {
		debug_msg[1] = d[0];
		d[0]++;
		debug_msg[3] = d[0];
	}

	bpf_trace_printk(debug_msg, sizeof(debug_msg));
	return skb->len;
}

SEC("prog_verdict")
int _prog_verdict(struct __sk_buff *skb)
{
	char debug_msg[] = "[_,_] prog_parser verdict\n";
	uint32_t key;

	if (skb->local_port == 8000)
		key = 1;
	else
		key = 0;

	bpf_trace_printk(debug_msg, sizeof(debug_msg));
	return bpf_sk_redirect_map(skb, &sock_map, key, 0);
}

SEC("prog_cgroup_sockops")
int _prog_cgroup_sockops(struct bpf_sock_ops *ops)
{
	if (ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
	    ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
		uint32_t key = 0;

		bpf_sock_map_update(ops, &sock_map_tx, &key, BPF_NOEXIST);
	}

	return 1;
}

SEC("prog_skmsg")
int _prog_skmsg(struct sk_msg_md *msg)
{
	char debug_msg[] = "[_,_] skmsg called\n";
	void *data, *data_end;
	uint32_t key;
	char *d;

	data = (void *)(long) msg->data;
	data_end = (void *)(long) msg->data_end;
	d = data;

	if (data_end < data + 1)
		return SK_DROP;

	key = d[0] == 'a' ? 1 : 0;

	debug_msg[1] = d[0];
	d[0]++;
	debug_msg[3] = d[0];

	bpf_trace_printk(debug_msg, sizeof(debug_msg));
	return bpf_msg_redirect_map(msg, &sock_map, key, 0);
}

