// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2018 Netronome Systems, Inc.

#include <stdbool.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "xdpdump_common.h"

struct bpf_map_def SEC("maps") perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = MAX_CPU,
};

static __always_inline bool parse_udp(void *data, __u64 off, void *data_end,
				      struct pkt_meta *pkt)
{
	struct udphdr *udp;

	udp = data + off;
	if (udp + 1 > data_end)
		return false;

	pkt->port16[0] = udp->source;
	pkt->port16[1] = udp->dest;
	return true;
}

static __always_inline bool parse_tcp(void *data, __u64 off, void *data_end,
				      struct pkt_meta *pkt)
{
	struct tcphdr *tcp;

	tcp = data + off;
	if (tcp + 1 > data_end)
		return false;

	pkt->port16[0] = tcp->source;
	pkt->port16[1] = tcp->dest;
	pkt->seq = tcp->seq;

	return true;
}

static __always_inline bool parse_ip4(void *data, __u64 off, void *data_end,
				      struct pkt_meta *pkt)
{
	struct iphdr *iph;

	iph = data + off;
	if (iph + 1 > data_end)
		return false;

	if (iph->ihl != 5)
		return false;

	pkt->src = iph->saddr;
	pkt->dst = iph->daddr;
	pkt->l4_proto = iph->protocol;

	return true;
}

static __always_inline bool parse_ip6(void *data, __u64 off, void *data_end,
				      struct pkt_meta *pkt)
{
	struct ipv6hdr *ip6h;

	ip6h = data + off;
	if (ip6h + 1 > data_end)
		return false;

	memcpy(pkt->srcv6, ip6h->saddr.s6_addr32, 16);
	memcpy(pkt->dstv6, ip6h->daddr.s6_addr32, 16);
	pkt->l4_proto = ip6h->nexthdr;

	return true;
}

#ifdef  __ACTION_TX__
static __always_inline void swap_mem(void *a, void *b, int len)
{
	int i;
	char c;

	for (i = 0; i < len; i++) {
		c = ((char *)a)[i];
		((char *)a)[i] = ((char *)b)[i];
		((char *)b)[i] = c;
	}
}

static __always_inline void ip_csum(struct iphdr *iph)
{
	int i;
	__u32 csum = 0;

	iph->check = 0;

	for (i = 0; i < (int)sizeof(*iph) >> 1; i++)
                csum += ((__u16 *)iph)[i];

	iph->check = ~((csum & 0xffff) + (csum >> 16));
}

struct icmphdr {
  __u8          type;
  __u8          code;
  __sum16       checksum;
  union {
        struct {
                __be16  id;
                __be16  sequence;
        } echo;
        __be32  gateway;
        struct {
                __be16  __unused;
                __be16  mtu;
        } frag;
        __u8    reserved[4];
  } un;
};

static __always_inline int ping_reply(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *iph = (struct iphdr *)(eth + 1);
	struct icmphdr *icmph = (struct icmphdr *)(iph + 1);

	if (icmph + 1 > data_end || icmph->type == 0)
		return XDP_PASS;

	swap_mem(eth->h_dest, eth->h_source, ETH_ALEN);

	iph->id = 0;
	iph->frag_off = 0;
	swap_mem(&iph->saddr, &iph->daddr, 4);
	ip_csum(iph);

	icmph->type = 0;
	icmph->checksum += 8;

	return XDP_TX;
}
#endif

SEC("xdp")
int process_packet(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct pkt_meta pkt = {};
	__u32 off;

	/* parse packet for IP Addresses and Ports */
	off = sizeof(struct ethhdr);
	if (data + off > data_end)
		return XDP_PASS;

	pkt.l3_proto = bpf_htons(eth->h_proto);

	if (pkt.l3_proto == ETH_P_IP) {
		if (!parse_ip4(data, off, data_end, &pkt))
			return XDP_PASS;
		off += sizeof(struct iphdr);
	} else if (pkt.l3_proto == ETH_P_IPV6) {
		if (!parse_ip6(data, off, data_end, &pkt))
			return XDP_PASS;
		off += sizeof(struct ipv6hdr);
	}

	if (data + off > data_end)
		return XDP_PASS;

	/* obtain port numbers for UDP and TCP traffic */
	if (pkt.l4_proto == IPPROTO_TCP) {
		if (!parse_tcp(data, off, data_end, &pkt))
			return XDP_PASS;
		off += sizeof(struct tcphdr);
	} else if (pkt.l4_proto == IPPROTO_UDP) {
		if (!parse_udp(data, off, data_end, &pkt))
			return XDP_PASS;
		off += sizeof(struct udphdr);
	} else {
		pkt.port16[0] = 0;
		pkt.port16[1] = 0;
	}

	pkt.pkt_len = data_end - data;
	pkt.data_len = data_end - data - off;

	#ifndef __PERF__
	bpf_perf_event_output(ctx, &perf_map,
			      (__u64)pkt.pkt_len << 32 | BPF_F_CURRENT_CPU,
			      &pkt, sizeof(pkt));
	#endif
	#ifdef __PERF_DROP__
	if (pkt.l3_proto == ETH_P_IP && pkt.l4_proto == IPPROTO_UDP)
		return XDP_DROP;
	#endif
	#ifdef __ACTION_DROP__
	if (pkt.l3_proto == ETH_P_IP && pkt.l4_proto == IPPROTO_ICMP)
		return XDP_DROP;
	#endif
	#ifdef __ACTION_ABORTED__
	if (pkt.l3_proto == ETH_P_IP && pkt.l4_proto == IPPROTO_ICMP)
		return XDP_ABORTED;
	#endif
	#ifdef __ACTION_TX__
	if (pkt.l3_proto == ETH_P_IP && pkt.l4_proto == IPPROTO_ICMP)
		return ping_reply(ctx);
	#endif
	return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
