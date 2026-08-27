#include "../packet.h"
#include <bpf/bpf_helpers.h>
#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

static __always_inline bool allow_port(__u16 p)
{
    return p == 11211 || p == 5201 || p == 12865 || p == 5202 || p == 12866;
}

static __always_inline int allow_packet(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u16 hproto = bpf_ntohs(eth->h_proto);

    if (hproto == ETH_P_ARP)
        return XDP_PASS;

    if (hproto != ETH_P_IP)
        return XDP_DROP;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    if (ip->protocol == IPPROTO_ICMP)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;
        __u16 sport = bpf_ntohs(tcp->source);
        __u16 dport = bpf_ntohs(tcp->dest);
        if (allow_port(sport) || allow_port(dport))
            return XDP_PASS;
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_UDP) {
        return XDP_PASS;
    }

    return XDP_DROP;
}

SEC("xdp")
int packet_filter_mb(struct xdp_md *ctx)
{
    return allow_packet(ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
