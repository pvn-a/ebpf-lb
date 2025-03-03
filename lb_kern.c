#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

// Define BPF maps
BPF_ARRAY(backend_ips, u32, 2); // Array to store backend IPs
BPF_ARRAY(backend_macs, u64, 2);
BPF_ARRAY(client_lb_ips, u32, 2); // Array to store backend IPs
BPF_ARRAY(client_lb_macs, u64, 2);
// Define a devmap with 2 entries (one for each backend)
// BPF_DEVMAP(dev_map, 3);
BPF_ARRAY(dev_map, u32, 3);


BPF_ARRAY(rr_index, u32, 1);    // Single-element array for round-robin index

static __always_inline __u16 csum_fold_helper(__u64 csum) {
int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph) {
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

int xdp_load_balancer(struct xdp_md *ctx) {
    bpf_trace_printk("Got something ----");
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
    bpf_trace_printk("Got something 1 ----");

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) 
        return XDP_PASS;
    bpf_trace_printk("Got something 2 ----");

    if (ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    bpf_trace_printk("Original client Packet: source IP: %x, dest IP: %x", ip->saddr, ip->daddr);
    bpf_trace_printk("Printing mac address of source - before modification");
    bpf_trace_printk("0-%x, 1-%x, 2-%x", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
    bpf_trace_printk("3-%x, 4-%x, 5-%x", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    bpf_trace_printk("Printing mac address of dest - before modification");
    bpf_trace_printk("0-%x, 1-%x, 2-%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
    bpf_trace_printk("3-%x, 4-%x, 5-%x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    // Retrieve round-robin index
    u32 index_key = 0;
    u32 *index = rr_index.lookup(&index_key);
    if (!index) return XDP_PASS;

    // Retrieve backend IP from the round-robin index
    u32 backend_key = *index;
    u32 *backend_ip = backend_ips.lookup(&backend_key);
    u64 *backend_mac = backend_macs.lookup(&backend_key);

    u32 zero_index = 0;
    u32 one_index = 1;
    u32 two_index = 2;
    u32 *client_ip = client_lb_ips.lookup(&zero_index);
    u64 *client_mac = client_lb_macs.lookup(&zero_index);
    u32 *backend_one_ip = backend_ips.lookup(&zero_index);
    u32 *backend_two_ip = backend_ips.lookup(&one_index);
    u64 *backend_one_mac = backend_macs.lookup(&zero_index);
    u64 *backend_two_mac = backend_macs.lookup(&one_index);

    u32 *backend_veth_index = dev_map.lookup(&backend_key);
    u32 *client_veth_index = dev_map.lookup(&two_index);

    u32 *lb_ip = client_lb_ips.lookup(&one_index);
    u64 *lb_mac = client_lb_macs.lookup(&one_index);

    if (!client_ip || !client_mac || !lb_ip || !lb_mac) {
        bpf_trace_printk("Failed to retrieve client or LB data from maps");
        return XDP_PASS;
    }

    if (!backend_ip || !backend_mac || !backend_one_ip || !backend_two_ip || !backend_veth_index || !client_veth_index) 
        return XDP_PASS;
    
    bpf_trace_printk("Printing IPs -- clientIP: %x, lbIP: %x", *client_ip, *lb_ip);
    bpf_trace_printk("Printing IPs -- backendIP1: %x, backendIP2: %x", *backend_one_ip, *backend_two_ip);
    bpf_trace_printk("Current index: %d\n", *index);

    // Increment the round-robin index
    // *index = (*index + 1) % 2;
    // rr_index.update(&index_key, index);

    if (ip->saddr == *client_ip && ip->daddr == *lb_ip) {
        bpf_trace_printk("Got : SRC - client, DEST - LB");
        bpf_trace_printk("Now : SRC - lb, DEST - backend");
        ip->daddr = *backend_ip;
        __builtin_memcpy(eth->h_dest, backend_mac, ETH_ALEN);
        ip->saddr = *lb_ip;
        __builtin_memcpy(eth->h_source, lb_mac, ETH_ALEN);
        ip->check = 0;
        ip->check = iph_csum(ip);
        // return XDP_TX;
        // __u32 if_index = 2;
        bpf_trace_printk("Packet modified: source IP: %x, dest IP: %x", ip->saddr, ip->daddr);
        bpf_trace_printk("Printing mac address of source - after modification");
        bpf_trace_printk("0-%x, 1-%x, 2-%x", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
        bpf_trace_printk("3-%x, 4-%x, 5-%x ", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        bpf_trace_printk("Printing mac address of dest - after modification");
        bpf_trace_printk("0-%x, 1-%x, 2-%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
        bpf_trace_printk("3-%x, 4-%x, 5-%x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        bpf_trace_printk("Backend veth index - %x", *backend_veth_index);
        // return bpf_redirect(*backend_veth_index, 0);
        *index = (*index + 1) % 2;
        rr_index.update(&index_key, index);
        return XDP_TX;
    } else if ((ip->saddr == *backend_one_ip || ip->saddr == *backend_two_ip) && ip->daddr == *lb_ip) {
        bpf_trace_printk("Got : SRC - backend, DEST - LB");
        bpf_trace_printk("Now : SRC - LB, DEST - client");
        ip->saddr = *lb_ip;
        __builtin_memcpy(eth->h_source, lb_mac, ETH_ALEN);
        ip->daddr = *client_ip;
        __builtin_memcpy(eth->h_dest, client_mac, ETH_ALEN);
        ip->check = 0;
        ip->check = iph_csum(ip);
        // return XDP_TX;
        bpf_trace_printk("Packet modified: source IP: %x, dest IP: %x", ip->saddr, ip->daddr);
        bpf_trace_printk("Printing mac address of source - after modification");
        bpf_trace_printk("0-%x, 1-%x, 2-%x", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
        bpf_trace_printk("3-%x, 4-%x, 5-%x ", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        bpf_trace_printk("Printing mac address of dest - after modification");
        bpf_trace_printk("0-%x, 1-%x, 2-%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
        bpf_trace_printk("3-%x, 4-%x, 5-%x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        bpf_trace_printk("Client veth index - %x", *client_veth_index);
        // return bpf_redirect(*client_veth_index, 0);
        //     *index = (*index + 1) % 2;
        // rr_index.update(&index_key, index);
        return XDP_TX;
    }

    return XDP_PASS; // Forward the packet
}
