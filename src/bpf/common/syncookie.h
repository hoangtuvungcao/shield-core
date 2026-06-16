#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "types.h"
#include "csum.h" // Sử dụng csum.h từ dự án proxy cũ

static __always_inline void swap_mac_addresses(struct ethhdr *eth) {
    u8 tmp_mac;
    #pragma clang loop unroll(full)
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp_mac = eth->h_source[i];
        eth->h_source[i] = eth->h_dest[i];
        eth->h_dest[i] = tmp_mac;
    }
}

static __always_inline void swap_ipv4_addresses(struct iphdr *iph) {
    u32 tmp = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp;
}

static __always_inline void swap_tcp_ports(struct tcphdr *tcph) {
    u16 tmp = tcph->source;
    tcph->source = tcph->dest;
    tcph->dest = tmp;
}

static __always_inline int process_tcp_syncookie(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph, struct tcphdr *tcph)
{
    // 1. Nếu là gói SYN (Không có ACK) -> Ta tự động gửi lại SYN-ACK chứa Cookie
    if (tcph->syn && !tcph->ack) {
        struct bpf_sock_tuple tuple = {};
        tuple.ipv4.saddr = iph->saddr;
        tuple.ipv4.daddr = iph->daddr;
        tuple.ipv4.sport = tcph->source;
        tuple.ipv4.dport = tcph->dest;
        
        struct bpf_sock *sk = bpf_skc_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
        if (!sk) return XDP_PASS;
        
        // Sinh cookie sử dụng tính năng native của Kernel (yêu cầu Kernel 5.8+)
        s64 cookie = bpf_tcp_gen_syncookie(sk, iph, sizeof(*iph), tcph, sizeof(*tcph));
        bpf_sk_release(sk);
        
        if (cookie < 0) return XDP_DROP; // Bị lỗi sinh cookie

        // Đổi hướng gói tin (Phản hồi lại Attacker/Client)
        swap_mac_addresses(eth);
        swap_ipv4_addresses(iph);
        swap_tcp_ports(tcph);

        // Biến gói SYN thành SYN-ACK
        tcph->ack = 1;
        tcph->ack_seq = bpf_htonl(bpf_ntohl(tcph->seq) + 1);
        tcph->seq = bpf_htonl((u32)cookie);

        // Tính lại IP checksum
        iph->ttl = 64;
        iph->check = 0;
        update_iph_checksum(iph, (void *)(long)ctx->data_end);

        // Tính lại TCP checksum (bắt buộc sau khi thay đổi seq/ack/flags/IP/port)
        tcph->check = 0;
        u32 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl * 4);
        u32 csum = 0;
        // Pseudo-header: src_ip + dst_ip + reserved + protocol + tcp_length
        csum += (iph->saddr >> 16) + (iph->saddr & 0xFFFF);
        csum += (iph->daddr >> 16) + (iph->daddr & 0xFFFF);
        csum += bpf_htons(IPPROTO_TCP);
        csum += bpf_htons(tcp_len);
        // TCP header + payload checksum
        u16 *tcp_ptr = (u16 *)tcph;
        void *data_end_ptr = (void *)(long)ctx->data_end;
        #pragma clang loop unroll(full)
        for (int i = 0; i < 30; i++) {
            if ((void *)(tcp_ptr + 1) > data_end_ptr) break;
            csum += *tcp_ptr;
            tcp_ptr++;
        }
        // Fold 32-bit sum to 16-bit
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        tcph->check = ~((u16)csum);

        return XDP_TX;
    }
    
    // 2. Nếu là gói ACK (Không có SYN) -> Kiểm tra xem cookie có đúng không
    if (tcph->ack && !tcph->syn) {
        struct bpf_sock_tuple tuple = {};
        tuple.ipv4.saddr = iph->saddr;
        tuple.ipv4.daddr = iph->daddr;
        tuple.ipv4.sport = tcph->source;
        tuple.ipv4.dport = tcph->dest;
        
        struct bpf_sock *sk = bpf_skc_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
        if (!sk) return XDP_PASS;

        // Nếu socket đã thiết lập kết nối (không ở trạng thái LISTEN), cho qua trực tiếp
        if (sk->state != 10) { // 10 là BPF_TCP_LISTEN
            bpf_sk_release(sk);
            return XDP_PASS;
        }

        int ret = bpf_tcp_check_syncookie(sk, iph, sizeof(*iph), tcph, sizeof(*tcph));
        bpf_sk_release(sk);

        if (ret == 0) {
            // Cookie hợp lệ -> Client thật -> Cho phép gói tin đi tiếp vào Kernel
            return XDP_PASS;
        } else {
            // Cookie không hợp lệ (Spoofed IP) -> Rớt
            return XDP_DROP;
        }
    }

    // Các TCP flag khác cho qua để Linux Kernel TCP Stack xử lý tiếp
    return XDP_PASS;
}

