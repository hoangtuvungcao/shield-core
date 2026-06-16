#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "types.h"
#include "maps.h"
#include "csum.h"

// IPIP Protocol ID
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif

// Hàm bọc gói tin IPIP để gửi luồng traffic sạch tới Backend
static __always_inline int encapsulate_ipip(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph) {
    if (unlikely(iph->ihl < 5)) return XDP_DROP;
    u32 vip = iph->daddr;
    
    // Tìm thông tin cấu hình Backend (IP & Loại hầm)
    struct backend_info *backend = bpf_map_lookup_elem(&backend_map, &vip);
    if (!backend) {
        // Nếu không có mapping, đẩy lên cho Kernel (chạy mode local) hoặc để cho AF_XDP.
        return XDP_PASS;
    }

    // Nếu Tunnel Type là WireGuard (1), ta KHÔNG bọc IPIP ở XDP.
    // Trả về XDP_PASS để hệ điều hành Linux nhận lấy và dùng iptables DNAT đẩy qua cổng wg0.
    if (backend->type == 1) {
        return XDP_PASS;
    }

    // Bỏ qua đóng gói đối với các cổng quản trị mặc định (22 cho SSH, 9090 cho API)
    // và các cổng đang chạy động được cập nhật qua local_ports_map
    void *data_end = (void *)(long)ctx->data_end;
    u16 dport = 0;
    if (iph->protocol == IPPROTO_TCP) {
        u16 ihl = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr *)((char *)iph + ihl);
        asm volatile("" : "+r"(tcph));
        if (unlikely((void *)tcph + sizeof(struct tcphdr) > data_end)) {
            return XDP_PASS;
        }
        dport = bpf_ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        u16 ihl = iph->ihl * 4;
        struct udphdr *udph = (struct udphdr *)((char *)iph + ihl);
        asm volatile("" : "+r"(udph));
        if (unlikely((void *)udph + sizeof(struct udphdr) > data_end)) {
            return XDP_PASS;
        }
        dport = bpf_ntohs(udph->dest);
    }

    if (dport != 0) {
        // Fallback cứng cổng quản trị
        if (dport == 22 || dport == 9090) {
            return XDP_PASS;
        }
    }

    // 1. Mở rộng khoảng trống 20 bytes (kích thước iphdr) phía trước gói tin hiện tại
    if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct iphdr))) {
        return XDP_DROP; // Bị lỗi không đủ dung lượng headroom
    }

    // 2. Gán lại các con trỏ sau khi adjust_head (bắt buộc vì bộ nhớ đã bị dời)
    void *data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end) return XDP_DROP;

    struct iphdr *outer_iph = (struct iphdr *)(new_eth + 1);
    if ((void *)(outer_iph + 1) > data_end) return XDP_DROP;

    // Ethernet header cũ bị đẩy lùi về sau 20 bytes
    struct ethhdr *old_eth = (struct ethhdr *)((char *)data + sizeof(struct iphdr));
    if ((void *)(old_eth + 1) > data_end) return XDP_DROP;

    // Copy toàn bộ dữ liệu MAC cũ lên header mới
    __builtin_memcpy(new_eth, old_eth, sizeof(struct ethhdr));

    // Lấy Inner IP
    struct iphdr *inner_iph = (struct iphdr *)(outer_iph + 1);
    if ((void *)(inner_iph + 1) > data_end) return XDP_DROP;
    if (unlikely(inner_iph->ihl < 5)) return XDP_DROP;

    // 3. Khởi tạo Outer IP Header (IPIP)
    outer_iph->ihl = 5;
    outer_iph->version = 4;
    outer_iph->tos = 0;
    outer_iph->tot_len = bpf_htons(bpf_ntohs(inner_iph->tot_len) + sizeof(struct iphdr));
    outer_iph->id = 0;
    outer_iph->frag_off = 0;
    outer_iph->ttl = 64;
    outer_iph->protocol = IPPROTO_IPIP;
    
    // Đổi Source/Dest cho outer IP: Tự biến Shield node thành Source, Backend thành Dest
    outer_iph->saddr = inner_iph->daddr; 
    outer_iph->daddr = backend->ip;
    
    outer_iph->check = 0;
    update_iph_checksum(outer_iph, data_end);

    // Tăng bộ đếm cho biết đã chuyển tiếp 1 gói thành công
    u32 stat_key = 0; // PASS/Forward
    u64 *stat_val = bpf_map_lookup_elem(&stats_map, &stat_key);
    if (stat_val) (*stat_val)++;

    // Gửi trực tiếp ngược lại ra card mạng để đi tới Backend Router
    return XDP_TX;
}

// Hàm giải bọc gói tin IPIP nhận từ Backend để trả về cho Client
static __always_inline int decapsulate_ipip(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph) {
    void *data_end = (void *)(long)ctx->data_end;
    
    if (unlikely(iph->ihl < 5)) return XDP_DROP;
    
    // Tìm vị trí của inner IP header dựa trên outer IP header length thực tế
    u16 outer_header_len = iph->ihl * 4;
    if (unlikely((void *)iph + outer_header_len > data_end)) return XDP_DROP;
    
    struct iphdr *inner_iph = (struct iphdr *)((char *)iph + outer_header_len);
    

    if ((void *)(inner_iph + 1) > data_end) return XDP_DROP;
    if (unlikely(inner_iph->ihl < 5)) return XDP_DROP;
    
    u8 redirect = 0;
    
    // Check inner protocol
    if (inner_iph->protocol == IPPROTO_UDP) {
        u16 ihl = inner_iph->ihl * 4;
        if (unlikely((void *)inner_iph + ihl + sizeof(struct udphdr) > data_end)) {
            return XDP_DROP;
        }
        struct udphdr *udph = (void *)inner_iph + ihl;
        
        // Check if it's A2S_INFO response (starts with 0xFF 0xFF 0xFF 0xFF 0x49)
        u8 *pl = (u8 *)udph + sizeof(struct udphdr);
        if (pl + 5 <= (u8 *)data_end) {
            if (pl[0] == 0xFF && pl[1] == 0xFF && pl[2] == 0xFF && pl[3] == 0xFF) {
                if (pl[4] == 0x49) {
                    redirect = 1; // Needs to be cached by AF_XDP
                } else if (pl[4] == 0x41) {
                    // Challenge response: save challenge to a2s_info map directly in XDP
                    struct flow a2s_key = {0};
                    a2s_key.ip = inner_iph->saddr;
                    a2s_key.port = udph->source;
                    a2s_key.protocol = IPPROTO_UDP;
                    a2s_info_val_t *a2s_val = bpf_map_lookup_elem(&a2s_info, &a2s_key);
                    if (a2s_val && pl + 9 <= (u8 *)data_end) {
                        __builtin_memcpy(&a2s_val->challenge, pl + 5, 4);
                        a2s_val->challenge_set = 1;
                    }
                }
            }
        }
    }
    
    // Save Ethernet header to stack securely padded to 16 bytes to prevent Clang 
    // from generating unaligned 8-byte reads that spill over 14 bytes
    u8 tmp_eth_bytes[16] __attribute__((aligned(8))) = {0};
    #pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(struct ethhdr); i++) {
        tmp_eth_bytes[i] = ((u8*)eth)[i];
    }
    
    // Strip outer IP header
    if (bpf_xdp_adjust_head(ctx, (int)outer_header_len)) {
        return XDP_DROP;
    }
    
    // Reinitialize pointers
    void *data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end) return XDP_DROP;
    
    // Copy swapped MAC onto the new ethernet header position
    #pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(struct ethhdr); i++) {
        ((u8*)new_eth)[i] = tmp_eth_bytes[i];
    }

    // Swap MAC directly on packet memory to avoid stack verifier issues
    u8 tmp_mac;
    #pragma clang loop unroll(full)
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp_mac = new_eth->h_source[i];
        new_eth->h_source[i] = new_eth->h_dest[i];
        new_eth->h_dest[i] = tmp_mac;
    }
    
    if (redirect) {
        u32 qid = ctx->rx_queue_index;
        void *xsk = bpf_map_lookup_elem(&xsks_map, &qid);
        if (xsk) {
            return bpf_redirect_map(&xsks_map, qid, 0);
        }
        // Fail-safe: Nếu shield-fastpath không hoạt động, chuyển tiếp thẳng ra ngoài cho Client (XDP_PASS)
        return XDP_PASS;
    }
    
    return XDP_TX;
}

