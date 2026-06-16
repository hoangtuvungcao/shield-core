#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Các thư viện nội bộ
#include "common/types.h"
#include "common/helpers.h"
#include "common/maps.h"
#include "common/rl.h"
#include "common/syncookie.h"
#include "common/routing.h"

#define unlikely(x) __builtin_expect(!!(x), 0)

SEC("xdp")
int xdp_prog_main(struct xdp_md *ctx)
{
    // Bắt đầu đọc packet data
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parsing L2 (Ethernet Header)
    struct ethhdr *eth = data;
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        return XDP_DROP;
    }

    // Shield-Core xử lý IPv4 filtering. IPv6 và ARP được pass-through tới kernel.
    // Điều này đảm bảo kết nối IPv6, ARP, VLAN tagging vẫn hoạt động bình thường.
    if (unlikely(eth->h_proto != bpf_htons(ETH_P_IP)))
    {
        return XDP_PASS; // IPv6, ARP, 802.1Q → kernel stack
    }

    // 2. Parsing L3 (IPv4 Header)
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (unlikely(iph + 1 > (struct iphdr *)data_end))
    {
        return XDP_DROP;
    }
    
    // Cấm IP Options (chỉ cho phép IPv4 Header đúng 20 bytes) để bảo vệ khỏi lỗ hổng parse header
    if (unlikely(iph->ihl != 5)) {
        return XDP_DROP;
    }
    
    // [Early Drop Blacklists] - Chặn sớm trước khi phân tích tiếp
    u32 src_ip = iph->saddr;

    // Tra cứu trong whitelist map
    u64 *whitelisted = bpf_map_lookup_elem(&ip_whitelist_map, &src_ip);
    if (whitelisted) {
        return XDP_PASS;
    }
    
    // Tra cứu trong blacklist map
    u64 *blocked = bpf_map_lookup_elem(&ip_blacklist_map, &src_ip);
    if (blocked) {
        u32 drop_key = 1;
        u64 *drop_stats = bpf_map_lookup_elem(&stats_map, &drop_key);
        if (drop_stats) {
            (*drop_stats)++;
        }
        update_vip_stats(iph->daddr, 1);
        return XDP_DROP;
    }
    
    // Chỉ xử lý TCP, UDP, ICMP và IPIP. Các giao thức khác bỏ qua
    if (iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_ICMP && iph->protocol != IPPROTO_IPIP)
    {
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_IPIP) {
        return decapsulate_ipip(ctx, eth, iph);
    }

    // 3. Parsing L4 (TCP/UDP/ICMP Header)
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;
    
    u8 protocol = iph->protocol;
    u16 dport = 0;

    switch (protocol)
    {
        case IPPROTO_TCP:
            if (unlikely((void *)iph + (iph->ihl * 4) > data_end))
                return XDP_DROP;
            tcph = (void *)iph + (iph->ihl * 4);
            if (unlikely(tcph + 1 > (struct tcphdr *)data_end))
                return XDP_DROP;
            dport = bpf_ntohs(tcph->dest);
            break;

        case IPPROTO_UDP:
            if (unlikely((void *)iph + (iph->ihl * 4) > data_end))
                return XDP_DROP;
            udph = (void *)iph + (iph->ihl * 4);
            if (unlikely(udph + 1 > (struct udphdr *)data_end))
                return XDP_DROP;
            dport = bpf_ntohs(udph->dest);
            break;

        case IPPROTO_ICMP:
            if (unlikely((void *)iph + (iph->ihl * 4) > data_end))
                return XDP_DROP;
            icmph = (void *)iph + (iph->ihl * 4);
            if (unlikely(icmph + 1 > (struct icmphdr *)data_end))
                return XDP_DROP;
            break;
    }

    // [CRITICAL] Bỏ qua toàn bộ GeoIP/RateLimit cho lưu lượng quản trị (SSH và API)
    if (dport == 22 || dport == 9090) {
        return XDP_PASS;
    }

    // Đọc GeoIP Policy từ config_map
    u32 policy_key = 2;
    u64 *policy_val = bpf_map_lookup_elem(&config_map, &policy_key);
    u64 geoip_policy = policy_val ? *policy_val : 0; // 0 = Blacklist (default), 1 = Whitelist (Block all except)

    // Tra cứu trong ASN/Country Blacklist Trie
    struct lpm_trie_key trie_key;
    trie_key.prefix_len = 32;
    trie_key.data = src_ip;

    if (geoip_policy == 0) {
        // Blacklist mode: Nếu có trong map -> DROP
        if (bpf_map_lookup_elem(&asn_blacklist_map, &trie_key) || 
            bpf_map_lookup_elem(&country_blacklist_map, &trie_key)) {
            u32 drop_key = 1;
            u64 *drop_stats = bpf_map_lookup_elem(&stats_map, &drop_key);
            if (drop_stats) (*drop_stats)++;
            update_vip_stats(iph->daddr, 1);
            return XDP_DROP;
        }
    } else {
        // Whitelist mode: Nếu KHÔNG có trong map -> DROP
        if (!bpf_map_lookup_elem(&asn_blacklist_map, &trie_key) && 
            !bpf_map_lookup_elem(&country_blacklist_map, &trie_key)) {
            u32 drop_key = 1;
            u64 *drop_stats = bpf_map_lookup_elem(&stats_map, &drop_key);
            if (drop_stats) (*drop_stats)++;
            update_vip_stats(iph->daddr, 1);
            return XDP_DROP;
        }
    }


    // 4. Các Pipeline sẽ được gắn vào đây:
    
    // [Pipeline 1] L3/L4 Firewall (Blacklist, Rate Limit)
    
    // [Pipeline 1.5] L4 Rate Limiting
    // Áp dụng cho UDP, ICMP và TCP non-SYN (ACK Flood / RST Flood protection)
    // TCP SYN packets được xử lý riêng bởi SYN Cookie phía dưới
    if (protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP) {
        if (dport != 22 && dport != 9090) {
            u16 pkt_len = data_end - data;
            u64 now = bpf_ktime_get_ns();
            
            if (check_rate_limit(src_ip, pkt_len, now) == 1) {
                u32 drop_key = 1;
                u64 *drop_stats = bpf_map_lookup_elem(&stats_map, &drop_key);
                if (drop_stats) {
                    (*drop_stats)++;
                }
                update_vip_stats(iph->daddr, 1);
                return XDP_DROP;
            }
        }
    }

    // [Pipeline 1.6] TCP Flood Protection (Fallback Kernel 5.4)
    // Trên Ubuntu 20.04 (Kernel 5.4), bpf_tcp_gen_syncookie chưa được hỗ trợ.
    // Thay vì SYN Cookie, ta áp dụng Rate Limit cho TOÀN BỘ gói TCP (cả SYN và ACK).
    if (protocol == IPPROTO_TCP && tcph != NULL) {
        if (dport != 22 && dport != 9090) {
            u16 pkt_len = data_end - data;
            u64 now = bpf_ktime_get_ns();
            if (check_rate_limit(src_ip, pkt_len, now) == 1) {
                u32 drop_key = 1;
                u64 *drop_stats = bpf_map_lookup_elem(&stats_map, &drop_key);
                if (drop_stats) {
                    (*drop_stats)++;
                }
                update_vip_stats(iph->daddr, 1);
                return XDP_DROP;
            }
        }
    }

    // [Pipeline 2] Flow Tracking & SYN Cookie - Khôi phục hoạt động cho Kernel 5.15+
    if (protocol == IPPROTO_TCP) {
        if (dport != 22 && dport != 9090) {
            int action = process_tcp_syncookie(ctx, eth, iph, tcph);
            if (action == XDP_TX || action == XDP_DROP) {
                u32 stat_key = 1;
                u64 *stat_val = bpf_map_lookup_elem(&stats_map, &stat_key);
                if (stat_val) (*stat_val)++;
                update_vip_stats(iph->daddr, (action == XDP_DROP) ? 1 : 0);
                return action;
            }
        }
    }
    
    
    // [Pipeline 2.5] Steam A2S Query Cache (L4 Cache)
    if (protocol == IPPROTO_UDP) {
        u8 *pl = (u8 *)udph + sizeof(struct udphdr);
        if (pl + 5 <= (u8 *)data_end) {
            if (pl[0] == 0xFF && pl[1] == 0xFF && pl[2] == 0xFF && pl[3] == 0xFF && pl[4] == 0x54) {
                struct flow info_key = {0};
                info_key.ip = iph->daddr;
                info_key.port = udph->dest;
                info_key.protocol = IPPROTO_UDP;
                a2s_info_val_t *a2s = bpf_map_lookup_elem(&a2s_info, &info_key);
                if (a2s) {
                    u64 now = bpf_ktime_get_ns();
                    u8 expired = (now > a2s->expires);
                    
                    // Điều chỉnh kích thước gói tin bằng adjust_tail
                    u16 pl_len = (u8 *)data_end - pl;
                    if (pl_len < a2s->size + 5) {
                        u16 grow = (a2s->size + 5) - pl_len;
                        if (bpf_xdp_adjust_tail(ctx, (int)grow) != 0) {
                            return XDP_DROP;
                        }
                    } else if (pl_len > a2s->size + 5) {
                        u16 shrink = pl_len - (a2s->size + 5);
                        if (bpf_xdp_adjust_tail(ctx, 0 - (int)shrink) != 0) {
                            return XDP_DROP;
                        }
                    }
                    
                    // Cập nhật lại các con trỏ sau khi adjust_tail
                    data = (void *)(long)ctx->data;
                    data_end = (void *)(long)ctx->data_end;
                    eth = data;
                    if (unlikely(eth + 1 > (struct ethhdr *)data_end)) return XDP_DROP;
                    iph = data + sizeof(struct ethhdr);
                    if (unlikely(iph + 1 > (struct iphdr *)data_end)) return XDP_DROP;
                    udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
                    if (unlikely(udph + 1 > (struct udphdr *)data_end)) return XDP_DROP;
                    
                    pl = (u8 *)udph + sizeof(struct udphdr);
                    // Explicit constant bounds check for the first 5 bytes
                    if (unlikely(pl + 5 > (u8 *)data_end)) return XDP_DROP;
                    
                    pl[0] = 0xFF; pl[1] = 0xFF; pl[2] = 0xFF; pl[3] = 0xFF;
                    pl[4] = expired ? 0x55 : 0x49; // 0x55: Expired (AF_XDP refresh), 0x49: Cached response
                    
                    // Copy dữ liệu cache (Loop bounded cho verifier Kernel 5.4)
                    #pragma clang loop unroll(full)
                    for (int i = 0; i < 512; i++) {
                        if (i >= a2s->size) break;
                        // Per-byte constant bounds check to satisfy old verifier
                        if (unlikely(pl + 5 + i + 1 > (u8 *)data_end)) break;
                        pl[5 + i] = a2s->data[i];
                    }
                    
                    // Hoán đổi MAC (Trực tiếp trên packet memory để tránh verifier errors)
                    u8 tmp_mac;
                    #pragma clang loop unroll(full)
                    for (int i = 0; i < ETH_ALEN; i++) {
                        tmp_mac = eth->h_source[i];
                        eth->h_source[i] = eth->h_dest[i];
                        eth->h_dest[i] = tmp_mac;
                    }
                    // Hoán đổi IP
                    u32 tmp_ip = iph->saddr;
                    iph->saddr = iph->daddr;
                    iph->daddr = tmp_ip;
                    iph->ttl = 64;
                    
                    // Hoán đổi Port
                    u16 tmp_port = udph->source;
                    udph->source = udph->dest;
                    udph->dest = tmp_port;
                    
                    udph->len = bpf_htons(sizeof(struct udphdr) + a2s->size + 5);
                    udph->check = 0; // Checksum sẽ được tính lại ở card mạng hoặc user-space
                    
                    iph->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct udphdr) + a2s->size + 5);
                    iph->check = 0;
                    update_iph_checksum(iph, data_end);
                    
                    if (expired) {
                        u32 qid = ctx->rx_queue_index;
                        void *xsk = bpf_map_lookup_elem(&xsks_map, &qid);
                        if (xsk) {
                            return bpf_redirect_map(&xsks_map, qid, 0);
                        }
                        // Fail-safe: Nếu user-space fastpath sập, phục vụ luôn cache cũ
                        expired = 0;
                    }
                    
                    update_vip_stats(iph->daddr, 0);
                    return XDP_TX;
                }
            }
        }
    }

    // [Pipeline 3] Forwarding Engine (IPIP / GRE)
    // Gói tin đã vượt qua mọi firewall filter (Blacklist, Rate Limit, SYN Cookie)
    // là gói tin sạch. Giờ ta đóng gói lại và chuyển cho backend server thật.
    u32 original_vip = iph->daddr;
    int forward_action = encapsulate_ipip(ctx, eth, iph);
    if (forward_action == XDP_TX || forward_action == XDP_DROP) {
        update_vip_stats(original_vip, (forward_action == XDP_DROP) ? 1 : 0);
        return forward_action;
    }

    // Mặc định cho qua nếu không dính rule nào
    update_vip_stats(original_vip, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
