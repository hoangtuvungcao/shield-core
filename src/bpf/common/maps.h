#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "types.h"

// -------------------------------------------------------------
// [MAP 1]: L3 IP Blacklist (IPv4)
// Lưu trữ các IP độc hại. Nếu IP có trong map này, lập tức DROP.
// Key: IPv4 Address (u32)
// Value: Block expire timestamp hoặc simply u64 (count/timestamp)
// -------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 65536); // Support up to 64k blocked IPs
} ip_blacklist_map SEC(".maps");

// -------------------------------------------------------------
// [MAP 1.5]: L3 IP Whitelist (IPv4)
// Nếu IP có trong map này, lập tức PASS (bỏ qua mọi rule chặn).
// Key: IPv4 Address (u32)
// Value: u64
// -------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10240); // 10k whitelist IPs
} ip_whitelist_map SEC(".maps");

// -------------------------------------------------------------
// [MAP 2]: Telemetry Stats
// Đếm số lượng packet PASS/DROP cho Dashboard
// -------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 2); // 0: PASS, 1: DROP
} stats_map SEC(".maps");

// -------------------------------------------------------------
// [MAP 3]: IP Rate Limit Stats
// Lưu trữ số PPS/BPS theo từng Source IP để kiểm tra Rate Limit
// Key: IPv4 (u32)
// Value: cl_stats_t (pps, bps, next_update)
// -------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, u32);
    __type(value, cl_stats_t);
    __uint(max_entries, 262144); // Hỗ trợ lưu stats của 256k IPs đồng thời
} ip_stats_map SEC(".maps");

struct backend_info {
    __u32 ip;
    __u8 type; // 0 = IPIP, 1 = WireGuard (DNAT)
};

// -------------------------------------------------------------
// [MAP 3]: Routing Table
// Ánh xạ Frontend VIP tới Backend IP/Info
// Key: Frontend VIP (u32)
// Value: struct backend_info
// -------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct backend_info);
    __uint(max_entries, 1024);
} backend_map SEC(".maps");

// [MAP 4]: Local Ports Map (Cổng đang lắng nghe trên server)
// Key: Port number (u16)
// Value: Active status (u8)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 65536);
} local_ports_map SEC(".maps");

// [MAP 5]: XSK Map
// Key: Queue ID (u32)
// Value: XSK FD (u32)
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 256);
} xsks_map SEC(".maps");

// [MAP 6]: A2S Info Cache
// Key: flow_t (IP, Port, Protocol)
// Value: a2s_info_val_t
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, flow_t);
    __type(value, a2s_info_val_t);
    __uint(max_entries, 1024);
} a2s_info SEC(".maps");

// [MAP 7]: ASN Blacklist Trie Map
// Key: lpm_trie_key_t (prefix_len, data)
// Value: u64 (action / block time)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, lpm_trie_key_t);
    __type(value, u64);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} asn_blacklist_map SEC(".maps");

// [MAP 8]: Country Blacklist Trie Map
// Key: lpm_trie_key_t
// Value: u64
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, lpm_trie_key_t);
    __type(value, u64);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} country_blacklist_map SEC(".maps");

// -------------------------------------------------------------
// [MAP 9]: VIP Stats Map (Multi-tenant Billing)
// Key: VIP (u32)
// Value: vip_stats_t (passed, dropped counters)
// -------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, vip_stats_t);
    __uint(max_entries, 1024);
} vip_stats_map SEC(".maps");

// [MAP 10]: Config Map for dynamic thresholds
// Key 0: PPS Threshold, Key 1: BPS Threshold
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 2);
} config_map SEC(".maps");



