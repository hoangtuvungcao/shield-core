#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "types.h"

// -------------------------------------------------------------
// [MAP 0]: CIDR Blacklist Map
// Lưu trữ các dải IP và Quốc Gia bị chặn vĩnh viễn (LPM Trie)
// -------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, lpm_trie_key_t);
    __type(value, u64); // Unix timestamp block
    __uint(max_entries, 524288);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cidr_blacklist_map SEC(".maps");

// -------------------------------------------------------------
// [MAP 1]: CIDR Whitelist Map
// Lưu trữ các dải IP và Quốc Gia được phép bypass rate limit
// -------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, lpm_trie_key_t);
    __type(value, u64); // Unix timestamp
    __uint(max_entries, 524288);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cidr_whitelist_map SEC(".maps");

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

struct backend_key {
    __u32 vip;
    __u16 vport;     // Cổng frontend (network byte order), nếu 0 tức là áp dụng cho mọi cổng
    __u8 protocol;   // Giao thức (IPPROTO_TCP/UDP), nếu 0 tức là áp dụng cho mọi giao thức
    __u8 pad;
};

struct backend_info {
    __u32 ip;
    __u16 port;      // Cổng backend (network byte order), nếu 0 tức là giữ nguyên cổng gốc
    __u8 type;       // 0 = IPIP, 1 = WireGuard (DNAT)
    __u8 pad;
};

// -------------------------------------------------------------
// [MAP 3]: Routing Table
// Ánh xạ Frontend VIP/Port tới Backend IP/Port/Info
// Key: struct backend_key
// Value: struct backend_info
// -------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct backend_key);
    __type(value, struct backend_info);
    __uint(max_entries, 1024);
} backend_map SEC(".maps");


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
// Key 0: PPS Threshold, Key 1: BPS Threshold, Key 2: GeoIP Policy (0: Default Pass/Blacklist, 1: Default Drop/Whitelist)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 4);
} config_map SEC(".maps");

// [MAP 11]: AF_XDP Ring Stats Map
// Do Fastpath cập nhật định kỳ, Go Control Plane đọc để tính Ring Pressure
// Key: 0
// Value: ring_stats_t
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, ring_stats_t);
    __uint(max_entries, 1);
} ring_stats_map SEC(".maps");


// [MAP 12]: Local Ports Map
// Bypass Rate Limit/GeoIP for local administration ports like 22, 9090
// Key: dport (u16)
// Value: Bypass Action (u8)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u16);
    __type(value, u8);
    __uint(max_entries, 1024);
} local_ports_map SEC(".maps");
