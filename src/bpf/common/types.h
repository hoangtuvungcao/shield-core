#pragma once

#include "int_types.h"

// Struct lưu thông tin thống kê của từng IP
struct cl_stats
{
    u64 pps;
    u64 bps;
    u64 next_update;
} typedef cl_stats_t;

// Struct lưu stats theo VIP khách hàng
struct vip_stats {
    u64 passed;
    u64 dropped;
} typedef vip_stats_t;

// Struct đại diện cho 1 luồng flow (IP, Port, Protocol)
struct flow
{
    u32 ip;
    u16 port;
    u8 protocol;
    u8 pad; // Explicit padding to prevent verifier error
} typedef flow_t;

// Cấu trúc key của LPM Trie map
struct lpm_trie_key
{
    u32 prefix_len;
    u32 data;
} typedef lpm_trie_key_t;

#define MAX_A2S_SIZE 1024

// Cấu trúc lưu thông tin cache phản hồi Steam A2S_INFO
struct a2s_info_val
{
    u16 size;
    u64 expires;
    unsigned char data[MAX_A2S_SIZE];
    unsigned char challenge[4];
    unsigned int challenge_set : 1;
} typedef a2s_info_val_t;