#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "types.h"
#include "maps.h"

static __always_inline int check_rate_limit(u32 ip, u16 pkt_len, u64 now)
{
    cl_stats_t* stats = bpf_map_lookup_elem(&ip_stats_map, &ip);

    // Đọc cấu hình ngưỡng động từ config_map (Single Source of Truth)
    u32 pps_key = 0;
    u32 bps_key = 1;
    u64 *pps_limit = bpf_map_lookup_elem(&config_map, &pps_key);
    u64 *bps_limit = bpf_map_lookup_elem(&config_map, &bps_key);

    u64 max_pps = pps_limit ? *pps_limit : 10000;              // Mặc định fallback 10k PPS
    u64 max_bps = bps_limit ? *bps_limit : (10 * 1024 * 1024); // Mặc định fallback 10MB/s

    if (stats)
    {
        // Reset bộ đếm nếu đã qua chu kỳ 1 giây
        if (now > stats->next_update)
        {
            stats->pps = 1;
            stats->bps = pkt_len;
            stats->next_update = now + NANO_TO_SEC;
        }
        else
        {
            stats->pps++;
            stats->bps += pkt_len;
        }

        // Bị Rate Limit nếu vượt ngưỡng PPS hoặc BPS
        if (stats->pps > max_pps || stats->bps > max_bps) {
            return 1; // Drop
        }
    }
    else
    {
        // Lần đầu thấy IP này, khởi tạo bộ đếm mới
        cl_stats_t new_stats = {0};
        new_stats.pps = 1;
        new_stats.bps = pkt_len;
        new_stats.next_update = now + NANO_TO_SEC;

        bpf_map_update_elem(&ip_stats_map, &ip, &new_stats, BPF_ANY);
    }

    return 0; // Pass
}
