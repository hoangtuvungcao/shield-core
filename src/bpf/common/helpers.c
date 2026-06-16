/**
 * Checks if an IP is within a specific CIDR range.
 * 
 * @param src_ip The source/main IP to check against.
 * @param net_ip The network IP.
 * @param cidr The CIDR range.
 * 
 * @return 1 on yes, 0 on no.
 */
static __always_inline int is_ip_in_range(u32 src_ip, u32 net_ip, u8 cidr)
{
    return !((src_ip ^ net_ip) & bpf_htonl(0xFFFFFFFFu << (32 - cidr)));
}

static __always_inline void update_vip_stats(u32 vip, u8 dropped) {
    vip_stats_t *stats = bpf_map_lookup_elem(&vip_stats_map, &vip);
    if (stats) {
        if (dropped) {
            __sync_fetch_and_add(&stats->dropped, 1);
        } else {
            __sync_fetch_and_add(&stats->passed, 1);
        }
    } else {
        vip_stats_t new_stats = {0};
        if (dropped) {
            new_stats.dropped = 1;
        } else {
            new_stats.passed = 1;
        }
        bpf_map_update_elem(&vip_stats_map, &vip, &new_stats, BPF_ANY);
    }
}
