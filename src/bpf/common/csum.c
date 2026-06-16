static __always_inline u16 csum_fold_helper(u32 csum) 
{
    u32 r = csum << 16 | csum >> 16;
    csum = ~csum;
    csum -= r;

    return (u16)(csum >> 16);
}

static __always_inline u32 csum_add(u32 add_end, u32 csum) 
{
    u32 res = csum;
    res += add_end;

    return (res + (res < add_end));
}

static __always_inline u32 csum_sub(u32 add_end, u32 csum) 
{
    return csum_add(csum, ~add_end);
}

static __always_inline void update_iph_checksum(struct iphdr *iph, void *data_end) 
{
    u16 *next_iph_u16 = (u16 *)iph;
    u32 csum = 0;
    iph->check = 0;
    
    // Đã cấm iph->ihl != 5 ở đầu file, nên IP header luôn có độ dài 20 bytes.
    #pragma clang loop unroll(full)
    for (u32 i = 0; i < 10; i++)
    {
        csum += *next_iph_u16++;
    }

    iph->check = ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline u16 csum_diff4(u32 from, u32 to, u16 csum) 
{
    u32 tmp = csum_sub(from, ~((u32)csum));

    return csum_fold_helper(csum_add(to, tmp));
}
