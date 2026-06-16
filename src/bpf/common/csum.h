#pragma once

#include "all.h"

#include <stdint.h>
#include <linux/ip.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "helpers.h"

static __always_inline u16 csum_fold_helper(u32 csum);
static __always_inline u32 csum_add(u32 add_end, u32 csum);
static __always_inline u32 csum_sub(u32 add_end, u32 csum);
static __always_inline void update_iph_checksum(struct iphdr *iph, void *data_end);
static __always_inline u16 csum_diff4(u32 from, u32 to, u16 csum);

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "csum.c"