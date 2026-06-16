#pragma once

// ====================================================
// Shield-Core XDP Configuration
// ====================================================

// Bật/tắt tính năng IP Range Drop (LPM Trie đã thay thế)
// #define ENABLE_IP_RANGE_DROP

// Ngưỡng tối đa số interfaces có thể gắn XDP
#define MAX_INTERFACES 6

// Cấu hình XDP Multi-program chaining
#define XDP_MULTIPROG_ENABLED 1
#define XDP_MULTIPROG_PRIORITY 10
#define XDP_MULTIPROG_ACTION XDP_PASS