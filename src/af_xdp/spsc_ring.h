#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stdalign.h>

#define SPSC_RING_SIZE 4096 // Phải là lũy thừa của 2

typedef struct {
    uint64_t addr;
    uint32_t len;
} packet_desc_t;

typedef struct {
    packet_desc_t buffer[SPSC_RING_SIZE];
    alignas(64) uint32_t write_idx;
    alignas(64) uint32_t read_idx;
} spsc_ring_t;

static inline void spsc_ring_init(spsc_ring_t *ring) {
    ring->write_idx = 0;
    ring->read_idx = 0;
}

static inline bool spsc_ring_push(spsc_ring_t *ring, packet_desc_t desc) {
    uint32_t w = ring->write_idx;
    uint32_t r = __atomic_load_n(&ring->read_idx, __ATOMIC_ACQUIRE);
    if ((uint32_t)(w - r) >= SPSC_RING_SIZE) {
        return false; // Hàng đợi đầy
    }
    ring->buffer[w & (SPSC_RING_SIZE - 1)] = desc;
    __atomic_store_n(&ring->write_idx, w + 1, __ATOMIC_RELEASE);
    return true;
}

static inline bool spsc_ring_pop(spsc_ring_t *ring, packet_desc_t *desc) {
    uint32_t r = ring->read_idx;
    uint32_t w = __atomic_load_n(&ring->write_idx, __ATOMIC_ACQUIRE);
    if (r == w) {
        return false; // Hàng đợi rỗng
    }
    *desc = ring->buffer[r & (SPSC_RING_SIZE - 1)];
    __atomic_store_n(&ring->read_idx, r + 1, __ATOMIC_RELEASE);
    return true;
}
