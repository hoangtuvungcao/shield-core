#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#include "spsc_ring.h"
#include "dpi.h"
#include <dirent.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE 2048
#define INVALID_UMEM_FRAME ((uint64_t)-1)
#define MAX_CPUS 64

#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif

// Struct lưu thông tin UMEM của một Socket AF_XDP
struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;
};

// Struct lưu thông tin AF_XDP Socket (XSK)
struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    uint32_t outstanding_tx;
};

// Các Struct lưu Key/Value khớp với BPF Maps
struct flow {
    uint32_t ip;
    uint16_t port;
    uint8_t protocol;
} __attribute__((packed));

struct a2s_info_val {
    uint16_t size;
    uint64_t expires;
    unsigned char data[1024];
    unsigned char challenge[4];
    unsigned int challenge_set : 1;
} __attribute__((packed));

// FDs của các BPF Map lấy từ sysfs
static int xsks_map_fd = -1;
static int a2s_info_fd = -1;
static int ip_blacklist_fd = -1;

static volatile int stop = 0;
static char iface_name[IFNAMSIZ] = "lo";
static int num_queues = 1;

// Biến lưu thông tin luồng
typedef struct {
    int queue_id;
    struct xsk_umem_info *umem;
    struct xsk_socket_info *xsk;
    spsc_ring_t rx_ring;
    spsc_ring_t tx_ring;
} thread_ctx_t;

static int numa_cpus[MAX_CPUS];
static int numa_cpus_count = 0;

static int get_num_queues(const char *iface) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/queues", iface);
    DIR *dir = opendir(path);
    if (!dir) return 1;
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "rx-", 3) == 0) {
            count++;
        }
    }
    closedir(dir);
    return count > 0 ? count : 1;
}

static int get_numa_node(const char *iface) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/device/numa_node", iface);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int node = -1;
    if (fscanf(f, "%d", &node) != 1) node = -1;
    fclose(f);
    return node;
}

static int get_numa_cpus(int node, int *cpus, int max_cpus) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/cpulist", node);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[256];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    
    int count = 0;
    char *token = strtok(buf, ", \n");
    while (token && count < max_cpus) {
        int start, end;
        if (sscanf(token, "%d-%d", &start, &end) == 2) {
            for (int c = start; c <= end && count < max_cpus; c++) {
                cpus[count++] = c;
            }
        } else if (sscanf(token, "%d", &start) == 1) {
            cpus[count++] = start;
        }
        token = strtok(NULL, ", \n");
    }
    return count;
}

static thread_ctx_t thread_contexts[MAX_CPUS];

static void signal_handler(int sig) {
    stop = 1;
}

// Hàm giải phóng và quản lý UMEM Frame
static uint64_t xsk_alloc_frame(struct xsk_umem_info *umem) {
    if (umem->umem_frame_free == 0) return INVALID_UMEM_FRAME;
    uint64_t frame = umem->umem_frame_addr[--umem->umem_frame_free];
    umem->umem_frame_addr[umem->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

static void xsk_free_frame(struct xsk_umem_info *umem, uint64_t frame) {
    if (umem->umem_frame_free >= NUM_FRAMES) return;
    umem->umem_frame_addr[umem->umem_frame_free++] = frame;
}

// Cấu hình UMEM
static struct xsk_umem_info *configure_umem(void) {
    struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
    if (!umem) return NULL;

    uint64_t size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&umem->buffer, getpagesize(), size)) {
        free(umem);
        return NULL;
    }

    int ret = xsk_umem__create(&umem->umem, umem->buffer, size, &umem->fq, &umem->cq, NULL);
    if (ret) {
        free(umem->buffer);
        free(umem);
        return NULL;
    }

    for (int i = 0; i < NUM_FRAMES; i++) {
        umem->umem_frame_addr[i] = i * FRAME_SIZE;
    }
    umem->umem_frame_free = NUM_FRAMES;

    return umem;
}

// Cấu hình AF_XDP Socket
static struct xsk_socket_info *configure_socket(struct xsk_umem_info *umem, int queue_id) {
    struct xsk_socket_info *xsk = calloc(1, sizeof(*xsk));
    if (!xsk) return NULL;

    xsk->umem = umem;

    struct xsk_socket_config cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_ZEROCOPY,
    };

    // QUAN TRỌNG: Xóa socket cũ khỏi map (nếu có do crash) để kernel giải phóng tài nguyên, tránh EBUSY
    bpf_map_delete_elem(xsks_map_fd, &queue_id);

    // Thử tạo với Driver Mode và Zero Copy
    int ret = xsk_socket__create(&xsk->xsk, iface_name, queue_id, umem->umem, &xsk->rx, &xsk->tx, &cfg);
    if (ret) {
        // Fallback 1: Driver Mode + Copy Mode
        printf("[AF_XDP Q%d] Zero-Copy không được hỗ trợ, chuyển sang DRV_MODE + COPY...\n", queue_id);
        cfg.bind_flags = XDP_COPY;
        ret = xsk_socket__create(&xsk->xsk, iface_name, queue_id, umem->umem, &xsk->rx, &xsk->tx, &cfg);
    }
    if (ret) {
        // Fallback 2: Generic SKB Mode + Copy Mode
        printf("[AF_XDP Q%d] Driver Mode không được hỗ trợ, fallback về SKB_MODE + COPY...\n", queue_id);
        cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
        cfg.bind_flags = XDP_COPY;
        ret = xsk_socket__create(&xsk->xsk, iface_name, queue_id, umem->umem, &xsk->rx, &xsk->tx, &cfg);
    }

    if (ret) {
        fprintf(stderr, "[AF_XDP Q%d] Lỗi nghiêm trọng: Không thể khởi tạo socket AF_XDP: %d\n", queue_id, ret);
        free(xsk);
        return NULL;
    }

    // Đẩy sẵn Fill Ring
    uint32_t idx = 0;
    ret = xsk_ring_prod__reserve(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret == XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
            *xsk_ring_prod__fill_addr(&umem->fq, idx++) = xsk_alloc_frame(umem);
        }
        xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
    }

    return xsk;
}

// Hoán đổi IP/MAC checksums helper
static inline uint16_t csum_fold(uint32_t csum) {
    uint32_t sum = csum;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static inline uint16_t udp_csum(uint32_t saddr, uint32_t daddr, uint16_t len, uint8_t proto, uint16_t *src) {
    uint32_t sum = 0;
    sum += (saddr & 0xffff) + (saddr >> 16);
    sum += (daddr & 0xffff) + (daddr >> 16);
    sum += htons(proto);
    sum += htons(len);

    int count = len >> 1;
    while (count--) {
        sum += *src++;
    }
    if (len & 1) {
        sum += *(uint8_t *)src;
    }
    return csum_fold(sum);
}

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// IO Thread xử lý nhận/gửi vòng lặp chính
void *io_thread_func(void *arg) {
    thread_ctx_t *ctx = (thread_ctx_t *)arg;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    int core_id = 2 * ctx->queue_id;
    if (numa_cpus_count >= 2) {
        int idx = 2 * (ctx->queue_id % (numa_cpus_count / 2));
        if (idx < numa_cpus_count) {
            core_id = numa_cpus[idx];
        }
    }
    CPU_SET(core_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    struct pollfd fds[1] = {
        {.fd = xsk_socket__fd(ctx->xsk->xsk), .events = POLLIN}
    };

    printf("[IO Thread Q%d] Đang chạy trên CPU %d...\n", ctx->queue_id, 2 * ctx->queue_id);

    uint32_t spin_count = 0;
    const uint32_t SPIN_LIMIT = 10000;

    while (!stop) {
        // 1. Nhận gói tin từ AF_XDP RX ring
        uint32_t idx_rx = 0;
        unsigned int rcvd = xsk_ring_cons__peek(&ctx->xsk->rx, 32, &idx_rx);
        if (rcvd > 0) {
            for (unsigned int i = 0; i < rcvd; i++) {
                uint64_t addr = xsk_ring_cons__rx_desc(&ctx->xsk->rx, idx_rx)->addr;
                uint32_t len = xsk_ring_cons__rx_desc(&ctx->xsk->rx, idx_rx)->len;
                idx_rx++;

                packet_desc_t desc = {.addr = addr, .len = len};
                // Đẩy vào hàng đợi SPSC để Worker xử lý
                if (!spsc_ring_push(&ctx->rx_ring, desc)) {
                    // Nếu hàng đợi đầy, lập tức dọn dẹp và trả frame về
                    xsk_free_frame(ctx->umem, addr);
                }
            }
            xsk_ring_cons__release(&ctx->xsk->rx, rcvd);

            // Refill Fill Ring
            uint32_t idx_fq = 0;
            unsigned int free_frames = ctx->umem->umem_frame_free;
            if (free_frames > 32) {
                unsigned int ret = xsk_ring_prod__reserve(&ctx->umem->fq, 32, &idx_fq);
                if (ret == 32) {
                    for (int j = 0; j < 32; j++) {
                        *xsk_ring_prod__fill_addr(&ctx->umem->fq, idx_fq++) = xsk_alloc_frame(ctx->umem);
                    }
                    xsk_ring_prod__submit(&ctx->umem->fq, 32);
                }
            }
        }

        // 2. Gửi các gói tin từ Worker Thread đẩy về trong tx_ring
        packet_desc_t tx_desc;
        int sent_batch = 0;
        while (spsc_ring_pop(&ctx->tx_ring, &tx_desc)) {
            uint32_t idx_tx = 0;
            if (xsk_ring_prod__reserve(&ctx->xsk->tx, 1, &idx_tx) == 1) {
                struct xdp_desc *tx_ring_desc = xsk_ring_prod__tx_desc(&ctx->xsk->tx, idx_tx);
                tx_ring_desc->addr = tx_desc.addr;
                tx_ring_desc->len = tx_desc.len;
                xsk_ring_prod__submit(&ctx->xsk->tx, 1);
                ctx->xsk->outstanding_tx++;
                sent_batch++;
            } else {
                // Hàng đợi TX đầy, trả frame về
                xsk_free_frame(ctx->umem, tx_desc.addr);
            }
        }

        if (sent_batch > 0) {
            // Wakeup socket
            if (xsk_ring_prod__needs_wakeup(&ctx->xsk->tx)) {
                sendto(xsk_socket__fd(ctx->xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            }
        }

        // 3. Quét dọn Completion Ring (Gói tin đã gửi xong)
        if (ctx->xsk->outstanding_tx > 0) {
            uint32_t idx_cq = 0;
            unsigned int completed = xsk_ring_cons__peek(&ctx->umem->cq, 32, &idx_cq);
            if (completed > 0) {
                for (unsigned int i = 0; i < completed; i++) {
                    uint64_t addr = *xsk_ring_cons__comp_addr(&ctx->umem->cq, idx_cq++);
                    xsk_free_frame(ctx->umem, addr);
                }
                xsk_ring_cons__release(&ctx->umem->cq, completed);
                ctx->xsk->outstanding_tx -= completed;
            }
        }

        // Adaptive Busy-waiting cho IO Thread
        if (rcvd == 0 && sent_batch == 0) {
            spin_count++;
            if (spin_count >= SPIN_LIMIT) {
                poll(fds, 1, 10);
                spin_count = SPIN_LIMIT;
            } else {
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
            }
        } else {
            spin_count = 0;
        }
    }

    return NULL;
}

// Worker Thread xử lý logic DPI, A2S cache và Block IP
void *worker_thread_func(void *arg) {
    thread_ctx_t *ctx = (thread_ctx_t *)arg;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    int core_id = 2 * ctx->queue_id + 1;
    if (numa_cpus_count >= 2) {
        int idx = 2 * (ctx->queue_id % (numa_cpus_count / 2)) + 1;
        if (idx < numa_cpus_count) {
            core_id = numa_cpus[idx];
        }
    }
    CPU_SET(core_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    printf("[Worker Thread Q%d] Đang chạy trên CPU %d...\n", ctx->queue_id, 2 * ctx->queue_id + 1);

    uint32_t spin_count = 0;
    const uint32_t SPIN_LIMIT = 10000;

    while (!stop) {
        packet_desc_t rx_desc;
        if (spsc_ring_pop(&ctx->rx_ring, &rx_desc)) {
            spin_count = 0;
            void *pkt_data = xsk_umem__get_data(ctx->umem->buffer, rx_desc.addr);
            struct ethhdr *eth = pkt_data;
            struct iphdr *iph = (struct iphdr *)(eth + 1);

            // Chỉ xử lý IPv4 UDP
            if (iph->protocol == IPPROTO_UDP) {
                struct udphdr *udph = (struct udphdr *)((char *)iph + (iph->ihl * 4));
                uint8_t *payload = (uint8_t *)(udph + 1);
                uint32_t pay_len = rx_desc.len - sizeof(struct ethhdr) - (iph->ihl * 4) - sizeof(struct udphdr);

                // 1. Kiểm tra gói tin phản hồi từ Backend (IPIP decapsulated)
                // Format: A2S Response starts with 0xFF 0xFF 0xFF 0xFF 0x49
                if (pay_len >= 5 && payload[0] == 0xFF && payload[1] == 0xFF && payload[2] == 0xFF && payload[3] == 0xFF && payload[4] == 0x49) {
                    // Đưa vào Cache BPF Map
                    struct flow key = {
                        .ip = iph->saddr,
                        .port = udph->source,
                        .protocol = IPPROTO_UDP
                    };
                    struct a2s_info_val val = {0};
                    val.size = pay_len - 5;
                    val.expires = get_time_ns() + (45ULL * 1000000000ULL); // 45 giây cache
                    memcpy(val.data, payload + 5, val.size);

                    if (a2s_info_fd >= 0) {
                        bpf_map_update_elem(a2s_info_fd, &key, &val, BPF_ANY);
                    }

                    // Forward gói tin này về Client
                    packet_desc_t tx_desc = rx_desc;
                    spsc_ring_push(&ctx->tx_ring, tx_desc);
                    continue;
                }

                // 2. Kiểm tra gói tin A2S Expired Cache (0x55) yêu cầu cập nhật cache từ Backend
                if (pay_len >= 5 && payload[0] == 0xFF && payload[1] == 0xFF && payload[2] == 0xFF && payload[3] == 0xFF && payload[4] == 0x55) {
                    // Đổi byte 0x55 thành 0x49 và trả về ngay cho Client
                    payload[4] = 0x49;
                    udph->check = 0;
                    udph->check = udp_csum(iph->saddr, iph->daddr, ntohs(udph->len), IPPROTO_UDP, (uint16_t *)udph);

                    // Trả cache cũ cho Client ngay lập tức để giảm độ trễ
                    packet_desc_t tx_desc = rx_desc;
                    spsc_ring_push(&ctx->tx_ring, tx_desc);

                    // Đồng thời gửi 1 gói Query (0x54) đóng gói IPIP tới Backend để cập nhật cache
                    // Ta mượn 1 frame UMEM mới để lưu gói tin đóng gói IPIP
                    uint64_t new_addr = xsk_alloc_frame(ctx->umem);
                    if (new_addr != INVALID_UMEM_FRAME) {
                        void *new_pkt = xsk_umem__get_data(ctx->umem->buffer, new_addr);
                        
                        // Đóng gói IPIP
                        struct ethhdr *new_eth = new_pkt;
                        memcpy(new_eth, eth, sizeof(struct ethhdr));

                        struct iphdr *oiph = (struct iphdr *)(new_eth + 1);
                        oiph->version = 4;
                        oiph->ihl = 5;
                        oiph->tos = 0;
                        oiph->protocol = IPPROTO_IPIP;
                        oiph->ttl = 64;
                        oiph->saddr = iph->daddr; // Gốc IP là Shield Node IP
                        oiph->daddr = iph->daddr; // (Nên là Backend IP, trong thực tế cần tìm từ backend_map)
                        oiph->id = 0;
                        oiph->frag_off = 0;

                        // Inner IP
                        struct iphdr *iiph = oiph + 1;
                        memcpy(iiph, iph, sizeof(struct iphdr));
                        iiph->saddr = iph->daddr; // IP spoofing / Edge IP logic
                        iiph->daddr = iph->saddr;

                        struct udphdr *iudph = (struct udphdr *)(iiph + 1);
                        memcpy(iudph, udph, sizeof(struct udphdr));
                        iudph->source = udph->dest;
                        iudph->dest = udph->source;

                        uint8_t *ipl = (uint8_t *)(iudph + 1);
                        ipl[0] = 0xFF; ipl[1] = 0xFF; ipl[2] = 0xFF; ipl[3] = 0xFF; ipl[4] = 0x54;
                        const char *a2s_req = "Source Engine Query";
                        memcpy(ipl + 5, a2s_req, 20);

                        uint16_t iplen = sizeof(struct iphdr) + sizeof(struct udphdr) + 25;
                        iiph->tot_len = htons(iplen);
                        oiph->tot_len = htons(iplen + sizeof(struct iphdr));

                        iudph->len = htons(sizeof(struct udphdr) + 25);
                        iudph->check = 0;
                        iudph->check = udp_csum(iiph->saddr, iiph->daddr, ntohs(iudph->len), IPPROTO_UDP, (uint16_t *)iudph);

                        // Cập nhật Checksum IP
                        iiph->check = 0;
                        uint16_t *ptr = (uint16_t *)iiph;
                        uint32_t csum = 0;
                        for (int k = 0; k < 10; k++) csum += *ptr++;
                        iiph->check = csum_fold(csum);

                        oiph->check = 0;
                        ptr = (uint16_t *)oiph;
                        csum = 0;
                        for (int k = 0; k < 10; k++) csum += *ptr++;
                        oiph->check = csum_fold(csum);

                        packet_desc_t backend_desc = {
                            .addr = new_addr,
                            .len = sizeof(struct ethhdr) + sizeof(struct iphdr) + iplen
                        };
                        spsc_ring_push(&ctx->tx_ring, backend_desc);
                    }
                    continue;
                }

                // 3. Thực hiện Thử thách (Challenge System) và DPI xác thực Query mới (0x54)
                if (pay_len >= 21 && payload[0] == 0xFF && payload[1] == 0xFF && payload[2] == 0xFF && payload[3] == 0xFF && payload[4] == 0x54) {
                    struct flow flow_key = {
                        .ip = iph->saddr,
                        .port = udph->source,
                        .protocol = IPPROTO_UDP
                    };
                    struct a2s_info_val session_val = {0};
                    int session_cached = 0;
                    if (a2s_info_fd >= 0) {
                        session_cached = (bpf_map_lookup_elem(a2s_info_fd, &flow_key, &session_val) == 0);
                    }

                    // Đọc token từ client gửi lên (4 byte cuối nếu pay_len >= 25)
                    uint32_t client_token = 0;
                    if (pay_len >= 25) {
                        memcpy(&client_token, payload + 21, 4);
                    }

                    uint32_t expected_token = 0;
                    if (session_cached && session_val.challenge_set) {
                        memcpy(&expected_token, session_val.challenge, 4);
                    }

                    // Nếu client chưa được challenge hoặc gửi sai token -> Gửi gói Challenge 0x41 phản hồi
                    if (client_token == 0 || client_token == 0xFFFFFFFF || client_token != expected_token) {
                        uint32_t new_token = (uint32_t)rand();
                        if (new_token == 0 || new_token == 0xFFFFFFFF) {
                            new_token = 987654;
                        }

                        session_val.challenge_set = 1;
                        memcpy(session_val.challenge, &new_token, 4);
                        session_val.expires = get_time_ns() + (30ULL * 1000000000ULL); // Token tồn tại trong 30 giây

                        if (a2s_info_fd >= 0) {
                            bpf_map_update_elem(a2s_info_fd, &flow_key, &session_val, BPF_ANY);
                        }

                        // Hoán đổi MAC
                        struct ethhdr tmp_eth;
                        memcpy(&tmp_eth, eth, sizeof(struct ethhdr));
                        uint8_t tmp_mac[ETH_ALEN];
                        memcpy(tmp_mac, tmp_eth.h_source, ETH_ALEN);
                        memcpy(tmp_eth.h_source, tmp_eth.h_dest, ETH_ALEN);
                        memcpy(tmp_eth.h_dest, tmp_mac, ETH_ALEN);
                        memcpy(eth, &tmp_eth, sizeof(struct ethhdr));

                        // Hoán đổi IP
                        uint32_t tmp_ip = iph->saddr;
                        iph->saddr = iph->daddr;
                        iph->daddr = tmp_ip;

                        // Hoán đổi Port
                        uint16_t tmp_port = udph->source;
                        udph->source = udph->dest;
                        udph->dest = tmp_port;

                        // Thay thế payload thành phản hồi Challenge (0xFF 0xFF 0xFF 0xFF 0x41 [4 bytes token])
                        payload[4] = 0x41; // 'A'
                        memcpy(payload + 5, &new_token, 4);

                        uint16_t new_pay_len = 9;
                        udph->len = htons(sizeof(struct udphdr) + new_pay_len);
                        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + new_pay_len);

                        udph->check = 0;
                        udph->check = udp_csum(iph->saddr, iph->daddr, ntohs(udph->len), IPPROTO_UDP, (uint16_t *)udph);

                        iph->check = 0;
                        uint16_t *ptr = (uint16_t *)iph;
                        uint32_t csum = 0;
                        for (int k = 0; k < 10; k++) csum += *ptr++;
                        iph->check = csum_fold(csum);

                        packet_desc_t challenge_tx = {
                            .addr = rx_desc.addr,
                            .len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + new_pay_len
                        };
                        spsc_ring_push(&ctx->tx_ring, challenge_tx);
                        continue;
                    }

                    // Nếu đã đúng challenge token -> Thực hiện DPI xác thực Query
                    if (!dpi_validate_a2s_query(payload, pay_len)) {
                        uint32_t attacker_ip = iph->saddr;
                        uint64_t block_expiry = get_time_ns() + (3600ULL * 1000000000ULL);
                        if (ip_blacklist_fd >= 0) {
                            bpf_map_update_elem(ip_blacklist_fd, &attacker_ip, &block_expiry, BPF_ANY);
                            struct in_addr blocked_addr = {.s_addr = attacker_ip};
                            printf("[DPI Q%d] Đã phát hiện fake A2S payload sau challenge! Đang chặn IP: %s\n", ctx->queue_id, inet_ntoa(blocked_addr));
                        }
                        xsk_free_frame(ctx->umem, rx_desc.addr);
                        continue;
                    }
                }
            }

            // Gói tin mặc định không khớp bộ lọc được giải phóng
            xsk_free_frame(ctx->umem, rx_desc.addr);
        } else {
            spin_count++;
            if (spin_count >= SPIN_LIMIT) {
                usleep(10);
                spin_count = SPIN_LIMIT;
            } else {
#if defined(__x86_64__) || defined(_M_X64)
                __builtin_ia32_pause();
#endif
            }
        }
    }

    return NULL;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        strncpy(iface_name, argv[1], IFNAMSIZ - 1);
    }
    if (argc > 2) {
        num_queues = atoi(argv[2]);
    } else {
        num_queues = get_num_queues(iface_name);
        printf("[AF_XDP] Tự động phát hiện số lượng RSS queues trên %s: %d\n", iface_name, num_queues);
    }
    if (num_queues > MAX_CPUS) num_queues = MAX_CPUS;

    // Phát hiện NUMA node và CPU cores
    int node = get_numa_node(iface_name);
    if (node >= 0) {
        numa_cpus_count = get_numa_cpus(node, numa_cpus, MAX_CPUS);
        if (numa_cpus_count > 0) {
            printf("[AF_XDP] Phát hiện %s ở NUMA Node %d. Ghim luồng vào %d CPU cores thuộc cùng node.\n", iface_name, node, numa_cpus_count);
        }
    } else {
        printf("[AF_XDP] Không tìm thấy NUMA node cho %s (mặc định Virtualized/fallback).\n", iface_name);
    }

    printf("Khởi động AF_XDP Fastpath Engine (%s - %d hàng đợi)...\n", iface_name, num_queues);

    // Mở các map được pin từ Go Control Plane
    xsks_map_fd = bpf_obj_get("/sys/fs/bpf/shield_core/xsks_map");
    a2s_info_fd = bpf_obj_get("/sys/fs/bpf/shield_core/a2s_info");
    ip_blacklist_fd = bpf_obj_get("/sys/fs/bpf/shield_core/ip_blacklist_map");

    if (xsks_map_fd < 0 || a2s_info_fd < 0 || ip_blacklist_fd < 0) {
        fprintf(stderr, "Lỗi: Không tìm thấy các BPF map pinned tại /sys/fs/bpf/shield_core/. Vui lòng chạy Control Plane trước!\n");
        return EXIT_FAILURE;
    }

    // Set rlimit
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    pthread_t io_threads[MAX_CPUS];
    pthread_t worker_threads[MAX_CPUS];

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 1. Khởi tạo toàn bộ UMEM và Sockets khi đang chạy quyền root
    for (int i = 0; i < num_queues; i++) {
        struct xsk_umem_info *umem = configure_umem();
        if (!umem) {
            fprintf(stderr, "Lỗi khi khởi tạo UMEM queue %d\n", i);
            return EXIT_FAILURE;
        }

        struct xsk_socket_info *xsk = configure_socket(umem, i);
        if (!xsk) {
            fprintf(stderr, "Lỗi khi khởi tạo XSK socket queue %d\n", i);
            return EXIT_FAILURE;
        }

        thread_contexts[i].queue_id = i;
        thread_contexts[i].umem = umem;
        thread_contexts[i].xsk = xsk;
        spsc_ring_init(&thread_contexts[i].rx_ring);
        spsc_ring_init(&thread_contexts[i].tx_ring);

        // Đăng ký FD của Socket AF_XDP này vào xsks_map để XDP Redirect
        int xsk_fd = xsk_socket__fd(xsk->xsk);
        int key = i;
        if (bpf_map_update_elem(xsks_map_fd, &key, &xsk_fd, BPF_ANY) != 0) {
            fprintf(stderr, "Cảnh báo: Không thể đăng ký XSK FD vào xsks_map tại index %d\n", i);
        }
    }

    // 2. Thực hiện hạ quyền xuống user nobody (UID 65534, GID 65534)
    if (getuid() == 0) {
        if (setgid(65534) != 0) {
            fprintf(stderr, "[Security] Cảnh báo: Không thể hạ GID xuống nobody: %s\n", strerror(errno));
        }
        if (setuid(65534) != 0) {
            fprintf(stderr, "[Security] Cảnh báo: Không thể hạ UID xuống nobody: %s\n", strerror(errno));
        } else {
            printf("[Security] Đã hạ quyền tiến trình thành công xuống user 'nobody'.\n");
        }
    }

    // 3. Khởi chạy các luồng xử lý IO và Worker dưới quyền nobody
    for (int i = 0; i < num_queues; i++) {
        pthread_create(&io_threads[i], NULL, io_thread_func, &thread_contexts[i]);
        pthread_create(&worker_threads[i], NULL, worker_thread_func, &thread_contexts[i]);
    }

    printf("Hệ thống AF_XDP Fastpath đã sẵn sàng phục vụ.\n");

    while (!stop) {
        sleep(1);
    }

    printf("Đang tắt hệ thống và dọn dẹp...\n");

    for (int i = 0; i < num_queues; i++) {
        pthread_join(io_threads[i], NULL);
        pthread_join(worker_threads[i], NULL);
        
        xsk_socket__delete(thread_contexts[i].xsk->xsk);
        xsk_umem__delete(thread_contexts[i].umem->umem);
        free(thread_contexts[i].umem->buffer);
        free(thread_contexts[i].xsk);
        free(thread_contexts[i].umem);
    }

    close(xsks_map_fd);
    close(a2s_info_fd);
    close(ip_blacklist_fd);

    return 0;
}
