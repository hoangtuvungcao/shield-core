# Kiến trúc Hệ thống Shield-Core

Shield-Core sử dụng mô hình bảo vệ lai (Hybrid Security Datapath) kết hợp giữa hiệu năng cực đỉnh của tầng nhân Linux (eBPF/XDP) và chiều sâu xử lý gói tin ở tầng người dùng (AF_XDP Fastpath) thông qua một kênh điều phối tập trung (Go Control Plane).

```mermaid
graph TD
    Client[Kẻ Tấn Công / Client] -->|Traffic| NIC[Card Mạng - eth0]
    subgraph Kernel Space (eBPF Datapath)
        NIC -->|XDP_DRV / XDP_SKB| XDP_Prog[xdp_main.o]
        XDP_Prog -->|Check Blacklist| Blacklist{L3/L4 Blacklist}
        Blacklist -->|Match| Drop[XDP_DROP]
        Blacklist -->|No Match| GeoIP{GeoIP / ASN Trie}
        GeoIP -->|Blocked Country/ASN| Drop
        GeoIP -->|Valid Traffic| TCP_SYN{TCP SYN Packets?}
        TCP_SYN -->|Yes| SYNCookies[process_tcp_syncookie]
        SYNCookies -->|Invalid Cookie| Drop
        SYNCookies -->|SYN-ACK Response| Tx[XDP_TX]
        TCP_SYN -->|No / Established| RateLimit[check_rate_limit]
        RateLimit -->|Exceeded Limit| Drop
        RateLimit -->|Passed| Redirect{Needs AF_XDP DPI?}
        Redirect -->|A2S / Custom L7| RedirectMap[bpf_redirect_map]
        Redirect -->|Bypass / Admin| Pass[XDP_PASS]
    end
    
    subgraph User Space (AF_XDP Fastpath)
        RedirectMap -->|Zero-Copy / Copy| XSK_Socket[af_xdp_main.c]
        XSK_Socket -->|Queue Rings| IO_Threads[IO Threads]
        IO_Threads -->|Packet Parser| DPI[dpi.c - Deep Packet Inspection]
        DPI -->|Challenge-Response / Rules| Decision[Decision Engine]
        Decision -->|Malicious Client| AddBlacklist[Write to Blacklist Map]
        Decision -->|Legitimate Client| PassToOS[Forward to Linux Kernel]
    end
    
    subgraph User Space (Control Plane)
        GoCtrl[shield-ctrl] -->|Config/GeoIP Load| Maps[(BPF Maps)]
        GoCtrl -->|HTTPS API| Admin[Admin / Web Dashboard]
        GoCtrl -->|Sync Event| OtherNodes[Other Cluster Nodes]
        AddBlacklist -->|Update| Maps
    end
```

---

## 1. Thành phần Cốt lõi (Core Components)

### 1.1. eBPF Datapath (XDP Kernel Space)
* **Vị trí:** Nhân hệ điều hành Linux (Chế độ Driver hoặc Generic).
* **Ngôn ngữ:** C (Biên dịch bằng Clang/LLVM sang byte-code eBPF).
* **Nguyên lý:** Can thiệp gói tin ngay tại card mạng (Network Interface Card - NIC) trước khi cấp phát bộ nhớ socket (`sk_buff`), giúp giảm thiểu hao tổn tài nguyên hệ thống xuống gần như bằng không.
* **Chức năng:**
  * Lọc nhanh IP Blacklist (`ip_blacklist_map`) với tốc độ $\sim 10$ Mpps+ trên card mạng thông thường.
  * Phân tích và chặn dải IP quy mô lớn theo Quốc gia và ASN qua cấu trúc dữ liệu LPM Trie (`asn_blacklist_map`, `country_blacklist_map`).
  * Thực thi SYN Cookie tự động (`process_tcp_syncookie`) chống TCP SYN Flood mà không cần duy trì trạng thái bắt tay trên Kernel.
  * Giới hạn tần suất PPS/BPS động theo từng IP thông qua Token Bucket rate limiting.
  * Bỏ qua các cổng SSH (22) và API (9090) cũng như các cổng dịch vụ đang lắng nghe thực tế trên máy chủ để tránh vô ý khoá kết nối quản trị.

### 1.2. AF_XDP Fastpath (User Space)
* **Vị trí:** Chế độ Người dùng (User Space) chạy bằng quyền `root` (yêu cầu `CAP_NET_RAW` + `CAP_BPF` để tạo AF_XDP socket và đọc BPF maps được pin bởi `shield-ctrl`).
* **Ngôn ngữ:** C (Tối ưu hoá cao độ luồng bộ nhớ UMEM).
* **Nguyên lý:** Nhận trực tiếp các gói tin cần phân tích sâu (như UDP Game Queries, Challenge-Response) từ BPF Map thông qua hàng đợi vòng đệm (Ring Buffers) bỏ qua TCP/IP stack của Linux.
* **Chức năng:**
  * Thực hiện Deep Packet Inspection (DPI) để phân tích cấu trúc Payload (như các gói tin truy vấn A2S game server).
  * Thực hiện thuật toán Thử thách - Phản hồi (Challenge-Response) sinh token động để xác thực Client thật và chặn đứng Botnet gửi flood một chiều.
  * Cập nhật các IP vi phạm vào `ip_blacklist_map` để eBPF tự động drop các gói tin tiếp theo ngay tại Kernel.

### 1.3. Control Plane (Go Daemon)
* **Vị trí:** Chế độ Người dùng (khởi động bằng `root`, tự hạ quyền xuống `nobody` (UID 65534) sau khi bind port và pin BPF maps).
* **Ngôn ngữ:** Go.
* **Chức năng:**
  * Nạp eBPF Program vào card mạng khi khởi động và tự động gỡ bỏ (Detach) khi tắt dịch vụ.
  * Cập nhật định kỳ GeoIP (MaxMind) và Reputation JSON vào không gian BPF Maps.
  * Theo dõi tải hệ thống (CPU Usage) và tự động ghi ngưỡng PPS/BPS động xuống `config_map` của eBPF.
  * Cung cấp HTTPS REST API bảo mật cho quản trị và đồng bộ cụm Multi-Node.
