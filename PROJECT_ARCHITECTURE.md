# Kiến Trúc Hệ Thống (Project Architecture)

Hệ thống Shield-Core được thiết kế với 3 thành phần chính để đạt được hiệu năng tối đa và tính linh hoạt cao.

## 1. XDP Datapath (`src/bpf/xdp_main.c`)
- **Vai trò:** Lá chắn đầu tiên, chạy trực tiếp trên Kernel/Network Driver.
- **Hoạt động:**
  - Nhận gói tin ngay khi vừa tới card mạng (NIC).
  - Tra cứu cấu hình từ BPF Maps.
  - Xử lý GeoIP & ASN (Blacklist/Whitelist qua LPM Trie).
  - Rate Limiting L4 (UDP/ICMP/TCP) bằng thuật toán Token Bucket.
- **Maps:** `config_map`, `whitelist_map`, `blacklist_map`, `asn_map`.

## 2. AF_XDP Fastpath (`src/af_xdp/af_xdp_main.c`)
- **Vai trò:** Deep Packet Inspection (DPI) bằng kỹ thuật Kernel Bypass Zero-Copy.
- **Hoạt động:**
  - Xử lý các gói tin mà XDP Datapath chuyển lên.
  - Giao tiếp cực nhanh với Userspace qua bộ đệm `UMEM`.
  - Có Thread pool độc lập ghim vào các CPU Core.
  - Phân tích payload ứng dụng phức tạp (VD: A2S Game Protocol).
  - Cập nhật thống kê ngược lại `ring_stats_map` cho Control Plane.

## 3. Go Control Plane (`src/control_plane/main.go`)
- **Vai trò:** Đầu não điều hành toàn bộ chiến dịch bảo vệ.
- **Hoạt động:**
  - **FSM Auto-Mitigation:** Tự động điều chỉnh các quy tắc và tốc độ (Rate Limit) trong BPF dựa trên áp lực Queue (XDP Drop Ratio) và CPU.
  - **API Server:** Cung cấp RESTful API cho Dashboard và Quản trị viên (HTTPS port 9090).
  - **Prometheus Metrics:** Expose `/metrics` để theo dõi tình trạng chặn/thả.
  - **State Persistence:** Lưu trạng thái (Whitelist/Blacklist/GeoPolicy) vào disk và khôi phục khi khởi động lại.
  - **Cluster Sync:** Phân tán thông tin tấn công sang các Node khác trong cụm (Nodes Config).
