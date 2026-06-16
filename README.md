# Shield-Core: XDP & AF_XDP Anti-DDoS Datapath

Shield-Core là một hệ thống Anti-DDoS hiệu năng cực cao, chạy trực tiếp trên Kernel (eBPF/XDP) kết hợp với userspace (AF_XDP) và Go Control Plane, thiết kế đặc biệt cho các Server Game và Web có độ nhạy cảm cao với độ trễ.

## Tính năng nổi bật

1. **Bảo vệ toàn diện Layer 3/4 (eBPF/XDP):**
   - Lọc gói tin ở mức Driver/NATIVE XDP (trước khi vào Network Stack).
   - Rate Limit theo IP với các thuật toán tối ưu.
   - Hỗ trợ Blacklist/Whitelist IP, ASN, và GeoIP.

2. **Xử lý Layer 7 cực nhanh (AF_XDP):**
   - Sử dụng Zero-Copy AF_XDP cho các ứng dụng có luồng xử lý riêng biệt.
   - Deep Packet Inspection (DPI) hiệu năng cao cho Game Protocol (vd: A2S).
   - Giao tiếp cực nhanh qua SPSC (Single Producer Single Consumer) Ring.

3. **Auto-Mitigation Engine (Control Plane bằng Go):**
   - Tự động thay đổi các mốc (Level) phòng thủ dựa trên Queue Pressure, RAM, CPU và Drop Ratio.
   - Quản lý đồng bộ tập trung trạng thái (State Persistence).
   - Tích hợp Prometheus Exporter cho giám sát Grafana.

4. **Cluster Sync (Đồng bộ đa cụm):**
   - API nội bộ giúp đồng bộ trạng thái tấn công và IP bị chặn giữa các node trong cùng một cụm.

## Yêu cầu hệ thống

- HĐH: Ubuntu 22.04 LTS hoặc 24.04 LTS.
- Kernel: >= 5.15 (Tối ưu cho NATIVE XDP và Zero-Copy AF_XDP).
- Network Card: Hỗ trợ XDP Driver Mode (Mellanox, Intel ixgbe/i40e/ice, v.v.).

## Kiến trúc Hệ thống

Xem chi tiết tại [PROJECT_ARCHITECTURE.md](PROJECT_ARCHITECTURE.md).

## Triển khai lên Production

Xem chi tiết tại [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md).

## API Reference

Xem chi tiết tại [API_REFERENCE.md](API_REFERENCE.md).

## Tình trạng

Dự án đã vượt qua bài kiểm tra **Final Project Audit** và sẵn sàng cho môi trường Production khắt khe nhất.
