# Cẩm nang Vận hành Sản xuất (Production Guide)

Tài liệu này cung cấp các hướng dẫn thực tế để tối ưu hóa hệ thống Shield-Core khi chạy trên môi trường sản xuất tải cao chịu tải hàng triệu gói tin mỗi giây.

---

## 1. Tối ưu hóa Card mạng vật lý (NIC Tuning)

### 1.1. Điều chỉnh Kích thước Ring Buffer
Kích thước hàng đợi nhận (`rx`) và truyền (`tx`) mặc định của card mạng thường khá nhỏ (như 256 hoặc 512). Khi bị tấn công DDoS với lượng PPS cực lớn, hàng đợi này sẽ nhanh chóng bị tràn dẫn đến rớt gói tin hợp lệ từ phần cứng.
* **Tối ưu hóa:** Hãy nâng kích thước hàng đợi lên mức tối đa hỗ trợ của card mạng (thường là 4096):
  ```bash
  # Xem giới hạn tối đa của card eth0
  sudo ethtool -g eth0
  
  # Thiết lập ring buffer lên 4096
  sudo ethtool -G eth0 rx 4096 tx 4096
  ```

### 1.2. Phân chia Hàng đợi RSS (Receive Side Scaling)
Nếu card mạng hỗ trợ nhiều hàng đợi nhận tin (Multi-Queue), hãy cấu hình số lượng hàng đợi trùng khớp với số lượng luồng IO của `shield-fastpath` (ví dụ: ghim 1 hàng đợi cho 1 luồng xử lý riêng biệt):
```bash
# Thiết lập số lượng hàng đợi nhận tin về 1 (nếu chạy 1 queue AF_XDP)
sudo ethtool -L eth0 combined 1
```

---

## 2. Cách ly Nhân xử lý CPU (CPU Isolation)

Để ngăn việc nhân hệ điều hành tự động phân phối các tiến trình ngẫu nhiên vào nhân CPU đang chạy luồng xử lý mạng thời gian thực của AF_XDP:

1. **Tắt irqbalance cho Card mạng:** Không cho phép hệ điều hành tự động hoán chuyển CPU xử lý ngắt (Interrupts) của card mạng:
   ```bash
   sudo systemctl stop irqbalance
   ```
2. **Ghim IRQ cứng vào nhân CPU:** Nhìn vào `/proc/interrupts` để tìm ID ngắt của card mạng `eth0` và ghim cứng nó vào CPU 0 hoặc 1 (trùng với luồng IO).

---

## 3. Kết nối Giám sát (Prometheus & Grafana)

Go Control Plane tích hợp sẵn một bộ xuất dữ liệu Prometheus Metrics chuẩn tại endpoint `/metrics`.
* **Cổng truy cập:** `GET /metrics` (Không cần API key xác thực để tương thích với các scraper của Prometheus).
* **Các chỉ số chính cung cấp:**
  * `shield_passed_packets_total`: Tổng số gói tin sạch được cho qua.
  * `shield_dropped_packets_total`: Tổng số gói tin tấn công bị chặn đứng.
  * `shield_geoip_cache_hits_total`: Số lượng tra cứu cache GeoIP thành công.
  * `shield_geoip_cache_misses_total`: Số lượng tra cứu cache GeoIP phải phân giải lại.
  * `shield_cpu_usage_percent`: Tải CPU thực tế của Control Plane.

**Mẫu cấu hình `prometheus.yml`:**
```yaml
scrape_configs:
  - job_name: 'shield-core'
    scheme: 'https'
    tls_config:
      insecure_skip_verify: true # Bắt buộc vì dùng SSL tự ký
    static_configs:
      - targets: ['103.77.246.191:9090', '103.77.246.198:9090']
```
