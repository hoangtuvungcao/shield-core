# Shield-Core XDP Anti-DDoS Platform

Shield-Core là một hệ thống tường lửa mạng và giảm thiểu tấn công từ chối dịch vụ (Anti-DDoS) mã nguồn mở, siêu nhẹ và siêu tốc độ dành cho hệ điều hành Linux. Dự án kết hợp sức mạnh xử lý gói tin cực hạn của eBPF/XDP trong Kernel và động cơ phân tích sâu gói tin (DPI) thời gian thực của AF_XDP ở User Space.

---

## Overview
Shield-Core đóng vai trò là lá chắn phòng thủ biên cho máy chủ Linux. Hệ thống phát hiện, phân loại và huỷ bỏ (`XDP_DROP`) các gói tin độc hại (như TCP SYN Flood, UDP Flood, A2S Query Flood) ngay tại hàng đợi nhận của card mạng (NIC) trước khi chúng tiêu tốn tài nguyên CPU hoặc bộ nhớ của hệ điều hành.

---

## Features
- **Hiệu năng cấp Driver (XDP Native):** Đạt tốc độ xử lý hàng chục triệu gói tin mỗi giây (Mpps) trên phần cứng tương thích.
- **Deep Packet Inspection (AF_XDP):** Chuyển hướng các luồng gói tin phức tạp lên User space để xác thựcChallenge-Response thời gian thực.
- **Chống Botnet diện rộng (GeoIP & ASN):** Chặn các quốc gia và nhà mạng lớn thông qua cấu trúc LPM Trie động trong Kernel.
- **SYN Cookie eBPF:** Tự động phản hồi SYN-ACK chứa Cookie ở mức Kernel, chống SYN Flood mà không tốn bộ nhớ lưu trạng thái.
- **Đồng bộ cụm bảo mật (HTTPS Cluster Sync):** Tự động phát sóng các IP bị chặn tới tất cả các node khác trong cụm qua HTTPS mã hóa.
- **An toàn Cổng Quản trị:** Bypass cứng các cổng SSH (22) và API (9090) để đảm bảo không bao giờ tự khoá cổng quản trị.

---

## Architecture
Hệ thống sử dụng kiến trúc phân lớp lai (Hybrid Datapath):
1. **eBPF Datapath (Kernel Space):** Thực thi các bộ lọc L3/L4 sớm (Blacklist, Whitelist, GeoIP, SYN Cookie, Rate Limiting).
2. **AF_XDP Fastpath (User Space):** Chạy DPI xác thực các gói tin phức tạp và ghi IP vi phạm vào blacklist.
3. **Go Control Plane (User Space):** Nạp chương trình BPF, quản lý Maps, cung cấp Web API HTTPS và đồng bộ hoá giữa các Node.

---

## Components
- `src/bpf/`: Mã nguồn eBPF C chạy trong nhân hệ điều hành.
- `src/af_xdp/`: Mã nguồn C của động cơ xử lý AF_XDP Fastpath.
- `src/control_plane/`: Mã nguồn Go quản lý toàn bộ hệ thống.
- `web/`: Giao diện Web Dashboard thời gian thực của Shield-Core.
- `conf/`: Thư mục chứa các file cấu hình JSON mẫu.

---

## Requirements
- **Hệ điều hành:** Ubuntu 22.04 LTS hoặc Ubuntu 24.04 LTS (Khuyên dùng).
- **Kernel:** Phiên bản **5.15 trở lên**.
- **Công cụ:** `clang` (v12+), `llvm`, `go` (v1.21+), `make`, `bpftool`, `libxdp-dev`.

---

## Installation
Cài đặt gói phụ thuộc trên Ubuntu:
```bash
sudo apt update && sudo apt install -y clang llvm libelf-dev libpcap-dev build-essential \
                                       git curl jq bpftool libxdp-dev libbpf-dev zlib1g-dev
```

---

## Build
Shield-Core sử dụng `Makefile` để biên dịch thống nhất:
```bash
# 1. Biên dịch eBPF
make bpf

# 2. Biên dịch Go Control Plane
make control_plane

# 3. Biên dịch AF_XDP Fastpath (Yêu cầu libxdp)
make af_xdp

# 4. Cài đặt toàn bộ vào /opt/shield-core
sudo make install
```

---

## Configuration
Hệ thống sử dụng tệp cấu hình chính là `/opt/shield-core/conf/config.json`:
```json
{
  "geoip": {
    "asn_db_path": "data/geoip/GeoLite2-ASN.mmdb",
    "country_db_path": "data/geoip/GeoLite2-Country.mmdb"
  },
  "api": {
    "api_key": "khoa_api_cua_ban",
    "listen": ":9090"
  }
}
```

---

## GeoIP
Cấu hình chặn dải IP quốc gia:
- **API Thêm Rule:** `POST /api/rules/country?country=CN` (Chặn Trung Quốc).
- **API Xoá Rule:** `DELETE /api/rules/country?country=CN`.
Hệ thống sẽ tự động duyệt database MaxMind, chuyển đổi các dải mạng của quốc gia đó thành các prefix và nạp vào map `country_blacklist_map` trong eBPF.

---

## ASN
Tương tự GeoIP, hỗ trợ chặn các nhà mạng lớn bằng số hiệu ASN:
- **API Thêm Rule:** `POST /api/rules/asn?asn=1234` (Chặn AS1234).
- **API Xoá Rule:** `DELETE /api/rules/asn?asn=1234`.

---

## XDP
Mã nguồn eBPF `src/bpf/xdp_main.c` được nạp trực tiếp vào card mạng (ví dụ `eth0`). Khi có gói tin đi vào, nó sẽ lọc và trả về:
- `XDP_DROP`: Huỷ gói tin tấn công.
- `XDP_TX`: Phản hồi ngược ra card (áp dụng cho SYN-ACK cookie và A2S cache).
- `XDP_PASS`: Cho gói tin sạch đi tiếp lên nhân OS.
- `bpf_redirect_map`: Đẩy gói tin cần phân tích vào AF_XDP.

---

## AF_XDP
Tiến trình `shield-fastpath` giao tiếp với nhân qua vùng nhớ dùng chung UMEM. Khi nhận các gói tin nghi vấn từ hàng đợi mạng, nó giải mã và thực thi kiểm tra cấu trúc Payload (trong `dpi.c`) trước khi đưa ra quyết định chặn.

---

## Metrics
Control Plane cung cấp metrics chuẩn Prometheus tại endpoint `/metrics` (HTTP plaintext, không yêu cầu xác thực).
Các chỉ số chính:
- `shield_passed_packets_total`: Tổng gói đi qua.
- `shield_dropped_packets_total`: Tổng gói bị huỷ bỏ.
- `shield_cpu_usage_percent`: Tỉ lệ CPU sử dụng.

---

## API
REST API chạy qua cổng HTTPS `9090` yêu cầu header xác thực `X-API-Key`.
Các endpoint chính:
- `GET /health` (Bypass auth)
- `GET /api/blacklist`
- `POST /api/blacklist?ip=IP`
- `DELETE /api/blacklist?ip=IP`
- `GET /api/routing`
- `POST /api/routing?vip=VIP&backend=BACKEND`
- `GET /api/stats`

---

## Dashboard
Shield-Core cung cấp một giao diện Web Dashboard HTML/JS tĩnh trong thư mục `web/`, được phục vụ trực tiếp bởi Go Control Plane tại địa chỉ `https://localhost:9090/`. Giao diện hiển thị biểu đồ CPU, RAM, lưu lượng thông qua, gói bị chặn và cho phép quản trị danh sách đen theo thời gian thực.

---

## Security
- **Hạ quyền tiến trình:** Cả hai tiến trình đều tự động hạ quyền xuống user `nobody` (UID 65534) sau khi hoàn tất khởi tạo socket và nạp BPF.
- **Mã hoá giao tiếp:** Node sync hoạt động hoàn toàn qua HTTPS/TLS sử dụng API Key.
- **An toàn cổng:** Tự động bypass các cổng 22, 9090 để chống tự khoá.

---

## Troubleshooting
Nếu kết nối mạng gặp sự cố nghiêm trọng, gỡ bỏ XDP khẩn cấp khỏi card mạng bằng lệnh:
```bash
sudo ip link set dev eth0 xdp off
```
Xem thêm chi tiết các lỗi verifier và socket trong [troubleshooting.md](docs/troubleshooting.md).

---

## Limitations
- Hệ thống tối ưu hóa và chỉ xử lý các bộ lọc cho địa chỉ **IPv4**.
- IPv6 và các gói tin ARP được tự động bỏ qua để hệ điều hành xử lý, tránh gây mất kết nối IPv6.

---

## Roadmap
- Hỗ trợ đầy đủ bộ lọc và bảo vệ cho địa chỉ IPv6.
- Tích hợp công cụ tự động phân tích hành vi tấn công học máy (Anomaly Detection) ở User space.
- Cải tiến giao diện Dashboard hiển thị chi tiết bản đồ tấn công trực quan.

---

## License
Hệ thống Shield-Core được phát hành dưới giấy phép mã nguồn mở **GPL-2.0**.
