# Hướng dẫn Triển khai Hệ thống (Deployment Guide)

Tài liệu này cung cấp hướng dẫn biên dịch và cài đặt Shield-Core trên môi trường Single-Node và Cluster Multi-Node.

---

## 1. Yêu cầu Môi trường

* **Hệ điều hành:** Ubuntu 22.04 LTS hoặc Ubuntu 24.04 LTS (Khuyên dùng).
* **Kernel:** Phiên bản **5.15 trở lên** (Hỗ trợ eBPF/AF_XDP hoàn chỉnh nhất).
* **Trình biên dịch:** `clang` (tối thiểu v12), `go` (tối thiểu v1.21).

---

## 2. Các Bước Cài đặt Single-Node

### Bước 2.1. Cài đặt Gói phụ thuộc
Chạy các lệnh sau với quyền `root`:
```bash
sudo apt update
sudo apt install -y clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386 \
                    linux-tools-common linux-tools-generic linux-tools-$(uname -r) \
                    git curl jq bpftool libxdp-dev libbpf-dev zlib1g-dev
```

### Bước 2.2. Cài đặt Go Compiler (Nếu chưa có)
```bash
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
```

### Bước 2.3. Biên dịch Toàn bộ Hệ thống
```bash
cd /opt
sudo git clone <YOUR_REPO_URL>
cd shield-core

# Đảm bảo submodules đã init (xdp-tools)
git submodule update --init --recursive

# Biên dịch tất cả (BPF + Go + AF_XDP fastpath)
make
```

### Bước 2.4. Cài đặt & Khởi chạy Services
```bash
# Thực hiện cài đặt các file binary, cấu hình và systemd service vào /opt/shield-core/
sudo make install

# Khởi chạy dịch vụ qua systemd
sudo systemctl daemon-reload
sudo systemctl enable --now shield-ctrl
sudo systemctl enable --now shield-fastpath
```

---

## 3. Triển khai Cụm Multi-Node (Cluster)

Khi có từ 2 Shield Node trở lên, cần đồng bộ hóa danh sách đen (Blacklist IP) theo thời gian thực để tạo ra một lá chắn đồng nhất.

### Bước 3.1. Tạo API Key dùng chung

Tạo một key ngẫu nhiên cho cụm:
```bash
openssl rand -hex 32
# Ví dụ output: a3f8b2e1d9c7...
```

Đặt key này vào file `/opt/shield-core/conf/config.json` trên **tất cả các node**:
```json
{
  "geoip": {
    "asn_db_path": "data/geoip/GeoLite2-ASN.mmdb",
    "country_db_path": "data/geoip/GeoLite2-Country.mmdb"
  },
  "api": {
    "api_key": "<YOUR_GENERATED_KEY>",
    "listen": ":9090"
  }
}
```

> **Bảo mật:** File `config.json` chứa API key — không commit vào git, phân quyền `chmod 600`.

### Bước 3.2. Cấu hình file `nodes.json`
Tạo file `/opt/shield-core/conf/nodes.json` chứa URL HTTPS của toàn bộ các node trong hệ thống (bao gồm cả chính nó). Hệ thống sẽ tự động lọc bỏ URL local khi gửi sync event để tránh lặp (Self-Sync Loop).

**Nội dung `/opt/shield-core/conf/nodes.json`:**
```json
[
  "https://NODE_1_IP:9090",
  "https://NODE_2_IP:9090"
]
```

### Bước 3.3. Khởi động lại dịch vụ
```bash
sudo systemctl restart shield-ctrl
```

---

## 4. Xác minh Vận hành

### 4.1. Kiểm tra API bằng HTTPS
```bash
# Thay YOUR_API_KEY bằng key trong conf/config.json
curl -k -H "X-API-Key: YOUR_API_KEY" https://localhost:9090/health
```

### 4.2. Thử nghiệm Đồng bộ Blacklist
1. Gọi API thêm IP cần chặn trên Node A:
   ```bash
   curl -k -X POST -H "X-API-Key: YOUR_API_KEY" \
     "https://NODE_1_IP:9090/api/blacklist?ip=198.51.100.99"
   ```
2. Kiểm tra log của Node A (`journalctl -u shield-ctrl -f`), bạn sẽ thấy thông báo đồng bộ thành công:
   ```text
   [Sync -> https://NODE_2_IP:9090] Đã đồng bộ sự kiện POST cho IP 198.51.100.99 (Status: 200)
   ```
3. Truy cập Node B để xác nhận IP đã được chặn tại eBPF map của Node B:
   ```bash
   curl -k -H "X-API-Key: YOUR_API_KEY" https://NODE_2_IP:9090/api/blacklist
   # Trả về: ["198.51.100.99"]
   ```
