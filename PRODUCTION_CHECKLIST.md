# Shield-Core — Production Deployment Checklist

> Thực hiện checklist này trước khi deploy Shield-Core lên môi trường production.
> Đánh dấu [ ] → [x] sau khi hoàn thành từng mục.

---

## 1. Chuẩn bị Hệ thống

- [ ] **Kernel version >= 5.10** (kiểm tra: `uname -r`)
- [ ] **clang/llvm >= 12** đã cài (build eBPF): `clang --version`
- [ ] **libelf-dev, zlib1g-dev** đã cài (link dependencies)
- [ ] **Git submodules** đã init: `git submodule update --init --recursive`
- [ ] **BPF filesystem** được mount: `mount | grep bpf`
- [ ] **Network interface** xác nhận đúng tên: `ip link show`
- [ ] **NIC driver** hỗ trợ XDP native/generic: `ethtool -i eth0 | grep driver`

## 2. Build & Compile

- [ ] **Build thành công**: `make clean && make`
- [ ] **3 artifacts** tồn tại:
  - [ ] `build/shield-ctrl`
  - [ ] `build/shield-fastpath`
  - [ ] `src/bpf/xdp_main.o`
- [ ] **Go tests pass**: `make test` (trong `src/control_plane`)

## 3. Cấu hình

- [ ] **`conf/config.json`** tồn tại và đúng format (xem `conf/config.example.json`)
- [ ] **API Key** được thay bằng key thực (không dùng default):
  ```bash
  openssl rand -hex 32
  ```
- [ ] **`conf/nodes.json`** chứa địa chỉ HTTPS của tất cả cluster nodes
- [ ] **GeoIP databases** tồn tại (nếu dùng Country/ASN blocking):
  - [ ] `data/geoip/GeoLite2-ASN.mmdb`
  - [ ] `data/geoip/GeoLite2-Country.mmdb`
- [ ] **`SHIELD_IFACE`** đặt đúng tên interface trong `conf/.env` hoặc systemd service

## 4. TLS / Certificates

- [ ] **Self-signed cert** được tạo hoặc cert CA riêng đã copy vào `conf/`
- [ ] **Cert permissions**: `chmod 600 conf/key.pem`
- [ ] **HTTPS API** hoạt động: `curl -k https://localhost:9090/health`

## 5. Firewall & Network

- [ ] **Cổng 9090** (API) chỉ cho phép từ cluster nodes và admin IPs
- [ ] **Cổng 22** (SSH) được bypass trong BPF map (tự động qua `local_ports_map`)
- [ ] **Không block** management traffic của chính server này

## 6. Systemd Services

- [ ] **Copy service files**:
  ```bash
  sudo cp scripts/shield-ctrl.service /etc/systemd/system/
  sudo cp scripts/shield-fastpath.service /etc/systemd/system/
  sudo systemctl daemon-reload
  ```
- [ ] **`shield-ctrl.service`** enabled: `sudo systemctl enable shield-ctrl`
- [ ] **`shield-fastpath.service`** enabled: `sudo systemctl enable shield-fastpath`
- [ ] **Thư mục logs** tồn tại: `sudo mkdir -p /opt/shield-core/logs && sudo chown nobody:nogroup /opt/shield-core/logs`
- [ ] **Thư mục `data/geoip/`** tồn tại và có quyền đọc

## 7. Kiểm thử Post-Deploy

- [ ] **Health check OK**:
  ```bash
  curl -k https://localhost:9090/health | python3 -m json.tool
  ```
- [ ] **`xdp_loaded: true`** trong health response
- [ ] **`status: healthy`** (không phải `degraded`)
- [ ] **GeoIP loaded**: `geoip.asn: true`, `geoip.country: true`
- [ ] **SSH vẫn hoạt động** sau khi XDP load (test từ máy khác)
- [ ] **Metrics endpoint**: `curl -k https://localhost:9090/metrics`
- [ ] **systemctl status shield-ctrl** — active (running)
- [ ] **systemctl status shield-fastpath** — active (running)
- [ ] **Logs không có ERROR**: `journalctl -u shield-ctrl -n 50`

## 8. Cluster Sync (nếu multi-node)

- [ ] **Block một IP trên node 1**, kiểm tra đồng bộ sang node 2:
  ```bash
  curl -k -X POST -H "X-API-Key: YOUR_KEY" \
    "https://node1:9090/api/blacklist?ip=1.2.3.4"
  # Sau ~2s kiểm tra node 2:
  curl -k -H "X-API-Key: YOUR_KEY" \
    "https://node2:9090/api/blacklist" | python3 -m json.tool
  ```

## 9. Monitoring

- [ ] **Prometheus scrape** cấu hình trỏ vào `/metrics`
- [ ] **Grafana dashboard** import (nếu có)
- [ ] **Alerting rule**: `shield_core_map_usage_percent > 90` → alert

## 10. Rollback Plan

- [ ] **Backup binary trước**:
  ```bash
  cp build/shield-ctrl build/shield-ctrl.bak
  cp build/shield-fastpath build/shield-fastpath.bak
  ```
- [ ] **Xóa XDP nhanh nếu cần**:
  ```bash
  sudo ip link set dev eth0 xdp off
  ```
- [ ] **Dừng tất cả**:
  ```bash
  sudo systemctl stop shield-fastpath shield-ctrl
  ```

---

**Sign-off:**
- Engineer: _______________
- Date: _______________
- Environment: _______________
