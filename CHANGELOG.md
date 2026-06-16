# Changelog

All notable changes to Shield-Core are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.1.0] - 2026-06-16

### 🔒 Security — CRITICAL Fixes

#### Secure Cluster Communication
- **BREAKING**: Loại bỏ HTTP plaintext trong cluster sync. Toàn bộ node-to-node sync đã migrate sang HTTPS/TLS.
- Tự động sinh self-signed TLS certificate tại `conf/cert.pem` / `conf/key.pem` nếu chưa có.
- `syncBlacklistEvent()` giờ enforce HTTPS — từ chối kết nối HTTP.
- TLS transport với timeout 2s cho cluster sync requests.

#### Privilege Dropping
- `shield-ctrl` khởi động bằng root (cần bind port < 1024 + pin BPF maps), sau đó tự hạ quyền xuống `nobody` (UID 65534) qua `syscall.Setuid/Setgid`.
- Quyền hạn file BPF maps (`/sys/fs/bpf/shield_core/*`) được `chown` sang `nobody` trước khi hạ quyền.

#### Fix TCP Lockout Bug (CRITICAL)
- **Lỗi:** XDP SYN Cookie logic chặn nhầm các TCP connection đã thiết lập (established connections) → SSH bị lock.
- **Fix:** Thêm kiểm tra `sk->state != BPF_TCP_LISTEN` trong `syncookie.h` — chỉ áp dụng SYN cookie cho NEW connections.

### ✅ Stability

#### Fail-Safe Fastpath
- `shield-fastpath` được cấu hình `Restart=on-failure` thay vì `always` → khi crash, kernel path tiếp quản (XDP_PASS) thay vì restart loop.
- `shield-fastpath.service` thêm `After=shield-ctrl.service` + `Requires=shield-ctrl.service` để đảm bảo BPF maps đã được pin trước khi fastpath khởi động.

#### Graceful Shutdown
- API Server có `Graceful Shutdown` với timeout 5 giây (chờ request đang xử lý hoàn thành).
- Systemd `TimeoutStopSec=10` cho `shield-ctrl`, 5s cho `shield-fastpath`.

### 📦 Infrastructure

#### Docker
- Dockerfile tối ưu multi-stage build: `builder` → `runner` (scratch-based image).
- Thêm `HEALTHCHECK` sử dụng `/health` endpoint.
- `docker-compose.prod.yml` tách riêng cho production với resource limits.

#### Systemd
- Cả hai service files được hardened với:
  - `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`
  - `ProtectKernelModules=yes`, `ProtectControlGroups=yes`
  - `RestrictNamespaces=yes`, `LockPersonality=yes`
  - `EnvironmentFile=-/opt/shield-core/conf/.env`
  - `StartLimitBurst` để tránh restart storm

### 📚 Documentation

- Viết lại toàn bộ `README.md` dựa trên source code thực tế.
- Xóa 5 file docs cũ chứa thông tin sai (API.md, ARCHITECTURE.md, CLUSTER_SETUP.md, SETUP.md, TROUBLESHOOTING.md).
- Tạo mới 10 file docs trong `docs/`: architecture, packet-flow, deployment, security, performance, geoip, api, troubleshooting, faq, production.
- Thêm `conf/config.example.json` và `conf/.env.example`.

### 🔧 Auto-Mitigation Engine

- Dynamic PPS/BPS thresholds: tự động hạ ngưỡng khi CPU > 80% (circuit breaker).
- Blacklist TTL expiry: tự động unblock IP sau 1 giờ; hạ TTL xuống 5 phút khi map > 90% đầy.
- Map health monitoring: metrics Prometheus cho `shield_core_map_usage_percent`, `shield_core_blacklist_entries`.

---

## [1.0.0] - 2026-06-01

### Initial Release

- eBPF XDP datapath (`xdp_main.c`) với:
  - IP Blacklist (LRU Hash Map, 65536 entries)
  - ASN/CIDR Blacklist (LPM Trie, 32768 entries)
  - Country Blacklist (LPM Trie)
  - Rate Limiting (PPS + BPS per IP)
  - SYN Cookie anti-flood
  - Backend routing map (VIP → Backend redirect)
- AF_XDP Fastpath (`shield-fastpath`) với DPI engine.
- Go Control Plane (`shield-ctrl`) với:
  - HTTPS REST API (port 9090)
  - GeoIP integration (MaxMind GeoLite2 ASN + Country)
  - Cluster sync (node-to-node blacklist replication)
  - Prometheus metrics (`/metrics`)
  - Auto-mitigation engine
  - Web dashboard (`/`)
- Systemd service files cho production deployment.
