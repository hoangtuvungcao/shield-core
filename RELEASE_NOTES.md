# Shield-Core v1.1.0 — Release Notes

**Release Date:** 2026-06-16
**Classification:** Production Hardening Release

---

## Tóm tắt

Release này tập trung 100% vào **Production Hardening** — không thêm tính năng mới.
Toàn bộ thay đổi giải quyết các phát hiện CRITICAL/HIGH từ quá trình kiểm định kỹ thuật.

---

## Thay đổi Breaking

### 1. HTTP plaintext bị loại bỏ hoàn toàn

**Trước (v1.0.0):**
```
# nodes.json
["http://node1:9090", "http://node2:9090"]
```

**Sau (v1.1.0):**
```
# nodes.json
["https://node1:9090", "https://node2:9090"]
```

> **Action required:** Cập nhật `conf/nodes.json` — đổi tất cả `http://` thành `https://`

Cluster sync code bây giờ **enforce HTTPS** và tự động upgrade HTTP → HTTPS.
Self-signed certificate được tự sinh nếu chưa có.

---

## Vấn đề Critical đã khắc phục

### TCP Lockout Bug

**Mô tả:** SYN Cookie validation trong eBPF kernel program chặn nhầm TCP connections đã được thiết lập (established), khiến SSH bị ngắt kết nối ngay khi XDP program load.

**Nguyên nhân gốc:** Logic kiểm tra SYN cookie áp dụng cho tất cả TCP packets, kể cả ACK/data packets thuộc existing sessions.

**Fix:** `src/bpf/common/syncookie.h` — thêm guard:
```c
if (sk->state != BPF_TCP_LISTEN) {
    // Existing connection — bypass SYN cookie check
    bpf_sk_release(sk);
    goto pass;
}
```

**Kiểm tra:** Deploy thành công trên 2 VPS production (103.77.246.191, 103.77.246.198) — SSH duy trì bình thường.

---

## Cải tiến Stability

| Thành phần | Trước | Sau |
|-----------|-------|-----|
| `shield-ctrl` privilege | Chạy root suốt | Hạ xuống nobody sau bind |
| `shield-fastpath` restart | Không có giới hạn | `on-failure`, max 3 lần/30s |
| Cluster sync | HTTP plaintext | HTTPS/TLS bắt buộc |
| Systemd hardening | Cơ bản | ProtectSystem, PrivateTmp, RestrictNamespaces... |
| API Server shutdown | Tắt ngay | Graceful 5s timeout |

---

## Cách upgrade từ v1.0.0

```bash
# 1. Dừng dịch vụ
sudo systemctl stop shield-fastpath shield-ctrl

# 2. Cập nhật binary
sudo make clean && make
sudo cp build/shield-ctrl build/shield-fastpath /opt/shield-core/build/

# 3. Cập nhật systemd service files
sudo cp scripts/shield-ctrl.service /etc/systemd/system/
sudo cp scripts/shield-fastpath.service /etc/systemd/system/
sudo systemctl daemon-reload

# 4. Cập nhật nodes.json (http -> https)
sudo nano /opt/shield-core/conf/nodes.json

# 5. Khởi động lại
sudo systemctl start shield-ctrl shield-fastpath
sudo systemctl status shield-ctrl shield-fastpath
```

---

## Checksum (sau khi build)

Sau khi build thành công, xác minh:

```bash
sha256sum build/shield-ctrl build/shield-fastpath src/bpf/xdp_main.o
```

---

## Known Issues

- `InsecureSkipVerify: true` trong cluster sync TLS client — chấp nhận được cho self-signed certs trong mạng nội bộ. Với môi trường yêu cầu strict CA verification, cần cung cấp cert bundle.
- AF_XDP cần `CAP_NET_RAW` + root để tạo UMEM socket — không thể hạ quyền thêm với kiến trúc hiện tại.
