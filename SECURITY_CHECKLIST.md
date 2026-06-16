# Shield-Core — Security Checklist

> Tài liệu này mô tả các biện pháp bảo mật đã triển khai và các kiểm tra cần thực hiện.
> Dựa trên phân tích source code thực tế — không có nội dung giả định.

---

## 1. Xác thực API (Authentication)

| Mục | Trạng thái | Ghi chú |
|-----|-----------|---------|
| API Key bắt buộc cho tất cả `/api/*` endpoints | ✅ Có | Header `X-API-Key` |
| API Key tự sinh nếu chưa cấu hình | ✅ Có | `config.go:LoadConfig()`, dùng `crypto/rand` |
| Rate limiting per-IP trên API | ✅ Có | 60 req/phút, `sync.Map` |
| `/health` và `/metrics` public (không cần key) | ✅ Có | Dành cho LB health check + Prometheus |

### Kiểm tra
```bash
# Phải trả 401 nếu không có key
curl -k https://localhost:9090/api/stats

# Phải trả 200 nếu có key đúng
curl -k -H "X-API-Key: YOUR_KEY" https://localhost:9090/api/stats
```

---

## 2. Mã hóa Transport (TLS)

| Mục | Trạng thái | Ghi chú |
|-----|-----------|---------|
| API Server chỉ phục vụ HTTPS | ✅ Có | `server.ServeTLS()`, không có HTTP listener |
| Self-signed cert tự động tạo | ✅ Có | ECDSA P-256, 1 năm validity |
| Cert bao gồm tất cả local IPs | ✅ Có | `net.InterfaceAddrs()` trong `generateSelfSignedCert()` |
| Cluster sync dùng HTTPS | ✅ Có | `syncBlacklistEvent()` enforce HTTPS |
| Key file permissions | ⚠️ Manual | Cần: `chmod 600 conf/key.pem` sau khi deploy |

### Kiểm tra
```bash
# Kiểm tra cert thông tin
openssl s_client -connect localhost:9090 </dev/null 2>&1 | openssl x509 -noout -dates

# Không được có HTTP listener
curl http://localhost:9090/health  # Phải timeout hoặc connection refused
```

---

## 3. Privilege Management

| Mục | Trạng thái | Ghi chú |
|-----|-----------|---------|
| `shield-ctrl` hạ quyền sau bind | ✅ Có | `syscall.Setuid/Setgid(65534)` |
| BPF map files chown sang nobody trước hạ quyền | ✅ Có | `os.Chown("/sys/fs/bpf/shield_core/...")` |
| `shield-fastpath` cần root (AF_XDP) | ⚠️ Yêu cầu | AF_XDP cần `CAP_NET_RAW` — không thể hạ thêm |
| `CapabilityBoundingSet` giới hạn | ✅ Có | Chỉ: `CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN` |

### Kiểm tra
```bash
# shield-ctrl phải chạy dưới nobody sau khi khởi động
ps aux | grep shield-ctrl | grep -v grep
# Output expected: nobody ... /opt/shield-core/build/shield-ctrl
```

---

## 4. Network Isolation

| Mục | Trạng thái | Ghi chú |
|-----|-----------|---------|
| Port 9090 chỉ cho phép cluster nodes | ⚠️ Manual | Cấu hình firewall ngoài scope code |
| Local ports tự động bypass XDP | ✅ Có | `startLocalPortsSync()` → `local_ports_map` |
| SSH port (22) không bị chặn | ✅ Có | Tự động phát hiện port đang listen |

### Kiểm tra
```bash
# Kiểm tra local_ports_map đã có port 22 và 9090
# (Kiểm tra qua bpftool hoặc logs khi khởi động)
journalctl -u shield-ctrl | grep "local_ports"
```

---

## 5. eBPF Map Security

| Mục | Trạng thái | Ghi chú |
|-----|-----------|---------|
| Maps pinned tại `/sys/fs/bpf/shield_core/` | ✅ Có | Tên map cố định |
| Map size limits (DoS prevention) | ✅ Có | ip_blacklist: 65536, asn: 32768 |
| Map exhaustion detection | ✅ Có | Alert khi > 90%, TTL giảm xuống 5 phút |
| Emergency cleanup khi map đầy | ✅ Có | `CleanExpiredBlacklist()` với dynamic TTL |

### Kiểm tra
```bash
curl -k -H "X-API-Key: YOUR_KEY" https://localhost:9090/metrics \
  | grep "shield_core_map_usage_percent"
```

---

## 6. Secrets Management

| Mục | Trạng thái | Ghi chú |
|-----|-----------|---------|
| API Key không hardcoded | ✅ Có | Đọc từ `conf/config.json` |
| API Key tự sinh nếu thiếu | ✅ Có | `crypto/rand` 32 bytes |
| `conf/.env` trong `.gitignore` | ⚠️ Cần kiểm tra | `cat .gitignore | grep env` |
| `conf/key.pem` trong `.gitignore` | ⚠️ Cần kiểm tra | Không commit private key |

### Kiểm tra
```bash
# Kiểm tra .gitignore
cat /opt/shield-core/.gitignore | grep -E "(\.env|key\.pem|cert\.pem)"

# Kiểm tra file không bị tracked
git -C /opt/shield-core check-ignore conf/.env conf/key.pem
```

---

## 7. Systemd Hardening

| Directive | shield-ctrl | shield-fastpath |
|-----------|------------|-----------------|
| `ProtectSystem=strict` | ✅ | ❌ (cần /sys/fs/bpf) |
| `ProtectHome=yes` | ✅ | ✅ |
| `PrivateTmp=yes` | ✅ | ✅ |
| `ProtectKernelModules=yes` | ✅ | ✅ |
| `ProtectControlGroups=yes` | ✅ | ✅ |
| `RestrictNamespaces=yes` | ✅ | ❌ (AF_XDP) |
| `LockPersonality=yes` | ✅ | ✅ |
| `NoNewPrivileges` | ❌ (cần Setuid) | ❌ (cần root) |
| `StartLimitBurst` | ✅ 5/60s | ✅ 3/30s |

---

## 8. Audit Log

| Mục | Trạng thái | Ghi chú |
|-----|-----------|---------|
| Mitigation events logged | ✅ Có | `logs/mitigation.log`, JSON format |
| Auto-block events logged | ✅ Có | `writeMitigationLog("mitigation_block", ...)` |
| Auto-unblock events logged | ✅ Có | `writeMitigationLog("auto_unblock", ...)` |
| Manual block events logged | ✅ Có | `writeMitigationLog("manual_block", ...)` |

### Kiểm tra
```bash
tail -f /opt/shield-core/logs/mitigation.log
# Format: {"timestamp":"...","event":"mitigation_block","ip":"...","reason":"..."}
```

---

## 9. Actions Required (Manual)

Những mục KHÔNG thể tự động hóa — cần thực hiện thủ công:

- [ ] Thay API Key mặc định bằng key tự sinh: `openssl rand -hex 32`
- [ ] Set `chmod 600 /opt/shield-core/conf/key.pem`
- [ ] Cấu hình firewall: `iptables -A INPUT -p tcp --dport 9090 -s CLUSTER_IPS -j ACCEPT; iptables -A INPUT -p tcp --dport 9090 -j DROP`
- [ ] Đảm bảo `conf/.env` và `conf/key.pem` không bị commit vào git
- [ ] Cấu hình log rotation: `cp scripts/shield-core.logrotate /etc/logrotate.d/`
- [ ] Backup API key và certificates ra nơi lưu trữ an toàn
