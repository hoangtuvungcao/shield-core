# Kiến trúc Bảo mật Hệ thống (Security Architecture)

Shield-Core được xây dựng dựa trên nguyên lý **tối thiểu đặc quyền** (Principle of Least Privilege) và tăng cường bảo mật chiều sâu để đảm bảo lá chắn bảo vệ an toàn cho hệ thống và tự bảo vệ mình trước các đòn tấn công khai thác đặc quyền.

---

## 1. Cơ chế Hạ quyền (Privilege Dropping)

BPF program và AF_XDP socket yêu cầu quyền `root` khi bắt đầu khởi chạy để nạp chương trình vào nhân và bind địa chỉ vùng nhớ UMEM. Sau khi hoàn thành các tác vụ khởi tạo đặc quyền này, cả hai tiến trình của Shield-Core lập tức hạ quyền xuống user không đặc quyền `nobody` (UID 65534, GID 65534).

### 1.1. Go Control Plane (shield-ctrl)
1. Khởi chạy bằng quyền đặc quyền để gắn XDP và nạp maps.
2. Mở cổng TLS Listener của Web API.
3. Thực hiện đổi quyền sở hữu (Chown) thư mục logs `/opt/shield-core/logs/` và thư mục pinned BPF maps `/sys/fs/bpf/shield_core/` sang user `nobody`.
4. Gọi `syscall.Setgid(65534)` và `syscall.Setuid(65534)` để hạ quyền vĩnh viễn tiến trình.
5. Phục vụ các API requests dưới tư cách user `nobody`.

### 1.2. AF_XDP Fastpath (shield-fastpath)
1. Đăng ký hàng đợi và ánh xạ UMEM bằng quyền root.
2. Đăng ký Socket FD vào bản đồ XSK BPF map (`xsks_map`).
3. Gọi `setgid(65534)` và `setuid(65534)` để chạy toàn bộ luồng IO/Worker dưới user không đặc quyền.

---

## 2. Thắt chặt Bảo mật bằng Systemd (Ambient Capabilities)

Để chạy dịch vụ `shield-ctrl` mà không cần quyền root ban đầu từ systemd, ta cấu hình Ambient Capabilities. Cơ chế này cho phép một user không đặc quyền (`nobody`) kế thừa các đặc quyền nhân (kernel capabilities) cần thiết cho eBPF:

* **`CAP_BPF`**: Cho phép tạo và cập nhật BPF maps, nạp chương trình eBPF.
* **`CAP_NET_ADMIN`**: Cho phép cấu hình các card mạng vật lý và điều phối các gói tin qua XDP.
* **`CAP_SYS_ADMIN`**: Cần thiết để tương tác với BPF filesystem (`/sys/fs/bpf`).

**Cấu hình bảo mật trong `shield-ctrl.service`:**
```ini
User=nobody
Group=nogroup
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN
NoNewPrivileges=no
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/sys/fs/bpf /opt/shield-core/logs /opt/shield-core/data /opt/shield-core/conf
```

---

## 3. Bảo mật Giao tiếp Cụm (HTTPS/TLS)

Toàn bộ quá trình đồng bộ hóa IP Blacklist giữa các node trong cluster được mã hóa bằng HTTPS:
* **Tự động sinh Chứng chỉ:** Lúc khởi động, nếu không tìm thấy file cấu hình SSL, Control Plane sẽ tự động tạo chứng chỉ SSL tự ký (`cert.pem`, `key.pem`) trong thư mục `conf/` bằng thuật toán mã hóa RSA-2048.
* **Xác thực API Key:** Mọi truy vấn đồng bộ hóa bắt buộc phải mang Header `X-API-Key` với mã khóa bảo mật tĩnh được lưu tại `config.json`.
* **InsecureSkipVerify:** Do sử dụng chứng chỉ tự ký (Self-signed) để triển khai nhanh mà không cần mua domain/SSL công cộng, client sync sử dụng cấu hình TLS `InsecureSkipVerify: true` nhưng dữ liệu (bao gồm cả API Key) vẫn được mã hóa 100% trên đường truyền bằng SSL/TLS, ngăn ngừa việc nghe trộm gói tin trên đường truyền mạng.

---

## 4. An toàn Cổng Quản trị (Admin Port Protection)

Một rủi ro cực lớn của các hệ thống tường lửa mạng tự động là việc hệ thống tự khóa (Self-Lockout) kết nối SSH hoặc API quản trị khi phát hiện tấn công giả mạo hoặc do lỗi cấu hình. Shield-Core ngăn ngừa lỗi này bằng cơ chế bypass cứng:
* **Cổng 22 (SSH)** và **Cổng 9090 (API HTTPS)** được định nghĩa bypass tĩnh ở cấp độ đầu tiên của eBPF:
  ```c
  if (dport == 22 || dport == 9090) {
      return XDP_PASS;
  }
  ```
  Nhờ đó, dù IP nguồn có bị rơi vào blacklist hay dính rate limit cực đoan, các gói tin gửi tới cổng 22 và 9090 vẫn luôn đi thẳng lên hệ điều hành, đảm bảo quản trị viên không bao giờ bị khóa SSH hay mất quyền truy cập Dashboard.
* **Bypass động (Local Ports Sync):** Control plane tự động quét các cổng TCP/UDP đang lắng nghe trên máy chủ và cập nhật vào `local_ports_map` để eBPF tự động bypass, bảo vệ các dịch vụ hợp lệ của server không bị lọc nhầm.
