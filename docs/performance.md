# Tối ưu hóa Hiệu năng (Performance Tuning Guide)

Shield-Core được thiết kế để xử lý hàng triệu gói tin mỗi giây với độ trễ tối thiểu. Để đạt hiệu suất tối đa trong môi trường sản xuất tải cao, quản trị viên cần hiểu rõ và cấu hình các thông số tối ưu dưới đây.

---

## 1. Chế độ Hoạt động XDP (Driver Mode vs Generic Mode)

XDP hỗ trợ 3 chế độ nạp chương trình vào card mạng:

| Chế độ | Vị trí thực thi | Yêu cầu phần cứng | Hiệu năng |
| :--- | :--- | :--- | :--- |
| **XDP Native (Driver Mode)** | Ngay tại Driver card mạng trước khi tạo `sk_buff`. | Yêu cầu Driver hỗ trợ XDP (Intel, Mellanox, Broadcom...). | **Cực cao** (Lên tới 10-40 Mpps tùy dòng card). |
| **XDP Generic (SKB Mode)** | Nạp ở tầng mạng OS sau khi tạo `sk_buff`. | Hoạt động trên mọi card mạng (kể cả VPS ảo hoá virtio_net). | **Trung bình** (Khoảng 1.5 - 2 Mpps, tốn CPU để tạo skb). |
| **XDP Offloaded** | Trực tiếp trên phần cứng SmartNIC. | Yêu cầu card SmartNIC chuyên dụng (Netronome...). | **Tuyệt đối** (0% CPU tiêu tốn của Host). |

*Khuyến cáo:* Trong môi trường ảo hoá VPS, Shield-Core tự động fallback về **XDP Generic (SKB Mode)**. Để chống đỡ các đòn DDoS quy mô lớn (>5 Mpps), hệ thống bắt buộc phải được triển khai trên máy chủ vật lý (Bare-metal) sử dụng các dòng card mạng hỗ trợ Native XDP như Intel `i40e`, Mellanox `ConnectX-4/5/6`.

---

## 2. AF_XDP Zero-Copy vs Copy Mode

Khi chuyển hướng gói tin từ driver mạng lên User space qua AF_XDP:
* **Zero-Copy Mode:** Driver mạng ghi dữ liệu gói tin trực tiếp vào vùng nhớ dùng chung UMEM mà User space đã đăng ký. Bỏ qua hoàn toàn việc sao chép dữ liệu giữa Kernel và User space. Yêu cầu card mạng và driver hỗ trợ.
* **Copy Mode:** Hệ điều hành tự động sao chép gói tin từ socket buffer của kernel vào vùng nhớ UMEM. Hoạt động trên mọi driver nhưng tốn tài nguyên CPU hơn.

Trong log khởi động của `shield-fastpath`, nếu hệ thống báo:
`Zero-Copy không được hỗ trợ, chuyển sang DRV_MODE + COPY...`
Điều đó có nghĩa card mạng hiện tại đang chạy ở chế độ Copy Mode. Trên máy chủ vật lý, bạn nên tối ưu hóa driver card để kích hoạt chế độ Zero-Copy bằng cách phân chia hàng đợi (RSS Queues).

---

## 3. CPU Affinity (Định tuyến luồng xử lý CPU)

Dịch vụ `shield-fastpath` xử lý hàng đợi mạng bằng các luồng IO và Worker riêng biệt. Để tránh hiện tượng đổi ngữ cảnh (Context Switch) làm giảm tốc độ xử lý gói tin, bạn nên cấu hình ghim cứng các luồng này vào các nhân CPU độc lập (không chia sẻ với OS).

Trong file `/etc/systemd/system/shield-fastpath.service`, bạn có thể ghim nhân CPU bằng chỉ thị `CPUAffinity`:
```ini
[Service]
# Ghim tiến trình chạy riêng biệt trên nhân CPU số 2 và 3
CPUAffinity=2,3
```

---

## 4. Tinh chỉnh Thông số Hệ điều hành (System Tuning)

### 4.1. Bộ nhớ khóa (Locked Memory - Memlock)
eBPF Maps và AF_XDP UMEM yêu cầu cấp phát các vùng nhớ lớn được ghim cứng vào RAM và không được phép đưa vào bộ nhớ tráo đổi (swap).
* **Cấu hình:** Đặt `LimitMEMLOCK=infinity` trong các file dịch vụ systemd để tránh lỗi từ chối cấp phát maps khi nạp tập luật lớn.

### 4.2. Giới hạn số lượng File descriptor (NOFILE)
AF_XDP mở một socket file descriptor cho mỗi hàng đợi mạng, và API Server mở nhiều socket TCP cho các request đồng bộ.
* **Cấu hình:** Đặt `LimitNOFILE=65536` để đảm bảo hệ thống không bị lỗi cạn kiệt file descriptor khi bị spam kết nối.
