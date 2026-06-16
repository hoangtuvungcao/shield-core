# Sổ tay Xử lý Sự cố (Troubleshooting)

Tài liệu này tổng hợp các lỗi phổ biến trong quá trình cài đặt, nâng cấp và vận hành Shield-Core trên hệ thống Linux, cùng các bước khắc phục chi tiết.

---

## 1. Lỗi Kernel Verifier từ chối nạp BPF Object

### Hiện tượng
Khi khởi động `shield-ctrl`, service báo lỗi và lập tức tắt:
```text
[CẢNH BÁO] Không thể load XDP program: lỗi khi load BPF object vào kernel: field XdpProgMain: program xdp_prog_main: load program: invalid argument...
```

### Nguyên nhân
1. **Lỗi Bounds Check:** eBPF Verifier yêu cầu kiểm tra ranh giới bộ nhớ chặt chẽ trước khi đọc/ghi gói tin. Nếu Clang tự động tối ưu hóa gộp thanh ghi hoặc thay đổi thứ tự lệnh, Verifier sẽ từ chối nạp vì nghi ngờ rủi ro tràn bộ nhớ.
2. **Không tương thích phiên bản Kernel:** File `xdp_main.o` được biên dịch sẵn trên một phiên bản Kernel khác và copy sang, không khớp các cấu trúc lõi của Kernel hiện tại.

### Cách khắc phục
* Luôn chạy biên dịch trực tiếp trên máy chủ đích để Clang sử dụng đúng kernel headers hệ thống:
  ```bash
  cd /opt/shield-core
  make clean
  make bpf
  systemctl restart shield-ctrl
  ```
* Nếu sửa mã nguồn C và gặp lỗi Verifier ở các cấu trúc TCP/UDP, hãy sử dụng rào cản tối ưu của Clang để giữ nguyên thứ tự bounds check:
  ```c
  asm volatile("" : "+r"(tcph));
  ```
  *(Rào cản này đã được áp dụng trong file `routing.h` của dự án để vượt qua verifier thành công trên Kernel 5.4/5.15).*

---

## 2. Dịch vụ AF_XDP Fastpath sập hoặc không bind được socket

### Hiện tượng
Log của `shield-fastpath` hiển thị lỗi `bind: Device or resource busy` hoặc sập ngay sau khi khởi động.

### Nguyên nhân
1. **Control Plane chưa chạy:** `shield-fastpath` cần các BPF maps đã được nạp và ghim (pinned) vào bộ nhớ ảo của hệ thống tại thư mục `/sys/fs/bpf/shield_core` bởi `shield-ctrl`.
2. **Trùng lặp Socket:** Một tiến trình fastpath khác đang chạy ngầm hoặc socket cũ chưa giải phóng hoàn toàn khỏi hàng đợi mạng.

### Cách khắc phục
1. Kiểm tra trạng thái của `shield-ctrl` xem có đang hoạt động hay không:
   ```bash
   systemctl status shield-ctrl
   ```
2. Kiểm tra xem maps đã được ghim thành công chưa:
   ```bash
   ls -la /sys/fs/bpf/shield_core
   ```
3. Khởi động lại dịch vụ theo đúng thứ tự (fastpath yêu cầu ctrl chạy trước):
   ```bash
   systemctl restart shield-ctrl
   sleep 1
   systemctl restart shield-fastpath
   ```

---

## 3. Lỗi thiếu headers khi biên dịch BPF

### Hiện tượng
Chạy `make bpf` báo lỗi thiếu file headers hệ thống như `asm/types.h` hoặc `stddef.h`.

### Cách khắc phục
Cài đặt đầy đủ gói Linux Kernel Headers tương ứng với phiên bản Kernel hiện tại của bạn:
```bash
sudo apt install -y linux-headers-$(uname -r) libc6-dev-i386
```

---

## 4. Cách cứu hộ mạng khẩn cấp (Emergency Rescue)

Nếu có bất kỳ sự cố kẹt mạng nghiêm trọng nào khiến bạn không thể truy cập hay kiểm soát hệ thống, hãy chạy lệnh sau để tháo gỡ hoàn toàn bộ lọc eBPF XDP khỏi card mạng:
```bash
sudo ip link set dev eth0 xdp off
```
*(Thay thế `eth0` bằng tên card mạng thực tế của bạn. Lệnh này sẽ tháo bộ lọc mạng XDP ngay lập tức ở mức phần cứng, đưa card mạng về chế độ xử lý mặc định của Linux).*
