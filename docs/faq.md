# Các Câu hỏi Thường gặp (FAQ)

Tổng hợp các câu hỏi và câu trả lời phổ biến về hệ thống lá chắn DDoS Shield-Core.

---

## 1. eBPF và XDP là gì? Tại sao chúng nhanh hơn iptables?
* **eBPF (Extended Berkeley Packet Filter):** Là công nghệ cho phép chạy các chương trình bytecode an toàn ngay bên trong nhân Linux mà không cần viết Kernel Module hay biên dịch lại nhân.
* **XDP (eXpress Data Path):** Là điểm móc (hook) sớm nhất trong luồng mạng Linux, nằm ngay tại Driver card mạng. 
* **Tại sao nhanh hơn:** Iptables hoạt động ở tầng rất cao của nhân, sau khi gói tin đã được chuyển đổi thành cấu trúc dữ liệu `sk_buff` phức tạp và đi qua nhiều bước phân tích định tuyến. XDP xử lý và có thể huỷ bỏ (`XDP_DROP`) gói tin xấu ngay khi mới nhận từ DMA ring của card mạng, giúp giảm thiểu 95% CPU tiêu hao so với iptables/nftables.

---

## 2. AF_XDP là gì? Nó giúp ích gì cho DPI?
AF_XDP là một họ socket mới của Linux được thiết kế cho việc xử lý gói tin hiệu năng cực cao. Nó cho phép chuyển tiếp gói tin trực tiếp từ card mạng lên User space (chế độ người dùng) thông qua các hàng đợi vòng đệm không sao chép (Zero-Copy).
Nhờ AF_XDP, chúng ta có thể viết các bộ quy tắc phân tích sâu Payload (DPI) bằng ngôn ngữ C/C++ ở User space mà không sợ làm sập nhân hệ điều hành (Kernel panic) nếu xảy ra lỗi logic, đồng thời tránh được độ trễ sao chép dữ liệu.

---

## 3. Hệ thống có hỗ trợ IPv6 không?
* **Hiện tại:** Shield-Core ưu tiên tối ưu hoá tuyệt đối hiệu năng cho **IPv4**.
* Các gói tin IPv6 và các giao thức mạng khác (như ARP) sẽ tự động được bỏ qua ở dòng đầu tiên của chương trình eBPF (`XDP_PASS`) để chuyển tiếp lên hệ điều hành Linux xử lý bình thường. Điều này tránh gây lỗi gián đoạn kết nối IPv6 của máy chủ.

---

## 4. Có thể cài đặt Shield-Core trên VPS ảo hoá không?
* **Có.** Shield-Core hoàn toàn chạy được trên các môi trường VPS (KVM, VMware, VirtIO).
* Tuy nhiên, do driver card mạng ảo hoá (`virtio_net`) thường không hỗ trợ Native XDP và Zero-Copy, hệ thống sẽ tự động chuyển về chạy ở chế độ **XDP Generic (SKB Mode)** và **Copy Mode**. Hiệu năng sẽ bị giới hạn ở khoảng 1 - 1.5 Mpps (triệu gói tin/giây) và tiêu tốn CPU của host hơn so với máy vật lý.

---

## 5. Làm thế nào để biết hệ thống đang thực sự chặn DDoS?
Bạn có thể theo dõi thống kê thông qua API `/api/stats` hoặc quan sát log trực tiếp trên console:
```bash
# Xem stats gói bị drop
curl -k -H "X-API-Key: ..." https://localhost:9090/api/stats

# Xem log các IP bị khoá tự động
curl -k -H "X-API-Key: ..." https://localhost:9090/api/logs
```
Nếu đang bị tấn công, số lượng `dropped` sẽ tăng lên rất nhanh (hàng vạn đến hàng triệu gói/giây) trong khi tải CPU của máy chủ thật vẫn duy trì ở mức thấp.
