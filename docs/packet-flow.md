# Luồng xử lý Gói tin (Packet Flow)

Tài liệu này mô tả chi tiết hành trình của một gói tin đi vào hệ thống Shield-Core từ card mạng vật lý đến khi được xử lý xong.

---

## Sơ đồ Quy trình Xử lý eBPF XDP Datapath

Dưới đây là luồng xử lý chi tiết từng bước của chương trình `xdp_main.c` khi một gói tin được nhận:

```text
               [ Gói tin đi vào NIC ]
                         |
                         v
            1. Kiểm tra biên bộ nhớ (Bounds Check)
                         |
                         v
          2. Loại bỏ IP Options (iph->ihl == 5 ?) ──[Không]──> [ XDP_DROP ]
                         | [Có]
                         v
         3. Tra cứu whitelist (ip_whitelist_map) ──[Tìm thấy]─> [ XDP_PASS ]
                         | [Không]
                         v
         4. Tra cứu blacklist (ip_blacklist_map) ──[Tìm thấy]─> [ XDP_DROP ]
                         | [Không]
                         v
        5. Tra cứu ASN Blacklist (LPM Trie) ──[Tìm thấy]─> [ XDP_DROP ]
                         | [Không]
                         v
      6. Tra cứu Country Blacklist (LPM Trie) ──[Tìm thấy]─> [ XDP_DROP ]
                         | [Không]
                         v
        7. Kiểm tra Giao thức (TCP/UDP/ICMP/IPIP?) ──[Không]──> [ XDP_PASS ]
                         | [Có]
                         +-----------------------------+
                         |                             |
                 [Giao thức IPIP]               [Giao thức TCP/UDP/ICMP]
                         |                             |
                         v                             v
             8. decapsulate_ipip()             9. Parse L4 Header (TCP/UDP/ICMP)
                         |                             |
                         v                             v
             Redirect về Client / AF_XDP       10. Bỏ qua Cổng Quản trị? (22, 9090, Local)
                                                       |
                                            [Không]    +───[Có]───> [ XDP_PASS ]
                                                       |
                                                       v
                                            11. Lọc giới hạn Tốc độ (Rate Limit) ─[Vượt]─> [ XDP_DROP ]
                                                       | [Hợp lệ]
                                                       v
                                            12. process_tcp_syncookie() (Nếu là TCP)
                                                       | [SYN] ──> Trả về SYN-ACK [ XDP_TX ]
                                                       | [Established / Valid ACK]
                                                       v
                                            13. A2S Query Cache (Nếu là UDP Steam Query)
                                                       | [Trùng khớp] ──> Trả về Cache [ XDP_TX ]
                                                       | [Expired] ──> Đẩy lên AF_XDP [ bpf_redirect_map ]
                                                       | [Không trùng khớp]
                                                       v
                                            14. encapsulate_ipip() (Định tuyến IPIP Backend)
                                                       | [Match VIP] ──> Encapsulate [ XDP_TX ]
                                                       | [No Match]
                                                       v
                                            15. Cho qua mặc định ───> [ XDP_PASS ]
```

---

## Chi tiết Từng Bước Xử lý

1. **Kiểm tra Biên (Bounds Check):** Trình kiểm duyệt eBPF (Verifier) bắt buộc chương trình phải kiểm tra độ dài gói tin (`data + offset > data_end`) trước khi đọc bất kỳ byte nào. Mọi gói tin lỗi hoặc bị cắt cụt đều bị huỷ (`XDP_DROP`).
2. **Loại bỏ IP Options:** Chỉ chấp nhận gói tin IPv4 có Header đúng 20 bytes (`ihl == 5`). Việc cấm IP Options bảo vệ hệ thống khỏi các cuộc tấn công khai thác lỗ hổng parser của hệ điều hành.
3. **Tra cứu Whitelist:** Nếu IP nguồn nằm trong `ip_whitelist_map`, gói tin được chuyển ngay cho Kernel (`XDP_PASS`) để đảm bảo không bị ảnh hưởng bởi các bộ lọc phía sau.
4. **Tra cứu Blacklist:** Nếu IP nguồn nằm trong `ip_blacklist_map`, gói tin bị huỷ ngay lập tức (`XDP_DROP`) và tăng biến thống kê rớt gói.
5. **Tra cứu ASN Blacklist:** Kiểm tra IP nguồn đối chiếu với cấu trúc LPM Trie chứa các dải mạng của ASN bị chặn.
6. **Tra cứu Country Blacklist:** Tương tự ASN, đối chiếu LPM Trie chứa dải IP của các quốc gia bị cấm.
7. **Kiểm tra Giao thức:** Hệ thống chỉ xử lý sâu các gói tin TCP, UDP, ICMP và IPIP. Các gói tin thuộc giao thức khác (như IGMP, OSPF) được chuyển thẳng cho OS xử lý (`XDP_PASS`).
8. **Giải bọc IPIP (`decapsulate_ipip`):** Khi gói tin IPIP nhận từ Backend quay trở lại, XDP tháo bỏ Outer Header, khôi phục Inner IP Header, hoán đổi địa chỉ MAC và gửi trả ngược ra ngoài card mạng (`XDP_TX`) hoặc đẩy lên AF_XDP (`bpf_redirect_map`) nếu cần cache lại phản hồi A2S.
9. **Phân tích L4 Header:** Phân tách cổng nguồn, cổng đích và các trường TCP Flags.
10. **Bỏ qua Cổng Quản trị (Admin Bypass):** Các gói tin đi tới cổng SSH (22), API HTTPS (9090) hoặc các cổng local đang lắng nghe (được đồng bộ tự động trong `local_ports_map`) sẽ được bỏ qua hoàn toàn, đi trực tiếp lên OS để tránh vô tình chặn kết nối của quản trị viên.
11. **Giới hạn Tốc độ (Rate Limiting):** Sử dụng thuật toán Token Bucket với PPS và BPS lấy động từ `config_map`. Nếu IP nguồn vượt ngưỡng, gói tin bị huỷ (`XDP_DROP`).
12. **Xử lý SYN Cookie (`process_tcp_syncookie`):** 
    * Nếu nhận gói SYN: XDP tự động sinh Cookie bảo mật và gửi trả ngay gói SYN-ACK chứa cookie (`XDP_TX`) mà không tiêu tốn bộ nhớ.
    * Nếu nhận gói ACK: Kiểm tra tính hợp lệ của Cookie. Nếu hợp lệ, cho qua (`XDP_PASS`). Nếu socket đã được thiết lập (`state != 10`), cũng cho qua trực tiếp. Nếu không hợp lệ, huỷ gói (`XDP_DROP`).
13. **Steam A2S Query Cache:** Nếu là truy vấn UDP tới game server, hệ thống tra cứu nhanh bản đồ Cache. Nếu khớp và còn hạn, tự sinh phản hồi và gửi trả ngược ra (`XDP_TX`). Nếu hết hạn, redirect lên AF_XDP (`bpf_redirect_map`) để fastpath tải phản hồi mới và lưu lại vào cache.
14. **Bọc gói IPIP (`encapsulate_ipip`):** Nếu IP đích là VIP được cấu hình trong `backend_map`, XDP sẽ tự động chèn thêm Outer IP Header với Source là Shield Node và Destination là IP Backend thật, rồi gửi trực tiếp ra ngoài card mạng (`XDP_TX`) hướng tới Backend.
15. **Cho qua Mặc định (Default Fallback):** Các gói tin sạch bình thường khác sẽ được trả về `XDP_PASS` để Linux Kernel Stack xử lý.
