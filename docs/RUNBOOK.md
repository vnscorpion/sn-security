# Runbook

## Cấp cứu một VPS đang full CPU

1. Dán lệnh (nếu chưa có `sn` trên máy — lệnh sinh từ hub kèm sha256):
   ```sh
   d=$(mktemp -d) && curl -fsSL https://HUB/sn/sn-x86_64 -o "$d/sn" && chmod +x "$d/sn" && "$d/sn" triage
   ```
   Nếu đã cài agent: chạy thẳng `sn triage`.
2. Đọc bảng triage: nhãn, process (exe thật, `(deleted)`, cwd, kết nối ra), persistence.
3. `sn contain` — nhốt process nghi ngờ vào cgroup 5% (không kill). Thêm `--freeze` khi chắc là miner. Thêm `--ban-flood` nếu nhãn `ddos-l7`.
4. `sn hunt` → xem findings → `sn clean --yes` để quarantine file `malicious`.
5. Việc tay: đổi mật khẩu WP admin/DB/FTP/SSH, cập nhật plugin/theme, kiểm user admin lạ, xem lại `authorized_keys`.
6. Khi xong hoặc đoán nhầm: `sn undo` (thả jail + gỡ ban), `sn restore <id>` (phục hồi file).

**Nếu `/etc/ld.so.preload` có nội dung**: `curl`/`sha256sum` có thể đã bị hook. Kiểm hash binary từ máy khác, hoặc dùng busybox tĩnh.

**disk-full giả nhưng không có mã độc**: triage gắn nhãn `disk-full` khi disk/inode ≥ 98%; xử lý log/cache trước.

## Đưa một VPS vào theo dõi

1. Hub → "Thêm VPS" → copy một dòng lệnh (đã kèm token) → dán vào VPS bằng root, xong. Token nằm trong biến môi trường chứ không nằm trong tham số lệnh; cài tự động thì xem README, mục "Thêm một VPS". Mặc định **observe**.
2. Để observe ít nhất 8 ngày, hoặc ít nhất tới khi trang VPS trên hub báo ngưỡng truy cập “Đã học” (`baseline_ready`) rồi thêm vài ngày. Trên hub xem `would_ban` của VPS; nếu có IP hợp lệ (bot, CDN, nhà mạng, IPN thanh toán) thì thêm vào `[fw] whitelist` trong `/etc/sn/agent.toml` (chỉ sửa trên VPS) hoặc chỉnh `trusted_proxies`. Mục “Chỉ ghi nhận, không chặn” là luật chỉ báo (hoặc `rate` khi ngưỡng còn đang học), không phải lệnh chặn sắp áp.
3. Khi `would_ban` sạch: trên hub đổi **mode → enforce**. Áp dụng ở chu kỳ kế (≤ 15 phút).

## Cài agent báo `SSL certificate problem: certificate is not yet valid`

Nguyên nhân là **đồng hồ của VPS bị chậm**, không phải lỗi hub: chứng chỉ Let's Encrypt chỉ có hiệu lực từ lúc được cấp, nên một VPS nghĩ giờ còn sớm hơn đó sẽ từ chối nó (hay gặp khi chứng chỉ vừa được cấp/gia hạn).

```sh
date -u && timedatectl                 # so với giờ UTC thật
sudo dnf install -y chrony || sudo yum install -y chrony   # AlmaLinux/Rocky/CentOS
sudo systemctl enable --now chronyd && sudo chronyc makestep
# Debian/Ubuntu:  sudo timedatectl set-ntp true
# Nếu NTP bị chặn: sudo date -u -s "YYYY-MM-DD HH:MM:SS"   (giờ UTC thật)
```
Sau đó tạo **token mới** trên hub (token dùng một lần, hết hạn sau 15 phút) rồi cài lại. Không dùng `curl -k`: nó tắt kiểm tra chứng chỉ trong khi script cài một binary chạy bằng root.

## Cảnh báo về log của web server (DirectAdmin, cPanel...)

Trên VPS chạy `sn env` để xem agent đang theo dõi file log nào:
```
log sources:
  /var/log/nginx/domains/*.log [combined] -> 12 file(s)
    - /var/log/nginx/domains/example.com.log (48213 bytes, readable)
```

| Cảnh báo trên hub | Nghĩa là | Cách xử lý |
| --- | --- | --- |
| Không tìm thấy file log nào khớp cấu hình | `glob` không khớp file nào | Sửa `[[watch.sources]]` cho đúng đường dẫn log |
| Có file log nhưng agent không đọc được | Không mở được file (quyền, SELinux) | Xem lỗi trong chi tiết cảnh báo; thử `sudo ls -lZ <file>` |
| Đọc được log nhưng sai định dạng | Hơn nửa số dòng không parse được | Đổi `format` (`combined` / `sn` / `nginx_json`) |
| Nhiều lần quét liền không có dòng log mới | Có kết nối web nhưng log đứng im ≥ 3 chu kỳ liền | Kiểm tra web server có ghi log vào đúng file không |

Lần quét đầu tiên sau khi cài **không** bị coi là lỗi: agent bắt đầu từ cuối file log (cố ý, để không đọc lại lịch sử rồi chặn hàng loạt), nên lần đó luôn đọc được 0 dòng.

### Log được chọn tự động (từ bản 0.3.0)

Agent **tự tìm log mỗi chu kỳ**, không cần cấu hình theo từng VPS: nó xem web server nào đang nghe cổng 80/443, rồi đọc log ở các vị trí quen thuộc của server đó.

| Web server | Nơi agent tìm log |
| --- | --- |
| nginx | `/var/log/nginx/domains/*.log` (DirectAdmin, Hestia), `/var/log/nginx/*access*.log`, `/www/wwwlogs/*.log` (aaPanel) |
| Apache | `/var/log/httpd/domains/*.log` (DirectAdmin), `/var/log/httpd/*access_log`, `/var/log/apache2/*access*.log`, `/usr/local/apache/domlogs/*` (cPanel), `/home/*/logs/*access*log` |
| LiteSpeed / OpenLiteSpeed | `/var/log/openlitespeed/*access*.log` (**OPanel**), `/usr/local/lsws/logs/*access*.log`, `/usr/local/apache/domlogs/*` (cPanel), `/home/*/logs/*access*log` (CyberPanel) |

- Chỉ đọc log của server **ngoài cùng**. Khi nginx đứng trước Apache (DirectAdmin `nginx_apache`), hai bên đều ghi mỗi request, đọc cả hai sẽ đếm đôi mỗi lượt truy cập.
- Chuyển web server sau khi đã cài agent (ví dụ Apache → nginx bằng custombuild) cũng tự đúng, không phải sửa gì.
- Bỏ qua file lỗi và file phụ: `*.error.log`, `*.bytes`, `*-bytes_log`, `*.gz`...
- `sn env` cho biết agent đã dò ra gì.
- Cấu hình cũ có `[[watch.sources]]` vẫn được giữ làm **phương án dự phòng** khi không dò ra gì.

Chỉ khi log nằm ở chỗ khác thường, đặt `sources_mode = "manual"` và liệt kê đường dẫn (các `[[watch.sources]]` phải nằm **cuối** mục `[watch]`):
```toml
[watch]
sources_mode = "manual"

[[watch.sources]]
glob   = "/duong/dan/rieng/*.log"
format = "combined"
```
**OPanel** (OpenLiteSpeed, Ubuntu 24.04) ghi mỗi website một file `/var/log/openlitespeed/<domain>.access.log` (định dạng `combined`, xoay vòng ở 100 MB); nếu dùng nginx thì `/var/log/nginx/<domain>.access.log`. File `*.error.log` và log lỗi PHP (`/var/log/opanel-php/...`) bị bỏ qua. Website đứng sau Cloudflare proxy sẽ thấy IP của Cloudflare trong log: các IP đó nằm trong `trusted_proxies` nên không bị đếm hay chặn nhầm, nhưng agent cũng không thấy IP khách thật.

## Kill switch (ban nhầm hàng loạt / nghi hub bị chiếm)

- Trên VPS: `sn disable` — gỡ table `inet sn`, thả jail, gỡ file luật WAF ngay (luật WAF giữ tắt tới khi chạy `sn waf-on`). (Hoặc đổi mode→observe từ hub, nhưng đó là chu kỳ sau; `sn disable` là tức thì, tại chỗ.)
- Gỡ một IP: trên hub, trang VPS → "Gỡ ban".

## VPS mất liên lạc

- Hub hiển thị "mất liên lạc" sau > 3 chu kỳ. Báo cáo được xếp hàng tại VPS (≤ 50 MB) và gửi bù khi có mạng. Kiểm `systemctl status sn-watch.timer`, `journalctl -u sn-watch`.

## Nâng cấp agent (v1: qua SSH/ansible)

```sh
curl -fsSL https://HUB/sn/sn-$(uname -m | sed 's/amd64/x86_64/;s/arm64/aarch64/') -o /tmp/sn.new
# kiểm sha256 với https://HUB/sn/SHA256SUMS, rồi:
install -m755 /tmp/sn.new /usr/local/bin/sn
sn --version && sn watch   # self-check một chu kỳ
```
Làm theo đợt (canary trước). Self-update do hub điều khiển là v1.1.

## Khôi phục hub

1. `systemctl stop snhub`
2. Khôi phục `/var/lib/snhub/snhub.sqlite` (+ `hub.key`) từ backup.
3. Nếu `seq` desired bị lùi do restore, agent sẽ từ chối desired cũ hơn — cần tăng `epoch` bằng thông điệp ký **root** (tính năng epoch-reset: v1.1; tạm thời bump version trên hub cho tới khi vượt mốc cũ).
4. `systemctl start snhub`. Backup SQLite hằng ngày và **test restore ít nhất một lần**.

## Gỡ agent

```sh
sudo sh uninstall.sh          # giữ /var/lib/sn (quarantine)
sudo sh uninstall.sh --purge  # xoá hết
```
