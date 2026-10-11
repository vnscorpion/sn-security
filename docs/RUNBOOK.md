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

1. Hub → "Thêm VPS" → copy lệnh → dán vào VPS (mặc định **observe**).
2. Để observe 3–7 ngày. Trên hub xem `would_ban` của VPS; nếu có IP hợp lệ (bot, CDN, nhà mạng, IPN thanh toán) thì thêm vào `[fw] whitelist` trong `/etc/sn/agent.toml` (chỉ sửa trên VPS) hoặc chỉnh `trusted_proxies`.
3. Khi `would_ban` sạch: trên hub đổi **mode → enforce**. Áp dụng ở chu kỳ kế (≤ 15 phút).
4. Chỉ bật `auto_contain=true` sau khi đã tin tưởng, và không bao giờ trên máy đang thử nghiệm.

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

## Kill switch (ban nhầm hàng loạt / nghi hub bị chiếm)

- Trên VPS: `sn disable` — gỡ table `inet sn`, thả jail ngay. (Hoặc đổi mode→observe từ hub, nhưng đó là chu kỳ sau; `sn disable` là tức thì, tại chỗ.)
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
