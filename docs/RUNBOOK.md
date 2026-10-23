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

## Sao lưu và khôi phục hub

Hai script: `deploy/backup-hub.sh` và `deploy/restore-hub.sh`. Backup là **một file mã hoá** (AES-256, khoá từ mật khẩu bạn đặt) chứa đúng những gì làm nên con master này:

| Trong file | Vì sao cần |
|---|---|
| `snhub.toml` | địa chỉ công khai, hash mật khẩu admin, `root_pubkey`, bật/tắt 2FA |
| `hub.key` | khoá mà **mọi VPS tin**; mất nó thì phải enroll lại từng VPS |
| `snhub.sqlite` | danh sách VPS, báo cáo, lệnh đã ký (`seq`/`epoch`), nhà cung cấp AI **và API key**, token Hermes, passkey, bí mật ứng dụng xác thực, mã khôi phục, luật WAF, nhật ký |
| `Caddyfile`, drop-in của `snhub.service` | cấu hình proxy và hardening (thêm chứng chỉ Caddy nếu dùng `--with-certs`) |

**Không** nằm trong file, có chủ đích: khoá **root offline** (`snhub init` in ra một lần: cất nơi bạn đang cất) và binary `snhub` cùng thư mục `public/` (cài lại bằng `install-hub.sh`/`update-hub.sh`).

File có `hub.key` và API key của AI, nên **đừng bỏ `--plain`** (không mã hoá) trừ khi bạn chỉ chép trong một ổ đã mã hoá. Mật khẩu không lưu ở đâu: mất mật khẩu là mất file.

### Sao lưu hằng ngày

```sh
# một lần, để thử (hỏi mật khẩu hai lần):
sudo bash backup-hub.sh
# hằng ngày bằng cron (giữ 14 file gần nhất trong /var/backups/snhub):
echo '17 3 * * * root SNHUB_BACKUP_PASSPHRASE="$(cat /root/.snhub-backup-pass)" bash /root/backup-hub.sh --keep 14' | sudo tee /etc/cron.d/snhub-backup
```

Tải file về chỗ khác (`scp`): backup chỉ nằm trên chính con master thì không cứu được khi máy mất. Backup trực tuyến không dừng hub (SQLite sao chép nguyên vẹn khi hub đang ghi); script tự kiểm tra bản sao bằng `PRAGMA integrity_check` và không lưu gì nếu bản sao hỏng.

### Chuyển master sang máy chủ mới

Nguyên tắc: **giữ nguyên tên miền** (`public_url`), hub key và cơ sở dữ liệu. Khi đó 7 hay 70 VPS không phải sửa gì: chúng vẫn gọi cùng địa chỉ, cùng tin cùng một khoá, và passkey vẫn dùng được vì gắn với tên miền.

1. **Trước 1 ngày:** hạ TTL của bản ghi DNS xuống 5 phút. Ghi lại bản hub đang chạy: `snhub --version` (cài đúng bản đó, hoặc mới hơn, trên máy mới).
2. **Máy mới:** cài hub như thường, đúng commit:
   ```sh
   curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/COMMIT/deploy/install-hub.sh \
     | sudo bash -s -- --repo-raw https://raw.githubusercontent.com/vnscorpion/sn-security/COMMIT --public-url https://TÊN-MIỀN-HUB
   ```
   Lệnh này tạo hub key, mật khẩu và khoá root **mới**: bỏ qua chúng, bước 5 sẽ thay bằng của master cũ. Chưa trỏ DNS vội.
3. **Master cũ, bản backup cuối:** dừng hub để lấy đúng một thời điểm và **để nó nằm yên**, nhờ vậy hub cũ không ký thêm lệnh nào mà bản backup không có (lệnh mới hơn sẽ làm `seq` bị lùi trên hub mới):
   ```sh
   sudo bash backup-hub.sh --quiesce --leave-stopped --with-certs --out /root/snhub-final.tar.gz.enc
   ```
   Từ lúc này VPS không gọi được hub: chúng tự thử lại, báo cáo nằm trong hàng đợi của agent. Làm tiếp các bước 4 đến 6 liền tay; nếu phải quay lại, `systemctl start snhub` trên máy cũ.
4. Chép file sang máy mới (`scp`).
5. **Máy mới:** `sudo bash restore-hub.sh snhub-final.tar.gz.enc --caddy` (máy chỉ chạy hub), hoặc `--caddy-add` nếu Caddy ở đó còn phục vụ site khác: chỉ thêm khối của hub (và chứng chỉ của nó), không đụng phần còn lại; `--caddy` sẽ **từ chối** khi thấy site khác, trước khi sửa bất cứ thứ gì. Script kiểm tra mật khẩu, checksum, `integrity_check` và phiên bản (từ chối nếu snhub trên máy mới **cũ hơn** bản backup), cất file của bản cài mới vào `/var/lib/snhub.before-restore-<giờ>` (không xoá gì), đặt đúng chủ sở hữu và quyền, rồi khởi động và chờ `/healthz`.
6. **Trỏ DNS** sang địa chỉ máy mới. Nếu đã chép chứng chỉ (`--with-certs`) thì HTTPS chạy ngay; nếu không, Caddy xin chứng chỉ mới ngay khi DNS trỏ tới, trong vài chục giây các lệnh gọi của VPS sẽ lỗi rồi tự hết.
7. **Kiểm tra:** đăng nhập bằng mật khẩu và passkey cũ; trang Tổng quan phải thấy mọi VPS báo cáo lại trong ~5 phút; Hermes vẫn dùng token cũ.
8. Trên máy cũ: `sudo systemctl disable snhub` để hub không tự bật lại khi khởi động. Giữ máy cũ và file backup thêm 1–2 ngày rồi mới huỷ.

Cần lưu ý:
- **Đổi tên miền** thì khác: mỗi VPS phải sửa `url` trong `/etc/sn/agent.toml` và hub phải ký lại. Tránh bằng cách giữ tên cũ.
- Nếu máy cũ có danh sách IP cho phép (trong Caddyfile, firewall của VPS hay IP cố định của Hermes), thêm IP máy mới trước khi trỏ DNS.
- Quay lui trong 1–2 ngày đầu: trỏ DNS về máy cũ và `systemctl enable --now snhub` ở đó. Dữ liệu hub mới đã ghi thêm (báo cáo, lệnh) sẽ mất, và `seq` của hub cũ có thể thấp hơn những gì agent đã nhận: xem mục "Khôi phục trên cùng máy" bên dưới.

### Khôi phục trên cùng máy (sự cố)

`sudo bash restore-hub.sh BACKUP --caddy` trên hub đã cài; hoặc thủ công: `systemctl stop snhub`, đặt lại `snhub.sqlite` và `hub.key` (`hub.key`: root:snhub 0640; DB: snhub 0600), `systemctl start snhub`. Nếu `seq` desired bị lùi do phục hồi một bản backup cũ, agent sẽ từ chối desired cũ hơn — cần tăng `epoch` bằng thông điệp ký **root** (tính năng epoch-reset: v1.1; tạm thời bump version trên hub cho tới khi vượt mốc cũ). Vì vậy bản backup cuối trước khi chuyển máy dùng `--quiesce`, và **test restore ít nhất một lần** (`deploy/tests/hub-backup-restore.sh` chạy cả vòng sao lưu và khôi phục trên một cây thư mục giả).

## Gỡ agent

```sh
sudo sh uninstall.sh          # giữ /var/lib/sn (quarantine)
sudo sh uninstall.sh --purge  # xoá hết
```
