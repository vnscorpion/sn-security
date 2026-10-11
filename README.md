# SN Secure

[![CI](https://github.com/vnscorpion/sn-security/actions/workflows/ci.yml/badge.svg)](https://github.com/vnscorpion/sn-security/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#giấy-phép)

Một binary Rust tĩnh (`sn`, ~3 MB) cấp cứu VPS Linux đang bị mã độc/traffic bẩn làm full CPU trong vài phút, rồi ở lại theo dõi traffic bằng systemd timer và báo về **hub trung tâm** (`snhub`) trên server của bạn. Không daemon nặng, không mở cổng trên VPS; phụ thuộc ngoài duy nhất của agent là `nftables` và cgroup (có sẵn trên mọi VPS hiện đại).

> **Trạng thái: bản 0.3.x (nền tảng).** Phần lõi đã chạy và biên dịch tĩnh (musl) cho amd64 + arm64: cấp cứu (`triage`/`contain`/`hunt`/`clean`/`undo`), theo dõi (`watch` observe/enforce), và hub (enroll, nhận báo cáo, desired-state ký ed25519, giao diện web). Một số phần là **v1.1/v2** (xem [docs/ROADMAP.md](docs/ROADMAP.md)): AI judgment, MCP, ban qua Cloudflare API, self-update do hub điều khiển, baseline dạng histogram, CloudLinux/OLS đầy đủ. **Bắt buộc test trên VPS thật và chạy `observe` vài ngày trước khi bật `enforce`** — xem [docs/RUNBOOK.md](docs/RUNBOOK.md).

## Tính năng

**Cấp cứu (chạy tay, không cần hub)**
- `triage` — ảnh chụp chỉ-đọc: top process theo CPU (đo delta 2 mẫu), exe thật/`(deleted)`, cwd, kết nối ra, persistence (cron/`ld.so.preload`/rc.local), disk/inode; gắn nhãn `miner`/`php-bot`/`ddos-l7`/`bruteforce`/`disk-full`/`mixed`/`unknown`.
- `contain` — nhốt process nghi ngờ vào cgroup 5% CPU (**cả cgroup v2 lẫn v1**), tuỳ chọn `--freeze`; **không bao giờ kill**; loại trừ dịch vụ hệ thống theo exe thật (miner đội tên `nginx` ở `/tmp` không thoát).
- `hunt` — quét webshell PHP bằng heuristic (source→sink, decode→eval, dropper, `preg_replace /e`, entropy, file PHP trong uploads/đuôi ảnh); nhận diện encoder thương mại (ionCube...) để tránh báo nhầm.
- `clean`/`quarantine`/`restore` — cách ly file giữ nguyên owner/mode/mtime, phục hồi được.
- `undo` — đảo ngược mọi contain/ban đã làm (log có cấu trúc `undo.jsonl`, không chạy shell).

**Theo dõi dài hạn (`watch`, systemd timer)**
- **Tự tìm log của web server** mỗi chu kỳ (nginx / Apache / LiteSpeed; DirectAdmin, cPanel, aaPanel...), không cần cấu hình theo từng VPS và tự đổi theo khi bạn chuyển web server. Chỉ đọc log của server ngoài cùng, bỏ file lỗi/nén.
- Đọc log tăng dần theo `(dev,inode,offset)`, nhận biết rotation; file log gặp lần đầu luôn bắt đầu từ cuối file; lấy IP thật sau Cloudflare/proxy.
- Cảnh báo cụ thể khi không đọc được log: không tìm thấy file, không đọc được, sai định dạng, hay log đứng im nhiều chu kỳ liền.
- Mẫu cố định: bruteforce, probe, scanner, bad_ua, xmlrpc_pingback; cộng ngưỡng truy cập tự học theo khung 15 phút (xem [Ngưỡng chặn IP](#ngưỡng-chặn-ip)).
- Ban nftables **chỉ cổng web**, TTL + leo thang theo số lần vi phạm (10 phút → 1 giờ → 24 giờ → 7 ngày); IPv6 gộp /64.
- Đo **RAM/swap** mỗi chu kỳ, cảnh báo khi RAM ≥ 90%.
- Hai chế độ **observe** (chỉ `would_ban`) / **enforce**; báo cáo ký số lên hub mỗi chu kỳ.

**Hub trung tâm (`snhub`)**
- Enroll token dùng một lần; nhận báo cáo (kiểm chữ ký); giữ & ký desired-state.
- Giao diện web tiếng Việt: tổng quan fleet (trạng thái, CPU, **RAM**, IP chặn, cảnh báo), chi tiết từng VPS (traffic, top IP, **danh sách IP đang bị chặn có lọc và phân trang**, triage, file nghi ngờ), nhật ký thao tác.
- **Ô "Tra cứu IP"** trên thanh đầu trang: một IP đang truy cập/bị chặn ở VPS nào, lịch sử thao tác, nút chặn/gỡ chặn.
- Nhận biết agent cũ (nhãn "cũ") và hiện sẵn lệnh cập nhật.
- **Điều khiển từ xa**: ban/unban, đổi observe↔enforce, **chạy hunt**, **undo** — áp ở chu kỳ kế (xem [Điều khiển từ hub](#điều-khiển-từ-hub)).
- Phân phối bộ cài + binary agent (kiểm sha256) cho các VPS.

**An toàn** — chống tự khoá admin, ban chỉ cổng web, pull model + ký ed25519 chống replay, tier chính sách cần root key offline (xem [An toàn](#an-toàn-những-bất-biến-đã-cài-trong-code)).

## Kiến trúc

```
   VPS 1 ─┐
   VPS 2 ─┤  sn (agent)  ──HTTPS pull──▶  snhub (master, server A)  ──▶  Web UI
   VPS N ─┘  triage/contain/hunt/watch       enroll · /report · /desired(ký)      admin
```

VPS **chủ động gọi lên hub** mỗi chu kỳ (5–15 phút): gửi báo cáo (ký bằng key riêng của VPS) và lấy desired-state (ký bằng key của hub). Hub không bao giờ gọi vào VPS. Chi tiết: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Yêu cầu

- **Hub (master):** Ubuntu 24.04 / Debian 12 (hay bản mới hơn) có systemd. Mặc định bind `127.0.0.1` — đặt sau VPN hoặc reverse proxy TLS.
- **Agent (VPS):** Linux với cgroup v2 hoặc v1 và `nftables` (installer tự cài nếu thiếu). Đã nhắm Ubuntu/Debian và AlmaLinux/Rocky; nginx / Apache / LiteSpeed (OpenLiteSpeed); panel DirectAdmin, cPanel, aaPanel, OPanel. **Đồng hồ VPS phải đúng** (HTTPS từ chối chứng chỉ nếu giờ lệch, xem [RUNBOOK](docs/RUNBOOK.md)).

## Quy trình làm việc

Từ lúc dựng tới lúc vận hành ổn định:

1. **Dựng hub** một lần trên server trung tâm → [Cài hub](#cài-hub-server-trung-tâm--ubuntu-2404--debian-12). Đặt mật khẩu admin, giấu root secret offline, đưa hub ra sau VPN/TLS.
2. **Thêm từng VPS** từ giao diện hub → [Thêm một VPS](#thêm-một-vps). Agent vào **observe** ngay, chưa ban gì.
3. **Theo dõi 3–7 ngày (observe)**: xem `would_ban` của mỗi VPS trên hub. Thấy IP hợp lệ (bot, CDN, nhà mạng, cổng thanh toán) thì thêm vào `[fw] whitelist` hoặc `trusted_proxies` trong `/etc/sn/agent.toml` (sửa trên VPS).
4. **Bật enforce** cho VPS đã sạch `would_ban` — ngay trên hub, không cần SSH ([Điều khiển từ hub](#điều-khiển-từ-hub)). Nên bật theo đợt: vài VPS nội bộ trước, rồi mở rộng.
5. **Vận hành hằng ngày từ hub**: ban/unban IP, đổi mode, bấm **Chạy hunt** để quét theo yêu cầu, **Undo** khi cần. Mọi thao tác vào nhật ký. `sn-hunt` cũng tự chạy mỗi 3h sáng.
6. **Khi một VPS gặp sự cố full CPU**: dùng ngay [cấp cứu chạy tay](#cấp-cứu-một-vps-đang-bị-chạy-tay) qua SSH (triage → contain → hunt → clean), rồi `undo` nếu cần. Không phụ thuộc hub.

Chi tiết từng tình huống (kill switch, VPS mất liên lạc, khôi phục hub, nâng cấp agent): [docs/RUNBOOK.md](docs/RUNBOOK.md).

## Cài hub (server trung tâm — Ubuntu 24.04 / Debian 12)

```sh
curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/main/deploy/install-hub.sh \
  | sudo bash -s -- --public-url https://hub.ten-mien-cua-ban.net
```

> **Nếu `raw.githubusercontent.com` trả 404** (repo để private), clone rồi cài từ file local, không cần raw:
> ```sh
> git clone https://github.com/vnscorpion/sn-security
> cd sn-security
> sudo bash deploy/install-hub.sh --local --public-url https://hub.ten-mien-cua-ban.net
> ```
> Agent không bị ảnh hưởng: bộ cài agent do **hub** phục vụ qua `public_url`, không lấy từ GitHub.

Script tải binary (kiểm sha256), tạo user `snhub`, sinh key (in **root secret offline** một lần — lưu ra ngoài server), cài `snhub.service`, và seed bộ cài agent để hub phục vụ cho các VPS. Sau đó:

```sh
# 1) Đặt mật khẩu admin
sudo -u snhub snhub --config /etc/snhub/snhub.toml set-admin-password --password 'MẬT_KHẨU_MẠNH'
sudo systemctl restart snhub

# 2) Đặt một reverse proxy TLS / VPN trước 127.0.0.1:8099, rồi mở giao diện web
```

> Hub mặc định bind `127.0.0.1`. **Đừng expose giao diện admin thẳng ra internet** — đặt sau VPN hoặc reverse proxy TLS có giới hạn IP. Giữ **root secret** ngoài server này (YubiKey / máy air-gapped).

## Thêm một VPS

Trên giao diện hub bấm **"Thêm VPS"** → nhập tên → copy lệnh cài (token dùng một lần, hết hạn 15 phút), dán vào VPS. Lệnh có dạng (`HUB` = URL hub của bạn):

```sh
curl -fsSL https://HUB/install.sh | sudo sh -s -- --hub https://HUB --name web-01 --token <TOKEN>
```

Bộ cài ghi `/etc/sn/agent.toml` ở **chế độ observe** (chỉ báo `would_ban`, chưa ban gì), enroll với hub, cài 2 timer (`sn-watch` mỗi 5 phút, `sn-hunt` lúc 3h sáng) và in ra những file log mà agent tự tìm được. Sau vài ngày `would_ban` sạch, bật **enforce** từ hub.

## Cập nhật

Khi có bản mới, cập nhật **hub trước, rồi từng VPS**. Mọi tải về đều kiểm sha256; cấu hình, khoá và dữ liệu giữ nguyên.

**1. Trên VPS master (hub)** — cập nhật binary hub và cả bản `sn` mà hub phục vụ cho các VPS:
```sh
curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/main/deploy/update-hub.sh | sudo bash
```
Script giữ bản cũ để quay lại, và tự khôi phục nếu hub không chạy lên được. Cuối cùng nó in sẵn lệnh ở bước 2 với địa chỉ hub của bạn.

**2. Trên từng VPS đã cài agent** (bằng root) — chỉ thay binary, không đụng cấu hình và timer:
```sh
curl -fsSL https://HUB/install.sh | sudo sh -s -- --hub https://HUB --upgrade
```
(`HUB` = địa chỉ hub của bạn. Trang VPS trên hub cũng hiện sẵn lệnh này khi agent cũ hơn hub.) Quay lại bản cũ nếu cần: `cp /usr/local/bin/sn.bak /usr/local/bin/sn`.

Trên hub, cột "Bản sn" ở Tổng quan có nhãn **"cũ"** cạnh agent chưa cập nhật.

## Kiểm tra nhanh trên VPS

```sh
sn env                                  # phiên bản, cgroup, nftables, whitelist, các file log agent đang theo dõi
systemctl start sn-watch.service        # chạy một chu kỳ ngay, không chờ timer
journalctl -u sn-watch -n 20 --no-pager # kết quả các chu kỳ gần đây
sn report                               # báo cáo gần nhất (JSON)
```
`sn env` hiện dòng `log sources (auto-detected; web server: nginx)` cùng số file khớp. Nếu hub báo cảnh báo về log, đây là lệnh đầu tiên cần chạy. Lần quét đầu tiên với một file log mới luôn đọc 0 dòng (cố ý: bắt đầu từ cuối file), số liệu thật xuất hiện từ chu kỳ kế tiếp.

## Điều khiển từ hub

Có — từ giao diện snhub bạn **đặt lệnh cho VPS mà không cần SSH**. Hub không gọi vào VPS; mọi lệnh chỉ ghi vào desired-state (ký số), VPS tự lấy và áp ở **chu kỳ kế tiếp (≤ 15 phút)** — đây là cái giá của việc không mở cổng trên VPS.

| Thao tác trên hub | Hiệu lực | Kiểm soát an toàn |
| --- | --- | --- |
| **Ban / Unban IP** (nhập tay hoặc nút cạnh top IP) | Agent áp vào nftables chu kỳ kế, TTL ≤ 24h | Chỉ cổng web; whitelist/trusted_proxies vẫn được loại trừ |
| **Đổi observe ↔ enforce** | Agent đổi chế độ chu kỳ kế | observe→enforce luôn được; enforce→observe cần `[remote] allow_mode_observe=true` (mặc định tắt) hoặc chữ ký root |
| **Quét ngay** (quét mã độc) | Agent chạy `sn hunt` trong một unit systemd riêng, ưu tiên thấp; kết quả lên hub ở báo cáo sau khi quét xong | Chạy một lần mỗi lần bấm; không chạy chồng hai lần quét |
| **Undo** (gỡ contain + ban của sn) | Agent chạy `sn undo` chu kỳ kế | Chỉ khi VPS bật `[remote] allow_undo=true` |

Tier chính sách (đổi `patterns`, `trusted_proxies`, ép observe hàng loạt) cần **chữ ký root key offline** — hub bị chiếm cũng không hạ được bảo vệ. `contain`/`fetch` từ xa là **v1.1** (hiện làm qua SSH). Cần tức thì tại chỗ thì dùng `sn disable` (kill switch) hoặc chạy lệnh qua SSH.

## Ngưỡng chặn IP

Mỗi chu kỳ (~5 phút) agent đếm các dòng log mới theo **từng IP** (IPv6 gộp theo /64) rồi áp các luật dưới đây theo thứ tự. Luật nào khớp trước thì dùng luật đó.

| Luật | Điều kiện (trong một chu kỳ) | Chặn trong |
| --- | --- | --- |
| `bruteforce` | **> 10** POST vào `wp-login.php` + `xmlrpc.php` | 1 giờ |
| `probe` | chạm **một** đường dẫn dò lỗ hổng: `/.env`, `/.git/`, `/phpmyadmin`, `/pma/`, `/wp-config.php.bak`, `/wp-config.php~`, `/.ds_store`, `/.aws/`, `/config.json`, `/.svn/`, `/vendor/phpunit` | 24 giờ |
| `scanner` | **> 30** lỗi 404 **và** **> 20** đường dẫn khác nhau | 30 phút |
| `bad_ua` | User-Agent công cụ tấn công (sqlmap, nikto, masscan, nmap, zgrab, dirbuster, wpscan, acunetix, nuclei, havij), hoặc có request UA rỗng khi tổng **> 50** request | 24 giờ |
| `rate` | số request của IP **≥ ngưỡng động** (bên dưới) | 10 phút |
| `xmlrpc_pingback` | **> 3** POST `xmlrpc.php` với UA `WordPress/` | chỉ báo, **không chặn** |

**Ngưỡng động của `rate`** = `max(min_requests, k × mức bình thường)`:
- `min_requests` mặc định **120** request/chu kỳ, `k` mặc định **5** (cả hai chỉnh được trong `[watch]` của `/etc/sn/agent.toml`).
- "Mức bình thường" là trung bình trượt của số request của **IP truy cập nhiều nhất** trong cùng khung 15 phút của ngày (96 khung/ngày). Khung chỉ được tin khi có ≥ 24 lần quan sát, với timer 5 phút nghĩa là khoảng **8 ngày**. Trước đó ngưỡng chỉ là `min_requests` = 120.

**Leo thang:** thời hạn chặn thực tế là mức lớn hơn giữa thời hạn của luật và bậc theo số lần vi phạm của IP đó: lần 1 → 10 phút, lần 2 → 1 giờ, lần 3 → 24 giờ, từ lần 4 → 7 ngày. Số lần vi phạm về 0 sau 7 ngày không vi phạm.

**Không bao giờ bị chặn:** IP trong `[fw] whitelist`, loopback, các IP của chính VPS, hub, phiên SSH/panel đang mở, IP vừa đăng nhập SSH, dải Cloudflare (`trusted_proxies`). Tối đa **200** lượt chặn mỗi chu kỳ; vượt thì dừng và báo cảnh báo khẩn. Ở chế độ **observe** các luật vẫn chạy nhưng chỉ ghi `would_ban`.

> **Giới hạn hiện tại — đọc trước khi bật enforce.**
> - Luật `rate` đếm **mọi** request, kể cả ảnh/CSS/JS. Một trang WordPress có thể kéo 30–100 file, nên 120 request/5 phút dễ bị khách bình thường vượt qua, nhất là nhiều người dùng chung một IP (văn phòng, mạng di động). Hãy xem `would_ban` ở chế độ observe ít nhất vài ngày trước khi bật chặn.
> - `/config.json` và `/phpmyadmin` trong luật `probe` cũng là đường dẫn hợp lệ của một số ứng dụng và của admin.
> - Chưa có danh sách bot tự miễn chặn: Googlebot, Bingbot... cần thêm tay vào `[fw] whitelist` (ví dụ `66.249.64.0/19` cho Googlebot).

## Quét mã độc

`sn hunt` quét **toàn bộ file PHP** trong `[hunt] allowed_roots` (mặc định `/home` và `/var/www`), cộng file `.php` giả đuôi ảnh trong `uploads/`. Mỗi file được chấm điểm bằng heuristic; **≥ 100 là "độc hại"**, **70–99 là "nghi ngờ"**.

```sh
sn hunt                 # quét ngay, in kết quả
sn clean --yes          # cách ly các file "độc hại" (khôi phục được: sn restore <id>)
```

Ba cách chạy: **tự động lúc 3 giờ sáng** (timer `sn-hunt`, ưu tiên CPU/IO thấp), **bấm "Quét ngay" trên hub**, hoặc chạy tay như trên. Kết quả (số file đã quét, số độc hại/nghi ngờ, danh sách file kèm đoạn mã trích ra) hiện ở mục **Quét mã độc** trên trang VPS; có file độc hại thì hub báo cảnh báo khẩn. Trang cũng cho biết "đã quét, không có gì" khác với "chưa quét lần nào".

**Nó bắt được gì:** request đi thẳng vào lệnh chạy mã/lệnh hệ thống (`eval`, `system`, `exec`, `call_user_func`...), biến lấy từ request rồi đưa vào các lệnh đó, request quyết định tên hàm được gọi, `eval` của dữ liệu đã giải mã (base64/gzinflate...), `preg_replace` với modifier `/e`, file ghi dữ liệu từ request ra đĩa, file PHP trong `uploads/` hoặc đuôi ảnh, blob base64/entropy cao.

**Độ chính xác đã đo, và chưa đo:**
- **Báo nhầm:** 0 trên **9.024 file PHP hợp lệ** (lõi WordPress, WooCommerce, Yoast SEO, Contact Form 7, Elementor). Con số này đo bằng công cụ `cargo run -p snsec-common --release --example scan_dir -- <thư mục>`, chạy lại mỗi khi sửa bộ chấm điểm. Phiên bản đầu từng báo nhầm 10 file "độc hại" trên cùng bộ này (kể cả file lõi WordPress); đã sửa.
- **Phát hiện:** mới kiểm trên các mẫu tự dựng của những dạng web shell phổ biến. **Chưa kiểm trên bộ mã độc thật**, nên không có số liệu tỷ lệ bắt được. Kết quả "sạch" không phải bằng chứng máy không bị nhiễm.

**Giới hạn:** chỉ quét file PHP (không quét database, không quét mã JavaScript bị chèn, không đối chiếu checksum lõi/plugin của WordPress); web shell dựng tên hàm bằng cách nối chuỗi (`$f = 'ev'.'al'; $f($x)`) chưa bắt được; file lớn hơn `max_file_mb` (5 MB) bị bỏ qua. `sn clean --yes` chỉ cách ly file "độc hại"; file "nghi ngờ" luôn để bạn xem tay. Heuristic có thể sai, nên đọc đoạn mã trích ra trước khi cách ly.

## Cấp cứu một VPS đang bị (chạy tay)

Không cần hub — tải binary về chạy trực tiếp:

```sh
sn triage            # ảnh chụp: process, kết nối ra, persistence, nhãn (miner/php-bot/ddos-l7/...)
sn contain           # nhốt process nghi ngờ vào cgroup 5% CPU (không kill), ban flood ở cổng web
sn hunt              # quét webshell PHP trong allowed_roots
sn clean --yes       # cách ly (quarantine) các file 'malicious' — hoàn tác được
sn undo              # trả lại nguyên trạng mọi thứ contain/ban đã làm
sn restore <id>      # phục hồi một file đã quarantine
```

Mọi thay đổi đều hoàn tác được (`sn undo`) và ghi vào `/var/lib/sn/undo.jsonl`. Các bước cấp cứu từng tình huống: [docs/RUNBOOK.md](docs/RUNBOOK.md).

## Lệnh `sn`

| Lệnh | Việc |
| --- | --- |
| `triage` | Ảnh chụp chỉ-đọc: process theo CPU, kết nối ra, cron/ld.so.preload, nhãn |
| `contain [--freeze] [--pid N] [--ban-flood] [--dry-run]` | Nhốt process vào cgroup 5% (v1+v2), ban flood cổng web |
| `hunt [--days N] [--root P] [--deep]` | Quét webshell PHP bằng heuristic |
| `clean --yes` / `quarantine <path>` / `restore <id>` / `list-quarantine` | Cách ly / phục hồi file |
| `undo` | Đảo ngược mọi hành động đã ghi |
| `watch [--replay FILE]` | Một chu kỳ theo dõi (tail log, đếm, ban/observe, báo hub) |
| `enroll --url --name --token` | Đăng ký với hub |
| `report` | In báo cáo gần nhất (JSON) |
| `env` | Phiên bản, cgroup, nftables, whitelist, **log đang theo dõi và web server đã dò ra** |
| `disable` | Kill switch: gỡ table `inet sn`, thả jail |

## An toàn (những bất biến đã cài trong code)

- **Ban từ log web chỉ chặn cổng 80/443** — một ban nhầm không bao giờ mất SSH/panel/FTP/mail.
- **Chống tự khoá admin**: whitelist tự động gồm loopback, mọi IP của chính VPS, hub, **phiên SSH/panel đang mở** (kể cả IPv6-mapped và cổng tùy biến), và IP từng đăng nhập SSH thành công gần đây.
- **Không kill, chỉ throttle**: `contain` chỉ giới hạn CPU; danh sách loại trừ (sshd/web/DB) xét theo exe hệ thống, nên miner đội tên `nginx` chạy từ `/tmp` không thoát.
- **Pull model + ký số**: desired-state ký ed25519 với envelope có `schema_version`/`epoch`/`seq`/`expires_at` (chống replay, chịu được lệch phiên bản). Tier chính sách cần chữ ký **root offline** riêng.
- **Undo có cấu trúc** (`undo.jsonl`, không phải shell script trên máy đã bị chiếm). Quarantine không bị `undo` khôi phục (phải `restore` tường minh).

Chi tiết mô hình đe doạ + giới hạn đã biết: [SECURITY.md](SECURITY.md).

## Cấu trúc repo

```
crates/
  common/   schema + ký ed25519 + parser log + heuristic PHP (dùng chung)
  sn/       agent trên VPS (triage/contain/hunt/clean/watch/enroll)
  snhub/    hub master (axum + SQLite, enroll/report/desired, UI web)
deploy/     install-hub.sh, install.sh, uninstall.sh, systemd/, *.toml.example
dist/       binary dựng sẵn (musl amd64+arm64) + SHA256SUMS cho install-hub.sh
rules/      patterns.yml, heuristics.yml (tài liệu rule đã nhúng trong binary)
docs/       ARCHITECTURE, SECURITY, RUNBOOK, ROADMAP, REVIEW
.github/    CI (fmt/clippy/test/build) + release (ký + checksum)
```

## Tài liệu

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — thành phần, giao thức, chu kỳ watch, cgroup, nftables
- [SECURITY.md](SECURITY.md) — mô hình đe doạ, bất biến đã cài, **giới hạn v1** (đọc trước khi enforce)
- [docs/RUNBOOK.md](docs/RUNBOOK.md) — cấp cứu, đưa VPS vào theo dõi, kill switch, khôi phục hub
- [docs/ROADMAP.md](docs/ROADMAP.md) — v1 / v1.1 / v2 và lộ trình triển khai thực tế
- [docs/REVIEW.md](docs/REVIEW.md) — các phát hiện review đã kiểm chứng và cách code xử lý

## Build từ nguồn

Workspace Cargo `snsec` gồm 3 crate: `common` (schema/ký/parser/heuristic), `sn` (agent), `snhub` (hub). Build tĩnh musl:

```sh
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
cargo install cargo-zigbuild      # cần zig
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo test --workspace            # chạy trên Linux

# Đo báo nhầm của bộ quét mã độc trên mã hợp lệ (vd. một bản WordPress giải nén):
cargo run -p snsec-common --release --example scan_dir -- /duong/dan/wordpress
```

## Giấy phép

MIT HOẶC Apache-2.0 — tuỳ bạn chọn. Xem [LICENSE-MIT](LICENSE-MIT) và [LICENSE-APACHE](LICENSE-APACHE).
