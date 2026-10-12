# SN Secure

[![CI](https://github.com/vnscorpion/sn-security/actions/workflows/ci.yml/badge.svg)](https://github.com/vnscorpion/sn-security/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#giấy-phép)

Một binary Rust tĩnh (`sn`, ~3 MB) cấp cứu VPS Linux đang bị mã độc/traffic bẩn làm full CPU trong vài phút, rồi ở lại theo dõi traffic bằng systemd timer và báo về **hub trung tâm** (`snhub`) trên server của bạn. Không daemon nặng, không mở cổng trên VPS; phụ thuộc ngoài duy nhất của agent là `nftables` và cgroup (có sẵn trên mọi VPS hiện đại).

> **Trạng thái: bản 0.4.x (nền tảng).** Phần lõi đã chạy và biên dịch tĩnh (musl) cho amd64 + arm64: cấp cứu (`triage`/`contain`/`hunt`/`clean`/`undo`), theo dõi (`watch` observe/enforce), và hub (enroll, nhận báo cáo, desired-state ký ed25519, giao diện web). Một số phần là **v1.1/v2** (xem [docs/ROADMAP.md](docs/ROADMAP.md)): AI judgment, MCP, ban qua Cloudflare API, self-update do hub điều khiển, baseline dạng histogram, CloudLinux/OLS đầy đủ. **Bắt buộc test trên VPS thật và chạy `observe` vài ngày trước khi bật `enforce`** — xem [docs/RUNBOOK.md](docs/RUNBOOK.md).

## Tính năng

**Cấp cứu (chạy tay, không cần hub)**
- `triage` — ảnh chụp chỉ-đọc: top process theo CPU (đo delta 2 mẫu), exe thật/`(deleted)`, cwd, kết nối ra, persistence (cron/`ld.so.preload`/rc.local), disk/inode; gắn nhãn `miner`/`php-bot`/`ddos-l7`/`bruteforce`/`disk-full`/`mixed`/`unknown`.
- `contain` — nhốt process nghi ngờ vào cgroup 5% CPU (**cả cgroup v2 lẫn v1**), tuỳ chọn `--freeze`; **không bao giờ kill**; loại trừ dịch vụ hệ thống theo exe thật (miner đội tên `nginx` ở `/tmp` không thoát).
- `hunt` — quét webshell PHP bằng heuristic (source→sink, decode→eval, dropper, `preg_replace /e`, entropy, file PHP trong uploads/đuôi ảnh); nhận diện encoder thương mại (ionCube...) để tránh báo nhầm.
- **AI xử lý sự cố**: hub nhờ mô hình AI bạn cấu hình (endpoint/model/key tuỳ ý; Hermes, Claude, OpenRouter, Ollama…) chẩn đoán từ bằng chứng agent thu thập và đề xuất hành động (cách ly file, khoá shell, gỡ dòng độc, tắt dịch vụ, dừng tiến trình), bạn duyệt hoặc cho tự xử — xem [AI xử lý sự cố](#ai-xử-lý-sự-cố-hub--agent).
- **ClamAV tuỳ chọn** làm engine thứ hai cho `hunt`; hub có nút **Cài ClamAV** (agent tự chọn công thức theo hệ điều hành, mặc định tắt vì chạy trình quản lý gói bằng root) — xem [ClamAV](#clamav-engine-thứ-hai-tuỳ-chọn).
- `clean`/`quarantine`/`restore` — cách ly file giữ nguyên owner/mode/mtime, phục hồi được.
- `undo` — đảo ngược mọi contain/ban đã làm (log có cấu trúc `undo.jsonl`, không chạy shell).

**Theo dõi dài hạn (`watch`, systemd timer)**
- **Tự tìm log của web server** mỗi chu kỳ (nginx / Apache / LiteSpeed; DirectAdmin, cPanel, aaPanel...), không cần cấu hình theo từng VPS và tự đổi theo khi bạn chuyển web server. Chỉ đọc log của server ngoài cùng, bỏ file lỗi/nén.
- Đọc log tăng dần theo `(dev,inode,offset)`, nhận biết rotation; file log gặp lần đầu luôn bắt đầu từ cuối file; lấy IP thật sau Cloudflare/proxy.
- Cảnh báo cụ thể khi không đọc được log: không tìm thấy file, không đọc được, sai định dạng, hay log đứng im nhiều chu kỳ liền.
- Mẫu cố định: bruteforce, probe, scanner, bad_ua, xmlrpc_pingback; cộng ngưỡng truy cập tự học theo khung 15 phút (xem [Ngưỡng chặn IP](#ngưỡng-chặn-ip)).
- Ban nftables **chỉ cổng web**, TTL + leo thang theo số lần vi phạm (10 phút → 1 giờ → 24 giờ → 7 ngày); IPv6 gộp /64.
- Đo **RAM/swap** mỗi chu kỳ, cảnh báo khi RAM ≥ 90%.
- **CPU cao liên tục** (≥ `cpu_alert_pct`, mặc định 85%, 2 chu kỳ liền) kèm **tài khoản và chương trình đang dùng CPU**.
- **Bot phân tán**: cùng một User-Agent hoặc kiểu request tăng vọt từ nhiều IP khác nhau (xem [Bot phân tán](#bot-phân-tán-và-cpu-cao)).
- Hai chế độ **observe** (chỉ `would_ban`) / **enforce**; báo cáo ký số lên hub mỗi chu kỳ.

**Hub trung tâm (`snhub`)**
- Enroll token dùng một lần; nhận báo cáo (kiểm chữ ký); giữ & ký desired-state.
- Giao diện web tiếng Việt: tổng quan fleet (trạng thái, CPU, **RAM**, IP chặn, cảnh báo), chi tiết từng VPS (traffic, top IP, **danh sách IP đang bị chặn có lọc, 10 IP mỗi trang**, triage, kết quả quét mã độc), nhật ký thao tác.
- **Quét mã độc trên hub**: kết quả lần quét cuối (số file đã quét, độc hại/nghi ngờ), danh sách file **10 mỗi trang**, **tải CSV** (tất cả) hoặc **`.txt`** (đường dẫn file độc hại) — xem [Quét mã độc](#quét-mã-độc).
- **Bot phân tán và CPU**: bảng User-Agent / kiểu request nhiều nhất (số lượt, số IP khác nhau), cảnh báo khi một mục tăng vọt từ nhiều IP, **luật ModSecurity gợi ý** để dán (hub không tự ghi), bảng "Ai đang dùng CPU" — xem [Bot phân tán và CPU cao](#bot-phân-tán-và-cpu-cao).
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

Script tải binary (kiểm sha256), tạo user `snhub`, sinh key (in **root secret offline** một lần — lưu ra ngoài server), cài `snhub.service`, và seed bộ cài agent để hub phục vụ cho các VPS. Chạy lại trên hub đang chạy: hub dừng trong lúc cài và được chạy lại nếu script lỗi giữa chừng.

Quyền file: `/var/lib/snhub` (0700) chỉ user `snhub` vào được, database `snhub.sqlite*` 0600 (chứa API key AI, khoá 2FA, hash mật khẩu admin, token cài đang hiệu lực), `/etc/snhub` 0750. `public/` (binary agent, `install.sh`, `SHA256SUMS` mà mọi VPS chạy bằng root) và `hub.key` thuộc **root**: service chỉ đọc (`ReadOnlyPaths=` trong `snhub.service`), chỉ script cài/cập nhật (chạy bằng root) mới ghi được. Sau đó:

```sh
# 1) Đặt mật khẩu admin
sudo -u snhub snhub --config /etc/snhub/snhub.toml set-admin-password --password 'MẬT_KHẨU_MẠNH'
sudo systemctl restart snhub

# 2) Đặt một reverse proxy TLS / VPN trước 127.0.0.1:8099, rồi mở giao diện web
```

> Hub mặc định bind `127.0.0.1`. **Đừng expose giao diện admin thẳng ra internet** — đặt sau VPN hoặc reverse proxy TLS có giới hạn IP. Giữ **root secret** ngoài server này (YubiKey / máy air-gapped).

### Bảo mật đăng nhập hub

Hub điều khiển được mọi VPS, nên đăng nhập hub được bảo vệ nhiều lớp. Mở **Bảo mật** trên thanh menu:

- **Trạng thái hiện tại:** xác thực hai bước đang **tắt mặc định** (chưa ổn định); muốn thử thì đặt `two_factor = true` trong `/etc/snhub/snhub.toml` rồi khởi động lại hub. Khi tắt, đăng nhập chỉ cần mật khẩu (vẫn Argon2id, chống dò, phiên có hạn), nên nên cài thêm **fail2ban** (bên dưới).
- **Xác thực hai bước**: ứng dụng xác thực (Google Authenticator, Authy, 1Password… quét mã QR) và/hoặc **passkey** (vân tay, khuôn mặt, khoá bảo mật). Đã bật thì mật khẩu đúng vẫn chưa vào được hub: phải qua bước hai (5 phút, tối đa 5 lần thử). Mã ứng dụng dùng một lần (không dùng lại được trong cùng 30 giây).
- **Mã khôi phục** (8 mã dạng `xxxxx-xxxxx-xxxxx`, mỗi mã một lần, chỉ hiện đúng một lần) cho lúc mất điện thoại. Mất cả mã: trên máy chủ chạy `sudo -u snhub snhub --config /etc/snhub/snhub.toml reset-2fa` (xoá mọi cách xác thực thứ hai, giữ mật khẩu). Mã bị từ chối khi bật: trang Bảo mật hiện ngay mã hub đang tính để so với ứng dụng, và `sudo -u snhub snhub --config /etc/snhub/snhub.toml totp-now` in cùng thông tin trên máy chủ. Nếu đồng hồ máy chủ lệch (tới ±5 phút), hub tự học độ lệch lúc bật và bù khi đăng nhập.
- **Passkey cần HTTPS**: đặt `public_url = "https://..."` trong `/etc/snhub/snhub.toml` (đúng tên miền bạn mở hub). Chỉ hỗ trợ khoá ES256 (hầu hết thiết bị hiện nay), không đòi chứng thực thiết bị.
- **Mật khẩu**: băm Argon2id; tối thiểu 10 ký tự; đổi ngay trong trang Bảo mật (đăng xuất mọi phiên khác). Mọi thay đổi (đổi mật khẩu, thêm/xoá passkey, bật/tắt 2FA, mã khôi phục mới) đều hỏi lại mật khẩu hiện tại.
- **Chống dò mật khẩu**: sai quá 5 lần (tính ngay khi nhận yêu cầu, kể cả gửi song song) thì khoá theo địa chỉ IP 30 giây, tăng gấp đôi mỗi lần sai tiếp (tối đa 15 phút); nếu bị dò từ nhiều nơi cùng lúc, hub tạm dừng mọi đăng nhập vài phút. Hub lấy IP khách từ mục cuối của `X-Forwarded-For` (mục do reverse proxy của bạn thêm; IPv6 gộp theo /64), nên chỉ để hub sau đúng một proxy tin cậy (Caddy/Nginx), đừng mở cổng hub thẳng ra internet. Nếu bị dò từ nhiều nơi cùng lúc, bước nhập mật khẩu tạm dừng vài phút, còn bước hai của người đã đúng mật khẩu vẫn vào được.
- **Phiên đăng nhập** hết hạn sau 24 giờ (hoặc 8 giờ không hoạt động), cookie `HttpOnly`, `SameSite=Strict`, thêm `Secure` khi `public_url` là HTTPS; trang Bảo mật liệt kê các phiên đang mở và nhật ký đăng nhập gần đây để đăng xuất từng phiên. Các yêu cầu ghi từ trình duyệt phải cùng nguồn (trình duyệt tự khai `Sec-Fetch-Site`, hoặc so `Origin` với `Host`/`X-Forwarded-Host`/`public_url`).

**fail2ban cho hub** (chặn IP đoán sai mật khẩu ở cổng 80/443, không đụng SSH): hub ghi một dòng `snhub-auth login-failed ip=...` mỗi lần đoán sai vào nhật ký của `snhub.service`, và script này cài fail2ban với bộ lọc tương ứng:

```sh
curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/COMMIT/deploy/install-fail2ban.sh | sudo bash -s -- --ignoreip IP_CỦA_BẠN
```

Mặc định 8 lần sai trong 10 phút thì chặn 1 giờ (`--maxretry`, `--findtime`, `--bantime`); luôn đặt IP của chính bạn vào `--ignoreip`. Gỡ: thêm `--uninstall`. Nếu hub nằm sau Cloudflare thì IP hub thấy là của Cloudflare, nên fail2ban sẽ chặn nhầm: dùng rate limit của Cloudflare thay thế.

Hub cập nhật từ bản trước: mật khẩu cũ vẫn dùng được (kể cả kiểu băm cũ); đặt lại bằng `set-admin-password` sẽ chuyển sang Argon2id.

## Thêm một VPS

Trên giao diện hub bấm **"Thêm VPS"** → nhập tên → hub hiện lệnh cài và, ở ô riêng bên dưới, **token** (dùng một lần, hết hạn 15 phút). Copy lệnh, dán vào VPS. Lệnh có dạng (`HUB` = URL hub của bạn):

```sh
curl -fsSL https://HUB/install.sh | sudo sh -s -- --hub https://HUB --name web-01
```

Bộ cài hỏi token: dán token vào khi được hỏi. Token không nằm trên dòng lệnh nào nên các user khác trên VPS không đọc được qua danh sách tiến trình (`ps`, `/proc`), và sudo không ghi nó vào nhật ký; bộ cài chuyển nó cho `sn enroll` qua biến môi trường `SN_ENROLL_TOKEN` (chỉ root đọc được). Trên máy hub, `snhub add-vps --name web-01` in lệnh cùng dạng và token ở dòng `Token:` riêng.

**Cài tự động (không có terminal):** gán token cho `SN_ENROLL_TOKEN` bằng `export` trong shell hoặc script chạy bộ cài, không bao giờ đặt nó trên một dòng lệnh, rồi:

- chạy bằng root (shell root, script cloud-init), không qua sudo:
  ```sh
  export SN_ENROLL_TOKEN=<TOKEN>
  curl -fsSL https://HUB/install.sh | sh -s -- --hub https://HUB --name web-01
  ```
- qua sudo: `export SN_ENROLL_TOKEN=<TOKEN>` như trên, rồi
  ```sh
  curl -fsSL https://HUB/install.sh | sudo --preserve-env=SN_ENROLL_TOKEN sh -s -- --hub https://HUB --name web-01
  ```
  Token không lên danh sách tiến trình, nhưng sudo ghi giá trị biến vào nhật ký của nó (`ENV=SN_ENROLL_TOKEN=…`, chỉ root và nhóm `adm` đọc được). Token dùng một lần nên hết giá trị ngay khi VPS enroll xong.

Đừng dùng `sudo SN_ENROLL_TOKEN=… sh …` hay `sudo env SN_ENROLL_TOKEN=… sh …`: token khi đó nằm trên dòng lệnh của sudo suốt lúc cài, user nào trên VPS cũng đọc được. Lệnh cũ có `--token <TOKEN>` vẫn chạy nhưng bộ cài cảnh báo vì cùng lý do.

Bộ cài ghi `/etc/sn/agent.toml` ở **chế độ observe** (chỉ báo `would_ban`, chưa ban gì), enroll với hub, cài 2 timer (`sn-watch` mỗi 5 phút, `sn-hunt` lúc 3h sáng) và in ra những file log mà agent tự tìm được. Sau vài ngày `would_ban` sạch, bật **enforce** từ hub.

## Cập nhật

Khi có bản mới, cập nhật **hub trước, rồi từng VPS**. Mọi tải về đều kiểm sha256; cấu hình, khoá và dữ liệu giữ nguyên.

> **sha256 chỉ bắt file hỏng hoặc lẫn bản khi tải, không chứng minh nguồn gốc.** `SHA256SUMS` lấy từ cùng nhánh `main` với binary, nên ai push được `main` là quyết định binary của hub và, qua hub, của mọi VPS (bản phát hành có chữ ký: SEC-5 trong [docs/REVIEW.md](docs/REVIEW.md), chưa làm). Muốn chỉ cài đúng bản đã xem: cố định theo commit như ở cuối mục này.

**1. Trên VPS master (hub)** — cập nhật binary hub và cả bản `sn` mà hub phục vụ cho các VPS:
```sh
curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/main/deploy/update-hub.sh | sudo bash
```
Script giữ bản cũ để quay lại, và tự khôi phục nếu hub không chạy lên được. Cuối cùng nó in sẵn lệnh ở bước 2 với địa chỉ hub của bạn. Hub dừng vài giây trong lúc thay file; nếu script lỗi giữa chừng, nó chạy lại hub trước khi thoát. Script cũng đưa quyền file của bản cài cũ về như bản cài mới (xem [Cài hub](#cài-hub-server-trung-tâm--ubuntu-2404--debian-12)), thêm `/etc/systemd/system/snhub.service.d/10-hardening.conf` (`UMask=0077`, `public/` và `hub.key` chỉ đọc với service) mà không ghi đè `snhub.service` bạn đã sửa, và dựng lại `public/` từ đầu: chỉ còn 4 file hub phục vụ cho VPS, không giữ gì bản cũ để lại trong đó.

**2. Trên từng VPS đã cài agent** (bằng root) — thay binary, giữ nguyên cấu hình, khoá và timer (chỉ nâng giới hạn RAM của timer quét hằng đêm từ 256 MB lên 2 GB để chạy được ClamAV, và đặt lại `/var/lib/sn` về 0700 để bằng chứng, báo cáo và file cách ly chỉ root đọc được):
```sh
curl -fsSL https://HUB/install.sh | sudo sh -s -- --hub https://HUB --upgrade
```
(`HUB` = địa chỉ hub của bạn. Trang VPS trên hub cũng hiện sẵn lệnh này khi agent cũ hơn hub.) Quay lại bản cũ nếu cần: `cp /usr/local/bin/sn.bak /usr/local/bin/sn`.

Trên hub, cột "Bản sn" ở Tổng quan có nhãn **"cũ"** cạnh agent chưa cập nhật.

> **Lệnh báo "checksum FAILED" ngay sau khi vừa có bản mới?** `raw.githubusercontent.com` lưu đệm vài phút nên có thể trả `SHA256SUMS` cũ lẫn với binary mới. Đợi vài phút rồi chạy lại, hoặc cố định theo commit (thay `COMMIT` bằng mã commit của bản cần cài):
> ```sh
> curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/COMMIT/deploy/update-hub.sh | sudo bash -s -- --repo-raw https://raw.githubusercontent.com/vnscorpion/sn-security/COMMIT
> ```

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
| **Đổi observe ↔ enforce** | Agent đổi chế độ chu kỳ kế | Hub quyết định cả hai chiều |
| **Quét ngay** (quét mã độc) | Agent chạy `sn hunt` trong một unit systemd riêng, ưu tiên thấp; kết quả lên hub ở báo cáo sau khi quét xong | Chạy một lần mỗi lần bấm; không chạy chồng hai lần quét |
| **Undo** (gỡ contain + ban của sn) | Agent chạy `sn undo` chu kỳ kế | Hub quyết định |

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

## AI xử lý sự cố (hub + agent)

Luật cố định không viết hết được các biến thể kiểu: miner giả tiến trình `[kworker/0:1Z]`, mã độc cài trong `.bashrc`, công cụ đào trong `/dev/shm`, đăng nhập SSH lạ, cổng 111 mở công khai. Hub vì thế có thể nhờ một mô hình AI do bạn cấu hình làm "bộ não": agent thu thập bằng chứng, AI chẩn đoán và đề xuất hành động, bạn duyệt (hoặc cho phép tự xử), agent thực hiện.

**1. Cài đặt AI (`/settings` trên hub).** Tự nhập **endpoint, model, API key**, không gắn cứng nhà cung cấp nào:
- **OpenAI-compatible**: Hermes (Nous Portal, OpenRouter, vLLM, Ollama `/v1`, LiteLLM…), OpenAI… Nhập địa chỉ gốc (ví dụ `https://openrouter.ai/api/v1`) hoặc đầy đủ tới `/chat/completions`.
- **OpenAI Responses API** (`wire_api = "responses"` trong Codex): endpoint `…/v1/responses`, gửi `instructions` + `input`. Hub đọc được cả câu trả lời dạng `output_text`/`output[]` lẫn dạng chat, và cả luồng SSE. Hermes chạy trên máy bạn thì dùng `http://127.0.0.1:11434/v1`, key có thể để trống.
- **Anthropic (Claude)**: để trống endpoint thì dùng `api.anthropic.com`.
- Có nút **Thử kết nối**, đặt mặc định, sửa (để trống key = giữ key cũ), xoá. Dưới mỗi nhà cung cấp hub hiện **URL sẽ gọi**; khi lỗi, thông báo nêu mã HTTP, loại nội dung, URL đã gọi và đoạn đầu phản hồi. “Phản hồi không phải JSON … trang web (HTML)” gần như luôn là endpoint sai (thiếu `/v1`, hoặc trỏ vào giao diện web của dịch vụ thay vì API); hub không theo chuyển hướng (để không gửi key sang máy khác) nên báo địa chỉ đích để bạn nhập lại. API key lưu nguyên văn trong file SQLite của hub (chỉ user chạy hub đọc được) vì hub phải dùng nó; trang chỉ hiện 4 ký tự cuối.

**2. Luồng làm việc.** Trên trang VPS có khung **"AI xử lý sự cố"**:
1. Bấm **Phân tích bằng AI** (hoặc để hub tự gọi khi có sự cố: cảnh báo `cpu_high`, `malware_found`, `ban_cap`, hoặc nhãn triage `miner`/`php-bot`/`mixed`; tối đa một lần mỗi 30 phút mỗi VPS). Hub ra lệnh cho agent thu thập **bằng chứng** (chỉ đọc), VPS gửi về trong ~5–15 phút.
2. Hub gửi bằng chứng cho AI. AI trả về chẩn đoán và danh sách hành động; hub loại những đề xuất không hợp lệ.
3. Bạn thấy chẩn đoán, từng hành động kèm **mức rủi ro** và lý do, rồi bấm **Thực hiện** từng việc hoặc **Thực hiện tất cả**. Hub gửi một lệnh ký số cho agent; kết quả từng hành động hiện lại trong khung.

**Bằng chứng agent thu thập** (`sn evidence`): tiến trình đáng ngờ (kể cả tên giả tiến trình nhân `[kworker]` nhưng có chương trình thật), kết nối ra ngoài, các **dòng đáng ngờ** trong file khởi động shell của các tài khoản (`.bashrc`, `.profile`, `.zshrc`… không gửi cả file), cron và `ld.so.preload`, `authorized_keys` (không gửi khoá), chương trình biên dịch/thực thi lạ trong `/dev/shm`, `/tmp`, `/var/tmp` và thư mục ẩn trong home, các lần đăng nhập SSH thành công gần đây, cổng đang lắng nghe ngoài loopback, tài khoản có shell. **Không** gửi nội dung website hay database. **Lưu ý:** dòng lệnh tiến trình và các dòng khởi động/cron có thể chứa mật khẩu hoặc token gõ trên dòng lệnh; agent che các dạng phổ biến (`password=…`, `--token`, `-pMẬT_KHẨU`, `user:pass@host`, `Bearer …`) nhưng **không đảm bảo che hết**, và bằng chứng cũng lưu trong database của hub. Muốn tránh gửi ra ngoài thì dùng model chạy trên máy bạn. Xem đúng những gì AI nhận được ở `/agent/<id>/evidence.json`.

**Hành động AI được phép đề xuất** (danh sách đóng, không có "chạy lệnh tuỳ ý"):

| Hành động | Rủi ro | Hoàn tác |
| --- | --- | --- |
| Cách ly file (`/dev/shm`, `/tmp`, `/var/tmp`, thư mục ẩn trong `/home`) | thấp | `sn restore <id>` |
| Khoá shell một tài khoản thường (UID ≥ 1000, **không** phải tài khoản sudo/wheel) | vừa | `sn undo --remediation` |
| Gỡ một dòng khỏi file khởi động shell của tài khoản (có bản sao lưu) | vừa | `sn undo --remediation` |
| Tắt một dịch vụ trong danh sách, chỉ khi đang lắng nghe cổng tương ứng (rpcbind:111, cups:631, telnet, rsh, rexec) | vừa | `sn undo --remediation` |
| Dừng một tiến trình (SIGKILL), chỉ khi có dấu hiệu mạnh: tên giả tiến trình nhân, dấu hiệu miner, hoặc chạy từ `/tmp`, `/dev/shm`, thư mục ẩn trong `/home` | cao | **không** |
| Dừng **mọi tiến trình giả danh** của một tài khoản chạy một chương trình (`kill_matching`, vd. perl mang tên `[kworker/2:51S]`): dùng cho mã độc tự khởi động lại, vì khi lệnh tới nơi pid cũ thường đã thoát. Agent kiểm tra lại từng tiến trình còn sống (vẫn giả danh, không phải dịch vụ hệ thống thật) | cao | **không** |

**Chống bị AI (và kẻ tấn công) lừa:**
- Nội dung bằng chứng do máy có thể đã bị xâm nhập tạo ra (tên file, dòng lệnh, dòng trong `.bashrc`) nên có thể chứa câu chữ dụ AI. Vì vậy AI **chỉ được nhắm vào thứ có trong bằng chứng** (đúng pid + thời điểm khởi động, đúng đường dẫn + số dòng + SHA-256 của dòng, tài khoản có liên quan trong bằng chứng, dịch vụ trong danh sách) và hub loại mọi đề xuất khác.
- Dịch vụ lõi (nginx, php-fpm, database, sshd…) và tài khoản hệ thống không bao giờ bị đụng tới.
- **Agent kiểm tra lại độc lập** bằng bằng chứng nó tự thu thập (còn mới dưới 2 giờ) và trạng thái thật của máy, rồi mới làm. File được sửa qua đường dẫn mở bằng `O_NOFOLLOW`.
- Mọi hành động (trừ dừng tiến trình) được ghi để hoàn tác.

**Độ trễ.** Agent hỏi hub mỗi 5 phút nên một lượt đầy đủ có thể mất vài phút. Sau khi thu thập bằng chứng cho AI, agent gửi báo cáo ngay và hỏi hub mỗi 15 giây trong tối đa 10 phút (`sn evidence --follow`), nên lệnh tới nơi trong vài giây thay vì chờ tới nhịp kế. Mã độc tự khởi động lại thường làm pid cũ biến mất, vì thế có hành động `kill_matching`. Nếu VPS còn một lệnh chưa chạy, đề xuất được tự gửi lại ở báo cáo kế tiếp.

**3. Mức tự xử lý (từng VPS).** Mặc định **"Duyệt từng bước"**. Bạn có thể chọn: *Tắt* (AI không tự chạy); *Tự xử lý việc hoàn tác được* (cách ly file, khoá shell, gỡ dòng độc, tắt dịch vụ chạy luôn, dừng tiến trình vẫn chờ bạn); *Tự xử lý tất cả* (kể cả dừng tiến trình). Ở hai mức tự xử, khi có sự cố hub tự thu thập bằng chứng, gọi AI và gửi lệnh mà không chờ bạn bấm. Mọi việc đều hiện ở khung AI và Nhật ký. **Nên bật sau khi bạn đã thấy AI đề xuất đúng vài lần ở chế độ duyệt**, vì AI vẫn có thể sai.

**4. Trên VPS không cần cài đặt gì thêm.** Agent đã cài thì **hub quyết định**: thu thập bằng chứng, thực hiện hành động của AI, cài ClamAV, quét, hoàn tác, đổi chế độ đều chạy theo lệnh từ hub, không có cờ hay tham số nào phải thêm. (Lệnh vẫn được ký bằng khoá của hub và nằm trong danh sách hành động cố định.) Muốn riêng một VPS chỉ báo cáo mà không nhận lệnh, đặt `hub_orders = false` trong `[remote]` của `/etc/sn/agent.toml`. Các cờ cũ `--allow-clamav-install` và `--allow-remote-fix` không còn tác dụng (vẫn chấp nhận để lệnh cũ không lỗi), và `--upgrade` tự xoá các dòng `allow_*` cũ khỏi cấu hình. **Hệ quả cần biết:** ai điều khiển được hub thì điều khiển được cả đội VPS, nên bảo vệ đăng nhập hub (mật khẩu mạnh, 2FA) là việc quan trọng nhất.

**Giới hạn đã biết:** các luật kiểm tra (đặc biệt "đáng ngờ" của dòng `.bashrc`, tiến trình giả danh) là heuristic nên có thể bỏ sót hoặc báo thừa; chưa chặn IP bằng ipset/firewall toàn cổng (nft của agent chỉ chặn cổng web) và chưa tự chặn bot ở Nginx của DirectAdmin; AI có thể chẩn đoán sai, nên đọc kỹ trước khi duyệt. **Chưa thử trên VPS thật.**

## Kết nối Hermes (MCP)

Hub có sẵn một **MCP server** (Model Context Protocol, kiểu Streamable HTTP) ở `https://HUB/mcp`, để Hermes Agent hoặc agent nào hỗ trợ MCP qua HTTP làm "bộ não" cho đội VPS: đọc tình trạng, lấy bằng chứng, và nếu được phép thì xử lý sự cố.

1. Vào **Hermes** trên menu hub, tạo token (hỏi lại mật khẩu). Chọn quyền:
   - **Chỉ xem**: `list_vps`, `get_vps_status`, `get_evidence`, `get_proposals`, `get_activity_log`.
   - **Xem + đề xuất**: thêm `request_evidence` (VPS thu thập bằng chứng mới) và `submit_plan` (kế hoạch xử lý chờ admin duyệt trên trang VPS).
   - **Toàn quyền xử lý**: thêm `submit_plan` với `execute: true`, `execute_proposal`, `reject_proposal`, `ban_ip`/`unban_ip` (một VPS hoặc `all`, tối đa 24 giờ), `set_mode`, `run_malware_scan`, `install_clamav`.
2. Trên máy chạy Hermes, thêm token vào `~/.hermes/.env` (`SNSEC_MCP_TOKEN=snmcp_…`) và vào `~/.hermes/config.yaml`:
   ```yaml
   mcp_servers:
     snsec:
       url: "https://HUB/mcp"
       headers:
         Authorization: "Bearer ${SNSEC_MCP_TOKEN}"
       timeout: 120
   ```
   Kiểm tra bằng `hermes mcp test snsec`. Hermes chạy trên chính máy hub thì dùng `http://127.0.0.1:8099/mcp`. Nếu hub nằm sau Caddy có giới hạn IP cho giao diện quản trị, cho `/mcp` đi qua riêng (khối `@mcp` trong `deploy/examples/Caddyfile`).

**Giới hạn an toàn (không phụ thuộc vào việc Hermes nghe lời):** mỗi kế hoạch đi đúng đường của AI tích hợp. Chỉ có danh sách hành động cố định (`kill_process`, `kill_matching`, `lock_user_shell`, `quarantine_file`, `remove_shell_line`, `disable_service`), không có lệnh tuỳ ý. Hub đối chiếu từng hành động với bằng chứng mới nhất của VPS (không quá 100 phút) và loại cái không khớp hoặc chạm dịch vụ được bảo vệ; agent trên VPS kiểm lại lần nữa trước khi làm và ghi cách hoàn tác. Lệnh chặn chỉ nhận một địa chỉ IP thường (hoặc một IPv6 /64). Thêm giới hạn riêng cho Hermes: chỉ chặn địa chỉ Internet công khai (không chặn dải nội bộ, CGNAT, link-local), mỗi VPS tối đa 500 lệnh chặn từ hub, mỗi token tối đa 60 thao tác thay đổi mỗi giờ (lệnh cho `all` tính theo số VPS), `unban_ip` chỉ gỡ lệnh chặn do hub đặt (không gỡ được IP mà VPS tự chặn), `set_mode` chỉ bật chế độ tự chặn chứ không tắt. Đề xuất từ Hermes hiện riêng trên trang VPS và không chặn AI tích hợp tự phân tích. Token lưu dạng băm, thu hồi được ngay, tự bị thu hồi hết khi đổi mật khẩu hay reset 2FA (hoặc `snhub mcp-revoke-all`), giới hạn 120 lần gọi/phút; token sai bị đếm như đoán mật khẩu. Mọi thao tác ghi vào Nhật ký với tên `mcp:<tên token>`. Dữ liệu trả về từ VPS được đánh dấu là không tin cậy để Hermes không làm theo chữ nằm trong đó.

## Bot phân tán và CPU cao

Luật theo IP ở trên **không chặn được** bot chạy qua hàng trăm IP dân dụng, mỗi IP chỉ vài request và trông như trình duyệt thường (ví dụ vụ `?tss-sc=…&tsscat=…` kéo CPU lên 100%). Với loại này agent **chỉ cảnh báo và cho bạn thấy**, không tự chặn:

- **Hub hiện** mục "Truy cập lặp lại từ nhiều IP": User-Agent nhiều nhất và kiểu request nhiều nhất (`METHOD /đường-dẫn?tên-tham-số`; **giá trị tham số không được lưu**, số/token trong đường dẫn gộp thành `{id}`), kèm số lượt và số IP khác nhau. Ảnh/CSS/JS không tính.
- **Cảnh báo** (`bot_ua` / `bot_shape`) khi trong một chu kỳ một mục có ≥ `bot_min_ips` IP khác nhau (25), ≥ `bot_min_requests` request (50), mỗi IP trung bình ≤ 8 request, và gấp ≥ `bot_surge` lần mức thường của chính mục đó (5). Mức thường là trung bình trượt riêng từng mục, **đóng băng trong lúc đang bị cảnh báo** (một vụ tấn công kéo dài không tự thành "bình thường"; tối đa 1 ngày, sau đó coi là bình thường). Một giờ đầu sau khi cài chỉ học, chưa cảnh báo. Khi CPU cũng cao thì cảnh báo thành khẩn.
- **Cách xử lý**: mục bất thường kèm sẵn **luật ModSecurity gợi ý** và vài IP mẫu. Với panel chính (cPanel, Plesk, DirectAdmin, OPanel) hãy dùng WAF: dán luật, để `DetectionOnly` xem có chặn nhầm khách thật không rồi mới bật. **Hub không tự ghi luật vào VPS**, và luật chưa được thử trên ModSecurity thật. VPS không có WAF thì chỉ chặn được theo IP/CIDR, và với bot phân tán cách đó gần như vô ích vì IP đổi liên tục.
- **Có thể báo nhầm:** một chiến dịch quảng cáo, crawler thật (Googlebot, Bing… cũng đến từ nhiều IP), hoặc tính năng mới cũng tạo ra đúng dấu hiệu này. Cảnh báo ghi chú khi UA tự nhận là crawler nhưng điều đó chưa được xác minh (cần reverse DNS).
- **Tắt** bằng `bot_detection = false` trong `[watch]`.
- **Giới hạn đã biết:** (1) mục mới hoàn toàn (bản Chrome mới, crawler bắt đầu quét) cũng bị gắn "bất thường" cho tới khi đủ lâu để được coi là bình thường (tối đa ~1 ngày); cảnh báo ghi "not seen recently". (2) Mỗi chu kỳ chỉ theo dõi tối đa 2.000 User-Agent và 2.000 kiểu request đầu tiên; ai đó cố tình gửi hàng nghìn UA lạ có thể che mục thật. (3) Chỉ kiểu request **có tham số** mới được cảnh báo; bot phân tán dò `wp-login.php` không tham số chỉ bị bắt nếu User-Agent của nó bất thường. (4) IP của proxy tin cậy (Cloudflare) bị bỏ qua vì không phải IP khách, nên sau Cloudflare với log dạng `combined` (không có IP thật) tính năng này gần như không thấy gì. (5) Request bị server từ chối (403/429/444) không được tính, nên cảnh báo tự tắt sau khi luật WAF có tác dụng. (6) Chu kỳ không có dòng log mới, hoặc đọc bù sau khi agent tắt một thời gian, không được dùng để cảnh báo hay để học mức bình thường. (7) Luật gợi ý khớp **đúng** đường dẫn (không có dấu `/` cuối) và không được tạo cho giá trị bị cắt ngắn hay có mã hoá `%`.

**CPU cao:** mỗi chu kỳ agent lưu bộ đếm CPU và chu kỳ sau lấy hiệu số, nên con số là **trung bình cả khoảng ~5 phút** chứ không phải một thời điểm. Khi ≥ `cpu_alert_pct` hai chu kỳ liền, cảnh báo `cpu_high` nêu tên các tài khoản/chương trình chiếm CPU nhiều nhất (cũng hiện ở bảng "Ai đang dùng CPU", tính theo % của cả máy). Tiến trình chạy xong giữa hai chu kỳ không thấy được nên tổng các dòng có thể nhỏ hơn mức CPU chung. Hai tuỳ chọn cũ `load_alert` và `auto_contain` đã bị bỏ vì không có tác dụng; file cấu hình cũ còn chúng vẫn chạy bình thường.

## Quét mã độc

`sn hunt` quét **toàn bộ file PHP** trong `[hunt] allowed_roots` (mặc định `/home` và `/var/www`), cộng file `.php` giả đuôi ảnh trong `uploads/`. Mỗi file được chấm điểm bằng heuristic; **≥ 100 là "độc hại"**, **70–99 là "nghi ngờ"**.

```sh
sn hunt                 # quét ngay, in kết quả
sn clean --yes          # cách ly các file "độc hại" (khôi phục được: sn restore <id>)
```

Ba cách chạy: **tự động lúc 3 giờ sáng** (timer `sn-hunt`, ưu tiên CPU/IO thấp), **bấm "Quét ngay" trên hub**, hoặc chạy tay như trên. Kết quả (số file đã quét, số độc hại/nghi ngờ, danh sách file kèm đoạn mã trích ra) hiện ở mục **Quét mã độc** trên trang VPS; có file độc hại thì hub báo cảnh báo khẩn. Trang cũng cho biết "đã quét, không có gì" khác với "chưa quét lần nào". Danh sách hiện 10 file mỗi trang, và có thể **tải xuống**: CSV (tất cả file, kèm điểm, dấu hiệu khớp, đoạn mã trích, sha256; các ô bắt đầu bằng `=`, `+`, `-`, `@` được thêm dấu `'` để Excel không chạy chúng như công thức) hoặc `.txt` chỉ gồm đường dẫn các file "độc hại", mỗi dòng một file. VPS chỉ gửi về hub tối đa 100 file điểm cao nhất mỗi lần; muốn đủ danh sách thì chạy `sn hunt` trên VPS. Danh sách IP đang bị chặn cũng hiện 10 IP mỗi trang.

**Nó bắt được gì:** request đi thẳng vào lệnh chạy mã/lệnh hệ thống (`eval`, `system`, `exec`, `call_user_func`...), biến lấy từ request rồi đưa vào các lệnh đó, request quyết định tên hàm được gọi, `eval` của dữ liệu đã giải mã (base64/gzinflate...), `preg_replace` với modifier `/e`, file ghi dữ liệu từ request ra đĩa, file PHP trong `uploads/` hoặc đuôi ảnh, blob base64/entropy cao.

**Độ chính xác đã đo, và chưa đo:**
- **Báo nhầm:** 0 trên **9.024 file PHP hợp lệ** (lõi WordPress, WooCommerce, Yoast SEO, Contact Form 7, Elementor). Con số này đo bằng công cụ `cargo run -p snsec-common --release --example scan_dir -- <thư mục>`, chạy lại mỗi khi sửa bộ chấm điểm. Phiên bản đầu từng báo nhầm 10 file "độc hại" trên cùng bộ này (kể cả file lõi WordPress); đã sửa.
- **Phát hiện:** mới kiểm trên các mẫu tự dựng của những dạng web shell phổ biến. **Chưa kiểm trên bộ mã độc thật**, nên không có số liệu tỷ lệ bắt được. Kết quả "sạch" không phải bằng chứng máy không bị nhiễm.

**Giới hạn:** chỉ quét file PHP (không quét database, không quét mã JavaScript bị chèn, không đối chiếu checksum lõi/plugin của WordPress); web shell dựng tên hàm bằng cách nối chuỗi (`$f = 'ev'.'al'; $f($x)`) chưa bắt được; file lớn hơn `max_file_mb` (5 MB) bị bỏ qua. `sn clean --yes` chỉ cách ly file "độc hại"; file "nghi ngờ" luôn để bạn xem tay. Heuristic có thể sai, nên đọc đoạn mã trích ra trước khi cách ly.

### ClamAV (engine thứ hai, tuỳ chọn)

Heuristic bắt được biến thể lạ nhưng không biết tên họ mã độc; chữ ký ClamAV thì ngược lại. Khi VPS có ClamAV, mỗi lần `sn hunt` đối chiếu thêm **cùng các file PHP** với chữ ký của nó, và hiện hai nguồn cạnh nhau (cột "Dấu hiệu khớp" có `clamav:Php.Webshell...`). Hub **không** lấy chữ ký về hay phân phối lại: mỗi VPS tự cập nhật bằng `freshclam` từ máy chủ chữ ký của ClamAV.

- **Dùng khi nào:** `[hunt] clamav = "auto"` (mặc định): có ClamAV và đủ điều kiện thì dùng, không thì bỏ qua. `"off"` để tắt hẳn. Có `clamd` đang chạy thì dùng `clamdscan`; không thì `clamscan`, loại này nạp cả CSDL chữ ký (hơn 1 GB) nên chỉ chạy khi RAM còn trống ≥ `clamav_min_ram_mb` (mặc định 1536), và tối đa `clamav_timeout_secs` (1200). Nếu `clamd` lỗi giữa chừng thì chuyển sang `clamscan`. **Quét tăng dần:** agent ghi lại file nào ClamAV đã quét (kích thước, mtime, ctime, kết quả) trong `/var/lib/sn/clamav-scanned.tsv`; mỗi lần quét ưu tiên file từng bị đánh dấu, rồi file mới hoặc vừa đổi, rồi file không đổi đến hạn quét lại (`clamav_rescan_days`, mặc định 7), file không đổi vừa quét thì bỏ qua. Hết giờ giữa chừng thì phần đã quét vẫn được giữ và lần sau quét tiếp, nên máy có hàng trăm nghìn file PHP được phủ dần qua vài lần quét.
- **Nút "Cài ClamAV" trên hub:** agent đọc `/etc/os-release` rồi cài: Debian/Ubuntu bằng `apt` (chỉ gói `clamav`, không cài daemon để khỏi chiếm ~1 GB RAM thường trực); AlmaLinux/Rocky/CentOS/Fedora bằng `dnf`/`yum` (EPEL + `clamav`, `clamav-update`, tắt dòng `Example` trong `freshclam.conf`, tải chữ ký, đặt timer cập nhật hằng ngày `sn-clamav-update.timer`). Hệ điều hành khác bị từ chối kèm lý do. Cần VPS có tổng RAM ≥ ~1,8 GB và còn ≥ 1,5 GB ổ đĩa ở `/var/lib`. Kết quả (đang cài / xong / lỗi và lý do) hiện ngay trong khung ClamAV của trang VPS.
- **Hub quyết định việc cài**: nút "Cài ClamAV" chạy trình quản lý gói bằng root trên VPS, không cần bật gì thêm ở VPS. Hub chỉ gửi lệnh cho agent đã báo hỗ trợ ClamAV.
- **Một file ClamAV báo sẽ thành "độc hại"** (đủ điều kiện để `sn clean --yes` cách ly) trừ chữ ký dạng `Heuristics.*` và `PUA.*` chỉ thành "nghi ngờ". ClamAV vẫn có thể báo nhầm; đọc kết quả trước khi cách ly.
- **Giới hạn:** ClamAV chỉ nhận các file mà heuristic đã mở (PHP, và file trong `uploads/` có dấu hiệu PHP), không quét cả ổ đĩa. File tên không phải UTF-8, tên có xuống dòng, hay quá 200.000 file được đếm và ghi vào ghi chú ("ClamAV bỏ qua N file"). Cờ dòng lệnh và gói của từng bản phân phối được viết theo tài liệu nhưng **chưa thử trên VPS thật**; hãy thử trên một VPS thử nghiệm trước.


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
| `enroll --url --name` | Đăng ký với hub (token lấy từ biến môi trường `SN_ENROLL_TOKEN`; `--token` vẫn nhận nhưng lộ trên danh sách tiến trình) |
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
dist/       những gì install-hub.sh/update-hub.sh tải về và hub phục vụ cho VPS: binary dựng sẵn (musl amd64+arm64),
            install.sh (bản sao y deploy/install.sh, CI kiểm) + SHA256SUMS
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
