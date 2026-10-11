# SN Secure

[![CI](https://github.com/vnscorpion/sn-security/actions/workflows/ci.yml/badge.svg)](https://github.com/vnscorpion/sn-security/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#giấy-phép)

Một binary Rust tĩnh (`sn`, ~3 MB) cấp cứu VPS Linux đang bị mã độc/traffic bẩn làm full CPU trong vài phút, rồi ở lại theo dõi traffic bằng systemd timer và báo về **hub trung tâm** (`snhub`) trên server của bạn. Không daemon nặng, không mở cổng trên VPS; phụ thuộc ngoài duy nhất của agent là `nftables` và cgroup (có sẵn trên mọi VPS hiện đại).

> **Trạng thái: v1 (nền tảng).** Phần lõi đã chạy và biên dịch tĩnh (musl) cho amd64 + arm64: cấp cứu (`triage`/`contain`/`hunt`/`clean`/`undo`), theo dõi (`watch` observe/enforce), và hub (enroll, nhận báo cáo, desired-state ký ed25519, giao diện web). Một số phần là **v1.1/v2** (xem [docs/ROADMAP.md](docs/ROADMAP.md)): AI judgment, MCP, ban qua Cloudflare API, self-update do hub điều khiển, baseline dạng histogram, CloudLinux/OLS đầy đủ. **Bắt buộc test trên VPS thật và chạy `observe` vài ngày trước khi bật `enforce`** — xem [docs/RUNBOOK.md](docs/RUNBOOK.md).

## Tính năng

**Cấp cứu (chạy tay, không cần hub)**
- `triage` — ảnh chụp chỉ-đọc: top process theo CPU (đo delta 2 mẫu), exe thật/`(deleted)`, cwd, kết nối ra, persistence (cron/`ld.so.preload`/rc.local), disk/inode; gắn nhãn `miner`/`php-bot`/`ddos-l7`/`bruteforce`/`disk-full`/`mixed`/`unknown`.
- `contain` — nhốt process nghi ngờ vào cgroup 5% CPU (**cả cgroup v2 lẫn v1**), tuỳ chọn `--freeze`; **không bao giờ kill**; loại trừ dịch vụ hệ thống theo exe thật (miner đội tên `nginx` ở `/tmp` không thoát).
- `hunt` — quét webshell PHP bằng heuristic (source→sink, decode→eval, dropper, `preg_replace /e`, entropy, file PHP trong uploads/đuôi ảnh); nhận diện encoder thương mại (ionCube...) để tránh báo nhầm.
- `clean`/`quarantine`/`restore` — cách ly file giữ nguyên owner/mode/mtime, phục hồi được.
- `undo` — đảo ngược mọi contain/ban đã làm (log có cấu trúc `undo.jsonl`, không chạy shell).

**Theo dõi dài hạn (`watch`, systemd timer)**
- Đọc log tăng dần theo `(dev,inode,offset)`, nhận biết rotation; lấy IP thật sau Cloudflare/proxy.
- Mẫu cố định: bruteforce, probe, scanner, bad_ua, xmlrpc_pingback.
- Baseline tự học theo 96 khung 15 phút + ngưỡng `k×baseline` (có cold-start guard).
- Ban nftables **chỉ cổng web**, TTL + leo thang strike (10m→1h→24h→7d); IPv6 gộp /64.
- Hai chế độ **observe** (chỉ `would_ban`) / **enforce**; báo cáo ký số lên hub mỗi chu kỳ.

**Hub trung tâm (`snhub`)**
- Enroll token dùng một lần; nhận báo cáo (kiểm chữ ký); giữ & ký desired-state.
- Giao diện web: tổng quan fleet, chi tiết từng VPS (traffic, top IP, ban, triage, findings), nhật ký.
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
- **Agent (VPS):** Linux với cgroup v2 hoặc v1 và `nftables` (installer tự cài nếu thiếu). Đã nhắm Ubuntu/Debian và AlmaLinux/Rocky; Nginx/Apache.

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

> **Repo đang private?** `raw.githubusercontent.com` trả 404 với repo private, nên lệnh một dòng ở trên **không chạy**. Hoặc để repo public, hoặc clone rồi cài từ file local (không cần raw):
> ```sh
> git clone https://github.com/vnscorpion/sn-security
> cd sn-security
> sudo bash deploy/install-hub.sh --local --public-url https://hub.ten-mien-cua-ban.net
> ```
> (Agent thì không bị ảnh hưởng: bộ cài agent do **hub** phục vụ qua `public_url`, không lấy từ GitHub.)

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

Agent tự nhận diện web server/log, ghi `/etc/sn/agent.toml` ở **chế độ observe** (chỉ báo `would_ban`, chưa ban gì), enroll với hub, và cài 2 timer (`sn-watch` mỗi 5 phút, `sn-hunt` lúc 3h sáng). Sau vài ngày `would_ban` sạch, bật **enforce** từ hub.

## Điều khiển từ hub

Có — từ giao diện snhub bạn **đặt lệnh cho VPS mà không cần SSH**. Hub không gọi vào VPS; mọi lệnh chỉ ghi vào desired-state (ký số), VPS tự lấy và áp ở **chu kỳ kế tiếp (≤ 15 phút)** — đây là cái giá của việc không mở cổng trên VPS.

| Thao tác trên hub | Hiệu lực | Kiểm soát an toàn |
| --- | --- | --- |
| **Ban / Unban IP** (nhập tay hoặc nút cạnh top IP) | Agent áp vào nftables chu kỳ kế, TTL ≤ 24h | Chỉ cổng web; whitelist/trusted_proxies vẫn được loại trừ |
| **Đổi observe ↔ enforce** | Agent đổi chế độ chu kỳ kế | observe→enforce luôn được; enforce→observe cần `[remote] allow_mode_observe=true` (mặc định tắt) hoặc chữ ký root |
| **Chạy hunt ngay** (chọn số ngày) | Agent spawn `sn hunt`, findings vào báo cáo sau | Chạy đúng một lần cho mỗi lần bấm |
| **Undo** (gỡ contain + ban của sn) | Agent chạy `sn undo` chu kỳ kế | Chỉ khi VPS bật `[remote] allow_undo=true` |

Tier chính sách (đổi `patterns`, `trusted_proxies`, ép observe hàng loạt) cần **chữ ký root key offline** — hub bị chiếm cũng không hạ được bảo vệ. `contain`/`fetch` từ xa là **v1.1** (hiện làm qua SSH). Cần tức thì tại chỗ thì dùng `sn disable` (kill switch) hoặc chạy lệnh qua SSH.

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
| `report` / `env` | In báo cáo cuối / thông tin môi trường |
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
```

## Giấy phép

MIT HOẶC Apache-2.0 — tuỳ bạn chọn. Xem [LICENSE-MIT](LICENSE-MIT) và [LICENSE-APACHE](LICENSE-APACHE).
