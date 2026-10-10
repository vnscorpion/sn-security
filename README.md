# SN Secure

[![CI](https://github.com/vnscorpion/sn-security/actions/workflows/ci.yml/badge.svg)](https://github.com/vnscorpion/sn-security/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#giấy-phép)

Một binary Rust tĩnh (`sn`, ~3 MB) cấp cứu VPS Linux đang bị mã độc/traffic bẩn làm full CPU trong vài phút, rồi ở lại theo dõi traffic bằng systemd timer và báo về **hub trung tâm** (`snhub`) trên server của bạn. Không daemon nặng, không mở cổng trên VPS; phụ thuộc ngoài duy nhất của agent là `nftables` và cgroup (có sẵn trên mọi VPS hiện đại).

> **Trạng thái: v1 (nền tảng).** Phần lõi đã chạy và biên dịch tĩnh (musl) cho amd64 + arm64: cấp cứu (`triage`/`contain`/`hunt`/`clean`/`undo`), theo dõi (`watch` observe/enforce), và hub (enroll, nhận báo cáo, desired-state ký ed25519, giao diện web). Một số phần là **v1.1/v2** (xem [docs/ROADMAP.md](docs/ROADMAP.md)): AI judgment, MCP, ban qua Cloudflare API, self-update do hub điều khiển, baseline dạng histogram, CloudLinux/OLS đầy đủ. **Bắt buộc test trên VPS thật và chạy `observe` vài ngày trước khi bật `enforce`** — xem [docs/RUNBOOK.md](docs/RUNBOOK.md).

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

## Cài hub (server trung tâm — Ubuntu 24.04 / Debian 12)

```sh
curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/main/deploy/install-hub.sh \
  | sudo bash -s -- --public-url https://hub.ten-mien-cua-ban.net
```

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
