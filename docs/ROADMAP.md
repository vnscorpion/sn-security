# Lộ trình

Rút ra từ một lượt review đa góc (6 lens) + kiểm chứng đối kháng của chính kế hoạch gốc. Kế hoạch "15 ngày" ban đầu **không khả thi**; con số trung thực là **~40 ngày công BUILD + 4–6 tuần ROLLOUT theo lịch**.

## Đã có trong v1 (repo này)

- `common`: schema + envelope ký ed25519 (`schema_version`/`epoch`/`seq`/`expires_at`), parser log (combined/sn/nginx_json, lấy IP thật sau proxy), heuristic PHP, CIDR/ban-key.
- `sn`: `triage` (/proc, netstat, persistence, nhãn + `mixed`), `contain`/`undo` (cgroup **v1+v2**, nft web-port), `hunt`/`clean`/`restore` (quarantine giữ owner/mode/mtime), `watch` (tail rotation-aware, mẫu cố định, baseline EWMA, strike ladder, whitelist chống tự khoá, observe/enforce, queue báo cáo), `enroll`/`report`, `disable` (kill switch).
- `snhub`: enroll (token một lần), `/report` (kiểm chữ ký), `/desired` (ký, đơn điệu), UI web (tổng quan, chi tiết VPS, ban/unban, mode, thêm VPS, nhật ký), SQLite.
- Hạ tầng: cross-build musl amd64+arm64, systemd units (2 tier quyền), install-hub.sh/install.sh/uninstall.sh, CI (fmt/clippy/test/build) + release (sha256 + minisign tùy chọn).

## v1.1 (sau RC)

- **AI judgment** chỉ cho mục `needs_judgment`, chỉ leo thang, phá huỷ luôn chờ người + 2FA; cần bảng chính sách, bộ 50 ca có nhãn, ≥ 10 ca prompt-injection, DPIA.
- **MCP cho trợ lý**: mặc định chỉ đọc + `ban_ip` (≤ 20 IP, TTL ≤ 24h). Tool ghi khác qua admin + 2FA.
- **UI**: TOTP + vai trò operator/viewer; nhúng panel qua SSO; trình soạn `patterns.yml` trên web.
- **Self-update do hub điều khiển** (bản ký, chặn hạ version, tự rollback nếu chu kỳ đầu hỏng).
- **Baseline histogram p99** theo vhost + ASN; seed từ log đã rotate khi cài.
- **`sn hunt --db`** (admin WP lạ, plugin/theme checksum từ wordpress.org), hub cache checksum. (`.user.ini auto_prepend_file` đã làm ở 0.10: xem mục "Ảnh và file cấu hình" trong README.)
- **Quét ảnh**: đo báo nhầm trên kho ảnh của site thật và bộ ảnh mã độc thật; bộ nhớ đệm (dev, ino, size, mtime) để không đọc lại ảnh không đổi mỗi đêm; bắt payload giữa ảnh lớn hơn 2 MB; steganography.
- Tín hiệu theo vhost (login-fail/phút), redaction PII trước khi lên hub, token chung cloud-init (vào trạng thái "chờ duyệt").

## v2

- **Ban L7 cho site sau Cloudflare**: deny theo real-ip ở nginx/apache, hoặc Cloudflare API (hub giữ token khách). Chain `prerouting`/`DOCKER-USER`.
- Danh sách CGNAT/ASN nhà mạng VN (ban mềm theo /64, không leo thang).
- `watch --follow` (long-poll) cho độ trễ thấp; YARA-X; Postgres cho hub lớn.
- CloudLinux (LVE/CageFS) + OpenLiteSpeed đầy đủ; persistence qua PAM/modules-load.

## Đã loại bỏ (không làm)

limit-rate toàn cổng (tự DDoS), ipset/iptables legacy, cpulimit SIGSTOP/SIGCONT, `undo.sh` dạng shell, pin TLS fingerprint lâu dài (dùng WebPKI + ký nội dung), CentOS 7, nút `kill` trong allowlist AI.

## ROLLOUT (lịch, không phải ngày công)

Observe (3 VPS nội bộ, 7 ngày) → canary enforce **chỉ mẫu cố định** (1 VPS) → enforce + baseline (5% fleet, chia theo OS) → 25% → 100% → **auto-contain** toàn fleet cuối cùng. Mỗi đợt qua khi: 0 IP hợp lệ trong `would_ban` đã xem tay, `parse_errors` < 1%, chu kỳ p95 < 3s, 0 lỗi chữ ký. **Đóng băng trước các mùa sale (11.11, Black Friday, 12.12, Tết).** Có người trực alert khẩn trước khi bật enforce.
