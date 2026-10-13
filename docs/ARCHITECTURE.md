# Kiến trúc

## Thành phần

| Thành phần | Ở đâu | Làm gì | Lưu gì |
| --- | --- | --- | --- |
| `sn` | mỗi VPS, `/usr/local/bin/sn` | Cấp cứu một lần; `watch` theo timer; báo hub | `/var/lib/sn/`: offsets, baseline, strikes, bans, undo.jsonl, quarantine/, queue/ |
| `snhub` | server trung tâm | Enroll, nhận báo cáo, giữ desired-state (ký), REST + UI | SQLite `/var/lib/snhub/snhub.sqlite` |
| Web UI | trong `snhub` | Tổng quan, chi tiết VPS, ban/unban, đổi mode, thêm VPS, nhật ký | — |

Crate: `common` (schema + ký + parser log + heuristic PHP, dùng chung), `sn`, `snhub`.

## Giao thức (pull, một chiều VPS → hub)

Mọi thông điệp bọc trong `Signed { env, sig, key_id }`, trong đó `env` là **đúng chuỗi JSON đã ký** của một `Envelope<T>`:

```
Envelope { schema_version, agent_id, epoch, seq, issued_at, expires_at, body }
```

- **`POST /v1/report`** — VPS → hub. `body = ReportBody` (cycle, bans, would_ban, alerts, triage, findings, applied_desired, capabilities). Ký bằng key VPS; hub kiểm bằng pubkey đã lưu lúc enroll; `seq` phải > seq đã nhận.
- **`GET /v1/desired?agent_id&epoch&seq`** — hub → VPS. `body = DesiredBody` (mode, k, bans, unbans, allow_temp, jobs, timer_interval, policy). Ký bằng key hub; VPS kiểm `(epoch,seq)` đơn điệu + `expires_at`; áp dụng rồi lưu `last_desired`.
- **`POST /v1/enroll`** — VPS → hub. `{ token, name, agent_pubkey }` → `{ agent_id, hub_pubkeys[], root_pubkeys[] }`. Token dùng một lần.

Mất mạng tới hub: watch vẫn chạy (đếm/ban cục bộ), báo cáo xếp hàng trong `/var/lib/sn/queue/` (trần 50 MB, drop cũ nhất), gửi bù ≤ 50/chu kỳ.

## Một chu kỳ `sn watch`

1. `collect` — tail log mới từ `(dev,inode,offset)` lưu trong `offsets.json`; rotation (inode đổi/file ngắn lại) → đọc từ đầu; lần đầu đọc từ EOF (không replay lịch sử để tránh ban hàng loạt ngày đầu). Parse theo format, lấy IP thật sau `trusted_proxies`, bỏ request của chính VPS (loopback, IP interface, IP công khai hub thấy), đếm per-IP và per-website (mỗi file log / vhost là một website; cap 50k IP, 8 website/IP, ngân sách 256 MB/chu kỳ). Đường dẫn đọc như web server hiểu (bỏ query, giải mã `%XX`, gộp `//`, `.`, `..`; đoạn `.php` đầu tiên là script, phần sau là PATH_INFO). Request động (không phải ảnh/CSS/JS/font/media/HLS/PDF, không 206/304) đếm riêng.
2. `baseline` — chỉ chu kỳ đại diện (có dòng log, không phải đọc bù sau quãng > 15 phút, không bị cắt vì chạm giới hạn đọc) cập nhật EWMA theo khung 15 phút và EWMA chung, với số request động trên một website của IP bận **thứ ba** trong các IP không khớp luật nào và dưới ngưỡng (mỗi lần học tối đa gấp đôi mức một IP được phép); ngưỡng = `max(min_requests, k × ewma)` theo khung khi khung đủ ấm (≥ 24 quan sát), nếu chưa thì theo EWMA chung (≥ 24 quan sát), nếu chưa thì `min_requests`; không bao giờ quá trần 3000 request động/website/chu kỳ. Chưa "ready" (khung chưa ấm và EWMA chung < 288 quan sát) thì `rate` chỉ báo, trừ khi chạm trần.
3. Quyết định (`watch/patterns.rs`, `watch/decide.rs`): mẫu cố định (`bruteforce`/`probe`/`scanner`/`bad_ua`/`xmlrpc_pingback`) hoặc vượt ngưỡng `rate` (× số trình duyệt có tải tài nguyên trang sau IP, tối đa ×4, ít nhất ×2 khi IP đang hiển thị trang; × 10 cho crawler xác minh bằng dải IP) → ban. Bỏ qua whitelist, trusted_proxies, dải Cloudflare có khách. Leo thang theo strike: 10m → 1h → 24h → 7d (reset sau 7 ngày sạch, 1 ngày nếu chỉ vi phạm `rate`); observe không tính strike; IP có lệnh chặn còn hiệu lực trong khoảng log của chu kỳ không bị tính lại vì cùng lý do; IP admin vừa gỡ chặn trên hub: 6 giờ `rate`/`scanner` chỉ báo. Trần 200 ban/chu kỳ (vượt → alert); > 20 ban `rate` một lúc → IP giống trình duyệt dưới 3× ngưỡng chỉ báo, flood bằng công cụ vẫn bị chặn (`rate_storm`, khẩn).
4. Thi hành: `enforce` → `nft` (ensure table, rồi whitelist gồm cả trusted_proxies, viết không có phần tử nằm trong phần tử khác; lỗi whitelist chỉ ghi log, ban vẫn áp; add bans TTL; ban chặn TCP tới cổng web và UDP 443 cho HTTP/3, tắt bằng `block_quic = false`); `observe` → chỉ ghi `would_ban`.
5. Báo cáo: dựng `ReportBody`, xếp hàng, flush queue + lấy/áp desired.

## cgroup (contain)

`detect()` qua `statfs(/sys/fs/cgroup)`: `cgroup2fs` → v2 (`cpu.max`, `cgroup.freeze`), `tmpfs` → v1 (`cpu,cpuacct/sn-jail/cpu.cfs_quota_us`, `freezer`). Chỉ throttle/freeze, không kill. `release()` trả PID về root cgroup và xoá jail.

## nftables (fw)

Table `inet sn`, chain `input` priority −10, policy accept:
```
ct state established,related accept   # không rớt phiên đang mở
iif lo accept
ip/ip6 saddr @sn_white4/6 accept      # whitelist trước
ip/ip6 saddr @sn_ban4/6 tcp dport { web_ports } drop
ip/ip6 saddr @sn_ban4/6 udp dport 443 drop   # HTTP/3; chỉ khi 443 là cổng web và block_quic = true
```
Sets `sn_ban4` (timeout), `sn_ban6` (interval+timeout, /64), `sn_white4/6` (interval). Áp theo batch `nft -f -`.
