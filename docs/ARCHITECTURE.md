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

1. `collect` — tail log mới từ `(dev,inode,offset)` lưu trong `offsets.json`; rotation (inode đổi/file ngắn lại) → đọc từ đầu; lần đầu đọc từ EOF (không replay lịch sử để tránh ban hàng loạt ngày đầu). Parse theo format, lấy IP thật sau `trusted_proxies`, đếm per-IP (cap 100k IP, ngân sách 256 MB/chu kỳ).
2. `baseline` — cập nhật EWMA theo khung 15 phút; ngưỡng = `max(min_requests, k × ewma)` khi khung đủ ấm (≥ 24 quan sát), nếu chưa thì chỉ `min_requests` + mẫu cố định.
3. Quyết định: mẫu cố định (`bruteforce`/`probe`/`scanner`/`bad_ua`/`xmlrpc_pingback`) hoặc vượt ngưỡng → ban. Bỏ qua whitelist + trusted_proxies. Leo thang theo strike: 10m → 1h → 24h → 7d (reset sau 7 ngày sạch). Trần 200 ban/chu kỳ (vượt → alert).
4. Thi hành: `enforce` → `nft` một transaction (ensure table + whitelist + add bans TTL); `observe` → chỉ ghi `would_ban`.
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
```
Sets `sn_ban4` (timeout), `sn_ban6` (interval+timeout, /64), `sn_white4/6` (interval). Áp theo batch `nft -f -`.
