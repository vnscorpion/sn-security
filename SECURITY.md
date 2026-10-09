# Bảo mật & mô hình đe doạ

SN Secure chạy trên máy mà, theo giả định, **có thể đã bị chiếm**. Code được viết quanh hai bất biến không bao giờ được vi phạm: (1) không tự khoá admin khỏi VPS; (2) hub bị chiếm không kéo theo toàn fleet.

## Ranh giới tin cậy

| Nguồn | Mức tin cậy | Xử lý |
| --- | --- | --- |
| Nội dung log, tên process, path, cron | **Thù địch** | Parser tổng (lỗi → `None`, không panic); mọi chuỗi hiển thị trên UI/Telegram được escape |
| Báo cáo từ VPS | Ký bằng key VPS; VPS có thể đã bị root | Hub coi là dữ liệu, rate-limit, không nhận sha256 do VPS khai |
| Desired-state từ hub | Ký bằng key hub (online) | VPS kiểm chữ ký + `(epoch,seq)` tăng dần + `expires_at`; giới hạn cứng tại VPS |
| Thay đổi chính sách | Phải ký bằng **root key offline** | VPS từ chối nếu không có chữ ký root |

## Những bất biến đã cài trong code

- **Ban web chỉ ở cổng 80/443** (`[fw] web_ports`). Table `inet sn` kiểm `sn_white4/6` và `ct state established` **trước** khi drop, nên phiên admin đang mở không bị rớt.
- **Chống tự khoá** (`whitelist.rs`): loopback; mọi IP interface; hub; phiên established trên cổng sshd **thật** (lấy từ inode socket của sshd, kể cả socket-activation và IPv6-mapped) và trên cổng panel đang listen; IP có dòng `Accepted` trong `auth.log`/`secure`.
- **Contain không kill** (`cgroup.rs`): chỉ `cpu.max`/`cfs_quota` 5% và freeze tùy chọn. Danh sách loại trừ xét **tên dịch vụ + exe nằm trong `/usr/`, `/sbin`...**, nên binary ở `/tmp` tự xưng `nginx` không được miễn (`contain.rs::protected_reason`).
- **Envelope ký** (`common/crypto.rs`): ký trên đúng bytes JSON đã truyền (không canonicalize). Kiểm `schema_version`, `expires_at`, và `(epoch,seq)` đơn điệu để chống replay. Trường mới dùng `#[serde(default)]` → agent cũ/hub mới nói chuyện được.
- **Phân tầng desired**: ban/unban/hunt nhận bằng key hub (TTL ≤ 24h); đổi `mode→observe`, `patterns`, `trusted_proxies` nằm ở `SignedPolicy` cần chữ ký **root**. Key hub lộ không hạ được chính sách.
- **Undo có cấu trúc** (`undo.jsonl`), chạy bằng syscall/`nft`, không execute shell trên máy đã bị chiếm. `undo` không khôi phục quarantine (cần `restore`).
- **Enrollment**: token dùng một lần, hết hạn 15 phút; danh tính VPS là chữ ký ed25519, agent_key (0600) không bao giờ rời máy.
- **Hub hardening**: `snhub.service` chạy user riêng, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`, bind localhost. UI autoescape (maud), cookie `HttpOnly; SameSite=Strict`.

## Giới hạn đã biết của v1 (đọc trước khi bật enforce)

1. **Sau Cloudflare/proxy**: nftables ở origin thấy IP của Cloudflare, không phải client. v1 lấy đúng IP thật để **đếm/`would_ban`** và loại dải CF khỏi mọi bộ đếm, nhưng **ban L3 chỉ có tác dụng với kết nối trực tiếp tới origin**. Chặn L7 thật (deny ở nginx/apache theo real-ip, hoặc Cloudflare API) là **v2**. → Với site sau CF, dùng observe + chặn ở Cloudflare, hoặc chỉ cho dải CF vào 80/443.
2. **Cổng Docker publish** đi qua DNAT nên hook `input` có thể không chặn; cần chain `prerouting`/`DOCKER-USER` (v2).
3. **cgroup v2 dưới systemd delegation**: bật controller `cpu` cho jail có thể thất bại; khi đó `--freeze` vẫn dừng được miner nhưng throttle CPU mềm có thể không áp. cgroup v1 dùng backend riêng.
4. **UI admin**: một mật khẩu + session trong RAM; **chưa có TOTP/vai trò** (v1.1). Phải đặt sau VPN/allowlist.
5. **Baseline** là EWMA xấp xỉ theo 96 khung 15 phút, chưa phải histogram p99 (v1.1). Khởi động lạnh chỉ dùng mẫu cố định + `min_requests`.
6. **Chưa có self-update do hub điều khiển**: nâng cấp agent bằng SSH/ansible theo đợt.
7. **CGNAT/di động VN, ASN bot** chưa có xử lý riêng (v2) — một lý do nữa để observe đủ lâu.

## Trước production

- [ ] Observe ≥ 3–7 ngày trên VPS thật; `would_ban` không chứa IP hợp lệ (bot, CDN, nhà mạng, IPN thanh toán).
- [ ] Fuzz parser log + parser desired (`cargo fuzz`), test `../`/symlink trong hunt/restore.
- [ ] Giả lập hub bị chiếm: desired 1.000 ban, `fetch /etc/shadow`, chữ ký sai, version cũ.
- [ ] Root secret đã cất offline; backup SQLite của hub + test restore.
- [ ] ToS/chính sách riêng tư nói về dữ liệu IP khách và việc `fetch` file.

Báo lỗi bảo mật: mở issue riêng tư hoặc liên hệ trực tiếp maintainer.
