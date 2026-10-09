# Review — các phát hiện đã kiểm chứng và cách code xử lý

14 agent (6 lens review + 6 kiểm chứng đối kháng + dựng lộ trình + critic) đã soi kế hoạch gốc. Dưới đây là các phát hiện **critical/high đã đứng vững**, và chúng được giải quyết thế nào trong v1 (hoặc hoãn có chủ đích).

| ID | Vấn đề | Trạng thái trong code |
| --- | --- | --- |
| LNX-1 / SEC-6 | Chống tự khoá chỉ nhìn SSH cổng 22; ban chặn mọi cổng | **Đã sửa.** Ban web chỉ cổng 80/443 (`fw.rs`); whitelist lấy cổng sshd thật từ inode socket (kể cả IPv6-mapped, cổng tùy biến, panel), IP interface, hub, IP `Accepted` gần đây (`whitelist.rs`) |
| SEC-1 | Neo tin cậy là key online; rotation ký bằng key đã lộ | **Một phần.** Tách tier chính sách cần chữ ký **root offline** (`SignedPolicy`, `verify_detached`); `snhub init` sinh root key, in một lần, không cần để chạy. Cert-chain/rotation đầy đủ: v1.1 |
| SEC-2 | Desired mang quá nhiều quyền | **Đã sửa phần lõi.** Giới hạn cứng tại VPS: ban TTL ≤ 24h, mode→observe và patterns/trusted_proxies nằm ở tier chính sách ký root; `timer_interval` kẹp [300,900] |
| SEC-4 | Cửa sổ ± 5 phút vs pull 5–15 phút; replay | **Đã sửa.** Envelope `(epoch,seq)` đơn điệu + `expires_at` (7 ngày), bỏ kiểm cửa sổ thời gian; receiver kiểm đơn điệu với state đã lưu |
| SEC-5 | Tải binary không kiểm chữ ký; pin TLS gãy khi gia hạn LE | **Một phần.** install/install-hub kiểm **sha256**; dùng WebPKI cho kênh + ký ed25519 cho nội dung. minisign + GitHub Releases trong `release.yml`. Self-update ký: v1.1 |
| SEC-8 | `undo.sh` là shell dựng từ dữ liệu kẻ tấn công | **Đã sửa.** `undo.jsonl` có cấu trúc, chạy bằng syscall/`nft`, không execute shell; quarantine không bị undo khôi phục |
| SEC-9 | XSS/injection trên UI/Telegram | **Đã sửa (UI).** maud autoescape mọi giá trị; cookie HttpOnly/SameSite. Telegram: v1.1 |
| DET-1 / SEC-11 | Sau Cloudflare, ban nftables vô hiệu, dễ chặn nhầm CF | **Giảm thiểu + ghi rõ giới hạn.** Lấy IP thật để đếm/would_ban, loại dải CF khỏi mọi bộ đếm (`trusted_proxies`). Ban L3 chỉ cho kết nối trực tiếp; backend L7/CF-API là **v2** (xem SECURITY.md) |
| DET-3 | Dấu hiệu miner dễ né; trigger theo load bắt không ra | **Đã sửa phần lõi.** triage dùng delta CPU 2 mẫu + exe `(deleted)`/suspicious-path/webroot + cổng pool + hint cmdline; nhãn `mixed` được định nghĩa. Tín hiệu "CPU không giải thích được"/package-verify: v1.1 |
| DET-6 | hunt theo mtime bị timestomp | **Đã sửa.** Lọc theo `max(mtime, ctime)` (`statx`/MetadataExt); luôn quét file PHP bất kể thời gian |
| DET-7 | Chỉ checksum WP core | **Hoãn (v1.1).** v1 quét heuristic PHP cho plugin/theme/uploads; checksum plugin/theme + `--db` là v1.1 |
| DET-8 | Trọng số heuristic vừa lọt vừa báo nhầm | **Đã sửa phần lõi.** Nhóm source→sink (một mình đủ malicious), decode→eval, dropper, preg_replace/e; encoder thương mại tách lớp riêng (không tính entropy). Lexer token hoá: v1.1 |
| DET-10 | Baseline chưa định nghĩa rõ | **Một phần.** EWMA theo 96 khung 15 phút + cold-start guard + `min_requests`; histogram p99 theo vhost: v1.1 |
| DET-12/13/14 | CGNAT/IPv6, bỏ sót bot/IPN, limit-rate tự chặn | **Một phần.** Ban IPv6 theo /64; bỏ limit-rate toàn cổng (trần 200 ban → alert). Danh sách ASN/bot công bố + miễn trừ theo path IPN: v2 |
| LNX-2 / PERF-3 | cgroup v2 không mặc định mọi OS; fallback cần daemon | **Đã sửa.** Hai backend v1+v2 thật (`cgroup.rs`), phát hiện bằng `statfs`; bỏ SIGSTOP/SIGCONT |
| LNX-4 | Unit watch thiếu cap, ProtectSystem chặn, oneshot không timeout | **Đã sửa.** `sn-watch.service` có `CAP_SYS_PTRACE`/`CAP_DAC_READ_SEARCH`, `ReadWritePaths=/var/lib/sn`, `TimeoutStartSec=90` |
| LNX-7 | Phụ thuộc binary ngoài trái "không phụ thuộc" | **Đã giảm.** Dùng `/proc`/netlink-free `/proc/net` + syscall; chỉ còn `nft` là phụ thuộc có ghi rõ; đã sửa câu mô tả |
| PERF-2 | Tiêu chí "load < 20% trong 10s" bất khả thi | **Đã sửa (đo đúng).** Báo cáo CPU busy từ `/proc/stat` (2 mẫu), không dựa load1 cho quyết định |
| PERF-6 | `state.json` khổng lồ dễ hỏng | **Đã sửa.** Tách file nhỏ (offsets/strikes/bans/baseline/meta), ghi tmp+fsync+rename; queue là thư mục spool có trần 50 MB |
| PERF-7 | Ngân sách chu kỳ không có trần khi bị tấn công | **Đã sửa phần lõi.** Trần 100k IP + 256 MB/chu kỳ (offset vẫn tiến), mimalloc; deadline HTTP 5s/15s; cờ `overload`/`watch_blind` |
| RM-1..10 | Lộ trình 15 ngày không khả thi, thiếu CI/ký/rollout | **Đã sửa.** CI + release ký ngay từ đầu; lộ trình thực tế trong [ROADMAP.md](ROADMAP.md): ~40 ngày công + rollout theo đợt, đóng băng mùa sale |

## Còn nợ (ghi để không quên)

Theo critic: kill switch từ hub chưa gỡ được ban cục bộ (đã bù bằng `sn disable` tại chỗ); alert Telegram (v1.1) phải có **trước** canary enforce; dead-man switch khi bật enforce lần đầu; redaction PII; runbook dựng lại máy; công cụ đo gate rollout tự động. Xem [ROADMAP.md](ROADMAP.md).
