# IP Checker — Build Plan (Back-end + Front-end)

> Tài liệu này là spec duy nhất để một model AI / lập trình viên khác implement toàn bộ app từ đầu, không cần hỏi lại người dùng và không cần đọc thêm hội thoại cũ.
> Ngôn ngữ UI: Tiếng Việt có dấu. Ngôn ngữ code, comment, commit: Tiếng Anh (trừ chuỗi hiển thị cho người dùng).
> Mục tiêu cuối cùng: app Windows chạy bằng 1 file `.exe` (installer NSIS + bản portable), người dùng chỉ cần nhập IP là xem được toàn bộ thông số của IP đó.

---

## 1. Tóm tắt sản phẩm

### 1.1. Bài toán

Người dùng cần kiểm tra một IP có "sạch" hay không trước khi dùng làm proxy / VPS / tài khoản, và cần biết chính xác IP đó đến từ đâu. Các web check lẻ tẻ hiện nay có 3 vấn đề: (a) mỗi web dùng 1 database khác nhau nên location lệch nhau, (b) 1 fraud score của 1 web không đủ tin, (c) leak DNS/WebRTC và tốc độ chỉ đo được khi traffic thực sự chạy qua proxy, không đo được bằng cách nhập IP suông.

### 1.2. Hai chế độ bắt buộc — không được nhập nhằng

| Chế độ | Input | Làm được | Không làm được / phải ghi rõ |
|---|---|---|---|
| **IP-only** | 1 IPv4 hoặc IPv6 duy nhất | Geo, ASN, loại IP, fraud score, blacklist, lịch sử abuse, ping, reverse DNS | Tốc độ thật, leak DNS/WebRTC, JA3, IP thoát thật |
| **Proxy-check** | `IP:port` + giao thức `HTTP` / `SOCKS5` (+ username/password nếu có, optional) | Tất cả của IP-only + IP thoát thật, tốc độ, leak DNS/WebRTC, timezone/browser consistency, headless flag | Không suy ra vị trí người thật đằng sau proxy, chỉ suy ra vị trí thoát |

Quy tắc UI: nếu người dùng chỉ nhập IP, các thẻ Leak / Tốc độ phải hiển thị trạng thái `Chưa đo được — cần nhập proxy` chứ KHÔNG được bịa số, KHÔNG được hiển thị 0.

### 1.3. Non-goals (không làm)

- Không quét port diện rộng, không quét toàn dải, không brute-force, không tấn công.
- Không khẳng định địa chỉ đường/phố/nhà từ IP. IP chỉ cho tối đa quốc gia (tin cậy cao) và thành phố/khu vực (tin cậy trung bình/thấp tùy loại IP).
- Không scrape các web không có API công khai để lấy fraud score (xem §5.4).
- Không gửi IP người dùng check lên server trung gian của nhà phát triển. Mọi request đi thẳng từ máy người dùng tới provider.
- Không hardcode API key vào code / vào file `.exe`.

---

## 2. Stack chốt

### 2.1. Lựa chọn chính: Tauri v2 + React + TypeScript + Rust

- **Front-end:** React 18+ + TypeScript + Vite, chạy trong WebView của Tauri. Không dùng Next.js (không cần SSR cho app desktop).
- **Back-end (core):** Rust, Tauri v2, `tokio` cho async, `reqwest` cho HTTP, `trust-dns-resolver` (hoặc `hickory`) cho DNSBL, `rusqlite` cho SQLite.
- **Đóng gói:** `tauri build` → installer NSIS + bản portable `.exe`. Kích thước mục tiêu 10–25 MB, không yêu cầu máy đích cài Node/Python.
- **Cập nhật:** Tauri Updater + GitHub Releases (xem §11).
- **Lưu key:** Windows Credential Manager qua crate `keyring`. Không lưu key plaintext trong file config, không lưu vào SQLite, không log key.
- **Lưu lịch sử/cache:** SQLite nhúng, file local duy nhất, ví dụ `%APPDATA%/ip-checker/app.db`.

### 2.2. Vì sao không chọn Electron / Python

- Electron: `.exe` ~150 MB+, tốn RAM, vẫn phải viết back-end Node riêng.
- Python + PyInstaller: đóng gói nặng, khó auto-update, khó chạy song song + DNSBL hiệu quả bằng Rust.
- Chỉ dùng Python làm prototype nhanh nếu cần, nhưng bản giao cuối vẫn phải là Tauri theo spec này.

### 2.3. Cấu trúc repo

```
ip-checker/
  src-tauri/
    Cargo.toml
    tauri.conf.json
    src/
      main.rs
      commands.rs          # Tauri commands, là API duy nhất front-end được gọi
      orchestrator.rs      # điều phối job song song, timeout, partial result
      validator.rs         # IPv4/IPv6, private/bogon
      providers/
        mod.rs             # trait Provider + ProviderEvidence chuẩn hoá
        registry.rs        # providers.yaml loader, metadata, upstream map
        ip_api.rs
        ipwho.rs
        ipinfo.rs
        ipqs.rs
        proxycheck.rs
        scamalytics.rs     # chỉ khi có key, xem §5.4
        abuseipdb.rs
        greynoise.rs
        ripestat.rs
        bgpview.rs
        team_cymru.rs
      dnsbl.rs             # query DNSBL trực tiếp, chia nhóm
      location.rs          # location_engine: triangulation, centroid, cloud range
      asn.rs
      network.rs           # ping, traceroute, reverse DNS
      browser_leak.rs      # Chromium headless qua proxy (chế độ proxy only)
      speed.rs             # đo tốc độ qua proxy (chế độ proxy only)
      scoring.rs           # chuẩn hoá + quorum + Clean Score + Confidence
      cache.rs             # SQLite: checks, provider_results, geo_db_versions
      export.rs            # JSON / CSV
      config.rs            # settings, providers.yaml
  src/
    App.tsx
    main.tsx
    components/
      InputConsole.tsx
      VerdictHUD.tsx
      ScanProgress.tsx
      GeoMapCard.tsx
      ReputationCard.tsx
      BlacklistTable.tsx
      NetworkCard.tsx
      LeakSpeedCard.tsx
      EvidenceTable.tsx
      HistoryPanel.tsx
      SettingsPanel.tsx
    lib/
      types.ts             # khớp 1-1 với struct Rust serialize sang JSON
      api.ts               # wrapper gọi Tauri invoke
  providers.yaml
  README.md
```

---

## 3. Front-end — phong cách Cyber, nhưng đọc được

### 3.1. Design tokens (bắt buộc)

- Nền: `#050810` (gần đen, hơi xanh), panel: `#0A0F1E`, panel border: `#1B2A4A`.
- Chữ chính: `#E6F1FF`, chữ phụ: `#8B9BB4`, mono cho dữ liệu kỹ thuật: `JetBrains Mono` hoặc `IBM Plex Mono`, fallback `Consolas, monospace`.
- Neon chính: cyan `#00F0FF` cho dữ liệu / đang quét.
- Trạng thái: Sạch `#22C55E`, Tạm `#EAB308`, Nghi ngờ `#F97316`, Bẩn `#EF4444`, Chưa đủ dữ liệu `#94A3B8`.
- Cảnh báo xung đột: magenta `#FF2D78`.
- Hiệu ứng: lưới nền mờ (CSS grid background), viền phát sáng nhẹ (box-shadow, không dùng quá 1px glow), hiệu ứng quét (scanline) chỉ ở header / verdict, KHÔNG dùng animation nhấp nháy liên tục gây khó đọc.
- Nguyên tắc: số liệu luôn rõ hơn trang trí. Không dùng chữ neon trên nền neon, không dùng font quá mỏng cho số quan trọng.

### 3.2. Layout — 1 màn hình chính, không bắt người dùng qua nhiều trang

```
┌──────────────────────────────────────────────────────────────┐
│ HEADER: IP CHECKER // TERMINAL  |  Provider health: ● ● ○    │
├──────────────────────────────────────────────────────────────┤
│ INPUT CONSOLE: [ 1.2.3.4  hoặc  1.2.3.4:8080 ] [HTTP▾] [SCAN] │
│   mode tự nhận: IP-only | Proxy-check   |  Lịch sử gần đây ▾ │
├──────────────────────────────────────────────────────────────┤
│ VERDICT HUD: [Clean Score 82] [Confidence 91%] [TẠM]         │
│   Lý do chính: 1 dòng, ví dụ "Dính 1 DNSBL cộng đồng, các     │
│   nguồn fraud còn lại sạch"                                  │
├──────────────────────────────────────────────────────────────┤
│ SCAN PROGRESS (log trực tiếp): geo ✓ | asn ✓ | fraud …      │
│   reputation … | dnsbl ✓ | location … | leak — (cần proxy)  │
├──────────────┬───────────────┬───────────────────────────────┤
│ TỔNG QUAN    │ LOCATION MAP  │ REPUTATION (từng provider)    │
│ ASN, ISP,    │ nhiều điểm +  │ IPQS, ProxyCheck, AbuseIPDB…  │
│ loại IP,     │ centroid +    │ mỗi dòng: score, signal, link │
│ reverse DNS  │ vòng bán kính │ gốc, thời gian check          │
├──────────────┼───────────────┼───────────────────────────────┤
│ BLACKLIST    │ MẠNG          │ LEAK + TỐC ĐỘ (proxy only)    │
│ bảng list    │ ping, loss,   │ WebRTC, DNS leak, timezone,   │
│ có/không,    │ traceroute,   │ JA3 (optional), down/up       │
│ nhóm list    │ TTL           │                               │
├──────────────────────────────────────────────────────────────┤
│ BẰNG CHỨNG: bảng tất cả provider, ai đồng ý / lệch / thiếu   │
│ LỊCH SỬ + [Xuất JSON] [Xuất CSV] [Copy báo cáo tóm tắt]       │
└──────────────────────────────────────────────────────────────┘
```

### 3.3. Component và trạng thái bắt buộc

- `InputConsole`: validate IP ngay khi gõ (đỏ nếu sai định dạng), tự detect IP-only vs proxy khi có `:port`, dropdown giao thức chỉ hiện khi có port, checkbox "Lưu vào lịch sử" mặc định bật, nút Scan disable khi đang quét.
- `VerdictHUD`: hiển thị Clean Score (0–100) và Confidence Score (0–100) TÁCH BIỆT, không gộp. Nhãn verdict là 1 trong 5: `Sạch`, `Tạm`, `Nghi ngờ`, `Bẩn`, `Chưa đủ dữ liệu`.
- `ScanProgress`: mỗi module có trạng thái `pending / running / done / error / skipped (thiếu key, cần proxy, hết quota)`. Kết quả về tới đâu render tới đó (streaming qua Tauri event, không chờ hết rồi mới hiện).
- `GeoMapCard`: bản đồ KHÔNG dùng tile map cần API key trả phí nếu có thể tránh. Dùng SVG world map tĩnh hoặc thư viện map miễn phí (Leaflet + OpenStreetMap tile, ghi attribution). Vẽ: tất cả điểm của từng nguồn (màu khác nhau theo nguồn), điểm centroid, vòng tròn bán kính không chắc chắn. Không bao giờ chỉ vẽ 1 chấm duy nhất.
- `ReputationCard`, `BlacklistTable`, `EvidenceTable`: mỗi dòng phải có: tên provider/list, kết quả, link gốc mở được, thời gian check, lý do nếu thiếu (timeout / hết quota / chưa nhập key).
- `HistoryPanel`: list lần check cũ, bấm vào load lại từ cache (ghi rõ "từ cache, check lúc HH:MM DD/MM"), nút "Check lại" để gọi mới.
- `SettingsPanel`: nhập API key từng provider (password input, lưu Credential Manager), bật/tắt từng nhóm DNSBL, timeout, thư mục xuất file, phiên bản Geo DB và ngày cập nhật, trạng thái health từng provider.

### 3.4. Trạng thái lỗi và edge case UI phải xử lý

- IP private / loopback / reserved → dừng ngay, banner giải thích, không gọi API.
- 1 provider lỗi → thẻ đó hiện `Lỗi: <lý do ngắn>` + nút thử lại riêng, không làm sập toàn bộ.
- Hết quota → hiện `Hết quota free, check lại sau / nhập key`, Confidence bị trừ, verdict bị chặn theo §6.
- Không có mạng → banner rõ ràng, vẫn cho xem lịch sử cache.
- Kết quả cũ từ cache phải ghi rõ thời gian, không giả vờ là kết quả mới.

---

## 4. Back-end — kiến trúc 4 tầng

### 4.1. Tầng giao diện (React)

Chỉ render + gọi Tauri command. Không chứa logic chấm điểm, không gọi trực tiếp API provider từ browser (tránh lộ key, tránh CORS, tránh bị chặn).

### 4.2. Tầng lệnh (Tauri commands — API duy nhất)

```ts
// Front-end gọi qua invoke, tên command giữ nguyên khi port sang Tauri
check_ip(input: string): Promise<CheckSession>
  // input: "1.2.3.4" hoặc "1.2.3.4:8080", kèm protocol + credentials nếu là proxy (truyền qua command, không lưu)
check_ip_stream(input: string): Promise<void>
  // bắn Tauri event "check-progress" từng module, front-end cập nhật dần
get_history(limit: number): Promise<CheckSummary[]>
get_check_detail(check_id: string): Promise<FullCheckResult>
export_report(check_id: string, format: "json" | "csv"): Promise<string> // trả về đường dẫn file đã ghi
get_provider_health(): Promise<ProviderHealth[]>
save_settings(settings: Settings): Promise<void>
get_settings(): Promise<Settings>
```

### 4.3. Tầng điều phối (orchestrator)

- Nhận input → `validator` → tách job: geo, asn, fraud, abuse, dnsbl, network. Location_engine chạy sau khi geo về. Leak/speed chỉ chạy nếu là proxy mode.
- Chạy song song bằng `tokio::join` / task set, semaphore giới hạn (ví dụ tối đa 8 request đồng thời) để không bị provider rate-limit vì burst.
- Timeout mỗi provider: 5–8 giây. Timeout toàn bộ IP-only: mục tiêu < 30 giây. Provider timeout → evidence `signal = unknown`, `error = timeout`, không retry quá 1 lần.
- Circuit breaker: provider lỗi liên tiếp 5 lần trong 10 phút → tạm ngắt 10 phút, UI hiện health đỏ, Confidence bị trừ.
- Partial result: trả về ngay khi từng job xong, không chờ job chậm nhất.

### 4.4. Tầng provider (adapter)

Mọi provider implement cùng 1 trait, trả về cùng 1 struct chuẩn hoá. Scoring và UI KHÔNG được đọc field riêng của từng provider.

```rust
// Pseudocode, implement tương đương trong Rust
trait Provider {
    fn id(&self) -> &'static str;          // vd "ipqualityscore"
    fn category(&self) -> Category;        // Geo | Asn | Fraud | Abuse | ThreatIntel
    fn upstream(&self) -> &'static str;    // nguồn dữ liệu gốc, để chống trùng phiếu (§6.2)
    fn requires_key(&self) -> bool;
    async fn check(&self, ip: &IpAddr) -> Result<ProviderEvidence, ProviderError>;
}

struct ProviderEvidence {
    provider: String,
    category: Category,
    upstream: String,
    signal: Signal,        // Clean | Suspicious | Bad | Unknown
    raw_score: Option<f64>,// score gốc của provider, giữ nguyên thang gốc
    raw: serde_json::Value,// payload gốc (đã xoá key), để debug / export
    checked_at: DateTime<Utc>,
    source_url: String,    // link gốc để người dùng đối chiếu tay
}
```

---

## 5. Provider matrix — đa nguồn, ưu tiên free, uy tín

### 5.1. Geo + ASN

| Nguồn | Cần key? | Dùng để | Ghi chú |
|---|---|---|---|
| ip-api.com | Không (45 req/phút) | Geo chính, ASN, hosting/proxy/mobile flag | Free tier giới hạn rate, phải cache + backoff |
| ipwho.is | Không | Geo fallback, ASN | Đối chiếu độc lập với ip-api |
| ipinfo.io | Token free (50k/tháng) | Geo, ASN, privacy flag | Có token thì dùng, không có thì bỏ qua, không chặn verdict chỉ vì thiếu nó |
| RIPEstat API | Không | ASN, prefix, quốc gia RIR | Dữ liệu RIR/BGP, không phải database geo thương mại |
| BGPView API | Không | ASN, prefix | Đối chiếu ASN |
| Team Cymru DNS | Không | IP → ASN qua DNS | `origin.asn.cymru.com`, không cần HTTP API |
| MaxMind GeoLite2 City/Country | Tài khoản free | Database local, geo chính xác hơn API lẻ | Tải DB về, đóng gói kèm app, cập nhật hàng tháng, hiển thị version + ngày DB |
| IP2Location LITE DB | Free | Database local đối chiếu | Hãng khác MaxMind, để triangulation |
| DB-IP Lite | Free | Database local đối chiếu | Hãng thứ 3, để triangulation |

### 5.2. Fraud / Proxy / VPN

| Nguồn | Cần key? | Free tier tham khảo (verify lại lúc implement) |
|---|---|---|
| IPQualityScore | Có | ~5.000/tháng |
| ProxyCheck.io | Không / có | ~1.000/ngày bản free |
| Scamalytics | Có | Xem §5.4, không scrape |
| ip-api / ipinfo flag | Không / token | Tín hiệu phụ proxy/hosting/mobile, không tính là phiếu fraud chính |

### 5.3. Abuse / Threat intel / Blacklist

| Nguồn | Loại | Ghi chú |
|---|---|---|
| AbuseIPDB | Báo cáo cộng đồng | ~1.000/ngày bản free, cần key. Field quan trọng: `abuseConfidenceScore`, số report 90 ngày, loại abuse, lần report gần nhất |
| GreyNoise | Honeypot | Community API giới hạn, cho biết IP có đang quét/tấn công diện rộng không |
| Blocklist.de | Log tấn công server | Đối chiếu abuse |
| VirusTotal (optional) | Threat intel tổng hợp | Cần key free, chỉ làm bằng chứng phụ, không bắt buộc |
| Abuse.ch (optional) | Feodo / URLhaus | Chỉ khi IP có trong list, không dùng làm phiếu chính |

**DNSBL — query DNS trực tiếp, KHÔNG scrape web multirbl/mxtoolbox.** Đảo ngược IP (`1.2.3.4` → `4.3.2.1`) rồi query `<reversed>.<zone>`, trả về `127.0.0.x` là listed.

Nhóm và ví dụ zone (verify zone còn hoạt động lúc implement, zone chết thì disable và log, không làm sập check):

- Spamhaus: `zen.spamhaus.org` (bao gồm SBL/XBL/PBL, tách riêng khi cần), lưu ý chính sách fair-use cho cá nhân / tần suất thấp.
- Thương mại: `b.barracudacentral.org` (cần đăng ký / lưu ý điều khoản).
- Cộng đồng: `bl.spamcop.net`, `dnsbl.sorbs.net`, `dnsbl-1.uceprotect.net` (chọn 1–2 zone UCEPROTECT còn hoạt động).
- Chuyên biệt: Tor exit list (`torexit.dan.me.uk` hoặc danh sách Tor Project), DroneBL (`dnsbl.dronebl.org`).
- Tổng mục tiêu: 40–50 list, chia 4 nhóm trên. Mỗi nhóm là 1 phiếu nhóm, không phải mỗi list là 1 phiếu độc lập vô hạn (tránh Spamhaus chiếm đa số).

### 5.4. Quy tắc với web không có API free công khai ổn định

- **Scamalytics, Whoer, BrowserLeaks, ipleak, dnsleaktest, creepjs, bot.sannysoft:** đây là web tương tác, không phải API. KHÔNG scrape, KHÔNG tự động vượt CAPTCHA để lấy số.
- Scamalytics: nếu người dùng nhập API key thì gọi API chính thức, nếu không có key thì chỉ tạo link tra tay + hiển thị `Chưa có nguồn này`, và Confidence bị trừ tương ứng.
- Whoer / BrowserLeaks / creepjs / bot.sannysoft: implement phiên bản local tương đương trong app (xem §8), không scrape web gốc.
- multirbl / mxtoolbox / ipvoid: chỉ dùng làm link đối chiếu tay, không dùng làm nguồn dữ liệu chính vì đã có DNSBL trực tiếp.

### 5.5. Provider registry và health

File `providers.yaml` (không chứa key) cho mỗi provider: `id, category, upstream, method (api/dns/bgp/local_db), requires_key, weight_in_category, timeout_ms, rate_limit, enabled_by_default`.

App tự theo dõi: success rate, latency trung bình, lần lỗi gần nhất, DB version (với local DB). Provider hay lỗi / DB cũ sẽ tự bị giảm trọng số và hiện health vàng/đỏ trong Settings. Thêm provider mới = thêm adapter + 1 dòng registry, không sửa scoring.

---

## 6. Scoring — nguyên tắc vàng: KHÔNG 1 provider nào quyết định sạch/bẩn

### 6.1. Chuẩn hoá trước khi cộng

Mỗi provider có thang khác nhau, phải map riêng về `Signal` trước:

- IPQS fraud score: ví dụ < 25 sạch, 25–75 nghi ngờ, > 75 bẩn — map này là ví dụ, implement phải đọc docs hiện tại của provider và ghi map vào `providers.yaml` / code, không hardcode mù.
- ProxyCheck risk score: map tương tự theo docs của nó.
- AbuseIPDB `abuseConfidenceScore`: ví dụ < 10 sạch, 10–50 nghi ngờ, > 50 bẩn (theo yêu cầu người dùng, < 10% là ngưỡng sạch).
- DNSBL: listed trong nhóm Spamhaus = Bad mạnh, listed nhóm cộng đồng = Suspicious/Bad tùy nhóm, không listed = Clean cho nhóm đó.
- Geo/ASN: không có "score", chỉ có signal nhất quán / không nhất quán.

### 6.2. Chống trùng phiếu trá hình

- Bảng `upstream` bắt buộc. Nhiều web tổng hợp cùng lấy Spamhaus thì dù hiện 3 tên cũng chỉ tính 1 phiếu Spamhaus.
- 2 database geo mua chung 1 nguồn cũng chỉ tính 1 phiếu.
- Scoring chỉ cộng theo `upstream + category`, không cộng theo tên provider hiển thị.

### 6.3. Quorum — thiếu nguồn thì không được kết luận sạch

- Fraud: cần ít nhất 2 phiếu chính (IPQS, ProxyCheck, Scamalytics nếu có) trả về kết quả (không phải Unknown). Chỉ có 1 → verdict tối đa `Chưa đủ dữ liệu`.
- Blacklist: cần ít nhất 3 nhóm list trả về kết quả.
- Geo/ASN: cần ít nhất 2 nguồn đồng ý country + ASN. Lệch → cờ `Không nhất quán`.
- Nếu provider chết/timeout/hết quota: fallback trong cùng khía cạnh, đồng thời trừ Confidence, không lặng lẽ bỏ qua.

### 6.4. Trọng số và công thức

- Clean Score (0–100) = trung bình có trọng số theo khía cạnh, ví dụ: Fraud 35%, Blacklist 25%, ASN/Loại IP 20%, Abuse history 10%, Nhất quán (geo/timezone/DNS) 10%. Tổng = 100%.
- Trong 1 khía cạnh, không provider nào chiếm quá 40% trọng số của khía cạnh đó. Nghĩa là 1 provider xấu nhất cũng chỉ kéo tổng điểm xuống ~14% (35% × 40%), không thể một mình lật verdict.
- Confidence Score (0–100) tách biệt: tính từ độ phủ (bao nhiêu phiếu có kết quả / tổng phiếu kỳ vọng) và độ đồng thuận (bao nhiêu phiếu cùng signal). Càng nhiều nguồn, càng đồng ý → Confidence càng cao.

### 6.5. Luật xung đột và hạ bậc

- 1 nguồn báo bẩn, các nguồn còn lại sạch, không blacklist → verdict `Nghi ngờ`, ghi rõ nguồn lệch + khả năng false positive, không kết luận bẩn ngay.
- 1 nguồn báo sạch, các nguồn còn lại bẩn / dính blacklist → không được kết luận sạch.
- Dính Spamhaus ZEN hoặc Tor exit: tự động hạ bậc, và cần ít nhất 1 nguồn blacklist khác hoặc abuse history xác nhận thì mới chốt `Bẩn`. Nếu chỉ có 1 bằng chứng đơn lẻ mạnh thì verdict tối đa là `Nghi ngờ cao`, ghi rõ là bằng chứng đơn lẻ.
- Verdict cuối là 1 trong 5, map từ Clean Score + quorum + xung đột, KHÔNG chỉ map từ Clean Score:

| Verdict | Điều kiện chính |
|---|---|
| Sạch | Clean ≥ 85, đủ quorum, không xung đột nặng, không dính nhóm Spamhaus/Tor |
| Tạm | Clean 65–84, đủ quorum, xung đột nhẹ hoặc 1 DNSBL cộng đồng |
| Nghi ngờ | Clean 40–64, hoặc xung đột mạnh giữa các nguồn |
| Bẩn | Clean < 40, hoặc đồng thuận đa nguồn báo bẩn / dính nhiều nhóm blacklist |
| Chưa đủ dữ liệu | Thiếu quorum ở bất kỳ khía cạnh bắt buộc nào, bất kể Clean Score tạm tính là bao nhiêu |

### 6.6. Ví dụ dữ liệu chuẩn hoá trả về UI

```json
{
  "ip": "1.2.3.4",
  "mode": "ip_only",
  "clean_score": 82,
  "confidence_score": 91,
  "verdict": "Tạm",
  "verdict_reason": "Dính 1 DNSBL cộng đồng, các nguồn fraud còn lại sạch",
  "evidence": [
    {
      "provider": "ipqualityscore",
      "category": "fraud",
      "upstream": "ipqualityscore",
      "signal": "Clean",
      "raw_score": 12,
      "checked_at": "2026-10-25T11:30:00+07:00",
      "source_url": "https://www.ipqualityscore.com/"
    }
  ]
}
```

---

## 7. Location — module riêng, triangulation, không tin 1 web

### 7.1. Giới hạn phải ghi rõ trong UI và tài liệu

- Quốc gia: tin cậy cao (~95% với IP cố định, thấp hơn với anycast).
- Thành phố/khu vực: tin cậy trung bình, phụ thuộc loại IP.
- Mã bưu chính / lat-lon chi tiết: chỉ kèm bán kính không chắc chắn, ví dụ `accuracy_radius_km` của MaxMind.
- Đường/phố/nhà: KHÔNG BAO GIỜ khẳng định từ IP. Nguồn nào trả về dạng địa chỉ chi tiết thì gắn cờ `Không đáng tin cho IP`.

### 7.2. Vì sao location hay sai

Database cập nhật lệch thời gian, IP vừa cấp lại cho ISP khác, ISP đăng ký vị trí trụ sở/PoP chứ không phải vị trí người dùng, mobile qua gateway tập trung, anycast cùng IP ở nhiều nước, VPN/datacenter cho vị trí thoát chứ không phải vị trí người thật.

### 7.3. Triangulation

- Lấy geo từ: ip-api, ipwho.is, ipinfo (API) + MaxMind GeoLite2 + IP2Location LITE + DB-IP Lite (local DB). Mỗi nguồn hiển thị riêng: country, region, city, postal, lat/lon, timezone, tên DB + ngày DB. DB cũ > 60 ngày → trừ điểm tin cậy.
- Quốc gia: bỏ phiếu đa số. Tất cả đồng ý → tin cậy cao, chia đôi → cờ tranh chấp.
- Thành phố: tính centroid từ các tọa độ, đo độ phân tán:
  - Các nguồn chụm trong 50 km → tin cậy cao.
  - 50–200 km → trung bình.
  - > 200 km → không chốt thành phố, chỉ chốt quốc gia/vùng, hiện cảnh báo lệch.
- Không lấy trung bình mù khi các điểm xa nhau (ví dụ 1 điểm VN, 1 điểm Singapore thì trung bình ra biển là vô nghĩa).

### 7.4. Đối chiếu độc lập ngoài database geo

- **ASN/BGP:** RIPEstat, BGPView, Team Cymru cho prefix, ASN, quốc gia ASN.
- **Cloud range:** với IP datacenter, đối chiếu dải IP chính thức: AWS `ip-ranges.json`, Google Cloud, Azure, Cloudflare. Nếu IP nằm trong dải `ap-southeast-1` của AWS thì vị trí datacenter Singapore đáng tin hơn database geo.
- **PeeringDB:** với IP hosting, tra facility của ASN.
- **Reverse DNS:** hostname có thể chứa mã thành phố / mã sân bay (ví dụ `hcm`, `hn`, `sg`, `tyo`). Chỉ làm bằng chứng phụ, hiển thị hostname gốc, không tự suy diễn thành kết luận.
- **Đăng ký vs sử dụng:** quốc gia RIR khác quốc gia geo → cờ, thường gặp ở IP mới cấp lại / thuê lại / VPN.
- **Timezone:** timezone từ từng DB có khớp nhau không. Ở proxy mode, timezone browser có khớp timezone IP thoát không.

### 7.5. Độ tin cậy theo loại IP

- Residential cố định: quốc gia rất cao, thành phố khá cao.
- Mobile / CGNAT: quốc gia cao, thành phố thấp, vị trí thường là gateway nhà mạng.
- Datacenter/hosting: vị trí datacenter có thể cao nếu tra được cloud range / PeeringDB, database geo hay sai.
- VPN/Tor: vị trí thoát là vị trí đánh giá, ghi rõ không phải vị trí người thật.
- Anycast: không chốt thành phố, chỉ ghi anycast + quốc gia theo ASN.

### 7.6. Đo độ trễ (nâng cao, phase 2)

- Phase 1: ping + traceroute từ máy người dùng, vị trí hop cuối có hostname rõ ràng làm bằng chứng phụ. RTT thấp thường gần, RTT cao + hop quốc tế thường xa, nhưng routing vòng vèo làm sai lệch nên chỉ dùng đối chiếu.
- Phase 2 (optional, cần tài khoản/credit): đo từ nhiều điểm qua RIPE Atlas hoặc looking glass công khai, suy vùng bằng giao nhau độ trễ. Đo 1 điểm không bao giờ suy ra thành phố chính xác. Nếu không có token RIPE Atlas thì bỏ qua module này, không fake.

### 7.7. UI location bắt buộc

- Bản đồ nhiều điểm + centroid + vòng bán kính, không phải 1 chấm duy nhất.
- Bảng phiếu: nguồn nào nói ở đâu, lệch centroid bao nhiêu km, DB ngày nào.
- Kết luận theo tầng: quốc gia chốt được hay không, thành phố chốt được hay không, lý do nếu không chốt được.
- Cảnh báo lệch: ví dụ 3 nguồn nói Singapore, 1 nguồn nói Việt Nam, lệch > 2.000 km → cảnh báo đỏ.
- Lịch sử: IP này trước đây check ra vị trí khác → hiện thay đổi theo thời gian (cấp lại / proxy xoay vị trí).

---

## 8. Proxy mode — Leak + Tốc độ (chỉ khi có proxy)

### 8.1. IP thoát thật

- Gọi `https://httpbin.org/ip`, `https://ip.oxylabs.io`, hoặc endpoint tương đương qua proxy, so sánh IP thoát với IP nhập. Khác nhau → cờ đỏ, ghi rõ IP thoát thực tế.
- Không dùng 1 endpoint duy nhất, dùng ít nhất 2 endpoint để đối chiếu.

### 8.2. Leak — implement local, không scrape web leak

Chạy Chromium headless của máy (hoặc Chromium đi kèm nếu cần) với `--proxy-server=<protocol>://<ip>:<port>`, mở trang test nội bộ đóng gói sẵn trong app. Trang này thu:

- **WebRTC ICE candidates:** nếu candidate chứa IP thật của máy người dùng (không phải IP proxy) → leak, verdict hạ bậc.
- **DNS leak:** request DNS của browser có đi qua proxy không. Với SOCKS5 thì DNS remote, với HTTP proxy thì kiểm tra resolver nhìn thấy. Ghi rõ phương pháp và giới hạn, không khẳng định tuyệt đối nếu browser tự dùng DoH riêng.
- **Timezone / ngôn ngữ / geo browser:** so sánh với geo của IP thoát. Lệch → cờ không nhất quán (dấu hiệu fingerprint lệch, dễ bị detect).
- **Headless / automation flag:** kiểm tra các flag kiểu bot.sannysoft (webdriver, plugins, languages, v.v.) ở mức local, chỉ để cảnh báo, không dùng làm verdict duy nhất.
- **JA3/JA4:** optional, độ tin cậy thấp. Chỉ hiển thị nếu lấy được qua endpoint JA3 công khai qua proxy (ví dụ ja3er) và ghi rõ nguồn không ổn định. Không tự bịa JA3.
- **TCP/IP fingerprint:** optional, nâng cao. Ping TTL cho đoán sơ OS (Windows ~128, Linux ~64), so sánh với User-Agent. Không làm SYN fingerprint xâm nhập.

### 8.3. Tốc độ

- Tải file test qua proxy từ ít nhất 2 CDN/endpoint (ví dụ Cloudflare CDN, file test công khai), đo download throughput, latency, jitter. Không đo 1 server duy nhất.
- Hiển thị: latency tới endpoint, tốc độ down (Mbps), thời gian tải, kích thước file test, thời điểm đo. Ghi chú: tốc độ phụ thuộc server đích và giờ đo, chỉ so sánh tương đối trong cùng 1 lần test.
- Không đo upload trừ khi có endpoint upload công khai và người dùng đồng ý, vì upload test tốn băng thông và có thể bị chặn.

### 8.4. An toàn khi chạy proxy mode

- Chỉ kết nối tới proxy người dùng tự nhập, không tự động thử credential mặc định.
- Timeout browser 20–30 giây, kill process sau khi xong, không để Chromium chạy nền.
- Không lưu username/password proxy vào SQLite/history. Chỉ lưu IP:port + giao thức, không lưu credential.

---

## 9. Network probe (IP-only cũng có)

- Ping: latency trung bình, jitter, loss (ICMP, nếu bị chặn thì fallback TCP ping tới port 80/443 và ghi rõ phương pháp).
- Traceroute: số hop, hop cuối, hostname hop (nếu có).
- Reverse DNS (PTR): hostname, có khớp với ISP/ASN không.
- TTL: đoán sơ OS, chỉ làm tín hiệu phụ.
- Port: CHỈ khi proxy mode và người dùng đồng ý, kiểm tra port proxy đã nhập có mở không. Không quét port khác.

---

## 10. Cache, lịch sử, export, settings

### 10.1. SQLite schema (tối thiểu)

```sql
-- checks: 1 dòng / 1 lần check
CREATE TABLE checks (
  id TEXT PRIMARY KEY,
  ip TEXT NOT NULL,
  mode TEXT NOT NULL, -- ip_only | proxy
  proxy_host TEXT, proxy_port INTEGER, proxy_protocol TEXT, -- KHÔNG lưu credential
  clean_score INTEGER, confidence_score INTEGER, verdict TEXT, verdict_reason TEXT,
  checked_at TEXT NOT NULL
);
-- provider_results: 1 dòng / 1 provider / 1 lần check
CREATE TABLE provider_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  check_id TEXT NOT NULL,
  provider TEXT NOT NULL, category TEXT NOT NULL, upstream TEXT NOT NULL,
  signal TEXT NOT NULL, raw_score REAL, raw_json TEXT, source_url TEXT,
  checked_at TEXT NOT NULL
);
-- geo_db_versions: version + ngày của từng local DB
CREATE TABLE geo_db_versions (
  db_name TEXT PRIMARY KEY, version TEXT, updated_at TEXT
);
-- settings: KHÔNG chứa API key, key nằm ở Credential Manager
CREATE TABLE settings (
  key TEXT PRIMARY KEY, value TEXT
);
```

### 10.2. TTL cache

- Geo: cache dài (ví dụ 7 ngày) vì geo ít đổi, trừ khi IP có lịch sử đổi vị trí.
- Reputation / fraud: 24 giờ.
- Blacklist: 6–12 giờ.
- Abuse history: 24 giờ.
- Leak / tốc độ: không cache, luôn đo mới vì phụ thuộc thời điểm và proxy.
- Check lại từ cache phải hiển thị rõ thời gian cũ. Nút "Check lại" luôn gọi mới, bỏ qua cache.

### 10.3. Export

- JSON: toàn bộ `FullCheckResult` kèm evidence, thời gian, version DB.
- CSV: 1 dòng / 1 IP, cột: ip, verdict, clean_score, confidence, country, city, asn, isp, ip_type, fraud signals, blacklist listed count, checked_at.
- Copy báo cáo tóm tắt: text ngắn gọn để dán chat, gồm verdict, score, country/city, ASN, lý do chính, link evidence chính.

---

## 11. Đóng gói, cập nhật, vận hành

- Build: `npm run tauri build` (hoặc `cargo tauri build` tùy cấu hình Tauri v2). Output: installer NSIS + portable `.exe`.
- Test trên máy Windows sạch (không cài Node/Rust) trước khi giao: mở app, nhập `8.8.8.8` và `1.1.1.1` làm smoke test, kiểm tra verdict, location, blacklist không crash khi thiếu key.
- Updater: Tauri Updater + GitHub Releases, ký release nếu có chứng chỉ, nếu không có thì ghi rõ "chưa ký, Windows SmartScreen có thể cảnh báo" và hướng dẫn bấm Run anyway.
- Geo DB update: kèm theo mỗi release, hoặc cho phép app tự tải DB mới từ nguồn chính thức (MaxMind / IP2Location / DB-IP) khi người dùng bấm "Cập nhật Geo DB" trong Settings, hiển thị version + ngày sau khi cập nhật.
- Log: log lỗi local, không log API key, không log credential proxy, không log toàn bộ payload nếu chứa thông tin nhạy cảm. Log rotation đơn giản (giữ 7 ngày).

---

## 12. Roadmap và Definition of Done

### Phase 1 — MVP IP-only (làm trước, giao được)

- [ ] Input IP, validate, verdict HUD, scan progress streaming.
- [ ] Geo (ip-api + ipwho.is + ipinfo nếu có token), ASN, loại IP.
- [ ] Fraud (IPQS + ProxyCheck), Abuse (AbuseIPDB), DNSBL trực tiếp (ít nhất Spamhaus + Barracuda + SpamCop + SORBS + Tor).
- [ ] Scoring + quorum + Confidence theo §6, Evidence table, export JSON/CSV.
- [ ] Lịch sử SQLite + cache theo §10.
- **Done khi:** nhập `8.8.8.8`, app trả verdict trong < 30s, thiếu key vẫn chạy được bằng nguồn free, 1 provider lỗi không làm sập check, export JSON đúng schema §6.6.

### Phase 2 — Location nâng cao + UI hoàn thiện

- [ ] Local DB MaxMind + IP2Location + DB-IP, triangulation + centroid + bán kính (§7).
- [ ] Cloud range + PeeringDB + reverse DNS + timezone consistency.
- [ ] Bản đồ nhiều điểm, bảng phiếu lệch km, cảnh báo lệch.
- [ ] Settings key, provider health, Geo DB version.
- **Done khi:** 1 IP có các nguồn lệch nhau phải hiện cảnh báo lệch, không chốt thành phố sai; DB version hiển thị đúng ngày.

### Phase 3 — Proxy mode

- [ ] Input IP:port + HTTP/SOCKS5, IP thoát thật (2 endpoint).
- [ ] Browser leak: WebRTC, DNS, timezone/language, headless flag.
- [ ] Speed: 2 endpoint, down + latency.
- [ ] JA3 optional, ghi rõ độ tin cậy thấp.
- **Done khi:** proxy test cho thấy IP thoát khác IP nhập thì cờ đỏ; WebRTC lòi IP thật thì verdict hạ bậc; không có proxy thì Leak/Speed hiện "Chưa đo được".

### Phase 4 — Đóng gói .exe + vận hành

- [ ] Installer NSIS + portable, test máy sạch.
- [ ] Updater, Geo DB update, log rotation.
- [ ] README hướng dẫn dùng, hướng dẫn nhập key free từng provider.
- **Done khi:** người dùng chỉ cần tải `.exe`, mở lên, nhập IP là dùng được, không cần cài thêm gì.

---

## 13. Test cases bắt buộc (không giao nếu fail)

1. IP công khai phổ biến (`8.8.8.8`, `1.1.1.1`): phải trả verdict, geo, ASN, không crash.
2. IP private (`192.168.1.1`, `10.0.0.1`): dừng sớm, banner giải thích, không gọi API.
3. IP sai định dạng (`999.999.999.999`, `abc`): báo lỗi ngay, nút Scan disable.
4. Thiếu tất cả API key: vẫn chạy bằng nguồn free, verdict tối đa `Chưa đủ dữ liệu` nếu thiếu quorum, không crash, không hiện score giả.
5. 1 provider timeout (giả lập bằng cách tắt mạng tới provider đó hoặc mock timeout): check vẫn hoàn tất, thẻ đó hiện lỗi, Confidence giảm.
6. Các nguồn location lệch nhau (mock 1 nguồn VN, 1 nguồn Singapore): UI hiện cảnh báo lệch, không chốt thành phố.
7. Proxy mode với IP thoát khác IP nhập (mock): cờ đỏ IP thoát.
8. WebRTC leak (mock candidate chứa IP thật): verdict hạ bậc, thẻ Leak đỏ.
9. Check lại IP cũ: load từ cache có ghi thời gian cũ; bấm "Check lại" gọi mới.
10. Export JSON/CSV: file mở được, đủ field theo §6.6 và §10.3, không chứa API key hay credential proxy.

---

## 14. Rủi ro và giới hạn phải nói rõ với người dùng cuối

- Không có nguồn nào khẳng định 100% residential, nhất là IP thuê lại / IP mới cấp lại.
- Spamhaus có chính sách fair-use, dùng cá nhân tần suất thấp thì ổn, query hàng loạt sẽ bị chặn.
- Free tier các provider thay đổi theo thời gian — implement phải verify quota và docs lúc code, không tin mù số trong tài liệu này.
- Tốc độ proxy phụ thuộc server đích và giờ đo, chỉ so sánh tương đối.
- JA3, TCP fingerprint, RIPE Atlas là optional, độ tin cậy thấp hoặc cần token, không dùng làm verdict duy nhất.
- IP anycast, mobile gateway, CGNAT làm location thành phố không đáng tin — app phải ghi rõ, không cố chốt cho bằng được.

---

## 15. Hướng dẫn cho model AI implement

1. Đọc hết tài liệu này trước khi code, không tự đổi stack, không tự đổi công thức scoring, không tự bỏ quorum.
2. Làm theo thứ tự Phase 1 → 2 → 3 → 4. Không làm Phase 3 trước khi Phase 1 pass hết test §13 (trừ test proxy).
3. Mỗi provider mới phải có: adapter riêng, entry trong `providers.yaml`, test mock (thành công + timeout + hết quota), và dòng trong Evidence table.
4. Mọi verdict phải trace được: từ verdict → Clean/Confidence → từng evidence → link gốc. Nếu không trace được thì coi như chưa xong.
5. Khi gặp mâu thuẫn giữa tài liệu này và docs của provider (thang score, quota, zone DNSBL), ưu tiên docs hiện tại của provider cho phần kỹ thuật đó, nhưng giữ nguyên nguyên tắc §6 (đa nguồn, quorum, không 1 provider quyết định) và ghi chú thay đổi vào README.
6. Giao cuối: code + README + file `.exe` test được trên máy sạch + video/screenshot demo 1 lần check IP-only và 1 lần check proxy (nếu có proxy test).

---

*End of spec.*
