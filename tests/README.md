# Kiểm thử — IP Checker

Thư mục này chứa **harness thực thi** cho 10 test bắt buộc §13 của
[`../../IP-Checker-Build-Plan.md`](../../IP-Checker-Build-Plan.md), cùng bộ fixture
đóng vai từng provider. Mục tiêu: mỗi yêu cầu trong §13 phải có một cổng kiểm tra
**chạy được, lặp lại được, và không thể nói dối**.

---

## 1. Chạy

```powershell
cd E:\auto-reg\check-ip\ip-checker

node tests\harness\spec13.test.mjs            # static + live probe nếu đã build
node tests\harness\spec13.test.mjs --static   # không mạng, không binary, không cargo
node tests\harness\spec13.test.mjs --cargo    # CÓ chạy `cargo test` (chỉ khi crate sạch)
node tests\harness\spec13.test.mjs --json     # tóm tắt máy đọc được
```

> **`cargo test` là opt-in.** Mặc định harness **không** gọi cargo: compile trong một
> lần chạy test có thể tranh build lock với agent khác và mất vài phút. Phải có cờ
> `--cargo` thì X5 mới chạy thật; không có cờ thì X5 = BLOCKED kèm lý do.

Mã thoát:

| Exit | Ý nghĩa |
|---|---|
| `0` | Tất cả PASS |
| `1` | Có ít nhất 1 FAIL → **phải sửa** |
| `2` | Chỉ có BLOCKED/SKIP, không FAIL |

Kết quả máy đọc được: `tests/spec13-report.json`.
Bản text lần chạy gần nhất: `tests/_last-run.txt`.

---

## 2. Ba trạng thái — và tại sao BLOCKED không phải PASS

| Trạng thái | Nghĩa |
|---|---|
| **PASS** | Điều kiện đã được chứng minh **ngay trong lần chạy này**. |
| **FAIL** | Đã kiểm tra và **sai**. Đây là bug thật. |
| **BLOCKED** | **Không kiểm tra được** vì thiếu điều kiện tiên quyết (chưa có code, chưa có exe, chưa được phép chạy cargo, không có mạng). |

**Quy tắc sắt:** thiếu điều kiện → `BLOCKED` + lý do cụ thể. **Không bao giờ** báo
PASS cho thứ chưa thực sự kiểm tra. Một báo cáo toàn PASS mà thật ra toàn BLOCKED
là báo cáo vô giá trị — tệ hơn không có báo cáo.

Nếu bạn thấy một dòng BLOCKED, đọc phần `lý do` để biết cần gì để mở khoá.

---

## 3. Cấu trúc

```
tests/
├── harness/
│   ├── lib.mjs             # Gate class, readiness probe, secret scanner, report writer
│   ├── strings.mjs         # MỌI chuỗi tiếng Việt, dựng bằng \u escape (xem §6)
│   ├── spec13.test.mjs     # 10 cổng §13 + 11 cổng cross-cutting X0…X10
│   └── mutation-x4.mjs     # chứng minh X4 thật sự bắt được lỗi (xem §8.6)
├── fixtures/
│   ├── providers/         # payload giả lập từng provider (68+ file)
│   ├── inputs.json        # IP public / private / invalid / mode detection
│   ├── proxy-mode.json    # exit IP, WebRTC, DNS leak, tốc độ, JA3
│   ├── cache-export.json  # sentinel secret, TTL, schema export
│   ├── geo-divergence.json# 2 nguồn lệch nhau 8429 km
│   ├── export.*.json|csv  # golden + negative control (cố tình rò secret)
│   └── log-redaction.samples.txt   # nửa MUST PASS / nửa MUST FAIL
└── README.md
```

---

## 4. Bản đồ 10 cổng §13

| Cổng | Yêu cầu spec | Chứng minh bằng |
|---|---|---|
| §13.1 | IP public → verdict + geo + ASN, không crash | Fixture IP public thật; `validator`/`orchestrator`/`scoring` wiring; 11/11 file adapter tồn tại. **Phần live: BLOCKED** (xem §7) |
| §13.2 | IP private → dừng sớm, **0 lời gọi API** | `validator.rs` xử lý private/loopback/link-local/unspecified/CGNAT 100.64/10/multicast/broadcast/documentation/ULA fc00::/7/IPv4-mapped; `orchestrator` short-circuit **trước** mọi việc gọi provider; `result.is_private = true`; UI có nhánh banner |
| §13.3 | Input sai định dạng → báo lỗi ngay, nút Scan bị disable | `std::parse::<IpAddr>` từ chối `999.999.999.999`; port phải `1..=65535`; `InputConsole` có state invalid + `disabled` + màu đỏ |
| §13.4 | Không có key nào → nguồn free vẫn chạy, **không bịa điểm** | Fixture no-key cho 6 provider cần key; scenario `no_keys` cấm verdict vượt `Chưa đủ dữ liệu`; `providers.yaml` có ≥4 provider `requires_key: false` |
| §13.5 | 1 provider timeout → check vẫn xong, Confidence giảm | 11/11 fixture timeout; `orchestrator` có timeout + circuit breaker + retry (≤1) + `Signal::Unknown` + progress event |
| §13.6 | Các nguồn geo lệch nhau → cảnh báo, **không chốt city** | `geo-divergence.json`: cùng IP, một nguồn SG một nguồn Moscow, khoảng cách **8429 km**; `location.rs` có centroid + ngưỡng 200 km (chốt city) + 2000 km (cảnh báo) + nhánh `city = None` |
| §13.7 | IP thoát ≠ IP nhập → cờ đỏ | ≥2 endpoint; mismatch → `differs_from_input=true`; 2 endpoint bất đồng → `exit_ip = null` (**không đoán**); proxy không tới được → `reachable=false`, **không bịa IP** |
| §13.8 | WebRTC leak → verdict bị hạ, thẻ Leak đỏ | Fixture leak/clean; `browser_leak.rs` có WebRTC ICE, `--proxy-server`, vòng đời child process + timeout + DNS leak + headless detect |
| §13.9 | Check lại từ cache vẫn giữ **timestamp gốc** | TTL geo = 168 h; `from_cache`; `use_cache` (models.rs); 4 bảng schema; `cache::history()` **không còn** là stub `Vec::new()`; UI có nhãn `từ cache, check lúc` + nút `Check lại` |
| §13.10 | File export mở được, đủ trường, **không rò key** | Golden export 0 hit; fixture `export.leaky.result.json` **6 hit** (chứng minh scanner không phải no-op); log đã redact 0 hit / log rò 7 hit; CSV đúng 12 cột §10.3 đúng thứ tự; source Rust + TS không hardcode key; **self-scan** chính report + `scripts/*.ps1` |

---

## 5. Cổng cross-cutting

| Cổng | Kiểm gì |
|---|---|
| **X0** | Tiến độ code của team (thông tin, luôn PASS) |
| **X1** | Contract 8 lệnh Tauri: `#[tauri::command]` **và** đăng ký trong `generate_handler!` (grep `lib.rs` trước, fallback `main.rs`) + `main.rs` gọi `::run()` + `setup()` có `.manage(` |
| **X2** | Contract kiểu front-end ↔ back-end: 11 interface trong `types.ts`, union `Verdict` đủ 5 nhãn, `Signal` PascalCase, `api.ts` tham chiếu đủ 8 lệnh + event `check-progress` |
| **X3** | §1.2: chế độ IP-only **không được** bịa Leak/Tốc độ. Chuỗi `Chưa đo được — cần nhập proxy` phải khớp **nguyên văn** trong UI và trong backend |
| **X4** | §6: trọng số 35/25/20/10/10, ngưỡng 85/65/40, de-dup theo `upstream`, cap 40% một provider, luật Spamhaus/Tor, và **scoring không đọc field riêng của provider** |
| **X5** | `cargo test --all-targets` thật (BLOCKED tới khi crate sạch) |
| **X6** | Có `.exe` + `scripts/build.ps1` + `scripts/smoke.ps1` + README đủ mục §11 |
| **X7** | `providers.yaml` 45 row vs 11 adapter → phải **SKIP + warn**, không được panic. Quét cả `panic!`/`unwrap()` trong code production (bỏ `#[cfg(test)]`) |
| **X8** | `tokens.css`: tỉ lệ tương phản WCAG AA ≥ 4.5 cho cả 6 cặp chip. Đo **thật** bằng công thức WCAG trong harness, không đọc comment. Ghim `--tint-bad ≤ 12%` |
| **X9** | §8.4/§10.1/§10.3: `FullCheckResult` **không có** field credential nào; chỉ `proxy_host`/`proxy_port`/`proxy_protocol` được phép; `ProxyCredentials` chỉ nằm ở request options và được zeroize; không có cột credential trong SQLite; không có cột credential trong CSV; golden export không có key `password`/`username`/`proxy_credentials` |
| **X10** | An toàn build: `CARGO_TARGET_DIR` **không được** nằm cùng ổ với project (ổ E: chỉ còn ~2.3 GB, target tree cần 2–4 GB → build sẽ chết vì ENOSPC). Kiểm `scripts/*.ps1` tự export biến này chứ không phụ thuộc shell. Kiểm harness tìm `probe.exe` ở **cả hai** vị trí target |

---

## 6. Quy tắc encoding — đọc trước khi sửa harness

Đây không phải chuyện phong cách. Đã từng làm hỏng cả một báo cáo.

### Thảm hoạ đã xảy ra

Dùng `Set-Content -Encoding utf8` để sửa `spec13.test.mjs` khiến PowerShell đọc file
UTF-8 bằng codepage CP1252 rồi ghi lại → literal `"Sạch"` biến thành `"Sáº¡ch"`
**trong chính source của harness**. Kết quả: 8/10 cổng FAIL sai, vì harness đi so
sánh chuỗi đã hỏng. Không phải bug của sản phẩm — bug của công cụ kiểm thử.

### Luật

1. **`tests/harness/*.mjs` là ASCII thuần.** Không một byte > 0x7F.
2. **Mọi chuỗi tiếng Việt nằm trong `strings.mjs`**, dựng bằng `\u` escape:

   ```js
   export const V_SACH = 'S\u1EA1ch';                    // Sạch
   export const NOT_MEASURED_PROXY =
     'Ch\u01B0a \u0111o \u0111\u01B0\u1EE3c \u2014 c\u1EA7n nh\u1EADp proxy';
   ```

3. **Không dùng `Set-Content -Encoding utf8`** trên `.js`/`.mjs`/`.json`/`.md`.
   Dùng `write`/`edit` tool, hoặc:

   ```js
   fs.writeFileSync(p, text, 'utf8');   // Node, không BOM
   ```

   ```powershell
   [System.IO.File]::WriteAllText($p, $t, (New-Object System.Text.UTF8Encoding($false)))
   ```

4. **Fixture JSON không được có BOM** — `JSON.parse` sẽ chết với `Unexpected token '﻿'`.
   `readText()` trong `lib.mjs` đã strip BOM để phòng, nhưng đừng dựa vào nó.

5. **Console PowerShell không render được tiếng Việt.** Nếu cần đọc output, chạy
   `node` qua `System.Diagnostics.ProcessStartInfo` với
   `StandardOutputEncoding = [System.Text.Encoding]::UTF8`, ghi ra file, rồi đọc file.

### Tự kiểm tra

Chỉ **`tests/harness/*.mjs`** phải là ASCII thuần. File tài liệu (`.md`, `.json`)
được chứa tiếng Việt thật.

```powershell
# Phải trả về 0 dòng — harness không được có bất kỳ byte > 0x7F nào
Select-String -Path tests\harness\*.mjs -Pattern '[^\x00-\x7F]'
```

Nếu muốn kiểm tra cả dấu hiệu mojibake (double-encoding) trên fixture:

```powershell
node -e "const fs=require('fs'),p=require('path');function w(d,a=[]){for(const e of fs.readdirSync(d,{withFileTypes:true})){const q=p.join(d,e.name);e.isDirectory()?w(q,a):a.push(q)}return a}const M=['S\u00E1\u00BA\u00A1ch','Ch\u00C6\u00B0a','\u00C3\u00A2\u20AC\u2122','\u00C1\u00BA','\u00C4\u2018'];let n=0;for(const f of w('tests/fixtures').filter(f=>/\.(json|csv|txt)$/.test(f))){const t=fs.readFileSync(f,'utf8');for(const m of M)if(t.includes(m)){console.log('MOJIBAKE:',f);n++}}console.log(n?'':'MOJIBAKE SWEEP: 0 files - OK')"
```

Chú ý: đừng viết chính các chuỗi mojibake đó vào `tests/README.md` — file này được
quét, và chính nó sẽ thành false positive. Đây là lý do các marker trong
`strings.mjs` và trong lệnh trên đều dựng bằng `\u` escape.

---

### 6.1 Encoding, phần 2: log build do PowerShell ghi là UTF-16

`§6` nói về mojibake khi **ghi** tiếng Việt. Đây là bẫy ngược lại, khi **đọc**:

PowerShell trên Windows ghi `>` redirection thành **UTF-16LE có BOM (`FF FE`)**. Nếu đọc
bằng `fs.readFileSync(f, 'utf8')` thì:

- **không** ném lỗi,
- trả về chuỗi xen kẽ `\0` (`"c\0a\0r\0g\0o\0"`),
- **mọi regex đều trượt** → file trông như rỗng.

Hậu quả thật đã xảy ra: harness bỏ qua `FINAL-test3.log` (321 passed) và **lặng lẽ dùng
log cũ hơn** (`302 passed / 21 failed`), rồi báo một kết quả **lỗi thời**. Loại bug này
nguy hiểm vì nó trông giống "PASS/FAIL bình thường", không có triệu chứng nào.

Cách chặn: `decodeText()` trong `lib.mjs` đọc BOM trước khi giải mã.

| BOM | Encoding | Xử lý |
|---|---|---|
| `EF BB BF` | UTF-8 | bỏ 3 byte đầu, decode utf8 |
| `FF FE` | UTF-16LE | decode `utf16le` |
| `FE FF` | UTF-16BE | đảo cặp byte, decode `utf16le` |
| không BOM, byte 2 = `00` | UTF-16LE | decode `utf16le` |
| không BOM | UTF-8 | decode utf8 |

**Quy tắc:** khi đọc bất kỳ file nào do công cụ khác (PowerShell, cargo, teammate) tạo
ra, dùng `readText()`/`readTextStrict()` của harness, **không** gọi `readFileSync(...,'utf8')`
trực tiếp.

**Quy tắc 2:** một gate đọc artefact bên ngoài phải **nói rõ nó đọc file nào**. X5 in
`source: <path>` + `scope: FULL|PARTIAL` + cảnh báo nếu có log mới hơn không đọc được.
Không có mấy dòng đó thì không ai biết kết quả đến từ đâu.

**Quy tắc 3:** khi có nhiều log, chọn theo **(full-run trước, mới nhất sau)**, không
phải "mới nhất". Log một module (`cargo test --lib geo_db` → 18p/0f) mới hơn log full
(313p/11f) rất nhiều — chọn theo mtime sẽ báo xanh trong khi crate đỏ.

### 6.2 Adapter `not_implemented` → chỉ PASS ở mức wiring

Các cổng §13.1 / §13.4 / §13.5 hiện chứng minh được: fixture đúng, contract đúng,
đường đi đúng, xử lý lỗi đúng. **Chưa** chứng minh được hành vi thật (quorum thật,
Confidence tụt thật khi timeout) vì phần lớn adapter còn trả
`ProviderError::new("not_implemented", …)`.

Cách phân loại: `providers.yaml` có trường `status`. Chỉ test hành vi cho entry
`status: "real"`; entry `status: "stub"` → ghi BLOCKED.

## 7. Giới hạn đã biết

### 7.1 §13.1 live — dùng `src/bin/probe.rs`

Harness chạy bằng Node, còn `check_ip` là lệnh async trong crate Rust. Để nối hai
bên, có một binary QA riêng: **`src-tauri/src/bin/probe.rs`**.

Nó gọi thẳng `orchestrator::run_check(input, opts).await`, in **đúng một** object JSON
ra stdout rồi thoát. Log đi stderr. Không cửa sổ, **không cache** (`use_cache=false`),
**không ghi DB** (`save_to_history=false`), **không credential**.

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
$env:CARGO_TARGET_DIR = "C:\cargo-target\ip-checker"
cargo build --bin probe
cargo run  --bin probe -- 8.8.8.8
node tests\harness\spec13.test.mjs        # §13.1 giờ chạy nhánh live
```

Mã thoát của probe, và harness diễn giải chúng:

| Exit | Nghĩa | Harness ghi |
|---|---|---|
| `0` | Check hoàn tất, có evidence | Assert tiếp verdict/geo/ASN/score → PASS hoặc FAIL thật |
| `2` | Chặn trước khi chạy provider (DNS/HTTPS chết, input sai) | **BLOCKED** + `reason` cụ thể. **Không bao giờ PASS** |
| `1` | Lỗi nội bộ ngoài dự kiến | FAIL, kèm stdout/stderr |

Probe làm **preflight bằng DNS** (`lookup_host("ipwho.is:443")`, timeout 6 s) trước khi
gọi pipeline. Mục đích: phân biệt "app hỏng" với "mạng bị chặn". Nếu evidence = 0 mà
IP hợp lệ, probe tự đánh `blocked: true` — vì §13.1 hỏi *public IP có ra verdict + geo
+ ASN không*, và không có evidence thì **không kết luận được**, đúng như tinh thần
BLOCKED ở mục 2.

> Probe **không** được bundle vào installer: `cargo tauri build` chỉ đóng gói binary
> mặc định từ `main.rs`. `[[bin]] probe` chỉ phục vụ QA.

### 7.3 `cargo test` / `cargo tauri build` chưa chạy

X5 và X6 BLOCKED. Cần Lead cho phép: `cargo test` chỉ có nghĩa khi `cargo check` xanh;
`tauri build` chỉ có nghĩa sau khi `cargo test` xanh.

Biến môi trường bắt buộc trên máy này:

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
$env:CARGO_TARGET_DIR = "C:\cargo-target\ip-checker"   # ổ E: chỉ còn ~2.4 GB
```

---

## 8. Thêm test mới

```js
// trong spec13.test.mjs
{
  const g = new Gate('§13.x', 'Tên ngắn', '§13.x');
  g.assert(điềuKiện, 'mô tả điều kiện đã chứng minh', điềuKiện ? null : 'lý do thất bại');
  g.note('dữ liệu phụ, không ảnh hưởng PASS/FAIL');
  gates.push(g.finish());   // hoặc crossGates
}
```

`Gate` hỗ trợ: `assert(ok, label, detail?)`, `note(text)`, `markLive(reason)`,
`finish()`.

Một assertion **phải** kiểm tra đúng thứ nó nói. Đừng grep một token rồi tuyên bố cả
một hành vi — đây chính là cách 5 bug của harness đã sinh ra. Ví dụ: grep `Semaphore`
trong khi code dùng `MAX_CONCURRENCY` → FAIL sai. Nếu code có thể triển khai theo
nhiều cách hợp lệ, chấp nhận tất cả các cách đó, nhưng đừng nới đến mức luôn đúng.

### Nguyên tắc viết assertion

1. **Kiểm tra hành vi, không kiểm tra cách viết.** `MAX_CONCURRENCY = 8` và
   `Semaphore::new(8)` đều đúng.
2. **Luôn có negative control** khi test một scanner/validator. Nếu không chứng minh
   được nó bắt được cái sai, nó có thể là no-op. Xem `export.leaky.result.json`.
3. **Không tin fixture của chính mình.** §13.2 tự tính lại private/reserved bằng
   `isClearlyPrivate()` thay vì tin `inputs.json`.
4. **Tính lại số liệu thay vì chép lại.** §13.6 tính khoảng cách great-circle thật;
   X8 tính tỉ lệ tương phản WCAG thật. Comment trong code có thể sai.
5. **Bỏ `#[cfg(test)]` trước khi quét `panic!`/`unwrap()`** — panic trong test là
   assertion hợp lệ.
6. **Đừng grep số. Hãy parse hằng số.** Đây là bug thật đã xảy ra với X4:

   ```js
   /0\.2\b/.test('("asn", 0.20)')   // false  <-- \b không khớp sau "2" vì còn "0"
   /20(\.0)?/.test('("blacklist", 0.25)')  // true  <-- khớp nhầm "20" trong "0.25"
   ```

   Cả hai đều **sai nhưng vẫn PASS** vì assertion khác che lỗi. Cách đúng: đọc
   `pub const WEIGHTS` rồi so từng cặp. Xem `parseWeights()` trong `spec13.test.mjs`.

### 8.6 Chứng minh gate không phải no-op: mutation test

Một assertion có thể PASS mãi mãi dù code sai — nếu nó grep sai thứ. Để chắc chắn,
`tests/harness/mutation-x4.mjs` cố tình **làm hỏng** một bản sao `scoring.rs` rồi kiểm
tra gate có bắt được không:

```powershell
node tests\harness\mutation-x4.mjs     # phải ra "10 ok / 0 fail"
```

Nó chứng minh 3 điều:
1. `asn 0.20 -> 0.30` bị bắt (và tổng ≠ 1.0 cũng bắt).
2. `asn 0.20 -> 0.30` **+** `abuse 0.10 -> 0.00` (tổng vẫn = 1.0) **vẫn bị bắt** —
   nghĩa là kiểm-tổng một mình không đủ, phải kiểm từng aspect.
3. `CLEAN_VERDICT_MIN 85 -> 80` bị bắt.
4. Ghi lại rằng regex cũ `/0\.2\b/` **không** khớp `0.20` — tài liệu hoá chính cái bug
   đã sửa, để không ai vô tình quay lại.

**Khi thêm gate mới kiểm một hằng số/quy tắc, hãy thêm một mutation cho nó.** Nếu
không làm hỏng được code để gate FAIL, thì gate đó chưa chứng minh được gì.

---

## 9. Fixture

### Provider (`fixtures/providers/`)

Mỗi provider có tối đa 6 biến thể:

| Hậu tố | Dùng cho |
|---|---|
| `.clean.json` | IP sạch, đủ dữ liệu |
| `.suspicious.json` | Tín hiệu nghi ngờ |
| `.bad.json` | Tín hiệu xấu rõ ràng |
| `.quota-403.json` | Hết quota — phải `skipped`, không làm sập check |
| `.timeout.json` | Quá thời gian — phải thành `Signal::Unknown` (§13.5) |
| `.no-key.json` | Thiếu/sai key — phải `skipped` + lý do (§13.4) |

`_manifest.json` mô tả từng provider (`requires_key`, `timeout.file`, scenario
`no_keys` / `timeout_one`) và **là nguồn sự thật** cho harness.

DNSBL mock: `dnsbl.spamhaus.not-listed.txt` / `.listed` / `.timeout`,
`dnsbl.community.listed.txt`, `dnsbl.tor-exit.listed.txt`, `team_cymru.*.txt`.

### Sentinel secret

`cache-export.json` chứa các chuỗi đánh dấu (sentinel) mà **không được** xuất hiện ở
bất kỳ output nào. `scanForSecrets()` chạy ba chế độ:

| Chế độ | Bỏ qua |
|---|---|
| `export` | không bỏ qua gì |
| `log` | không bỏ qua gì |
| `source` | bỏ `#[cfg(test)]` + literal có tiền tố `test-`/`dummy`/`fake`/`mock`/`sample`/`example`/`fixture` |

Chế độ `source` tồn tại vì `const TEST_TOKEN: &str = "test-token-abc123456";` trong
`#[cfg(test)]` là **đúng** — nó không bao giờ được ship. Đừng "sửa" bằng cách xoá
ngoại lệ đó; hãy giữ nó hẹp.

---

## 10. Checklist trước khi báo PASS

- [ ] `node tests\harness\spec13.test.mjs --static` exit 0 (hoặc exit 2 chỉ vì BLOCKED đã biết)
- [ ] Không còn dòng `✗` nào
- [ ] Mọi BLOCKED có lý do cụ thể, không phải "chưa làm"
- [ ] `Select-String -Path tests\harness\*.mjs -Pattern '[^\x00-\x7F]'` → 0 dòng
- [ ] Không có fixture JSON nào có BOM
- [ ] Nếu sửa assertion: assertion mới vẫn **bắt được** lỗi cũ (thử revert tạm rồi chạy lại)
