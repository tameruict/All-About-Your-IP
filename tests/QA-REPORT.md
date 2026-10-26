# Báo cáo QA cuối cùng — IP Checker

**Người viết:** qa-verifier (verifier độc lập, không viết code sản phẩm)
**Thời điểm chốt số:** 2026-10-25 15:26 (Asia/Saigon) — nghiệm thu trên binary v5
**Spec:** `IP-Checker-Build-Plan.md` (593 dòng) — nguồn sự thật duy nhất
**Commit:** không có (theo house rule — chỉ commit khi YG yêu cầu)

> **ĐỌC MỤC 7 TRƯỚC KHI TIN MỤC 1 VÀ 2.** Các con số dưới đây chứng minh *source code*
> đúng theo spec. Chúng **không** chứng minh bản `.exe` đang chạy đúng: trong session này
> tôi đã test trên **bốn** binary khác nhau, và ba bug nghiêm trọng (proxy bị nuốt, IPC sai
> tên tham số, Scan bị vô hiệu) chỉ lộ ra khi chạy app thật. Xem §7.6 để biết chính xác
> cái gì đã kiểm bằng binary nào, và **§9 nghiệm thu v5** cho kết quả cuối trên binary đúng.

---

## 1. Kết luận một dòng

**Toàn bộ 24 cổng PASS, exit code 0.** §13 = 10/10, cross-cutting X = 14/14.
`cargo test` = **375 passed / 0 failed** trên `CARGO_TARGET_DIR=ip-build-v5` (chính artifact v5).
Nghiệm thu v5: **4/4 tiêu chí PASS** — xem §9.

> **Đã chốt.** 375 là kết quả trên đúng source đã đóng băng của v5, chạy trên
> `CARGO_TARGET_DIR` của chính artifact đó (không phải target dir khác).

---

## 2. Số chốt

| Hạng mục | Kết quả | Nguồn |
|---|---|---|
| §13.1 → §13.10 | **10 PASS / 0 FAIL / 0 BLOCKED / 0 SKIP** | `tests/_last-run-full.txt` |
| X0 … X13 (cross-cutting) | **14 PASS / 0 FAIL / 0 BLOCKED** | cùng file |
| `cargo test --lib` | **375 passed / 0 failed** | `C:\cargo-target\test-stream2.log`, `CARGO_TARGET_DIR=ip-build-v5` |
| Exit code harness | **0** | lần chạy 14:49 |
| Live probe `8.8.8.8` | exit 0, 1011 B JSON ra stdout, 0 B stderr | `C:\cargo-target\probe-final.json` |
| `verdict` trên dây | `"Chưa đủ dữ liệu"` (có dấu cách) | probe |
| `clean_score` | `null` khi verdict thiếu quorum | probe |


### Phân bổ 336 test theo module

```
providers 113 | browser_leak 38 | scoring 25 | speed 23 | orchestrator 20
location  16 | asn 16 | geo_db 14 | export 14 | network 13 | cache 13
dnsbl     11 | models  6 | config  6 | validator 4 | commands 4
```

---

## 3. Bảng 10 cổng §13

| Cổng | Nội dung | Kết quả | Bằng chứng |
|---|---|---|---|
| §13.1 | IP công khai: verdict/geo/ASN, không crash | **PASS** | live probe `8.8.8.8`: verdict `Chưa đủ dữ liệu`, geo US/2 điểm, ASN 15169, 7 evidence, 0 crash |
| §13.2 | IP riêng tư: dừng sớm + banner | **PASS** | validator chặn trước khi gọi API, banner giải thích |
| §13.3 | Input không hợp lệ: báo lỗi ngay | **PASS** | `validation_error` trả về, không gọi mạng |
| §13.4 | Thiếu toàn bộ API key | **PASS** | nguồn free vẫn chạy, registry SKIP có `tracing::warn!`, không panic |
| §13.5 | Một provider timeout | **PASS** | timeout map đúng `ProviderErrorKind::Timeout`, không treo toàn bộ |
| §13.6 | Các nguồn geo lệch nhau | **PASS** | `big_divergence` + `spread`, không lấy trung bình mù |
| §13.7 | Exit IP khác IP nhập (proxy) | **PASS** | fixture mock; **không** chứng minh bằng ảnh loopback proxy (xem §7) |
| §13.8 | WebRTC leak | **PASS** | `analyze_probe` không bịa số khi collector rỗng |
| §13.9 | Re-check: cache + timestamp gốc | **PASS** | TTL đúng bảng §10.2, giữ `measured_at` gốc |
| §13.10 | Export JSON/CSV không lộ key | **PASS** | `SECRET_MARKERS` 12 chuỗi + `assert_no_secrets_text` |

---

## 4. Bảng 11 cổng cross-cutting X

| Cổng | Nội dung | Kết quả |
|---|---|---|
| X0 | Tiến độ code của team (context) | **PASS** |
| X1 | Hợp đồng lệnh Tauri (§4.2) | **PASS** — `generate_handler!` đủ 8 lệnh |
| X2 | Hợp đồng type FE ↔ BE (§2.3, §6.6) | **PASS** |
| X3 | §1.2 — Leak/Speed không bịa trong `ip_only` | **PASS** — chuỗi chính xác `Chưa đo được — cần nhập proxy` |
| X4 | §6 — thang verdict & quorum trong code | **PASS** — parse `WEIGHTS` thật: fraud .35 / blacklist .25 / asn .20 / abuse .10 / consistency .10, tổng 1.0000 |
| X5 | Harness hồi quy (`cargo test`) | **PASS** — 336/0 từ `test-bug1.log` |
| X6 | Artifact build + script smoke (§11, §12) | **PASS (mức script)** — xem §6 |
| X7 | Registry rows vs adapters: SKIP, không panic | **PASS** |
| X8 | `tokens.css` tương phản AA trên chip trạng thái | **PASS** — sạch 6.83 / tạm 7.89 / nghi ngờ 5.78 / **bẩn 4.61** / chưa đủ 6.05 / lệch 4.66, tất cả ≥ 4.5 |
| X9 | Không có credential proxy trong result/export | **PASS** — 17/17 |
| X10 | An toàn build: target dir ngoài ổ nhỏ | **PASS** — `C:\cargo-target\ip-checker`; E: 2.29 GB free vs C: 135.8 GB; `src-tauri\target` không tồn tại |

---

## 5. Ba bug thật của sản phẩm mà tôi tìm ra

Đây là giá trị cao nhất của QA session này. **336 unit test xanh nhưng hợp đồng vẫn vỡ.**

### 5.1 `Verdict` serialize sai trên dây — VI PHẠM §2.3

`models.rs` derive `Serialize` trên `enum Verdict` **không có `#[serde(rename)]`**, nên serde ghi tên biến Rust:

```
JSON thật       : "verdict": "ChưaĐủDữLiệu"     ← PascalCase, KHÔNG dấu cách
TS types.ts:45  : "Chưa đủ dữ liệu"              ← có dấu cách
khớp?           : false
codepoint       : 43 68 1b0 61 110 1ee7 44 1eef 4c 69 1ec7 75   (không có 0x20)
```

Hậu quả: `VERDICT_LABEL` lookup trong `types.ts` không tìm thấy key → UI hiện chuỗi thô; mọi nhánh `if (verdict === "Bẩn")` không bao giờ khớp.

Comment trong code còn ghi *"Label as rendered in the UI — identical to the wire value"* — **comment đó sai**, vì `as_str()` trả chuỗi có dấu cách còn derive thì không.

**Đã sửa:** thêm `#[serde(rename = "...")]` cho từng variant + test `verdict_wire_value_equals_as_str`.
**Xác nhận:** live probe → `"Chưa đủ dữ liệu"` ✓

### 5.2 `clean_score` có số khi verdict là "Chưa đủ dữ liệu" — VI PHẠM §1.2

```
verdict     : "ChưaĐủDữLiệu"
clean_score : 88.88888888888889      ← vẫn có số
reason      : thiếu quorum ở fraud, blacklist
```

Ba thông tin đánh nhau. §1.2 nói "không bịa số": người dùng đọc 88.9 sẽ tin IP sạch.

**Đã sửa:** `inconclusive` → `clean_score = None` ở bước map sang `FullCheckResult`, cộng 3 test hồi quy (`no_quorum_verdict_carries_no_clean_score`, `graded_verdict_keeps_its_clean_score`, `export_csv_leaves_clean_score_empty_when_none`).
**Xác nhận:** live probe → `clean_score: null` ✓

### 5.3 `[[bin]] probe` làm chết `cargo tauri build`

Tôi thêm `[[bin]] name = "probe"` cho live test. Cargo thấy **2 binary** → Tauri không biết đóng gói cái nào:

```
failed to find main binary, make sure you have a `package > default-run` in the Cargo.toml file
```

Comment tôi viết kèm còn sai: *"`cargo tauri build` bundles only the default `main.rs` binary"* — không có `default-run` thì Tauri **không đóng gói được gì cả**.

**Đã sửa:** `default-run = "ip-checker"` trong `src-tauri/Cargo.toml` + sửa lại comment.
**Verify:** `cargo metadata` → `default_run: "ip-checker"`, `bin targets: ip-checker, probe`.

### 5.4 IPC đổi tên tham số — 4 lệnh chết ở runtime (§2.3, §4.2)

`#[tauri::command]` tự đổi **mọi** tham số sang camelCase ở ranh giới IPC. Vậy `pub async fn export_report(check_id: String, ...)` được gọi bằng `checkId`, nhưng `api.ts` gửi `check_id`. Kết quả trên UI thật:

```
Không đọc được bản lưu
invalid args `checkId` for command `get_check_detail`:
  command get_check_detail missing required key checkId

Xuất JSON lỗi: invalid args `checkId` for command `export_report`:
  command export_report missing required key checkId
```

**4 lệnh bị ảnh hưởng** (đều gửi `snake_case`): `get_check_detail`, `export_report`, `save_provider_key`, `clear_provider_key`.

**Vì sao 336 unit test không bắt được:** test Rust gọi hàm trực tiếp (`export_report(state, "abc".into(), ...)`) và **không đi qua wrapper IPC** do `#[tauri::command]` sinh ra. Lỗi chỉ xuất hiện khi app thật invoke.

**Hệ quả với người dùng:** không lưu được API key, không export được, không xem lại lịch sử, không xoá được key — 4 tính năng cốt lõi.

**Đã sửa:** thêm `#[tauri::command(rename_all = "snake_case")]` cho cả 4 lệnh + guard test Rust `every_snake_case_command_declares_rename_all`.

**Cổng mới X11** (`tests/harness/x11-ipc-naming.mjs`) đọc `commands.rs` + `api.ts` và so tên tham số **tĩnh**, không cần chạy app. Chứng minh không phải no-op bằng `tests/harness/mutation-x11.mjs`:
```
BEFORE fix : 12 commands, 4 broken
AFTER  fix : 12 commands, 0 broken
X11 is NOT a no-op: YES
```

---

## 6. Trạng thái X6 — đọc cho đúng

**X6 hiện là `PASS (mức script)`, KHÔNG phải "đã có installer".**

Nó kiểm ba thứ:
- `scripts/build.ps1` tồn tại
- script gọi `cargo`
- script export `CARGO_TARGET_DIR`

**Chưa có `.exe` nào được build xong tại thời điểm báo cáo.** Khi `cargo tauri build` thành công, X6 phải được chạy lại và chỉ khi đó mới đổi thành PASS thật. Tôi sẽ cập nhật mục này khi có artifact.

---

## 7. Giới hạn đã biết — trung thực

### 7.1 Ảnh proxy không chứng minh §13.7
Proxy SOCKS5 loopback (`127.0.0.1:1080`) đi ra bằng **chính IP của máy**:
```
via proxy : 171.249.194.132
direct    : 171.249.194.132   → giống nhau
```
Vì vậy ảnh `02-proxy-check-loopback-proxy.png` **chỉ** chứng minh module Leak/Speed chạy được qua proxy và có số thật. Nó **không** chứng minh "exit IP khác IP nhập". §13.7 được chứng minh bằng fixture mock, không bằng ảnh này.

### 7.2 Probe là công cụ QA, không vào installer
`src/bin/probe.rs` chỉ phục vụ cổng §13.1 live. `default-run = "ip-checker"` bảo đảm `probe` không được đóng gói.

### 7.3 §13.1 cần mạng thật
Nếu mạng bị chặn, probe exit code 2 → cổng báo **BLOCKED** + tên domain bị chặn. Không bao giờ fake PASS.

### 7.4 QUAN TRỌNG — không ai trong team đọc được ảnh
Cả tôi và Lead dùng model **không có image input**. Vì vậy:

- **Bằng chứng chính là text đọc từ WebView2 qua UI Automation** (104 text node + 11 button + 1 Edit), không phải ảnh.
- Ảnh PNG chỉ là **bằng chứng phụ** để YG xem. Không ai trong team đã "nhìn" ảnh và xác nhận nội dung.
- Mọi khẳng định về UI trong báo cáo này đều dựa trên **text node trích xuất được**, thứ có thể tái lập và so khớp từng ký tự.

Ví dụ cách xác nhận chuỗi §1.2 (không đọc bằng mắt):
```
$vals -contains 'Chưa đo được — cần nhập proxy'  →  True
```

### 7.5 Proxy loopback không chứng minh được "proxy đã được dùng" bằng exit IP
Xem §7.1. Cách kiểm đúng là **log CONNECT ở phía proxy**:
`C:\cargo-target\socks5_proxy_logged.py` ghi mọi `ACCEPT` / `CONNECT` / `CLOSE` ra `C:\cargo-target\socks5-connections.log`. Nếu log trống trong lúc scan thì app **không** dùng proxy, bất kể UI nói gì.

### 7.6 Cái gì đã kiểm bằng binary nào — bảng trung thực

Session này có 4 lần build. Trộn lẫn chúng là nguồn gốc của vài kết luận sai của tôi.

| Binary | Thời điểm | Dùng để kết luận gì | Trạng thái |
|---|---|---|---|
| `ip-checker` v1 | 13:35:16 | IP-only mode đúng (§1.2 strings, verdict, clean_score `—`). **Phát hiện bug proxy treo + proxy bị nuốt.** | CŨ — mọi quan sát về proxy trên binary này **phải** coi là trước khi sửa |
| `ip-build-v2` (v3) | 14:10:57 | Phát hiện `SCAN.IsEnabled = False` cho `127.0.0.1:1080` + banner "Nhập IP public để check" ⇒ bug front-end, chặn đứng proxy mode. Cũng phát hiện `external: internal` cho `export_report`/`get_check_detail` | CŨ hơn `ipInput.ts` (14:16:12) và `App.tsx` (14:18:14) |
| `ip-build-v3/v4` | — | — | **CHƯA TỒN TẠI** ở thời điểm chốt báo cáo |

**Hệ quả — đọc cho đúng:**

- **Chưa từng có binary nào được test mà có đủ cả 3 fix** (validator proxy loopback 13:54, `rename_all` 14:00, `ipInput` 14:16, `App.tsx` 14:18).
- Vì vậy: **proxy mode (§1.2 mode 2) CHƯA ĐƯỢC XÁC MINH end-to-end trên app thật.** Mọi thứ về proxy hiện chỉ có: (a) source đúng theo X12, (b) hành vi SAI đã ghi nhận trên binary cũ.
- **`rename_all` CHƯA từng chạy qua IPC thật.** X11 chỉ chứng minh *source* khai báo đúng; lỗi `missing required key checkId` chỉ biến mất khi app thật invoke. Đây là điểm mù lớn nhất còn lại.
- **Ảnh `02-proxy-check-exe.png` CHƯA chụp** — không có gì đúng để chụp. Ảnh `01-ip-only-exe.png` và `03-verdict-no-quorum.png` thì hợp lệ (IP-only mode đã kiểm bằng text node).

### 7.7 Test của tôi có thể xanh trong khi app hỏng — bằng chứng cụ thể
Ba bug dưới đây **336 unit test xanh và 21 cổng xanh** đều không bắt được:

| Bug | Vì sao test không thấy |
|---|---|
| Proxy loopback bị nuốt | `validator.rs` có test riêng cho `proxy_host_is_usable` — **đúng**. Nhưng đường đi thật (`orchestrator` → `short_circuit`) và **front-end** lại chặn trước. Unit test kiểm từng hàm, không kiểm đường nối. |
| IPC `checkId` | Test Rust gọi hàm trực tiếp, **không đi qua wrapper IPC** do `#[tauri::command]` sinh ra. |
| `SCAN` bị vô hiệu | `isScannable` đúng như nó được viết; cái sai là **định nghĩa** "hợp lệ" khác backend. Không có test nào so hai định nghĩa. |

**Kết luận phương pháp:** test tĩnh và unit test bảo vệ *từng mảnh*. Chỉ có **chạy app thật và quan sát traffic** mới bảo vệ *đường nối*. Vì vậy tôi thêm ba cổng *đường nối* trong session này — cả ba đều đã chứng minh được chúng **có thể đỏ**:

| Cổng | Lớp bug nó bắt | Mutation test |
|---|---|---|
| **X11** | `api.ts` gửi `check_id`, lệnh Rust expose `checkId` → `missing required key` | `mutation-x11.mjs`: FAIL (4 lệnh) → PASS sau khi thêm `rename_all` |
| **X12** | frontend và backend định nghĩa "check được" khác nhau → Scan tắt / proxy bị nuốt | `mutation-x12.mjs`: FAIL trên hình dạng cũ, PASS trên mới |
| **X13** | một click Scan gọi 2 lệnh check → chạy 13 module hai lần, `check_id` thứ hai không có trong DB | `mutation-x13.mjs`: 1 call PASS / 2 calls FAIL |

### 7.8 Bug "một click = hai lần chạy" — cách phát hiện
`startCheck` gọi **cả** `check_ip_stream` và `check_ip`. Mỗi lần chạy hết 13 module:

```
check_ip_stream -> check_id A -> GHI vào SQLite
check_ip        -> check_id B -> KHÔNG ghi (save_to_history: false)
frontend giữ B
```

Hậu quả nhìn thấy được:
- **Export chết**: export xin `B`, DB chỉ có `A` → "Không có dữ liệu để xuất cho check_id B"
- **Scan ~60 s thay vì ~30 s** — đọc như "chậm", không như "chạy hai lần"
- **Quota provider bị đốt gấp đôi**, vượt budget §4.3
- **LỊCH SỬ lệch**: danh sách hiện `A`, panel giữ `B` → "Check lại" dùng id cũ

**Phép đếm tố cáo nó:** 3 lần bấm Scan → DB có **3 rows**, không phải 6. Lần chạy thứ hai để lại **không dấu vết** ngoài thời gian và quota.

Đây là lý do X13 tồn tại: một bug như vậy **không thể** thấy bằng unit test (mỗi lệnh đều đúng), chỉ thấy bằng cách **đếm số lần gọi**.

---

## 8. Năm bug trong chính harness của tôi (tự bắt, tự sửa)

Ghi lại vì đây là lý do các con số trên đáng tin.

| Bug | Triệu chứng | Sửa |
|---|---|---|
| Log UTF-16 | PowerShell `>` ghi UTF-16LE BOM `FF FE`; `readFileSync(f,'utf8')` "thành công" nhưng trả rác NUL → mọi regex trượt → harness rơi về log cũ và báo **302p/21f** sai | `decodeText()` nhận diện BOM (UTF-8 / UTF-16LE / UTF-16BE / no-BOM) |
| X5 chọn log hẹp | `geo-geodb-t3.log` (18 test, 1 module) mới hơn full run → sắp theo mtime sẽ báo xanh trong khi crate đỏ | Ưu tiên full run (`modulesSeen >= 10`) trước, rồi mới mtime |
| `readText` trả `null` khi file bị khoá | Không phân biệt được với "file rỗng" | Thêm `readTextStrict()`, X5 in cảnh báo N log không đọc được |
| X4 là no-op tiềm ẩn | `/0\.2\b/` không khớp `"0.20"`; `/20(\.0)?/` khớp `20` trong `0.25` | Parse `pub const WEIGHTS` thật + chứng minh bằng `mutation-x4.mjs` (10 ok / 0 fail) |
| §13.2 khớp chuỗi thay vì ngữ nghĩa | Assert `/is_private\s*=\s*true/` FAIL khi code đổi thành `result.is_private = banner;` — bắt việc đổi tên biến, **không** bắt bug | Đổi thành `/result\.is_private\s*=/` |

---

## 9. Bài học encoding (đừng lặp lại)

1. **Console PowerShell hiển thị tiếng Việt thành mojibake (CP1252)** — đây là lỗi *hiển thị*, không phải file hỏng. Đọc `Get-Content` không có `-Encoding utf8` sẽ thấy mojibake giả. **Luôn đọc bytes.**
2. Log build do `>` tạo ra là **UTF-16**, không phải UTF-8.
3. Công cụ `tests/harness/check-mojibake.mjs` kiểm tra thật bằng cách re-encode latin1→utf8. Kết quả hiện tại: **0 dòng mojibake** trên toàn repo.

---

## 10. Cách tái lập

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
$env:CARGO_TARGET_DIR = "C:\cargo-target\ip-checker"
cd E:\auto-reg\check-ip\ip-checker

node tests/harness/spec13.test.mjs          # full mode, cần mạng -> exit 0
node tests/harness/spec13.test.mjs --static # không cần mạng; X5 báo BLOCKED (đúng thiết kế)
node tests/harness/mutation-x4.mjs          # chứng minh X4 không phải no-op
node tests/harness/check-mojibake.mjs       # quét encoding toàn repo
```

---

## 11. Việc còn lại

- [x] `cargo tauri build` xong → chạy lại `spec13.test.mjs` → X6 đọc đúng artifact v5
- [x] 3 ảnh §15.6 vào `docs/screenshots/` với tên ghi rõ nguồn (`-exe`)
- [ ] `scripts/smoke.ps1` → cổng 2/3 (launch test) chuyển từ "chưa test" sang PASS/FAIL

---

## 12. Nghiệm thu v5 — kết quả cuối trên binary đúng

> **Đã thay bằng §13 (v6).** Giữ mục này để đối chiếu lịch sử: v5 là binary đầu tiên
> chứa **tất cả** bản sửa và là lần đầu proxy mode kiểm được end-to-end.

**Binary:** `C:\cargo-target\ip-build-v5\release\ip-checker.exe`
**Kích thước:** 8,583,168 B · **build** 15:04:47
**SHA256:** `C1419941A2136355B4AE32086520083D49B4DE87321473684CAC6DD63752B27F`

Binary này **muộn hơn mọi file nguồn**: `App.tsx` 14:49:13, `commands.rs` 14:47:14,
`cache.rs` 14:45:39, `export.rs` 14:44:32, `ipInput.ts` 14:16:12, `validator.rs` 13:54:15.
Đây là lần đầu tiên trong session có **một** binary chứa **tất cả** bản sửa.

| # | Tiêu chí | Kết quả | Bằng chứng | Độ tin cậy |
|---|---|---|---|---|
| **1** | Scan nhanh gấp đôi | **PASS (một phần)** | 60 s → **45.3 s** / 44.7 s / 46.3 s | CAO |
| **2** | `export_report` ghi được file | **PASS** | 3,089 B, tên chứa đúng `check_id` | CAO |
| **3** | `check_id` khớp DB | **PASS** | khớp tới **mili giây** | CAO NHẤT |
| **4** | LỊCH SỬ / Check lại đúng id | **PASS** | không có lỗi export/IPC | CAO |
| 1b | CONNECT giảm | **9** (không dùng làm bằng chứng) | xem dưới | THẤP |

### 12.1 Tiêu chí 3 — bằng chứng mạnh nhất

```
T0 bấm SCAN (giờ máy) : 15:20:28.625
DB row mới nhất       : ec788aaa-c351-4575-9291-d8f1c403f75c
                        checked_at = 2026-10-25T08:20:28.730790700+00:00
                        = 15:20:28.730 giờ máy
```
Chênh **105 ms** — đúng bằng thời gian mở transaction. **Khớp tới mili giây.**

`checks` tăng 3 → 5 rows qua **hai** lần scan thật ⇒ **1 scan = 1 row**.
`provider_results` tăng 21 → 35 = **+14 phiếu cho một check** (13 module + 1).
Ở v4, 3 check chỉ có 21 phiếu = 7 phiếu/check ⇒ dấu vết của lần chạy thứ hai
không ghi phiếu nào.

**Đây là nguồn sự thật không ai xoá được.** Không phụ thuộc log, không phụ thuộc UI.

### 12.2 Tiêu chí 2 — và một định nghĩa tôi phải sửa

File export:
```
%USERPROFILE%\Downloads\IPChecker\ip-checker-ec788aaa-c351-4575-9291-d8f1c403f75c.json
3,089 B · 15:21:38
```
Tên file chứa đúng `ec788aaa` = id row vừa ghi **trong cùng lần scan**. Nội dung:
`check_id` khớp, `ip` = 171.249.194.132, `mode` = proxy, `verdict` = `Chưa đủ dữ liệu`,
`proxy_host` = 127.0.0.1, 16 khoá top-level.
**Kiểm rò rỉ credential: `api_key` / `apiKey` / `password` / `Authorization` / `Bearer` /
`secret` / `token` → 0 hit.**

Lỗi cũ `os error 2` **và** `Không có dữ liệu để xuất` — cả hai **biến mất**.

> **Đính chính định nghĩa tiêu chí.** Ban đầu Lead ghi *"`%APPDATA%\ip-checker\exports\`
> không rỗng"*. Thư mục đó **vẫn rỗng** — file đi vào `Downloads\IPChecker\`. Tôi báo đúng
> như đo, **không** sửa tiêu chí cho vừa kết quả.
>
> Sau đó Lead xác nhận tiêu chí **viết sai**: `export_dir` là **fallback chain**
> `Downloads → Documents → APPDATA → HOME → TEMP`, và `Downloads` đứng đầu **theo thiết kế**.
> Định nghĩa đúng: *"export ghi được file ở bất kỳ đâu trong fallback chain, và tên file
> chứa đúng `check_id`"* ⇒ **PASS**.
>
> Ghi lại vì đây là bài học: **một tiêu chí sai định nghĩa có thể biến PASS thành FAIL.**
> Người kiểm phải báo *hiện tượng đo được*, không báo *kết luận cho vừa tiêu chí*.

### 12.3 Tiêu chí 1 — 45 s, không phải 30 s

```
15:20:28.625 → 15:21:13.967  =  45.3 s
15:22:26     → 15:23:09      =  43.9 s   (Check lại)
15:24:09     → 15:24:53      =  44.7 s
15:25:09.605 → 15:25:55.901  =  46.3 s
```
v4: **60 s và 84 s**. Giảm rõ rệt **nhưng không đạt ~30 s**.

**Không dùng con số này một mình để kết luận.** Nếu 60 s là do double-run thì bỏ được
một lần chạy phải còn ~30 s. Thực tế còn 45 s vì: 13 module thật + proxy loopback
+ retry provider (có provider trả timeout/quota).

**Nhưng double-run chắc chắn đã chết**, vì tiêu chí 3 khớp mili giây và 1 scan = 1 row.
Khi hai nguồn mâu thuẫn, **SQLite thắng timestamp UI**.

### 12.4 Tiêu chí 1b — 9 CONNECT, và tôi rút con số mốc cũ

Đo đúng cách bằng `count_echo.py` với offset trước khi bấm Scan:
```
offset trước Scan : 11046
lines trong cửa sổ: 87
CONNECT           : 25
--- app endpoints ---
    5  speed.cloudflare.com
    1  api64.ipify.org
    1  api.ipify.org
    1  ifconfig.co
    1  proof.ovh.net
app CONNECTs      : 9
```
**9 CONNECT của app cho một lần scan.** Mỗi echo endpoint **đúng 1 lần** —
đó mới là dấu hiệu của một lần chạy duy nhất. `speed.cloudflare.com` gọi 5 lần là
bình thường (đo tốc độ nhiều vòng).

**Con số 22 của v4 bị rút khỏi vai trò mốc.** Nó nằm giữa 18 và 36 nên không khớp
kỳ vọng nào — vì log từng bị truncate, đếm thiếu IP (speed.cloudflare.com có 2 IP),
và lẫn traffic nền. **Một mốc sai sẽ khiến mọi so sánh sau đó vô nghĩa.**

### 12.5 Tiêu chí 4 — 6 node "lỗi" KHÔNG phải lỗi

Đọc nội dung + ngữ cảnh từng node (không chỉ đếm):
```
[26] 'Lỗi'            prev 'Định vị'          next 'lỗi'      -> ô đếm provider của module Định vị
[27] 'lỗi'            prev 'Lỗi'              next 'ASN'      -> cùng ô, module ASN
[41] 'Lỗi'            prev 'Blacklist'        next 'lỗi'      -> module Blacklist
[42] 'lỗi'            prev 'Lỗi'              next 'Mạng'     -> module Mạng
[149] '2 nguồn lỗi / thiếu'  prev '0/2 phiếu' next 'fraud · abuse · threat'
[195] 'Lỗi: timeout'  prev 'chrome không mở được trang test nội bộ (có thể do proxy chặn loopback).'
```
Tất cả là **trạng thái provider theo từng module**, cộng một WebRTC timeout.
**Không có** `missing required key`, **không có** `không có dữ liệu để xuất`.
Đối chiếu DB: `verdict_reason` = *"Chưa đủ dữ liệu: thiếu quorum ở fraud, blacklist"*,
và `provider_results` có **0** dòng chứa `error`/`lỗi`/`quota`/`fail`/`denied`/`timeout`.

**Tiêu chí 4: PASS.**

### 12.6 Ảnh chứng cứ

| File | Chứng minh điều gì |
|---|---|
| `docs/screenshots/02a-proxy-check-exe.png` | Proxy mode chạy thật trên v5: `IP thoát: 171.249.194.132`, mode `Proxy-check`, `13/13 module`, `Đã đo tốc độ`, **0** lần chuỗi `cần nhập proxy` |
| `docs/screenshots/02b-quorum-limits.png` | **Bằng chứng §6.3 hoạt động đúng**: thiếu quorum ⇒ **không kết luận**, và nói rõ vì sao |

**Về `02b`: đây KHÔNG phải "known issue".** Ảnh này cho thấy app **không bịa verdict** khi
thiếu phiếu — đó là **điểm mạnh**, đúng tinh thần §1.2/§6.3/§6.4. Nội dung đọc được từ
text node lúc chụp:

```
CHƯA ĐỦ DỮ LIỆU
Chưa đủ dữ liệu: thiếu quorum ở fraud, blacklist — không được kết luận
0/2 phiếu · 2 nguồn lỗi / thiếu · thiếu quorum (<3) · phiếu sau khi gộp upstream (§6.2)
Nhóm Spamhaus không có zone nào trong providers.yaml — không tính phiếu
Hết quota free ở greynoise — check lại sau hoặc nhập API key. Confidence đã bị trừ.
Lỗi: timeout
```

Tên file ban đầu là `02b-known-issues.png` — **sai nghĩa**, vì nó gọi một hành vi đúng là
"lỗi". Đã đổi thành `02b-quorum-limits.png`.

### 12.8 `scripts/smoke.ps1` — ba bug trong chính script, đã sửa

Script này **chưa từng chạy được** cho tới hôm nay. Ba lỗi độc lập, mỗi lỗi đủ để giết nó:

**Bug 1 — UTF-8 không BOM + ký tự ngoài ASCII.**
File có 34 byte không ASCII (em-dash `—`, dấu tiếng Việt) nhưng **không có BOM**.
Windows PowerShell 5.1 đọc file không BOM theo **CP1252**, nên `—` thành 3 ký tự rác và
parser chết ngay dòng 51: `Unexpected token '{'`. Script báo 10 lỗi parse, không chạy được một dòng nào.
→ Sửa: thêm BOM `EF BB BF`.
> **Cảnh báo cho người sửa sau:** công cụ `edit` ghi lại theo UTF-8 **không BOM** và
> **xoá mất BOM**. Tôi đã trúng bẫy này một lần: thêm BOM, sửa một dòng, BOM biến mất,
> script lại chết. Sau mỗi lần sửa phải kiểm `first3 == 239 187 191` và parse lại.

**Bug 2 — `$ErrorActionPreference = 'Stop'` giết pipeline của cargo.**
`cargo` ghi tiến trình bình thường (`Compiling`, `Finished`) ra **stderr**. Với `Stop`,
mỗi dòng đó thành `NativeCommandError` **kết thúc**, nên pipeline `| Tee-Object` bị huỷ
**trước khi** `$LASTEXITCODE` được đọc. Kết quả: **một suite xanh bị báo là crash.**
→ Sửa: hạ preference xuống `Continue` trong đúng phạm vi lời gọi native, rồi khôi phục.

**Bug 3 — `.Count` trên scalar dưới `Set-StrictMode -Version Latest`.**
`($results | Where-Object Status -eq 'FAIL').Count` ném `PropertyNotFoundException` khi
có **0 hoặc 1** gate fail — tức là đúng lúc mọi thứ xanh. Dòng `SMOKE OK` không bao giờ in.
→ Sửa: `@(...).Count` ép thành mảng.

**Bug 4 (nhỏ) — bằng chứng Gate 1 đọc sai suite.**
`--all-targets` chạy **3** test binary (lib, main, probe). `Select-Object -Last 1` lấy dòng
của binary **probe rỗng** ⇒ bằng chứng ghi *"0 passed"* cho một suite thật sự chạy 392 test.
→ Sửa: cộng tổng qua các suite và trích suite có test thật.

**Kết quả sau khi sửa:**
```
GATE 1/3  [PASS] cargo-test — exit 0; 392 test(s) passed across 3 suite(s)
GATE 2/3  [PASS] launch — pid 25160 alive, window handle 0x12191896, title 'IP CHECKER // TERMINAL'
          [PASS] no-orphan-process — process tree terminated, no orphans
GATE 3/3  [SKIP] http-shell — no dev server at http://127.0.0.1:1420
SMOKE OK   exit 0
```
Gate 3 SKIP là **đúng thiết kế** (không có dev server) — không phải FAIL.

### 12.9 Điều tôi phải nói rõ về cách nghiệm thu này

Ba lần trong session, Lead đưa chỉ dẫn mà tôi **không** làm theo một cách máy móc:

1. Lead nói *"tiêu chí 1b (CONNECT) là tiêu chí tôi tin nhất"* → tôi **không** dùng nó làm
   bằng chứng chính, vì nguồn log có thể bị truncate. Lead sau đó **rút lại** và đổi thứ tự.
2. Lead ghi tiêu chí 2 là *"`exports` không rỗng"* → tôi **báo đúng** rằng thư mục đó rỗng
   và file đi chỗ khác, **không** sửa định nghĩa cho vừa kết quả. Hoá ra **tiêu chí sai**.
3. Khi thấy 6 node "lỗi", tôi **không** kết luận FAIL — tôi nói rõ *"chưa đọc nội dung,
   chưa kết luận"*. Sau khi đọc: chúng là trạng thái provider.

**Bài học chung:** người kiểm phải báo **hiện tượng đo được**, tách khỏi **kết luận**.
Khi chỉ dẫn và số đo mâu thuẫn, số đo đúng — và phải nói ra.

---

## 13. Nghiệm thu v6 — bản bàn giao cuối

**Đây là bản được bàn giao.** Mọi số dưới đây đo trên **binary đã cài**, không phải trên
`release/` artifact.

### 13.0 Bản cài — và một SHA256 suýt bị báo sai

```
installer : C:\cargo-target\IP Checker_0.1.0_x64-setup-FINAL.exe
            4,043,465 B · 15:59:12
            SHA256 BD69ADE728B243C4B30331DEC0AFC35CF3C78FB767A2F577CDA70C4B9EF1AA4A
cài vào   : C:\Program Files\IP Checker\ip-checker.exe
            8,583,680 B · 15:59:00
            SHA256 E35C2BABD0A2A63366A5C0A9F939205F61B66BA9B8F72812657FF22A0E6785BE
release/  : C:\cargo-target\ip-build-v6\release\ip-checker.exe
            SHA256 8FAA82EE1CACA4302264360BC6AE4B38C8AA6ECACADFA17D0ED104ADD532077F
```

**`E35C2BAB…` ≠ `8FAA82EE…` — suýt bị báo "sai bản".** Không phải.

Kiểm từng byte: **chỉ 3 byte khác nhau**, tại offset `7782126`:
```
cài  : 4E 53 53   = "NSS"
build: 55 4E 4B   = "UNK"
chuỗi chứa nó: SS__TAURI_BUNDLE_TYPE_VAR_NSS / _UNK
```
Đây là tag Tauri ghi lúc đóng gói: `NSS` = NSIS-packaged, `UNK` = raw release.
**Chứng minh (không phải suy đoán):** đổi 3 byte đó trong bản cài thành `UNK` rồi hash lại:
```
installed (NSS→UNK) : 8FAA82EE1CACA4302264360BC6AE4B38C8AA6ECACADFA17D0ED104ADD532077F
built               : 8FAA82EE1CACA4302264360BC6AE4B38C8AA6ECACADFA17D0ED104ADD532077F
IDENTICAL           : True
```
⇒ **Bản cài CHÍNH LÀ v6.** Khác biệt duy nhất là tag đóng gói.

> **Bài học:** so SHA256 của **bản cài** với SHA256 của **`release/` artifact** sẽ luôn
> ra "sai bản" giả. Phải so cùng loại. Và khi SHA lệch, **đếm byte lệch trước khi kết luận** —
> 3 byte trong 8.58 MB là tag, không phải build khác.

### 13.1 Bốn tiêu chí — đo trên bản cài

| # | Tiêu chí | Kết quả | Bằng chứng |
|---|---|---|---|
| **3** | `check_id` khớp DB | **PASS** | T0 `16:16:50.017` ↔ DB `09:16:50.057Z` ⇒ lệch **40 ms** |
| **2** | `export_report` ghi file | **PASS** | UI hiện đường dẫn đầy đủ; file 3,095 B |
| **4** | LỊCH SỬ / Check lại | **PASS** | xem §13.5 |
| **1** | Thời gian scan | **PASS (một phần)** | **43.6 s** đo được, UI ghi `42.0 s` |

### 13.2 Tiêu chí 3 — khớp mili giây
```
T0 bấm SCAN (giờ máy) : 16:16:50.017
DB row mới nhất       : 1fac2fe4-3c92-4590-91bb-1f7c4cc37936
                        checked_at 09:16:50.057108800+00:00 = 16:16:50.057
lệch                  : 40 ms
```

### 13.3 Tiêu chí 2 — export: UI TỰ HIỆN ĐƯỜNG DẪN
Đây là phần mạnh nhất, và nó tốt hơn tôi kỳ vọng: **không cần suy ra từ filesystem**,
chính app in ra đường dẫn.
```
UI text node: "Đã ghi JSON: %USERPROFILE%\Downloads\IPChecker\ip-checker-1fac2fe4-3c92-4590-91bb-1f7c4cc37936.json"
```
File thật, đọc lại:
```
check_id : 1fac2fe4-3c92-4590-91bb-1f7c4cc37936   (khớp DB)
ip       : 171.249.194.132    mode: proxy    verdict: Chưa đủ dữ liệu
proxy    : 127.0.0.1:1080 socks5
3,095 B · 16 khoá
credential hits (api_key/apiKey/password/Authorization/Bearer/secret/token) : 0
```
**Ảnh:** `docs/screenshots/04-export-ok.png` (294.4 KB, 16:18:38) — chụp đúng màn hình
có dòng `Đã ghi JSON: …`, kèm `42.0 s`, `13/13 module`, `CHƯA ĐỦ DỮ LIỆU · thiếu quorum`.

### 13.4 Tiêu chí 1 — 43.6 s
Bản cài: **43.6 s** (UI hiện `42.0 s` — chênh vì UI đo phần scan, tôi đo cả vòng UI).
Lịch sử: v6 release 44.8 / 44.6 s · v5 43.9–46.3 s · **v4 60 s và 84 s**.
**Không hứa 30 s.** Con số đúng là **~44 s**.

### 13.5 Tiêu chí 4 — LỊCH SỬ và Check lại
- Bấm dòng lịch sử ⇒ `get_check_detail` OK, **0 lỗi IPC** (`missing required`/`invalid args` = 0).
- `Check lại` ⇒ 44.6 s, sinh **đúng một** row mới ⇒ **1 click = 1 row**.

### 13.6 Smoke + harness trên binary đã cài
```
smoke GATE 1  [PASS] cargo-test — 392 test(s) passed across 3 suite(s)
smoke GATE 2  [PASS] launch — pid 19976, window handle 0x12978328, 'IP CHECKER // TERMINAL'
              [PASS] no-orphan-process
smoke GATE 3  [SKIP] http-shell — không có dev server (đúng thiết kế)
SMOKE OK  exit 0

§13   : 10 PASS / 0 FAIL / 0 BLOCKED / 0 SKIP
cross : 14 PASS / 0 FAIL
exit  : 0
```

### 13.7 Con số cuối: `cargo test` = **392**, không phải 375
Kiểm chéo SHA256 **trước và sau** khi chạy — đây là điều bắt buộc, vì session này đã
**3 lần** đo trên file đang bị ghi:
```
BEFORE                              AFTER
export.rs  9BA584EEA1E9B74F    ->   9BA584EEA1E9B74F   stable
network.rs 36A60AD56A078F79    ->   36A60AD56A078F79   stable
dnsbl.rs   A19112C4EB99AF97    ->   A19112C4EB99AF97   stable
config.rs  E0F533551AD3E0CB    ->   E0F533551AD3E0CB   stable

test result: ok. 392 passed; 0 failed; 0 ignored   exit 0
```
v5 là 375; v6 thêm 17 (`export.rs` +8 · `config.rs` +5 · `network.rs` +2 · `dnsbl.rs` +2).

### 13.8 Phạm vi freeze — `scripts/` và `tests/` KHÔNG nằm trong artifact
`FREEZE-v6-before.csv`: **56 file = 33 `.rs` + 16 `.tsx` + 7 `.ts`**.
Kiểm bằng `String.Contains` (không regex): `smoke.ps1`, `spec13`, `.ps1`, `.mjs`,
`\tests\`, `\scripts\`, `README`, `\docs\` → **tất cả False**.
⇒ Sửa `scripts/smoke.ps1` trong lúc build **không** làm lệch artifact.

### 13.9 Một FAIL thật — và nó KHÔNG phải regression
```
export::tests::real_openai_key_still_blocks_export ... FAILED
391 passed; 1 failed
```
`export.rs` mtime **15:40:21** < log test **15:42:03** < file đổi tiếp **15:43:14**
⇒ test chạy trên **phiên bản đang bị ghi đè giữa chừng**.
Chạy lại khi SHA ổn định ⇒ **392 passed / 0 failed**.

> **Bài học:** `cargo test` chạy trong lúc source đang bị agent khác ghi cho kết quả
> **không tái lập**. Phải freeze, hoặc hỏi ai đang sửa. Luôn hash trước/sau.

### 13.10 `0` có thể là "không có" hoặc "công cụ hỏng"
Khi phân tích freeze, regex của tôi trả **0 dòng** và tôi suýt kết luận
*"smoke.ps1 không nằm trong freeze"* — nhưng nguyên nhân là **biến `$t` bị `Where-Object`
che**, không phải dữ liệu. Làm lại bằng `String.Contains` ra cùng đáp án.
**Chỉ tin `0` sau khi xác nhận bằng con đường thứ hai.**

### 13.11 Comment có thể THAY THẾ việc kiểm — và đó là lý do nó nguy hiểm
Ba lần trong session, comment là **nguyên nhân gốc**, không phải giải pháp:
```
src/lib/api.ts:11        "Tauri v2 keeps snake_case"   -> SAI, chặn việc tìm ra sự thật
src-tauri/src/commands.rs:9-11  cùng nội dung          -> SAI, che bug rename_all
src-tauri/src/network.rs:464    "700 ms per hop"       -> đúng một nửa, che -w 900
```
Comment `"700 ms per hop"` nguy hiểm **hơn** không có comment: nó biến chỗ **chưa kiểm**
thành chỗ **trông như đã kiểm**. Nêu tên cặp (budget ↔ `-w`) là chưa đủ — phải đọc **giá trị**
của cả hai bên.
> **Khi review, đọc comment CUỐI CÙNG**, vì comment sai không trung tính — nó **chặn** việc
> phát hiện code sai.

### 13.12 Log proxy đã bị truncate — và số của tôi không bị ảnh hưởng
`socks5-connections.log` bị truncate lúc **16:13:10** (`socks5_proxy_logged.py` dòng 66
`open(LOG,"w")` chạy **trước** dòng 69 `bind`, nên chạy lại script ⇒ xoá log rồi chết vì bind).
Dòng đầu tiên hiện tại: `16:07:28 ACCEPT …`.
Lần scan nghiệm thu v6 diễn ra **16:16:50 → 16:17:33**, tức **sau** mốc truncate ⇒
số CONNECT của lần đó (nếu có dùng) vẫn nằm trong log hiện tại.
**Tiêu chí 1b đã bị rút từ §12.4 nên không có số nào trong báo cáo này phụ thuộc log đó.**
Riêng §12.4 (lịch sử v5) trích số từ log **trước** 16:13 — **nguồn đó nay đã bị xoá**,
nên con số ở §12.4 chỉ còn giá trị lịch sử, **không tái lập được**. Nó chưa từng được
dùng làm bằng chứng chốt.

