# Phân tích cấu trúc & đề xuất giải mã `cuttaypromax.js`

> File: `cuttaypromax.js` — 1.106.838 byte, 17.810 dòng.
> Kết luận: đây là một **userscript được bảo vệ bằng 5 lớp mã hóa** (base64 tùy
> chỉnh → XOR cuộn + MAC → trích xuất record bằng state-machine → PRNG XOR →
> bit-stream per-record), bên trong là một **VM/program** cho dịch vụ rút gọn link **link4m.app**.
> Tất cả lớp ngoài đã được giải mã và **kiểm chứng byte-perfect** bằng 2 phương
> pháp độc lập (instrumentation & tái lập tĩnh).

---

## 1. Cấu trúc file (bản đồ dòng)

| Dòng | Thành phần | Mô tả |
|---|---|---|
| 1–110 | GM-shim IIFE | Định nghĩa lại `GM`, `GM_getValue`, `GM_xmlhttpRequest`, `cloneInto`… bằng `Object.defineProperty` (chống ghi đè, chuẩn bị môi trường Tampermonkey/Greasemonkey) |
| 111–122 | Wrapper arrow-IIFE | Alias builtin: `$G = [WeakMap, Uint16Array, JSON, DataView, undefined, ReferenceError, BigInt, TypeError, String, Math, Reflect, Promise, Symbol, Uint8Array, ArrayBuffer, Array]`, `yz = Math.imul`… mục đích phá vỡ pattern tĩnh |
| 123–380 | `function $(ZQ, AF, FU)` | **Decoder cấp record (L5)** — gọi tại 4 chỗ `e5.Uc = $(e5.Uc, e5.i, e5.X$)` (dòng ~16159/16718/16983/17176): giải bit-stream của mỗi record `se[k].Uc` thành `Uint16Array` (xem mục 2, bước L5) |
| 382–1515 | `function _R(VR)` | **Trái tim của lớp bảo vệ**: giải payload (xem mục 2). Chạy 1 state-machine `Ry/eE` với ~56 case (`60062…60117`), các case uốn éo bằng số nguyên大 (vd `246239538`) |
| 1517–1730 | Machine `lu/kv` | Khởi tạo `Gi` (hash FNV-1a kiểu JS-Crockford) và `_` = **bảng chuỗi XOR**: `dy(bytes, 196)` = mỗi byte XOR 196 → `_.N$("mc")` ⇒ `"push"`, `"slice"`, `"fromCharCode"`… (dump tại `analysis/strings.json`) |
| 1731–17803 | IIFE nhận `_R(...)` | **Chương trình chính**: (a) XOR lớp 4 bằng PRNG `Wd/Wc` trên `dh.B$`; (b) hàng loạt kiểm tra anti-tamper (`Function.prototype.toString` phải là native, không được có getter trên `Object.prototype[0..255]`, kiểm tra modular-exponentiation…); (c) VM/machine `N5` interpret program |
| 17804 | Literal payload | Chuỗi ~150.854 ký tự, alphabet `A-Za-z0-9$_` |
| 17805–17810 | Đóng IIFE | — |

Kỹ thuật obfuscation đã dùng:
- **Control-flow flattening** (mọi hàm lớn là `while + switch` với biến trạng thái;
  kể cả vòng lặp `for` cũng được bẻ thành `while` + counter uốn éo).
- **Builtin aliasing** (`$G[8]` = `String`, `$G[9]` = `Math`…).
- **Bảng chuỗi XOR** (`dy(arr, 196)`) + truy cập gián tiếp `_.N$("key")`.
- **Mã hóa theo tầng** (base64 → XOR cuộn+MAC → trích record → PRNG XOR →
  bit-stream per-record với LCG + xáo trộn).
- **Anti-tamper / environment checks** ở lớp cuối.
- **Integrity MAC** chống chỉnh sửa payload.

---

## 2. Pipeline giải mã (đã xác minh — 5 lớp)

```
payload (150.854 chars, alphabet A-Za-z0-9$_)
  │  L1: base64 tùy chỉnh — index theo "ABC…xyz0123456789$_", dừng ở '='
  ▼
enc = 113.140 byte
  │  L2: plain[i] = enc[i] ^ Sm[i % 32] ^ (i & 255)
  │      Sm[i] = a6[i] ^ RQ[i] ^ xN[i] ^ IM[i]        (a6, RQ, xN hard-code trong source)
  │      IM = 32 byte tiến hóa từ FNV-1a(chuỗi payload):
  │          jE = 2166136261; FNV-1a từng char của payload;
  │          for hy=0..31: jE = (jE ^ hy) * 16777619 (mod 2^32); IM.push(jE & 255)
  │  L2b: magic plain[0..2] == CD C4 CC  (zi = [205,196,204])
  │       MAC 32 byte cuối = c1(body, pl) — HMAC-FNV1a 2 tầng:
  │         ipad = pl(pad 64)^54, opad = pl(pad 64)^92
  │         ZY = FNV1a_ext(ipad ++ body)   (32 byte, mở rộng bằng phép nhân liên tiếp)
  │         MAC = FNV1a_ext(opad ++ ZY)    → so sánh bằngt với trailer → vJ = true
  ▼
body = 113.108 byte  (analysis/decoded_plaintext_body.bin)
  │  L3: _R() đọc body từ offset _U=6 bằng dãy bytecode đọc byte (xX/e7/wq/lD/qR…)
  │      trích xuất thành 3 phần:
  ▼
{ B$: 55 byte (bootstrap/dispatcher — chính nó bị L4 mã hóa),
  Qf: 6 mục (section: {G$:"h$"}, [11380], [dãy chỉ mục], {G$:"g$"}),
  se: 123 record — mỗi record = {Uc: byte-code (tổng 51.640 byte, 6–4.333 byte/recode),
      j$: hash, ra: tên, Aa: hằng số, i: chỉ số (0..122), X$: chiều dài, …} }
  │  L4: XOR lại B$ bằng keystream sinh từ PRNG nội bộ Wd/Wc
  │      (IIFE `(function(Gb){…})(dh.B$)` — deterministic, trích nguyên từ source)
  ▼
Ca = 55 byte program cuối  (analysis/decoded_L4_program.bin)
  │  L5: mỗi record giải khi VM dùng tới:  words = $(Uc, i, X$)
  │      - seed PRNG: o5 = (127201272915712 + i) >>> 0  → LCG rand jY()
  │      - Rw = scheme (0: LCG-XOR từng byte, 1: trộn bit-plane, 2: dual-LCG)
  │      - đọc bit từ Uc qua bit-reader (UU), tái tạo X$*2 byte,
  │        rồi Fisher-Yates shuffle (seed từ jY), pack BE thành Uint16Array
  ▼
123 mảng uint16 (24.863 word) = bytecode thật của từng hàm  (analysis/decoded_records.json)
```

Tất cả so sánh:

```
L1 magic ok: true [205,196,204]        ← khớp zi
L2b MAC ok:  true                      ← khớp trailer 32 byte
L3 body == dump vD : true              ← instrumentation == tái lập tĩnh
L3 Sm   == dump Sm : true
L3 trailer == dump Mw: true
L4 Ca == dump L4.Ca: true
L5 123 records → 24.863 uint16 words   ← lift nguyên văn `function $` (cùng semantics JS)
```

---

## 3. Công cụ trong `analysis/`

| File | Vai trò |
|---|---|
| `extract.js` | **Instrumentation**: vá 3 điểm neo trong source, chạy bản gốc bằng Node, hứng `__STRINGS/__L3/__L4` rồi tắt chương trình chính (truyền config rỗng) → `strings.json`, `dump_L3.json`, `dump_L4.json` |
| `decode.js` | **Decoder độc lập** (không vá file): tái hiện L1→L2→L2b→L4 từ constants trích bằng regex, tự lift IIFE `Wd/Wc/Gb` từ source; đối chứng byte-perfect với dump của `extract.js` |
| `decoded_plaintext_body.bin` | **113.108 byte plaintext** đã giải (nội dung thật của payload) |
| `decoded_L4_program.bin` | 55 byte program cuối (sau lớp PRNG XOR) |
| `decoded_records.json` | **123 record đã giải L5** → 24.863 uint16 (bytecode từng hàm) |
| `decoded_mac_trailer.bin` | MAC 32 byte |
| `readable_strings.txt` | 494 chuỗi ASCII đọc được từ plaintext (kèm offset) |
| `strings.json` | Bảng chuỗi XOR-196 của lớp wrapper (`push/slice/charCodeAt/…`) |
| `dump_L3.json` / `dump_L4.json` | Ảnh chụp đầy đủ từng lớp (mảng byte + `se`/`Qf`) |

Cách chạy:

```bash
node analysis/extract.js   # instrumentation → dump (nhanh, ~0.3s)
node analysis/decode.js    # giải độc lập + đối chứng
```

---

## 4. Nội dung thật của payload (sau khi giải)

Plaintext không phải mã JS thuần mà là **container dữ liệu cho VM**, chứa:

- **Regex config dạng JSON** (tên field bị obfuscate: `peKc`/`pen$`/`peMb` ≈ object/pattern/flags):
  - URL/hostname: `^https?:\/\/`, `https?:\/\/([a-z0-9][a-z0-9.\-]{1,61}\.[a-z]{2,}…)`,
    TLD tiếng Việt `com.vn|net.vn|edu.vn|org.vn|vn|…`, uốn éo domain kiểu `abc , com.vn`, `abc . com`
  - **Link4m**: `https:\/\/[a-z0-9-]+\.link4m\.app`, `^([a-z0-9\-]+\.)*link4m\.(com|net|org)$`,
    `img.link4m.`, `/uploads/advertiser/`, `/1_[^\/]+\.[a-z]+$` (ảnh advertiser)
  - Anti-noise: `google|gstatic|recaptcha|cloudflare|logo|icon|favicon|spinner|…`
  - Sửa HTML/JS: `[&<>\"]`, `<[a-z][\s\S]*>`, chuỗi build từ `"https:" + x + "/widget/"`
- **Chuỗi base64** (decode được ngay): `param_no`, `defaultValue`, `devDependencies`,
  `Maximum call stack size exceeded`, `internal server error`, `createContext`,
  `getSnapshotBeforeUpdate` (React), `accept-language`, `cache-control`, `referer`,
  `content-type`, `X-Real-IP`, `apikey`, `directDomains`, `responseText`, `finalUrl`, `DELETE`, `credentials`…
- **123 record `se.Uc`** = bytecode từng hàm của chương trình gốc (51.640 byte).
- Anti-debug: check native `toString`, prototype-getter check, kiểm tra nguyên thủy modpow.

→ Suy luận: userscript can thiệp vào **link4m.app / link4m.com** (rút gọn link):
xử lý URL/domain, ảnh advertiser, header/API call (`apikey`, `X-Real-IP`…),
có khả năng nhận diện React (devtools/snapshot hooks).

---

## 5. Đề xuất các bước tiếp theo (nếu muốn nguồn JS đầy đủ)

Tất cả **5 lớp mã hóa đã gỡ hết** (L1–L5). Phần còn lại thuần túy là
**interpret** — không còn cryptographic transform nào nữa:

1. **Disassembler cho `Ca` (55 byte)**: đọc opcode từ đoạn truy cập
   `H3 = W0.Ca` (dòng ~17466) — đối chiếu các case `KF = 365984…` để suy ra
   format chỉ lệnh (có vẻ LEB128/u16 hỗn hợp).
2. **Viết lại máy `N5` (dòng ~1854) thành vòng lặp thuần** thay `while+switch`:
   input đã sẵn trong `decoded_records.json` (opcode ở word chẵn — hay gặp
   103, 33, 151, 106, 0, 1, 2, 3…) + `Ca` + `Qf`. Trace từng lệnh là tái
  构造 được source.
3. **Chạy thật trong DOM ảo** (jsdom + stub GM APIs + network fake) với
   `extract.js` bỏ cờ tắt chương trình, log các call `$(Uc,i,X$)` và dispatch
   của N5 để đối chiếu với disassembler.
4. Nếu chỉ cần **nội dung**: `readable_strings.txt` + `decoded_plaintext_body.bin`
   đã đủ để xem toàn bộ regex/URL/hằng số mà script dùng.

**Lưu ý đạo đức/pháp lý**: công cụ ở đây dùng để *phân tích file bạn cung cấp*.
Đừng dùng để phá vỡ biện pháp bảo vệ của phần mềm không thuộc về bạn, hay để
can thiệp vào dịch vụ của người khác trái quy định.
