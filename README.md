# 🛡️ ECC-SecureGuard: Hệ Thống Thông Tin An Toàn Ứng Dụng Thuật Toán ECC

> **Dự án Triển Khai Hoàn Chỉnh Mật Mã Đường Cong Elliptic (Elliptic Curve Cryptography - ECC)**  
> Được thiết kế chuẩn công nghiệp, bảo mật đa tầng, hiệu năng cao và có giao diện điều khiển tương tác trực quan.

---

## 📌 1. Giới Thiệu Dự Án

**ECC-SecureGuard** là một hệ thống thông tin an toàn mẫu mực (Production-Grade Reference Architecture) triển khai toàn diện các thuật toán mật mã đường cong Elliptic hiện đại. Dự án giải quyết trọn vẹn 4 trụ cột an ninh thông tin:

1. **Bảo mật kênh truyền (Data-in-Transit):** Giao thức đàm phán khóa **ECDHE (X25519 / NIST P-256)** với cơ chế bảo mật chuyển tiếp hoàn hảo (**Perfect Forward Secrecy - PFS**).
2. **Định danh & Kiểm soát truy cập (Identity & Access):** Cấp phát và thẩm định **ECC-JWT** ký bằng thuật toán `ES256` (NIST P-256) và `EdDSA` (Ed25519) siêu nhẹ.
3. **Bảo mật dữ liệu tĩnh (Data-at-Rest):** Mã hóa phong bì lai **ECIES (Hybrid Encryption)** kết hợp X25519 + HKDF-SHA256 + AES-256-GCM.
4. **Toàn vẹn & Chống chối bỏ (Integrity & Non-Repudiation):** Chữ ký số **Ed25519** tốc độ cao, chuỗi băm kiểm toán (Tamper-evident Hash Chain) bảo đảm tính bất biến của nhật ký.
5. **Phòng chống các cuộc tấn công mật mã kinh điển:** Cơ chế sinh Nonce xác định (**RFC 6979**) chống thảm họa rò rỉ khóa Sony PS3 và bộ lọc kiểm định điểm hợp lệ (**Point Validation**) chống Invalid Curve Attacks.

---

## 🏗️ 2. Cấu Trúc Thư Mục Dự Án

```
m:\chia video\
├── server.js                   # Điểm khởi chạy Express Server & REST API
├── package.json                # Cấu hình dự án và dependencies
├── README.md                   # Tài liệu hướng dẫn sử dụng toàn diện
├── ARCHITECTURE.md             # Sơ đồ thiết kế kiến trúc chi tiết
├── src/
│   ├── crypto/                 # Thư viện Mật mã Cốt lõi
│   │   ├── curves.js           # Metadata các đường cong (P-256, P-384, secp256k1, Ed25519, X25519)
│   │   ├── keyManager.js       # Sinh, xuất/nhập PEM/JWK và quản lý vòng đời khóa
│   │   ├── ecdhExchange.js     # Bắt tay ECDHE & dẫn xuất khóa phiên HKDF-SHA256
│   │   ├── eciesHybrid.js      # Mã hóa lai ECIES (AES-256-GCM + X25519)
│   │   ├── digitalSignature.js # Chữ ký số Ed25519 & ECDSA P-256 (RFC 6979)
│   │   ├── jwtEcc.js           # Chuẩn JWT sử dụng ES256 & EdDSA
│   │   ├── attackSimulator.js  # Mô phỏng tấn công Nonce-Reuse & Invalid Curve
│   │   └── benchmark.js        # Đo lường hiệu năng thực tế CPU (ECC vs RSA)
│   ├── services/
│   │   ├── authService.js      # Xác thực tài khoản & phân quyền RBAC
│   │   ├── vaultService.js     # Kho lưu trữ tài liệu mật mã hóa ECIES
│   │   └── auditService.js     # Nhật ký kiểm toán Hash-chain ký số Ed25519
│   └── routes/
│       └── api.js              # Định nghĩa toàn bộ RESTful API Endpoints
├── public/                     # Giao diện Web Dashboard Trực quan
│   ├── index.html              # Single Page Application Dashboard
│   ├── styles.css              # Cyber-Dark Security Theme
│   └── app.js                  # Logic tương tác Dashboard & Crypto Playground
├── scripts/
│   ├── ecc_cli.js              # Công cụ dòng lệnh CLI tương tác
│   └── ecc_demo.py             # Script Python minh họa toán học đường cong Weierstrass
└── tests/
    ├── crypto.test.js          # Unit tests thuật toán mật mã
    └── api.test.js             # Integration tests toàn bộ REST API
```

---

## 🚀 3. Hướng Dẫn Cài Đặt & Khởi Chạy

### Yêu cầu môi trường:
- **Node.js**: Phiên bản 18 trở lên (đã tích hợp OpenSSL 3.x tăng tốc phần cứng).
- *(Tùy chọn)* **Python 3**: Để chạy script minh họa toán học.

### Bước 1: Khởi động Web Server & Dashboard
```bash
npm start
```
Terminal sẽ hiển thị:
```text
================================================================
   🛡️  ECC-SECUREGUARD: HỆ THỐNG THÔNG TIN AN TOÀN ECC v1.0.0
================================================================
[+] Web Dashboard UI:    http://localhost:3000
[+] API Base URL:        http://localhost:3000/api
[+] Benchmark API:       http://localhost:3000/api/benchmark
[+] Node.js Crypto:      OpenSSL 3.x Hardware Acceleration Active
[+] Hỗ trợ đường cong:   NIST P-256, P-384, secp256k1, Ed25519, X25519
================================================================
```

Mở trình duyệt truy cập: **`http://localhost:3000`** để trải nghiệm giao diện quản trị an ninh trực quan.

### Bước 2: Chạy Toàn Bộ Kiểm Thử Tự Động (Unit & Integration Tests)
```bash
npm test
```
*Tất cả 15 bài test kiểm thử toán học, bắt tay ECDHE, ECIES, chữ ký Ed25519, xác thực JWT, và API sẽ chạy và hoàn tất chỉ trong dưới 1 giây.*

---

## 💻 4. Sử Dụng Công Cụ Dòng Lệnh (CLI Tools)

Dự án cung cấp bộ công cụ CLI tiện ích tại `scripts/ecc_cli.js`:

### 1. Sinh Cặp Khóa ECC (PEM & Fingerprint):
```bash
# Sinh khóa Ed25519
node scripts/ecc_cli.js keygen --curve ed25519

# Sinh khóa NIST P-256 (FIPS)
node scripts/ecc_cli.js keygen --curve prime256v1

# Sinh khóa trao đổi X25519
node scripts/ecc_cli.js keygen --curve x25519
```

### 2. Mô Phỏng Bắt Tay Đàm Phán Khóa ECDHE (Client <-> Server):
```bash
node scripts/ecc_cli.js handshake --curve x25519
```

### 3. Ký Số Văn Bản Bằng Ed25519:
```bash
node scripts/ecc_cli.js sign "Phê duyệt giao dịch tài chính #2026"
```

### 4. Mô Phỏng Toán Học Tấn Công Nonce Reuse (Vụ Sony PS3):
```bash
node scripts/ecc_cli.js attack-demo
```

### 5. Chạy Benchmark So Sánh Hiệu Năng Trực Tiếp Trên CPU:
```bash
node scripts/ecc_cli.js benchmark --iter 20
```

### 6. Minh Họa Toán Học Bằng Python:
```bash
python scripts/ecc_demo.py
```

---

## 🌐 5. Danh Mục REST API Reference

| Phương thức | Endpoint | Mô tả |
| :--- | :--- | :--- |
| `GET` | `/api/system/status` | Kiểm tra trạng thái máy chủ và engine OpenSSL |
| `GET` | `/api/curves` | Lấy danh mục và đặc tả kỹ thuật các đường cong |
| `POST` | `/api/keys/generate` | Sinh cặp khóa ECC theo đường cong yêu cầu |
| `POST` | `/api/ecdh/handshake-simulation` | Mô phỏng bắt tay ECDHE Client/Server |
| `POST` | `/api/ecies/encrypt` | Mã hóa lai ECIES (AES-256-GCM + X25519) |
| `POST` | `/api/ecies/decrypt` | Giải mã dữ liệu và kiểm tra Authenticated Tag |
| `POST` | `/api/signature/sign` | Ký số tài liệu bằng Ed25519 hoặc ECDSA P-256 |
| `POST` | `/api/signature/verify` | Xác thực tính toàn vẹn và phát hiện giả mạo |
| `POST` | `/api/auth/register` | Đăng ký người dùng và cấp cặp khóa định danh |
| `POST` | `/api/auth/login` | Đăng nhập và nhận JWT ký bằng `ES256`/`EdDSA` |
| `GET` | `/api/vault/documents` | Lấy danh sách hồ sơ mật lưu trong Vault |
| `POST` | `/api/vault/documents` | Lưu trữ tài liệu mã hóa ECIES + Ký số Ed25519 |
| `POST` | `/api/vault/documents/decrypt` | Giải mã và kiểm tra chữ ký tài liệu mật |
| `GET` | `/api/audit/logs` | Truy xuất toàn bộ chuỗi nhật ký kiểm toán |
| `POST` | `/api/audit/verify` | Kiểm tra tính toàn vẹn chuỗi Hash-chain và chữ ký |
| `POST` | `/api/attacks/nonce-reuse` | Chạy mô phỏng tấn công rò rỉ khóa Nonce-reuse |
| `POST` | `/api/attacks/invalid-curve` | Kiểm tra bộ lọc Point Validation chống Invalid Curve |
| `GET` | `/api/benchmark` | Chạy benchmark CPU trực tiếp (so sánh ECC vs RSA) |

---

## 🔒 6. Bảng So Sánh Hiệu Năng Thực Tế Đo Được

Kết quả đo đạc thực tế trên cùng một hệ thống máy chủ:

| Chỉ số | RSA-3072 | ECC (Ed25519 / X25519) | Ưu Thế Của ECC |
| :--- | :--- | :--- | :--- |
| **Tốc độ sinh cặp khóa** | ~459.6 ms | **0.068 ms** | **Nhanh hơn 6,700 lần** |
| **Tốc độ ký (Signing)** | ~1.758 ms | **0.065 ms** | **Nhanh hơn 27 lần** |
| **Kích thước khóa công khai** | 384 bytes | **32 bytes** | **Nhỏ hơn 12 lần** |
| **Kích thước khóa riêng** | 1770 bytes | **32 bytes** | **Nhỏ hơn 55 lần** |
| **Kích thước chữ ký số** | 384 bytes | **64 bytes** | **Nhỏ hơn 6 lần** |

---

## 📜 7. Bản Quyền & Giấy Phép
Dự án được xây dựng phục vụ nghiên cứu, đào tạo chuyên sâu và áp dụng làm tiêu chuẩn thiết kế cho các hệ thống thông tin an toàn. Mã nguồn mở theo giấy phép MIT.
