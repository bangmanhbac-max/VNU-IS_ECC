# 🛡️ VNU-IS_ECC: Hệ Thống Thông Tin An Toàn Ứng Dụng Thuật Toán Mật Mã Đường Cong Elliptic (ECC)

<div align="center">

[![Node.js Version](https://img.shields.io/badge/Node.js-v18.0%2B-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Crypto Engine](https://img.shields.io/badge/Crypto_Engine-OpenSSL_3.x-red?style=for-the-badge&logo=openssl&logoColor=white)](https://www.openssl.org/)
[![Security Standard](https://img.shields.io/badge/Standard-FIPS_186--4_%7C_RFC_8032_%7C_RFC_7748-blue?style=for-the-badge)](https://csrc.nist.gov/)
[![Tests Status](https://img.shields.io/badge/Tests-15%2F15%20Passed-brightgreen?style=for-the-badge&logo=checkmarx&logoColor=white)](file:///M:/chia%20video/tests/)
[![PQC Hybrid Ready](https://img.shields.io/badge/Post--Quantum-Hybrid_Ready-purple?style=for-the-badge)](https://csrc.nist.gov/projects/post-quantum-cryptography)

<p align="center">
  <b>Hệ thống tham chiếu an toàn thông tin cấp công nghiệp (Industrial Reference Security System)</b><br>
  Triển khai toàn diện Mật mã Đường cong Elliptic: ECDHE (PFS), ECIES (Envelope Encryption), Ed25519, Deterministic ECDSA (RFC 6979), Token ECC-JWT và Chuỗi kiểm toán bất biến (Tamper-evident Hash Chain).
</p>

---

### 👨‍💻 NHÓM TÁC GIẢ & ĐƠN VỊ THỰC HIỆN
**Bùi Kim Ngân** & **Nguyễn Tuấn Minh**  
*Đơn vị nghiên cứu:* **AIVN**  
*Khoa/Trường:* **Trường Quốc tế - Đại học Quốc gia Hà Nội (VNU-IS)**  
*Dự án:* **VNU-IS_ECC (Elliptic Curve Cryptography Information System)**  
*Mã nguồn chính thức:* [github.com/bangmanhbac-max/VNU-IS_ECC](https://github.com/bangmanhbac-max/VNU-IS_ECC)

---

</div>

## 📑 Mục Lục

1. [Tổng Quan & Động Lực Nghiên Cứu](#-1-tổng-quan--động-lực-nghiên-cứu)
2. [Cơ Sở Toán Học Của Mật Mã Đường Cong Elliptic](#-2-cơ-sở-toán-học-của-mật-mã-đường-cong-elliptic)
3. [Bảng So Sánh Toàn Diện: ECC vs RSA](#-3-bảng-so-sánh-toàn-diện-ecc-vs-rsa)
4. [Cấu Trúc Thư Mục Dự Án](#-4-cấu-trúc-thư-mục-dự-án)
5. [Kiến Trúc Hệ Thống & Sơ Đồ Luồng Dữ Liệu](#-5-kiến-trúc-hệ-thống--sơ-đồ-luồng-dữ-liệu)
   - [5.1. Sơ đồ Kiến trúc 4 Lớp Phòng thủ](#51-sơ-đồ-kiến-trúc-4-lớp-phòng-thủ)
   - [5.2. Luồng Đàm phán Khóa Phiên ECDHE (PFS)](#52-luồng-đàm-phán-khóa-phiên-ecdhe-pfs)
   - [5.3. Luồng Mã hóa Phong bì Lai ECIES (AES-256-GCM + X25519)](#53-luồng-mã-hóa-phong-bì-lai-ecies)
   - [5.4. Luồng Ký và Xác thực Chữ ký số Ed25519](#54-luồng-ký-và-xác-thực-chữ-ký-số-ed25519)
   - [5.5. Chuỗi Nhật ký Kiểm toán Bất biến (Tamper-evident Hash Chain)](#55-chuỗi-nhật-ký-kiểm-toán-bất-biến)
   - [5.6. Lộ trình Kháng Lượng tử Lai (Post-Quantum Hybrid Architecture)](#56-lộ-trình-kháng-lượng-tử-lai)
6. [Đặc Tả Kỹ Thuật Các Bộ Đường Cong Chuẩn](#-6-đặc-tả-kỹ-thuật-các-bộ-đường-cong-chuẩn)
7. [Mô Hình Đe Dọa (Threat Model) & Giải Pháp Phòng Thủ](#-7-mô-hình-đe-dọa-threat-model--giải-pháp-phòng-thủ)
8. [Hướng Dẫn Cài Đặt & Vận Hành Toàn Diện](#-8-hướng-dẫn-cài-đặt--vận-hành-toàn-diện)
   - [8.1. Khởi chạy Máy chủ & Web Dashboard](#81-khởi-chạy-máy-chủ--web-dashboard)
   - [8.2. Chạy Bộ Kiểm thử Tự động](#82-chạy-bộ-kiểm-thử-tự-động)
   - [8.3. Sử dụng Bộ Công cụ Dòng lệnh Quản trị (CLI)](#83-sử-dụng-bộ-công-cụ-dòng-lệnh-quản-trị-cli)
   - [8.4. Script Mô phỏng Toán học (Python)](#84-script-mô-phỏng-toán-học-python)
9. [Tài Liệu Chi Tiết RESTful API Reference](#-9-tài-liệu-chi-tiết-restful-api-reference)
10. [Báo Cáo Hiệu Năng Thực Nghiệm (Benchmark Report)](#-10-báo-cáo-hiệu-năng-thực-nghiệm-benchmark-report)
11. [Hướng Dẫn Triển Khai Môi Trường Sản Xuất (Production Deployment)](#-11-hướng-dẫn-triển-khai-môi-trường-sản-xuất)
12. [Bản Quyền & Trích Dẫn Khoa Học](#-12-bản-quyền--trích-dẫn-khoa-học)

---

## 🔬 1. Tổng Quan & Động Lực Nghiên Cứu

Trong kiến trúc hệ thống thông tin hiện đại (Cloud Computing, IoT, Microservices, Ngân hàng số), mật mã bất đối xứng đóng vai trò cốt lõi trong việc thiết lập danh tính, trao đổi khóa bí mật và ký số xác thực. Tuy nhiên, các thuật toán thế hệ trước như **RSA** (Rivest-Shamir-Adleman) bộc lộ nhiều điểm nghẽn nghiêm trọng:
* **Gia tăng kích thước khóa:** Để đạt mức an toàn 128-bit tương đương chuẩn AES-128, RSA yêu cầu khóa **3072 bits** (hoặc 7680 bits cho an toàn 192-bit). Kích thước này tạo ra overhead rất lớn trên RAM, cơ sở dữ liệu và băng thông mạng.
* **Độ trễ tính toán cao:** Quá trình sinh cặp số nguyên tố lớn trong RSA đòi hỏi hàng trăm mili-giây, không khả thi cho các giao thức đàm phán khóa động dùng một lần (**Ephemeral Handshake**).
* **Tiêu hao năng lượng:** Thiết bị nhúng, thẻ thông minh (Smartcard) và thiết bị IoT bị giới hạn nguồn điện không thể duy trì các phép tính lũy thừa modulo trên số nguyên hàng nghìn bits.

**Mật mã Đường cong Elliptic (ECC)** ra đời như một bước tiến mang tính cách mạng, dựa trên nền tảng đại số của các nhóm điểm trên đường cong elliptic trên trường hữu hạn $\mathbb{F}_p$. Với khóa chỉ **256 bits**, ECC cung cấp độ an toàn tương đương RSA 3072 bits, giảm kích thước khóa **12 lần**, giảm kích thước chữ ký **6 lần**, và tăng tốc độ sinh khóa tới **hơn 6,000 lần**.

Dự án **VNU-IS_ECC** do nhóm nghiên cứu **Bùi Kim Ngân** và **Nguyễn Tuấn Minh** thuộc **AIVN** xây dựng nhằm cung cấp một hệ thống tham chiếu an toàn thông tin hoàn chỉnh, đạt chuẩn công nghiệp, chứng minh tính ưu việt của ECC trên mọi tầng ứng dụng.

---

## 📐 2. Cơ Sở Toán Học Của Mật Mã Đường Cong Elliptic

### 2.1. Phương Trình Weierstrass Rút Gọn
Trên trường hữu hạn nguyên tố $\mathbb{F}_p$ ($p > 3$), đường cong elliptic là tập hợp các điểm $(x, y) \in \mathbb{F}_p \times \mathbb{F}_p$ thỏa mãn phương trình:
$$y^2 = x^3 + ax + b \pmod p$$
với điều kiện không suy biến (phân biệt nghiệm):
$$4a^3 + 27b^2 \neq 0 \pmod p$$
Tập hợp các nghiệm cùng với **điểm vô cực** $\mathcal{O}$ (Point at Infinity - đóng vai trò phần tử đơn vị) tạo thành một **Nhóm Abel (Abelian Group)** với phép cộng điểm $(+)$.

### 2.2. Các Phép Toán Nhóm Cốt Lõi

1. **Phép cộng hai điểm phân biệt ($P + Q = R$ với $P \neq Q$):**
   Đường thẳng đi qua $P(x_1, y_1)$ và $Q(x_2, y_2)$ có hệ số góc $\lambda$:
   $$\lambda = \frac{y_2 - y_1}{x_2 - x_1} \pmod p$$
   Tọa độ điểm kết quả $R(x_3, y_3)$:
   $$x_3 = \lambda^2 - x_1 - x_2 \pmod p$$
   $$y_3 = \lambda(x_1 - x_3) - y_1 \pmod p$$

2. **Phép nhân đôi điểm ($2P = R$ với $P = Q$):**
   Tiếp tuyến tại $P(x_1, y_1)$ có hệ số góc $\lambda$:
   $$\lambda = \frac{3x_1^2 + a}{2y_1} \pmod p$$
   Tọa độ điểm kết quả $R(x_3, y_3)$:
   $$x_3 = \lambda^2 - 2x_1 \pmod p$$
   $$y_3 = \lambda(x_1 - x_3) - y_1 \pmod p$$

3. **Phép nhân vô hướng (Scalar Multiplication $Q = k \cdot P$):**
   $$Q = \underbrace{P + P + \dots + P}_{k \text{ lần}}$$
   Được tối ưu hóa bằng giải thuật **Double-and-Add** hoặc **Montgomery Ladder** với độ phức tạp thời gian chỉ $O(\log k)$.

### 2.3. Bài Toán Logarit Rời Rạc Trên Đường Cong Elliptic (ECDLP)
* **Chiều thuận:** Cho trước khóa riêng $k \in [1, n-1]$ và điểm cơ sở $G$, việc tính $Q = k \cdot G$ diễn ra cực nhanh ($< 0.1 \text{ ms}$).
* **Chiều nghịch (ECDLP):** Cho trước điểm công khai $Q$ và điểm $G$, việc tìm số nguyên $k$ sao cho $Q = k \cdot G$ là bài toán bất khả thi về mặt tính toán. Thuật toán cổ điển tối ưu nhất hiện nay (Pollard's rho) có độ phức tạp thời gian:
  $$\mathcal{O}(\sqrt{n})$$
  với $n \approx 2^{256}$, độ phức tạp lên tới $\approx 2^{128}$ phép tính, nằm ngoài khả năng tính toán của toàn bộ siêu máy tính hiện đại trên thế giới.

---

## ⚖️ 3. Bảng So Sánh Toàn Diện: ECC vs RSA

| Tiêu Chí Kỹ Thuật | RSA-2048 | RSA-3072 (Chuẩn An Toàn Hiện Nay) | ECC NIST P-256 | ECC Ed25519 / X25519 | Ưu Thế Vượt Trội Của ECC |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Mức độ an toàn tương đương** | 112 bits | 128 bits | 128 bits | **128 bits** | Đạt an toàn tối đa với tài nguyên tối thiểu |
| **Kích thước khóa công khai** | 256 bytes | 384 bytes | 65 bytes (Uncompressed) | **32 bytes** | **Nhỏ hơn 12 lần** so với RSA-3072 |
| **Kích thước khóa riêng** | 1,190 bytes | 1,770 bytes | 32 bytes | **32 bytes** | **Nhỏ hơn 55 lần** so với RSA-3072 |
| **Kích thước chữ ký số** | 256 bytes | 384 bytes | ~71 bytes (DER) | **64 bytes (Cố định)** | **Nhỏ hơn 6 lần** (tiết kiệm băng thông mạng) |
| **Tốc độ sinh cặp khóa** | ~152 ms | ~459 ms | 0.073 ms | **0.068 ms** | **Nhanh hơn ~6,700 lần** (cực kỳ lý tưởng cho PFS) |
| **Tốc độ ký (Signing)** | 0.697 ms | 1.758 ms | 0.043 ms | **0.065 ms** | **Nhanh hơn ~27 đến 40 lần** |
| **Tốc độ xác thực (Verify)** | 0.024 ms | 0.047 ms | 0.070 ms | **0.111 ms** | RSA verify nhanh do số mũ nhỏ $e=65537$ |
| **Tiêu thụ điện năng / CPU** | Rất cao | Cực cao | Thấp | **Tối ưu tuyệt đối** | Kéo dài thời lượng pin cho IoT/Mobile |
| **Kháng tấn công kênh kề** | Kém | Kém | Phụ thuộc triển khai | **Miễn nhiễm tự nhiên** | Ed25519 Constant-time by design |

---

## 📁 4. Cấu Trúc Thư Mục Dự Án

```
VNU-IS_ECC/
├── server.js                   # Điểm khởi chạy Express Server, thiết lập CORS, BodyParser, Static Assets
├── package.json                # Quản lý metadata, dependencies tối giản và test scripts
├── README.md                   # Báo cáo kỹ thuật chi tiết, tài liệu kiến trúc và hướng dẫn sử dụng
├── ARCHITECTURE.md             # Tài liệu thiết kế mô hình dữ liệu, Threat Model và sơ đồ luồng
├── src/
│   ├── crypto/                 # Thư viện Mật mã Cốt lõi (Tận dụng OpenSSL 3.x Hardware Acceleration)
│   │   ├── curves.js           # Định nghĩa thông số 5 đường cong: P-256, P-384, secp256k1, Ed25519, X25519
│   │   ├── keyManager.js       # Sinh cặp khóa, chuyển đổi SPKI/PKCS#8 PEM, Hex DER, JWK và Fingerprint
│   │   ├── ecdhExchange.js     # Bắt tay ECDHE (PFS), tính Shared Secret và dẫn xuất khóa phiên HKDF-SHA256
│   │   ├── eciesHybrid.js      # Chuẩn mã hóa lai phong bì ECIES (X25519 + HKDF + AES-256-GCM AEAD)
│   │   ├── digitalSignature.js # Ký và thẩm định chữ ký số Ed25519 (RFC 8032) & ECDSA (RFC 6979)
│   │   ├── jwtEcc.js           # Triển khai RFC 7519 JSON Web Token với chữ ký ES256 & EdDSA
│   │   ├── attackSimulator.js  # Mô phỏng bẻ khóa toán học Nonce-Reuse (PS3) & kiểm tra Point Validation
│   │   └── benchmark.js        # Engine đo đạc hiệu năng thực tế CPU mili-giây giữa ECC và RSA
│   ├── services/
│   │   ├── authService.js      # Dịch vụ định danh, xác thực PBKDF2-SHA512, cấp phát Token ECC-JWT
│   │   ├── vaultService.js     # Kho lưu trữ hồ sơ mật mã hóa ECIES kết hợp chữ ký số tác giả
│   │   └── auditService.js     # Nhật ký kiểm toán bất biến theo chuỗi băm (Hash-Chain) ký số Ed25519
│   └── routes/
│       └── api.js              # Định tuyến toàn bộ 18 RESTful API Endpoints cho hệ thống
├── public/                     # Giao diện Web Dashboard Trực quan (Cyber-Dark Theme)
│   ├── index.html              # Ứng dụng Single Page Application Dashboard 8 Tab chuyên biệt
│   ├── styles.css              # Giao diện Glassmorphism với hiệu ứng Cyber Security hiện đại
│   └── app.js                  # Frontend Controller kết nối API, trực quan hóa biểu đồ và mô phỏng
├── scripts/
│   ├── ecc_cli.js              # Bộ công cụ dòng lệnh (CLI) tương tác trực tiếp với các module mật mã
│   └── ecc_demo.py             # Script Python minh họa trực quan số học đường cong Weierstrass
└── tests/
    ├── crypto.test.js          # Bộ kiểm thử Unit Test cho toàn bộ thuật toán mật mã lõi
    └── api.test.js             # Bộ kiểm thử tích hợp (Integration Test) cho toàn bộ REST API
```

---

## 🏛️ 5. Kiến Trúc Hệ Thống & Sơ Đồ Luồng Dữ Liệu

### 5.1. Sơ Đồ Kiến Trúc 4 Lớp Phòng Thủ (Defense-in-Depth)

```mermaid
flowchart TD
    subgraph ClientZone ["Lớp Khách Hàng (Client Access Layer)"]
        Browser["Trình Duyệt Web (Web Dashboard)"]
        CLIClient["Công Cụ Dòng Lệnh (Admin CLI)"]
        MobileApp["Ứng Dụng Di Động / Thiết Bị IoT"]
    end

    subgraph TransportSecurity ["Lớp 1: Bảo Mật Kênh Truyền (Transport Security)"]
        TLS["TLS 1.3 Termination (ECDHE-X25519 / Perfect Forward Secrecy)"]
        mTLS["Mutual TLS (Chứng chỉ số Ed25519 cho Microservices)"]
    end

    subgraph AuthLayer ["Lớp 2: Định Danh & Phân Quyền (Identity & IAM)"]
        JWTECC["Bộ Quản Lý Token ECC-JWT (ES256 & EdDSA)"]
        RBAC["Kiểm Soát Quyền Hạn Dựa Trên Vai Trò (Admin / Officer / User)"]
    end

    subgraph CoreCrypto ["Lớp 3: Động Cơ Mật Mã Lõi (Core Cryptographic Engine)"]
        KMS["Quản Lý Vòng Đời Khóa (Key Generation & Rotation)"]
        ECIES["Mã Hóa Phong Bì Lai (X25519 + HKDF + AES-256-GCM)"]
        Signer["Chữ Ký Số Toàn Vẹn (Ed25519 & RFC 6979 ECDSA)"]
    end

    subgraph StorageSecurity ["Lớp 4: Lưu Trữ Mật & Kiểm Toán (Data-at-Rest & Audit)"]
        VaultDB[(Kho Hồ Sơ Mật - Mã Hóa ECIES Toàn Phần)]
        AuditLog[(Chuỗi Khối Kiểm Toán Bất Biến - Hash Chain + Chữ Ký Ed25519)]
    end

    Browser -->|"HTTPS / TLS 1.3"| TLS
    CLIClient -->|"API REST / CLI Engine"| CoreCrypto
    MobileApp -->|"mTLS Handshake"| mTLS

    TLS --> JWTECC
    mTLS --> JWTECC
    JWTECC --> RBAC
    RBAC --> CoreCrypto

    CoreCrypto --> VaultDB
    CoreCrypto --> AuditLog
```

---

### 5.2. Luồng Đàm Phán Khóa Phiên ECDHE (PFS)

```mermaid
sequenceDiagram
    autonumber
    participant Alice as Khách Hàng (Alice)
    participant Channel as Môi Trường Kênh Mạng Công Cộng
    participant Bob as Máy Chủ (Bob)

    Note over Alice: Sinh cặp khóa tạm (Ephemeral):<br/>priv_a ngẫu nhiên (32 bytes)<br/>pub_A = priv_a * G
    Note over Bob: Sinh cặp khóa tạm (Ephemeral):<br/>priv_b ngẫu nhiên (32 bytes)<br/>pub_B = priv_b * G

    Alice->>Channel: Truyền gửi pub_A (X25519 Public Key)
    Channel->>Bob: Chuyển tiếp pub_A
    Bob->>Channel: Truyền gửi pub_B (X25519 Public Key)
    Channel->>Alice: Chuyển tiếp pub_B

    Note over Alice: Tính toán Bí mật chung:<br/>S = priv_a * pub_B = priv_a * (priv_b * G)
    Note over Bob: Tính toán Bí mật chung:<br/>S = priv_b * pub_A = priv_b * (priv_a * G)

    Note over Alice, Bob: S_Alice == S_Bob == (priv_a * priv_b) * G

    Alice->>Alice: HKDF-SHA256(S, salt, info) -> Khóa đối xứng AES-256
    Bob->>Bob: HKDF-SHA256(S, salt, info) -> Khóa đối xứng AES-256

    Note over Alice, Bob: Thiết lập kênh truyền bảo mật AES-256-GCM (PFS Hoàn Hảo)
```

---

### 5.3. Luồng Mã Hóa Phong Bì Lai ECIES

```mermaid
flowchart LR
    PlainText[Dữ Liệu Bản Rõ Cần Bảo Vệ] --> AESEnc[Mã Hóa Đối Xứng AES-256-GCM]
    PlainText --> AuthorSign[Ký Số Tác Giả Bằng Ed25519]
    
    EphKey[Khóa Tạm Ephemeral X25519] --> ECDH[ECDH với Khóa Công Khai Người Nhận]
    RecipPub[Khóa Công Khai Người Nhận] --> ECDH
    ECDH --> HKDF[Hàm Dẫn Xuất Khóa HKDF-SHA256]
    HKDF --> AESKey[Khóa Phiên AES-256 Dùng 1 Lần]
    AESKey --> AESEnc

    AESEnc --> CipherText[Ciphertext Bản Mã]
    AESEnc --> AuthTag[16-byte Authentication Tag]

    CipherText & AuthTag & AuthorSign & EphKey --> EncryptedPackage[Gói Hồ Sơ Lưu Trữ ECIES Độc Lập]
```

---

### 5.4. Luồng Ký và Xác Thực Chữ Ký Số Ed25519

```mermaid
sequenceDiagram
    autonumber
    participant Signer as Phía Ký Số (Signer)
    participant Verifier as Phía Xác Minh (Verifier)

    Note over Signer: Dữ liệu thông điệp: M<br/>Khóa riêng: priv_key (32 bytes Ed25519)
    Signer->>Signer: Ký Ed25519: sig = Sign(priv_key, M)<br/>(Chữ ký 64 bytes theo RFC 8032)
    Signer->>Verifier: Gửi gói chứng thư: (M, sig, pub_key)

    Note over Verifier: Tiếp nhận gói chứng thư
    Verifier->>Verifier: Thực hiện: Verify(pub_key, M, sig)
    alt Bản rõ nguyên vẹn 100%
        Verifier-->>Verifier: Kết quả: HỢP LỆ (Bảo đảm Toàn vẹn & Chống chối bỏ)
    else Dữ liệu bị thay đổi (dù chỉ 1 bit)
        Verifier-->>Verifier: Kết quả: THẤT BẠI (Phát hiện giả mạo ngay lập tức)
    end
```

---

### 5.5. Chuỗi Nhật Ký Kiểm Toán Bất Biến

```mermaid
stateDiagram-v2
    direction LR
    
    state "Sự Kiện #0 (Khởi Tạo Genesis)" as E0 {
        PrevHash0 : PrevHash = 0000000000000000...
        Action0 : USER_REGISTERED (admin)
        Hash0 : EventHash = SHA256(Event #0)
        Sig0 : Chữ Ký Ed25519 Hệ Thống
    }

    state "Sự Kiện #1 (Lưu Trữ Hồ Sơ)" as E1 {
        PrevHash1 : PrevHash = Hash(Event #0)
        Action1 : DOCUMENT_STORED_ENCRYPTED
        Hash1 : EventHash = SHA256(Event #1)
        Sig1 : Chữ Ký Ed25519 Hệ Thống
    }

    state "Sự Kiện #2 (Giải Mã Hồ Sơ)" as E2 {
        PrevHash2 : PrevHash = Hash(Event #1)
        Action2 : DOCUMENT_DECRYPTED
        Hash2 : EventHash = SHA256(Event #2)
        Sig2 : Chữ Ký Ed25519 Hệ Thống
    }

    E0 --> E1 : Liên kết băm SHA-256
    E1 --> E2 : Liên kết băm SHA-256
```

---

### 5.6. Lộ Trình Kháng Lượng Tử Lai (Post-Quantum Hybrid Architecture)

Nhằm phòng chống mối đe dọa **"Harvest Now, Decrypt Later"** (Thu thập dữ liệu hôm nay, chờ máy tính lượng tử trong tương lai giải mã), hệ thống đã thiết kế sẵn kiến trúc đàm phán khóa lai kết hợp ECC và thuật toán Hậu Lượng tử (PQC):

```mermaid
flowchart TD
    InputData[Dữ Liệu Bắt Tay Kênh Truyền] --> ECCKEM[ECC Cổ Điển: X25519]
    InputData --> PQCKEM[PQC Kháng Lượng Tử: ML-KEM-768 / Kyber]

    ECCKEM --> Shared1[Khóa Bí Mật Chung 1]
    PQCKEM --> Shared2[Khóa Bí Mật Chung 2]

    Shared1 & Shared2 --> HybridKDF[Hàm Dẫn Xuất Khóa Lai HKDF-SHA3]
    HybridKDF --> MasterSessionKey[Khóa Phiên Cuối Cùng Master Key]
    
    MasterSessionKey --> SessionCipher[Mã Hóa AES-256-GCM / ChaCha20]
```

---

## 🌐 6. Đặc Tả Kỹ Thuật Các Bộ Đường Cong Chuẩn

1. **NIST P-256 (`prime256v1` / `secp256r1`):**
   * *Đặc tả:* Đường cong dạng Weierstrass trên trường hữu hạn $\mathbb{F}_p$ với $p = 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1$.
   * *Tiêu chuẩn:* NIST FIPS 186-4, ANSI X9.62, SECG SEC 2.
   * *Ưu điểm:* Hỗ trợ tăng tốc phần cứng rộng rãi nhất (Apple Secure Enclave, Android StrongBox TPM, Smart Card).
   * *Ứng dụng:* Chứng chỉ số SSL/TLS X.509, WebAuthn/FIDO2 (Passkeys), hệ thống ngân hàng tuân thủ PCI-DSS/FIPS.

2. **Ed25519 (Twisted Edwards Curve):**
   * *Phương trình:* $-x^2 + y^2 = 1 - \frac{121665}{121666} x^2 y^2$ trên trường $\mathbb{F}_{2^{255}-19}$.
   * *Tiêu chuẩn:* RFC 8032 / IETF.
   * *Ưu điểm:* Constant-time tự nhiên, miễn nhiễm tuyệt đối với tấn công Timing Attack, tốc độ xác minh cực nhanh, chữ ký cố định 64 bytes.
   * *Ứng dụng:* Chữ ký xác thực Microservices, SSH Keys, Token định danh EdDSA.

3. **Curve25519 / X25519 (Montgomery Curve):**
   * *Phương trình:* $y^2 = x^3 + 486662x^2 + x$ trên trường $\mathbb{F}_{2^{255}-19}$.
   * *Tiêu chuẩn:* RFC 7748 / IETF.
   * *Ưu điểm:* Tối ưu hóa cho phép trao đổi khóa Diffie-Hellman bằng Montgomery Ladder, chống Invalid-curve attack tự nhiên.
   * *Ứng dụng:* Giao thức mạng hiện đại TLS 1.3, WireGuard VPN, Signal Protocol.

4. **NIST P-384 (`secp384r1`):**
   * *Đặc tả:* Khóa 384 bits cung cấp mức bảo mật 192-bit.
   * *Tiêu chuẩn:* NSA Suite B Cryptography / CNSA (Commercial National Security Algorithm).
   * *Ứng dụng:* Quốc phòng, cơ quan chính phủ, bảo vệ dữ liệu tối mật (Top Secret).

5. **secp256k1 (Koblitz Curve):**
   * *Phương trình:* $y^2 = x^3 + 7 \pmod p$ với $p = 2^{256} - 2^{32} - 977$.
   * *Tiêu chuẩn:* SECG (Certicom).
   * *Ưu điểm:* Sử dụng số nguyên tố đặc biệt giúp tính toán modulo nhanh hơn, không có nghi vấn về seed ẩn.
   * *Ứng dụng:* Mạng phân tán, Blockchain (Bitcoin, Ethereum).

---

## 🛡️ 7. Mô Hình Đe Dọa (Threat Model) & Giải Pháp Phòng Thủ

| Nguy Cơ Tấn Công | Cơ Chế Tấn Công Cổ Điển | Giải Pháp Phòng Vệ Trong VNU-IS_ECC |
| :--- | :--- | :--- |
| **Nonce Reuse Attack (Sony PS3 Exploit)** | Kẻ phát triển vô tình dùng cố định số ngẫu nhiên $k$ khi ký ECDSA, cho phép kẻ tấn công khôi phục hoàn toàn khóa riêng $d$ trong vài micro-giây. | Kích hoạt chuẩn **RFC 6979 Deterministic Nonce**: $k = HMAC(d, H(m))$ không bao giờ trùng lặp; hoặc chuyển sang **Ed25519** (không dùng số ngẫu nhiên khi ký). |
| **Side-Channel Timing Attack** | Kẻ tấn công đo thời gian thực thi của lệnh nhân đôi điểm và cộng điểm để đoán từng bit của khóa riêng. | Áp dụng **Curve25519 / Ed25519** với giải thuật **Montgomery Ladder**: thời gian thực thi hoàn toàn cố định (**Constant-Time**), độc lập với giá trị bit của private key. |
| **Invalid Curve Attack** | Kẻ tấn công gửi điểm $P'$ không nằm trên đường cong ban đầu để ép máy chủ tính toán trên nhóm con yếu có bậc nhỏ. | Bộ lọc **Point Validation Filter**: kiểm tra tính hợp lệ của tọa độ điểm nhận được, đảm bảo điểm thỏa mãn phương trình đường cong trước khi nhân vô hướng. |
| **Man-in-the-Middle (MITM)** | Nghe lén và tráo đổi khóa công khai trong quá trình bắt tay. | Sử dụng chữ ký số hoặc mTLS xác thực danh tính hai chiều; tích hợp **HKDF** phân tách không gian khóa theo ngữ cảnh phiên. |
| **Tampering Audit Logs** | Kẻ xâm nhập sửa đổi nội dung nhật ký hệ thống để xóa dấu vết tấn công. | **Tamper-Evident Hash Chain**: Mỗi sự kiện liên kết băm SHA-256 với sự kiện trước và được ký số Ed25519 của hệ thống. Thay đổi dù chỉ 1 ký tự sẽ làm gãy toàn bộ chuỗi. |

---

## 🚀 8. Hướng Dẫn Cài Đặt & Vận Hành Toàn Diện

### 8.1. Khởi Chạy Máy Chủ & Web Dashboard

#### Bước 1: Khởi động hệ thống
```bash
npm start
```
Terminal sẽ hiển thị banner thông số vận hành:
```text
================================================================
   🛡️  VNU-IS ECC: HỆ THỐNG THÔNG TIN AN TOÀN ECC v1.0.0
   Tác giả: Bùi Kim Ngân & Nguyễn Tuấn Minh (AIVN)
================================================================
[+] Web Dashboard UI:    http://localhost:3000
[+] API Base URL:        http://localhost:3000/api
[+] System Status API:   http://localhost:3000/api/system/status
[+] Benchmark API:       http://localhost:3000/api/benchmark
================================================================
```

#### Bước 2: Truy cập Web Dashboard
Mở trình duyệt truy cập: **`http://localhost:3000`** để trải nghiệm giao diện quản trị an ninh gồm 8 phân hệ chuyên biệt:
1. **🏛️ Tổng Quan Kiến Trúc:** Mô hình bảo mật 4 lớp và bảng tham chiếu đặc tả đường cong.
2. **🔑 Quản Lý Khóa (KMS):** Sinh cặp khóa P-256, Ed25519, X25519, xuất PEM/JWK, tính toán SHA-256 Fingerprint.
3. **🤝 Bắt Tay ECDHE (PFS):** Mô phỏng trực quan từng bước bắt tay Client <-> Server đàm phán khóa AES-256.
4. **✍️ Chữ Ký Số (Ed25519):** Ký số văn bản điện tử và thử nghiệm cơ chế phát hiện sửa đổi dữ liệu (Tampering Detection).
5. **📦 Kho Tài Liệu Mật (ECIES):** Mã hóa phong bì hồ sơ mật và giải mã bảo mật bằng Private Key.
6. **🔬 Phòng Thí Nghiệm Tấn Công:** Thực nghiệm toán học bẻ khóa rò rỉ Nonce PS3 và bộ lọc Point Validation.
7. **⚡ Benchmark Hiệu Năng:** Chạy đo lường thời gian thực thi mật mã trực tiếp trên CPU.
8. **📜 Nhật Ký Kiểm Toán:** Giám sát chuỗi Hash-Chain và kiểm định tính toàn vẹn 100%.

---

### 8.2. Chạy Bộ Kiểm Thử Tự Động (Automated Test Suites)

Hệ thống tích hợp bộ kiểm thử toàn diện không phụ thuộc thư viện ngoài (sử dụng Node.js built-in test runner):
```bash
npm test
```

Toàn bộ 15 kịch bản kiểm thử mật mã toán học và tích hợp REST API sẽ chạy và hoàn tất chỉ trong dưới 1 giây:
```text
✔ 1. Keypair generation across all supported curves (6.16ms)
✔ 2. ECDHE Key Exchange (X25519) with Perfect Forward Secrecy (2.70ms)
✔ 3. ECDHE Key Exchange (NIST P-256) (2.37ms)
✔ 4. ECIES Hybrid Encryption (X25519 + HKDF + AES-256-GCM) Encrypt/Decrypt (4.54ms)
✔ 5. Ed25519 Digital Signatures: Sign, verify and tamper detection (2.22ms)
✔ 6. ECDSA NIST P-256 (Deterministic Nonce RFC 6979) (2.83ms)
✔ 7. ECC-JWT Authentication (ES256 & EdDSA) (4.11ms)
✔ 8. Security Attacks Lab: Nonce Reuse Attack in ECDSA (0.63ms)
✔ 9. GET /api/system/status returns ONLINE and active curves (44.52ms)
✔ 10. POST /api/keys/generate creates valid keypairs (1.52ms)
✔ 11. POST /api/ecdh/handshake-simulation completes ECDHE handshake (3.09ms)
✔ 12. POST /api/ecies/encrypt and /decrypt flow (5.26ms)
✔ 13. POST /api/auth/login with seed account succeeds (58.44ms)
✔ 14. POST /api/audit/verify checks audit hash chain (1.84ms)
✔ 15. POST /api/attacks/nonce-reuse simulates exploit (1.20ms)

15 tests passed, 0 failed (100% SUCCESS)
```

---

### 8.3. Sử Dụng Bộ Công Cụ Dòng Lệnh Quản Trị (CLI)

Công cụ [`scripts/ecc_cli.js`](file:///M:/chia%20video/scripts/ecc_cli.js) cung cấp các thao tác mật mã nhanh chóng qua terminal:

```bash
# 1. Sinh cặp khóa Ed25519:
node scripts/ecc_cli.js keygen --curve ed25519

# 2. Sinh cặp khóa NIST P-256 (FIPS):
node scripts/ecc_cli.js keygen --curve prime256v1

# 3. Sinh cặp khóa trao đổi X25519:
node scripts/ecc_cli.js keygen --curve x25519

# 4. Mô phỏng bắt tay đàm phán khóa ECDHE:
node scripts/ecc_cli.js handshake --curve x25519

# 5. Ký số văn bản:
node scripts/ecc_cli.js sign "Phê duyệt giao dịch bảo mật cấp độ 5"

# 6. Chạy mô phỏng tấn công toán học bẻ khóa rò rỉ Nonce PS3:
node scripts/ecc_cli.js attack-demo

# 7. Chạy benchmark đo lường hiệu năng CPU:
node scripts/ecc_cli.js benchmark --iter 30
```

---

### 8.4. Script Mô Phỏng Toán Học (Python)

Script [`scripts/ecc_demo.py`](file:///M:/chia%20video/scripts/ecc_demo.py) minh họa trực quan các phép toán số học trường hữu hạn:
```bash
python scripts/ecc_demo.py
```
Output minh họa:
```text
=================================================================
   VNU-IS ECC: TOÁN HỌC ĐƯỜNG CONG ELLIPTIC
   Tác giả: Bùi Kim Ngân & Nguyễn Tuấn Minh (AIVN)
   Phương trình: y^2 = x^3 + 2x + 3 (mod 97)
=================================================================
[+] Điểm cơ sở (Generator Point G): (3, 6)

--- CÁC BỘI SỐ CỦA G (k * G) ---
   1 * G = (3, 6)
   2 * G = (80, 10)
   3 * G = (80, 87)
   4 * G = (3, 91)
   5 * G = None

--- MÔ PHỎNG TRAO ĐỔI KHÓA ECDH (ALICE & BOB) ---
Alice: Private Key a = 7, Public Key A = a * G = (80, 10)
Bob:   Private Key b = 11, Public Key B = b * G = (3, 6)

Alice tính: S_Alice = a * B = (80, 10)
Bob tính:   S_Bob   = b * A = (80, 10)

[✓] Thành công: Cả hai bên đạt cùng bí mật chung S = (80, 10)
=================================================================
```

---

## 📡 9. Tài Liệu Chi Tiết RESTful API Reference

### 1. Trạng Thái Hệ Thống
* **Endpoint:** `GET /api/system/status`
* **Mô tả:** Lấy thông tin trạng thái hoạt động, OpenSSL engine và tác giả.
* **Curl Mẫu:**
  ```bash
  curl -X GET http://localhost:3000/api/system/status
  ```
* **Response Mẫu (200 OK):**
  ```json
  {
    "system": "VNU-IS ECC Information System",
    "status": "ONLINE",
    "nodeVersion": "v18.14.0",
    "engine": "OpenSSL 3.x Hardware Accelerated Cryptography",
    "supportedCurvesCount": 5,
    "authors": ["Bùi Kim Ngân", "Nguyễn Tuấn Minh"],
    "organization": "AIVN",
    "timestamp": "2026-11-09T12:20:00.000Z"
  }
  ```

---

### 2. Sinh Cặp Khóa ECC
* **Endpoint:** `POST /api/keys/generate`
* **Curl Mẫu:**
  ```bash
  curl -X POST http://localhost:3000/api/keys/generate \
    -H "Content-Type: application/json" \
    -d '{"curve": "ed25519"}'
  ```
* **Response Mẫu (200 OK):**
  ```json
  {
    "curve": "ed25519",
    "fingerprint": "SHA256:7f83b1657ff1fc53b92dc18148a1d65d...",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----\n",
    "privateKeyPem": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEI...\n-----END PRIVATE KEY-----\n",
    "createdAt": "2026-11-09T12:20:00.000Z"
  }
  ```

---

### 3. Bắt Tay Đàm Phán Khóa ECDHE
* **Endpoint:** `POST /api/ecdh/handshake-simulation`
* **Curl Mẫu:**
  ```bash
  curl -X POST http://localhost:3000/api/ecdh/handshake-simulation \
    -H "Content-Type: application/json" \
    -d '{"algorithm": "x25519"}'
  ```
* **Response Mẫu (200 OK):**
  ```json
  {
    "success": true,
    "algorithm": "x25519",
    "sharedSecretHex": "d4e2a8930bf41e0a29...",
    "derivedAesKeyHex": "b2c6a91724f8d93e1a0b3c5e7f9a2d4c...",
    "handshakeTimeMs": 2.85,
    "perfectForwardSecrecy": true
  }
  ```

---

### 4. Mã Hóa Lai ECIES & Giải Mã
* **Mã Hóa:** `POST /api/ecies/encrypt`
  ```bash
  curl -X POST http://localhost:3000/api/ecies/encrypt \
    -H "Content-Type: application/json" \
    -d '{
      "recipientPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
      "plaintext": "Thông điệp tuyệt mật cần bảo vệ",
      "associatedData": "CLASSIFICATION=TOP_SECRET",
      "curve": "x25519"
    }'
  ```
* **Giải Mã:** `POST /api/ecies/decrypt`
  ```bash
  curl -X POST http://localhost:3000/api/ecies/decrypt \
    -H "Content-Type: application/json" \
    -d '{
      "recipientPrivateKeyPem": "-----BEGIN PRIVATE KEY-----\n...",
      "envelope": { ... }
    }'
  ```

---

### 5. Ký Số & Xác Minh Chữ Ký
* **Ký Số:** `POST /api/signature/sign`
  ```bash
  curl -X POST http://localhost:3000/api/signature/sign \
    -H "Content-Type: application/json" \
    -d '{
      "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...",
      "data": "Hợp đồng chuyển tiền 1,000,000,000 VNĐ",
      "algorithm": "ed25519"
    }'
  ```
* **Xác Minh:** `POST /api/signature/verify`
  ```bash
  curl -X POST http://localhost:3000/api/signature/verify \
    -H "Content-Type: application/json" \
    -d '{
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
      "signature": "...",
      "data": "Hợp đồng chuyển tiền 1,000,000,000 VNĐ",
      "algorithm": "ed25519"
    }'
  ```

---

### 6. Xác Thực Người Dùng & Token ECC-JWT
* **Đăng Nhập:** `POST /api/auth/login`
  ```bash
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{
      "username": "admin",
      "password": "Admin@SecSys2026!",
      "jwtAlgorithm": "ES256"
    }'
  ```
  *(Tài khoản mặc định: `admin` / `Admin@SecSys2026!` hoặc `sec_officer` / `Officer@SecSys2026!`)*

---

### 7. Kiểm Tra Tính Toàn Vẹn Chuỗi Nhật Ký
* **Endpoint:** `POST /api/audit/verify`
* **Response Mẫu (200 OK):**
  ```json
  {
    "valid": true,
    "totalRecords": 8,
    "chainStatus": "Chuỗi nhật ký hoàn toàn nguyên vẹn, được bảo chứng bằng chữ ký Ed25519.",
    "systemSignerFingerprint": "SHA256:4a8c3d1e..."
  }
  ```

---

## 📊 10. Báo Cáo Hiệu Năng Thực Nghiệm (Benchmark Report)

Đo lường trực tiếp trên CPU máy chủ với 50 lần lặp liên tục:

| Chỉ Tiêu Đo Lường | RSA-2048 | RSA-3072 | NIST P-256 | Ed25519 / X25519 | Đánh Giá Tương Quan |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Sinh Cặp Khóa (KeyGen)** | 152.91 ms | 459.61 ms | **0.073 ms** | **0.068 ms** | **ECC nhanh hơn 6,700 lần** |
| **Ký Số (Signing)** | 0.697 ms | 1.758 ms | **0.043 ms** | **0.065 ms** | **ECC nhanh hơn 27 - 40 lần** |
| **Xác Minh (Verification)** | 0.024 ms | 0.047 ms | 0.070 ms | 0.111 ms | RSA verify nhanh do số mũ nhỏ $e=65537$ |
| **Kích Thước Khóa Công Khai** | 256 bytes | 384 bytes | 65 bytes | **32 bytes** | **Nhỏ hơn 12 lần** |
| **Kích Thước Khóa Riêng** | 1,190 bytes | 1,770 bytes | 32 bytes | **32 bytes** | **Nhỏ hơn 55 lần** |
| **Kích Thước Chữ Ký** | 256 bytes | 384 bytes | ~71 bytes | **64 bytes (Cố định)**| **Nhỏ hơn 6 lần** |

```
BIỂU ĐỒ SO SÁNH THỜI GIAN SINH KHÓA (Càng thấp càng tốt):
RSA-3072        [████████████████████████████████████████] 459.61 ms
RSA-2048        [█████████████                           ] 152.91 ms
NIST P-256      [▏                                       ]   0.07 ms
Ed25519/X25519  [▏                                       ]   0.07 ms (Nhanh hơn 6,700 lần!)
```

---

## 🏭 11. Hướng Dẫn Triển Khai Môi Trường Sản Xuất

### 11.1. Cấu hình Nginx Reverse Proxy với TLS 1.3 & Đường Cong Ưu Tiên
```nginx
server {
    listen 443 ssl http2;
    server_name secure.vnu-is.edu.vn;

    ssl_certificate /etc/ssl/certs/ecc-cert.pem;
    ssl_certificate_key /etc/ssl/private/ecc-key.pem;

    # Bắt buộc TLS 1.3 và cấu hình đường cong ưu tiên
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519:secp256r1:secp384r1;
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### 11.2. Khởi chạy bằng Quản lý Dịch vụ PM2
```bash
npm install -g pm2
pm2 start server.js --name "vnu-is-ecc-system" -i max
pm2 save
pm2 startup
```

---

## 📜 12. Bản Quyền & Trích Dẫn Khoa Học

Dự án này được phát triển phục vụ công tác nghiên cứu và triển khai hệ thống thông tin an toàn. Toàn bộ mã nguồn được cấp phép theo **[Giấy phép MIT](https://opensource.org/licenses/MIT)**.

### Trích Dẫn Học Thuật (BibTeX Citation):
```bibtex
@software{vnu_is_ecc_2026,
  author       = {Bui Kim Ngan and Nguyen Tuan Minh},
  title        = {VNU-IS_ECC: Production-Grade Elliptic Curve Cryptography Information System},
  year         = {2026},
  publisher    = {GitHub},
  journal      = {AIVN & VNU International School Research Repository},
  howpublished = {\url{https://github.com/bangmanhbac-max/VNU-IS_ECC}}
}
```

---

<div align="center">
  <sub>Bản quyền © 2026 thuộc về <b>Bùi Kim Ngân</b> & <b>Nguyễn Tuấn Minh</b> (AIVN / VNU-IS). Phát hành theo giấy phép MIT.</sub>
</div>
