# Sơ Đồ & Thiết Kế Kiến Trúc Hệ Thống Thông Tin An Toàn ECC-SecureGuard

Tài liệu này mô tả chi tiết kiến trúc tầng, mô hình đe dọa (Threat Model), luồng dữ liệu mật mã, và cơ chế phòng ngự của hệ thống **ECC-SecureGuard**.

---

## 1. Sơ Đồ Kiến Trúc Hệ Thống (Architecture Blueprint)

```mermaid
flowchart TD
    subgraph ClientZone ["Khu Vực Người Dùng & Thiết Bị (Client Zone)"]
        Browser["Trình Duyệt Web (Web Dashboard)"]
        Mobile["Mobile / IoT Client"]
        CLI["Công Cụ Dòng Lệnh (Admin CLI)"]
    end

    subgraph SecurityBoundary ["Biên Giới Bảo Mật & Cổng Vào (Ingress)"]
        LB["TLS 1.3 Termination (ECDHE-X25519)"]
        WAF["API Gateway / WAF (Xác thực JWT ES256/EdDSA)"]
    end

    subgraph CoreEngine ["Mô-đun Mật Mã Lõi (Core Cryptographic Engine)"]
        KMS["Key Management (P-256, Ed25519, X25519)"]
        ECDHE["ECDHE Engine (Perfect Forward Secrecy)"]
        ECIES["ECIES Engine (AES-256-GCM + HKDF)"]
        Signer["Digital Signer (Ed25519 / RFC 6979)"]
    end

    subgraph BusinessServices ["Các Dịch Vụ Nghiệp Vụ An Toàn"]
        AuthSvc["Auth Service (Identity & RBAC)"]
        VaultSvc["Vault Service (Mã hóa Lưu trữ Tài liệu)"]
        AuditSvc["Audit Service (Tamper-evident Hash Chain)"]
    end

    subgraph StorageLayer ["Lớp Lưu Trữ Dữ Liệu"]
        EncryptedDB[(Cơ Sở Dữ Liệu Mã Hóa ECIES)]
        ImmutableLogs[(Chuỗi Khối Nhật Ký Kiểm Toán)]
    end

    Browser -->|"TLS 1.3 (ECDHE-X25519)"| LB
    Mobile -->|"mTLS (Ed25519 Certs)"| LB
    CLI -->|"Local Crypto Engine"| CoreEngine

    LB --> WAF
    WAF --> AuthSvc
    WAF --> VaultSvc
    WAF --> AuditSvc

    AuthSvc <--> KMS
    AuthSvc <--> Signer
    VaultSvc <--> ECIES
    VaultSvc <--> Signer
    VaultSvc --> EncryptedDB
    AuditSvc <--> Signer
    AuditSvc --> ImmutableLogs
```

---

## 2. Luồng Dữ Liệu Mật Mã (Cryptographic Data Flows)

### 2.1. Luồng Bắt Tay Trao Đổi Khóa Phiên (ECDHE Flow)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (Alice)
    participant S as Server (Bob)

    C->>C: Sinh Ephemeral Key: priv_a, pub_A = a * G
    S->>S: Sinh Ephemeral Key: priv_b, pub_B = b * G
    
    C->>S: Gửi pub_A (32 bytes X25519)
    S->>C: Gửi pub_B (32 bytes X25519)
    
    C->>C: Tính S = a * pub_B = a * (b * G)
    S->>S: Tính S = b * pub_A = b * (a * G)
    
    Note over C,S: Bí mật chung S giống nhau hoàn toàn!
    
    C->>C: HKDF-SHA256(S) -> Sinh Session Key K_aes (256-bit)
    S->>S: HKDF-SHA256(S) -> Sinh Session Key K_aes (256-bit)
    
    Note over C,S: Mọi gói tin sau đó được mã hóa bằng AES-256-GCM với K_aes
```

### 2.2. Luồng Mã Hóa Phong Bì Tài Liệu Mật (ECIES Envelope Encryption)

```mermaid
flowchart LR
    Doc[Tài liệu Bản Rõ] --> AESEnc[Mã hóa AES-256-GCM]
    Doc --> SignEd[Ký số Ed25519 của Tác Giả]
    
    EphKey[Khóa Tạm Ephemeral X25519] --> ECDH[ECDH với Khóa Công Khai Người Nhận]
    RecipientPub[Khóa Công Khai Người Nhận] --> ECDH
    ECDH --> HKDF[Hàm Dẫn Xuất Khóa HKDF-SHA256]
    HKDF --> AESKey[Khóa AES-256 Tạm Dùng 1 Lần]
    AESKey --> AESEnc
    
    AESEnc --> Ciphertext[Ciphertext]
    AESEnc --> AuthTag[16-byte Auth Tag]
    
    Ciphertext & AuthTag & SignEd & EphKey --> EncryptedPackage[Gói Tin Mật Mã Hóa ECIES]
```

---

## 3. Mô Hình Đe Dọa (Threat Model) & Giải Pháp Phòng Thủ

| Nguy Cơ Tấn Công | Điểm Yếu Tiềm Ẩn Cổ Điển | Cơ Chế Phòng Ngự Trong ECC-SecureGuard |
| :--- | :--- | :--- |
| **Kẻ đứng giữa (Man-in-the-Middle - MITM)** | Nghe lén và tráo đổi khóa trong lúc bắt tay trao đổi khóa | Khóa công khai trao đổi được bảo chứng qua chữ ký số hoặc chứng chỉ mTLS đã xác thực. |
| **Lộ khóa trong tương lai (Future Key Compromise)** | Kẻ tấn công ghi lại lưu lượng hôm nay, chờ lộ khóa Master Key để giải mã | Bắt buộc dùng **ECDHE (Ephemeral)**: Mỗi phiên dùng một cặp khóa dùng-một-lần, bảo đảm **Perfect Forward Secrecy**. |
| **Tái sử dụng Nonce (Nonce Reuse - Sony PS3 Attack)** | Bộ sinh số ngẫu nhiên bị lỗi lặp lại nonce $k$ khi ký ECDSA | Kích hoạt **RFC 6979 Deterministic Nonce** hoặc chuyển hẳn sang **Ed25519** (loại bỏ hoàn toàn bộ sinh ngẫu nhiên khi ký). |
| **Tấn công Kênh Kề (Timing & Power Side-Channel)** | Thời gian tính toán phụ thuộc vào số bit 0 hoặc 1 của private key | Toàn bộ phép toán trên **Curve25519 / Ed25519** được triển khai theo nguyên tắc **Constant-Time** (thời gian thực thi độc lập với dữ liệu bí mật). |
| **Invalid Curve / Small Subgroup Attack** | Gửi điểm $P'$ không thuộc đường cong để ép server tính toán trên nhóm con nhỏ | **Point Validation Filter:** Kiểm tra tọa độ điểm thỏa mãn phương trình đường cong trước khi thực hiện phép nhân vô hướng. |
| **Sửa đổi trái phép Nhật ký kiểm toán** | Kẻ xâm nhập xóa hoặc sửa bản ghi log để che giấu vết tích | **Tamper-Evident Hash Chain:** Mỗi sự kiện liên kết băm SHA-256 với sự kiện trước và được ký số Ed25519 của hệ thống. Bất kỳ sửa đổi 1 ký tự nào cũng làm gãy toàn bộ chuỗi. |
