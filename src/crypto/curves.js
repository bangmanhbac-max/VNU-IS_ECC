const SUPPORTED_CURVES = {
    'prime256v1': {
        aliases: ['secp256r1', 'nistp256', 'P-256'],
        type: 'weierstrass',
        field: 'F_p',
        keySizeBits: 256,
        securityLevelBits: 128,
        standard: 'NIST FIPS 186-4 / SECG',
        description: 'Đường cong phổ biến nhất trong TPM, Secure Enclave, Smartcard và TLS 1.2/1.3.',
        recommendedFor: ['WebAuthn / Passkeys', 'TLS Certificates', 'Doanh nghiệp tuân thủ FIPS 140-3', 'Ngân hàng'],
        signatureAlgorithm: 'SHA256withECDSA',
        jwtAlgorithm: 'ES256'
    },
    'secp384r1': {
        aliases: ['nistp384', 'P-384'],
        type: 'weierstrass',
        field: 'F_p',
        keySizeBits: 384,
        securityLevelBits: 192,
        standard: 'NIST FIPS 186-4 / NSA Suite B (CNSA)',
        description: 'Mức bảo mật quân sự (Top Secret), chống thám mã cao cấp.',
        recommendedFor: ['Cơ quan chính phủ', 'Quốc phòng', 'Bảo vệ dữ liệu dài hạn'],
        signatureAlgorithm: 'SHA384withECDSA',
        jwtAlgorithm: 'ES384'
    },
    'secp256k1': {
        aliases: ['koblitz256'],
        type: 'koblitz',
        field: 'F_p',
        keySizeBits: 256,
        securityLevelBits: 128,
        standard: 'SECG (Certicom)',
        description: 'Đường cong Koblitz sử dụng số nguyên tố p = 2^256 - 2^32 - 977, tối ưu hóa phép nhân vô hướng.',
        recommendedFor: ['Blockchain (Bitcoin, Ethereum)', 'Hợp đồng thông minh', 'Hệ thống phi tập trung'],
        signatureAlgorithm: 'SHA256withECDSA',
        jwtAlgorithm: 'ES256K'
    },
    'ed25519': {
        aliases: ['Ed25519', 'edwards25519'],
        type: 'twisted-edwards',
        field: 'F_2^255-19',
        keySizeBits: 256,
        securityLevelBits: 128,
        standard: 'RFC 8032 / IETF',
        description: 'Thuật toán chữ ký số EdDSA. Constant-time tuyệt đối, chống timing attack, không cần CSPRNG khi ký.',
        recommendedFor: ['Microservices', 'Xác thực API', 'SSH Keys', 'Giao thức thời gian thực'],
        signatureAlgorithm: 'Ed25519',
        jwtAlgorithm: 'EdDSA'
    },
    'x25519': {
        aliases: ['Curve25519'],
        type: 'montgomery',
        field: 'F_2^255-19',
        keySizeBits: 256,
        securityLevelBits: 128,
        standard: 'RFC 7748 / IETF',
        description: 'Thuật toán đàm phán khóa ECDH trên đường cong Montgomery. Tốc độ cực cao, chống invalid-curve attack.',
        recommendedFor: ['Kênh truyền bảo mật TLS 1.3', 'WireGuard VPN', 'Signal Protocol'],
        signatureAlgorithm: null,
        jwtAlgorithm: null
    }
};

module.exports = {
    SUPPORTED_CURVES
};
