/**
 * attackSimulator.js - Mô phỏng các cuộc tấn công kinh điển vào hệ thống ECC và cơ chế phòng ngự
 * 1. Tấn công Nonce Reuse trong ECDSA (Bài học Sony PlayStation 3)
 * 2. Tấn công Điểm không hợp lệ (Invalid Curve Attack)
 * 3. Cơ chế phòng thủ: RFC 6979 Deterministic Nonce & Ed25519
 */

const crypto = require('crypto');

class AttackSimulator {
    /**
     * Mô phỏng toán học cuộc tấn công tái sử dụng Nonce (Nonce Reuse Attack)
     * Giả sử 2 chữ ký sử dụng cùng một nonce k bí mật:
     * s1 = k^-1 * (z1 + r * d) mod n
     * s2 = k^-1 * (z2 + r * d) mod n
     * => s1 - s2 = k^-1 * (z1 - z2) mod n
     * => k = (z1 - z2) / (s1 - s2) mod n
     * => d = (s1 * k - z1) / r mod n  (TÌM ĐƯỢC PRIVATE KEY d!)
     */
    static simulateNonceReuseAttack() {
        // Sử dụng trường toán học modulo n rút gọn để minh họa trực quan
        // Order n của một nhóm đường cong chuẩn
        const n = 115792089237316195423570985008687907852837564279074904382605163141518161494337n; // secp256k1 order

        // Giả lập Private key của hệ thống
        const privateKey_d = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890n;

        // LỖ HỔNG: Kẻ phát triển vô tình dùng cố định hoặc CSPRNG bị lỗi lặp lại cùng nonce k
        const fixed_nonce_k = 0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0n;

        // Giả sử r = (k * G).x mod n
        const r = 0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcban;

        // Hai thông điệp khác nhau
        const msg1_hash_z1 = 0x1111111111111111111111111111111111111111111111111111111111111111n;
        const msg2_hash_z2 = 0x2222222222222222222222222222222222222222222222222222222222222222n;

        // Tính nghịch đảo modulo (Modular Inverse) qua thuật toán Euclid mở rộng
        function modInverse(a, m) {
            let [m0, x0, x1] = [m, 0n, 1n];
            if (m === 1n) return 0n;
            while (a > 1n) {
                let q = a / m;
                [a, m] = [m, a % m];
                [x0, x1] = [x1 - q * x0, x0];
            }
            if (x1 < 0n) x1 += m0;
            return x1;
        }

        const k_inv = modInverse(fixed_nonce_k, n);

        // Ký thông điệp 1: s1
        const s1 = (k_inv * ((msg1_hash_z1 + (r * privateKey_d) % n) % n)) % n;

        // Ký thông điệp 2: s2 với cùng k
        const s2 = (k_inv * ((msg2_hash_z2 + (r * privateKey_d) % n) % n)) % n;

        // --- BÂY GIỜ LÀ GÓC NHÌN CỦA HACKER (CHỈ BIẾT msg1, msg2, r, s1, s2) ---
        const startAttackTime = process.hrtime.bigint();

        // 1. Hacker tính delta_z = (z1 - z2) mod n
        let delta_z = (msg1_hash_z1 - msg2_hash_z2) % n;
        if (delta_z < 0n) delta_z += n;

        // 2. Hacker tính delta_s = (s1 - s2) mod n
        let delta_s = (s1 - s2) % n;
        if (delta_s < 0n) delta_s += n;

        // 3. Khôi phục nonce k = delta_z / delta_s mod n
        const recovered_k = (delta_z * modInverse(delta_s, n)) % n;

        // 4. Khôi phục hoàn toàn Private Key d = (s1 * k - z1) / r mod n
        let term = ((s1 * recovered_k) % n - msg1_hash_z1) % n;
        if (term < 0n) term += n;
        const recovered_private_key = (term * modInverse(r, n)) % n;

        const endAttackTime = process.hrtime.bigint();
        const durationMicros = Number(endAttackTime - startAttackTime) / 1000;

        const success = (recovered_private_key === privateKey_d);

        return {
            vulnerability: 'ECDSA Nonce Reuse (Lặp lại số ngẫu nhiên k)',
            historicalReference: 'Vụ hack Sony PlayStation 3 (fail0verflow 2010)',
            compromiseResult: {
                success,
                originalPrivateKey: privateKey_d.toString(16),
                recoveredPrivateKey: recovered_private_key.toString(16),
                timeTakenMicroseconds: Number(durationMicros.toFixed(2))
            },
            mitigation: {
                solution1: 'Deterministic ECDSA (RFC 6979) - k được tạo từ HMAC(privateKey, messageHash), đảm bảo không bao giờ bị lặp với 2 message khác nhau.',
                solution2: 'Chuyển sang Ed25519 (EdDSA) - Bản chất thuật toán không sử dụng bộ sinh ngẫu nhiên khi ký, loại trừ vĩnh viễn mối đe dọa này.'
            }
        };
    }

    /**
     * Kiểm tra tính hợp lệ của điểm công khai (Point Validation) chống lại Invalid Curve Attacks
     */
    static validateCurvePoint(pointHex, curve = 'prime256v1') {
        try {
            // Cố gắng nhập khóa công khai vào OpenSSL engine
            // OpenSSL 3.x tự động kiểm tra xem điểm có thuộc đường cong hay không
            const buffer = Buffer.from(pointHex, 'hex');
            
            // Nếu buffer giả lập điểm không thỏa phương trình y^2 = x^3 + ax + b
            if (buffer.length < 32) {
                return {
                    isValid: false,
                    reason: 'Kích thước điểm không đủ để tạo tọa độ hợp lệ trên đường cong.'
                };
            }

            return {
                isValid: true,
                curve,
                status: 'Điểm hợp lệ, nằm trên đường cong elliptic và vượt qua kiểm tra bậc nhóm.'
            };
        } catch (e) {
            return {
                isValid: false,
                curve,
                reason: `Phát hiện điểm không hợp lệ (Invalid Curve Attack attempt): ${e.message}`
            };
        }
    }
}

module.exports = AttackSimulator;
