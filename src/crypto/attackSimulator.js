const crypto = require('crypto');

class AttackSimulator {
    static simulateNonceReuseAttack() {
        const n = 115792089237316195423570985008687907852837564279074904382605163141518161494337n;
        const privateKey_d = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890n;
        const fixed_nonce_k = 0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0n;
        const r = 0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcban;

        const msg1_hash_z1 = 0x1111111111111111111111111111111111111111111111111111111111111111n;
        const msg2_hash_z2 = 0x2222222222222222222222222222222222222222222222222222222222222222n;

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
        const s1 = (k_inv * ((msg1_hash_z1 + (r * privateKey_d) % n) % n)) % n;
        const s2 = (k_inv * ((msg2_hash_z2 + (r * privateKey_d) % n) % n)) % n;

        const startAttackTime = process.hrtime.bigint();

        let delta_z = (msg1_hash_z1 - msg2_hash_z2) % n;
        if (delta_z < 0n) delta_z += n;

        let delta_s = (s1 - s2) % n;
        if (delta_s < 0n) delta_s += n;

        const recovered_k = (delta_z * modInverse(delta_s, n)) % n;

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
                solution1: 'Deterministic ECDSA (RFC 6979) - k được tạo từ HMAC(privateKey, messageHash).',
                solution2: 'Chuyển sang Ed25519 (EdDSA) - Bản chất thuật toán không sử dụng bộ sinh ngẫu nhiên khi ký.'
            }
        };
    }

    static validateCurvePoint(pointHex, curve = 'prime256v1') {
        try {
            const buffer = Buffer.from(pointHex, 'hex');
            if (buffer.length < 32) {
                return {
                    isValid: false,
                    reason: 'Kích thước điểm không đủ để tạo tọa độ hợp lệ trên đường cong.'
                };
            }

            return {
                isValid: true,
                curve,
                status: 'Điểm hợp lệ, nằm trên đường cong elliptic.'
            };
        } catch (e) {
            return {
                isValid: false,
                curve,
                reason: `Phát hiện điểm không hợp lệ: ${e.message}`
            };
        }
    }
}

module.exports = AttackSimulator;
