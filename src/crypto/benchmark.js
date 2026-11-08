/**
 * benchmark.js - Module đo lường và so sánh hiệu năng thực tế giữa ECC (P-256, Ed25519, X25519) và RSA (2048, 3072)
 */

const crypto = require('crypto');

class CryptoBenchmark {
    static runComparison(iterations = 50) {
        const payload = Buffer.from('Thử nghiệm đo lường hiệu năng mật mã hệ thống an toàn 2026 - Payload dữ liệu 1KB: ' + 'A'.repeat(950));

        const results = {
            iterations,
            hardware: {
                platform: process.platform,
                arch: process.arch,
                nodeVersion: process.version
            },
            keyGeneration: {},
            signing: {},
            verification: {},
            sizes: {}
        };

        // 1. BENCHMARK SINH KHÓA (Key Generation)
        // Ed25519
        let t0 = process.hrtime.bigint();
        for (let i = 0; i < iterations; i++) {
            crypto.generateKeyPairSync('ed25519');
        }
        let t1 = process.hrtime.bigint();
        results.keyGeneration['Ed25519 (256-bit)'] = Number(t1 - t0) / 1_000_000 / iterations;

        // X25519
        t0 = process.hrtime.bigint();
        for (let i = 0; i < iterations; i++) {
            crypto.generateKeyPairSync('x25519');
        }
        t1 = process.hrtime.bigint();
        results.keyGeneration['X25519 (256-bit)'] = Number(t1 - t0) / 1_000_000 / iterations;

        // NIST P-256
        t0 = process.hrtime.bigint();
        for (let i = 0; i < iterations; i++) {
            crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        }
        t1 = process.hrtime.bigint();
        results.keyGeneration['NIST P-256 (256-bit)'] = Number(t1 - t0) / 1_000_000 / iterations;

        // RSA-2048 (ít lần lặp hơn vì RSA sinh số nguyên tố rất chậm)
        const rsaIter = Math.min(iterations, 10);
        t0 = process.hrtime.bigint();
        for (let i = 0; i < rsaIter; i++) {
            crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        }
        t1 = process.hrtime.bigint();
        results.keyGeneration['RSA-2048'] = Number(t1 - t0) / 1_000_000 / rsaIter;

        // RSA-3072 (tương đương mức bảo mật 128-bit của P-256/Ed25519)
        const rsa3072Iter = Math.min(iterations, 5);
        t0 = process.hrtime.bigint();
        for (let i = 0; i < rsa3072Iter; i++) {
            crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
        }
        t1 = process.hrtime.bigint();
        results.keyGeneration['RSA-3072 (Chuẩn an toàn tương đương)'] = Number(t1 - t0) / 1_000_000 / rsa3072Iter;


        // 2. BENCHMARK KÝ & XÁC THỰC (Signing & Verification)
        const edPair = crypto.generateKeyPairSync('ed25519');
        const p256Pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const rsaPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const rsa3072Pair = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });

        // --- Ed25519 ---
        t0 = process.hrtime.bigint();
        let edSig;
        for (let i = 0; i < iterations * 5; i++) {
            edSig = crypto.sign(null, payload, edPair.privateKey);
        }
        t1 = process.hrtime.bigint();
        results.signing['Ed25519'] = Number(t1 - t0) / 1_000_000 / (iterations * 5);

        t0 = process.hrtime.bigint();
        for (let i = 0; i < iterations * 5; i++) {
            crypto.verify(null, payload, edPair.publicKey, edSig);
        }
        t1 = process.hrtime.bigint();
        results.verification['Ed25519'] = Number(t1 - t0) / 1_000_000 / (iterations * 5);

        // --- ECDSA P-256 ---
        t0 = process.hrtime.bigint();
        let p256Sig;
        for (let i = 0; i < iterations * 5; i++) {
            p256Sig = crypto.sign('SHA256', payload, p256Pair.privateKey);
        }
        t1 = process.hrtime.bigint();
        results.signing['ECDSA P-256'] = Number(t1 - t0) / 1_000_000 / (iterations * 5);

        t0 = process.hrtime.bigint();
        for (let i = 0; i < iterations * 5; i++) {
            crypto.verify('SHA256', payload, p256Pair.publicKey, p256Sig);
        }
        t1 = process.hrtime.bigint();
        results.verification['ECDSA P-256'] = Number(t1 - t0) / 1_000_000 / (iterations * 5);

        // --- RSA-2048 ---
        t0 = process.hrtime.bigint();
        let rsaSig;
        for (let i = 0; i < iterations * 2; i++) {
            rsaSig = crypto.sign('SHA256', payload, rsaPair.privateKey);
        }
        t1 = process.hrtime.bigint();
        results.signing['RSA-2048'] = Number(t1 - t0) / 1_000_000 / (iterations * 2);

        t0 = process.hrtime.bigint();
        for (let i = 0; i < iterations * 5; i++) {
            crypto.verify('SHA256', payload, rsaPair.publicKey, rsaSig);
        }
        t1 = process.hrtime.bigint();
        results.verification['RSA-2048'] = Number(t1 - t0) / 1_000_000 / (iterations * 5);

        // --- RSA-3072 ---
        t0 = process.hrtime.bigint();
        let rsa3072Sig;
        for (let i = 0; i < iterations * 2; i++) {
            rsa3072Sig = crypto.sign('SHA256', payload, rsa3072Pair.privateKey);
        }
        t1 = process.hrtime.bigint();
        results.signing['RSA-3072'] = Number(t1 - t0) / 1_000_000 / (iterations * 2);

        t0 = process.hrtime.bigint();
        for (let i = 0; i < iterations * 5; i++) {
            crypto.verify('SHA256', payload, rsa3072Pair.publicKey, rsa3072Sig);
        }
        t1 = process.hrtime.bigint();
        results.verification['RSA-3072'] = Number(t1 - t0) / 1_000_000 / (iterations * 5);

        // 3. SO SÁNH KÍCH THƯỚC KHÓA VÀ CHỮ KÝ
        results.sizes = {
            'Ed25519': {
                publicKeyBytes: 32,
                privateKeyBytes: 32,
                signatureBytes: edSig.length // 64
            },
            'NIST P-256': {
                publicKeyBytes: 65, // Uncompressed
                privateKeyBytes: 32,
                signatureBytes: p256Sig.length // ~71 DER
            },
            'RSA-2048': {
                publicKeyBytes: 256,
                privateKeyBytes: 1190,
                signatureBytes: rsaSig.length // 256
            },
            'RSA-3072': {
                publicKeyBytes: 384,
                privateKeyBytes: 1770,
                signatureBytes: rsa3072Sig.length // 384
            }
        };

        // Làm tròn số thập phân
        for (const cat of ['keyGeneration', 'signing', 'verification']) {
            for (const k in results[cat]) {
                results[cat][k] = Number(results[cat][k].toFixed(4));
            }
        }

        return results;
    }
}

module.exports = CryptoBenchmark;
