#!/usr/bin/env node

const KeyManager = require('../src/crypto/keyManager');
const ECDHExchange = require('../src/crypto/ecdhExchange');
const ECIESHybrid = require('../src/crypto/eciesHybrid');
const DigitalSignature = require('../src/crypto/digitalSignature');
const AttackSimulator = require('../src/crypto/attackSimulator');
const CryptoBenchmark = require('../src/crypto/benchmark');

const [,, command, ...args] = process.argv;

function printUsage() {
    console.log(`
🛡️  VNU-IS ECC CLI - Bộ công cụ dòng lệnh Mật mã Đường cong Elliptic
Tác giả: Nguyễn Tuấn Minh (AIVN)

Sử dụng: node scripts/ecc_cli.js <lệnh> [tùy chọn]

Các lệnh khả dụng:
  keygen [--curve <name>]      Sinh cặp khóa ECC (prime256v1, secp384r1, ed25519, x25519)
  handshake [--curve <name>]   Mô phỏng bắt tay đàm phán khóa ECDHE (PFS)
  sign <text>                  Ký số chuỗi văn bản bằng Ed25519
  attack-demo                  Mô phỏng toán học bẻ khóa khi Nonce bị tái sử dụng (Sony PS3)
  benchmark [--iter <num>]     Chạy đo lường và so sánh hiệu năng trực tiếp giữa ECC và RSA
  help                         Hiển thị hướng dẫn này
`);
}

switch (command) {
    case 'keygen': {
        const curveIndex = args.indexOf('--curve');
        const curve = curveIndex !== -1 ? args[curveIndex + 1] : 'ed25519';
        console.log(`[+] Đang sinh cặp khóa cho đường cong: ${curve}...`);
        const pair = KeyManager.generateKeyPair(curve);
        console.log('\n--- KHÓA CÔNG KHAI (PUBLIC KEY) ---');
        console.log(pair.pem.publicKey);
        console.log('--- KHÓA RIÊNG (PRIVATE KEY) ---');
        console.log(pair.pem.privateKey);
        console.log(`Fingerprint: ${pair.fingerprint}\n`);
        break;
    }

    case 'handshake': {
        const curveIndex = args.indexOf('--curve');
        const curve = curveIndex !== -1 ? args[curveIndex + 1] : 'x25519';
        console.log(`[+] Đang mô phỏng bắt tay ECDHE Client <-> Server với ${curve}...`);
        const result = ECDHExchange.simulateFullHandshake(curve);
        console.log('\n[✓] Bắt tay thành công!');
        console.log(`- Thuật toán:                  ${result.algorithm}`);
        console.log(`- Thời gian thực thi:          ${result.handshakeTimeMs} ms`);
        console.log(`- Bí mật chung (Shared Secret): ${result.sharedSecretHex.substring(0, 32)}...`);
        console.log(`- Khóa phiên AES-256 (HKDF):   ${result.derivedAesKeyHex}`);
        console.log(`- Perfect Forward Secrecy:     ${result.perfectForwardSecrecy ? 'BẬT (Khóa tạm thời)' : 'TẮT'}\n`);
        break;
    }

    case 'sign': {
        const text = args.join(' ') || 'Thông điệp mặc định cần ký số bảo mật.';
        console.log(`[+] Tạo cặp khóa ký Ed25519 và ký dữ liệu: "${text}"...`);
        const signer = KeyManager.generateKeyPair('ed25519');
        const sig = DigitalSignature.signEd25519(signer.keyObjects.privateKey, text);
        console.log('\n[✓] Chữ ký Ed25519 được tạo:');
        console.log(`- Kích thước chữ ký: ${sig.signatureLengthBytes} bytes (chuẩn RFC 8032)`);
        console.log(`- Signature Hex:     ${sig.signatureHex}`);
        
        const verified = DigitalSignature.verifyEd25519(signer.keyObjects.publicKey, sig.signatureHex, text);
        console.log(`- Xác thực chữ ký:   ${verified.valid ? 'HỢP LỆ (ORIGINAL)' : 'KHÔNG HỢP LỆ'}\n`);
        break;
    }

    case 'attack-demo': {
        console.log('[+] Đang chạy mô phỏng tấn công Nonce-Reuse trong ECDSA...');
        const result = AttackSimulator.simulateNonceReuseAttack();
        console.log('\n============================================================');
        console.log(`Lỗ hổng:               ${result.vulnerability}`);
        console.log(`Sự kiện lịch sử:       ${result.historicalReference}`);
        console.log(`Tấn công thành công:   ${result.compromiseResult.success}`);
        console.log(`Thời gian khôi phục:   ${result.compromiseResult.timeTakenMicroseconds} microseconds`);
        console.log(`Khóa riêng ban đầu:    0x${result.compromiseResult.originalPrivateKey}`);
        console.log(`Khóa riêng bị tính ra: 0x${result.compromiseResult.recoveredPrivateKey}`);
        console.log('------------------------------------------------------------');
        console.log('GIẢI PHÁP PHÒNG THỦ:');
        console.log(`1. ${result.mitigation.solution1}`);
        console.log(`2. ${result.mitigation.solution2}`);
        console.log('============================================================\n');
        break;
    }

    case 'benchmark': {
        const iterIndex = args.indexOf('--iter');
        const iters = iterIndex !== -1 ? parseInt(args[iterIndex + 1]) : 20;
        console.log(`[+] Đang chạy benchmark mật mã (${iters} lần lặp)... Vui lòng đợi trong giây lát...`);
        const data = CryptoBenchmark.runComparison(iters);
        console.log('\n=================== BÁO CÁO HIỆU NĂNG MẬT MÃ ===================');
        console.log('1. TỐC ĐỘ SINH KHÓA (Key Generation Time - Càng thấp càng tốt):');
        for (const [k, v] of Object.entries(data.keyGeneration)) {
            console.log(`   - ${k.padEnd(42)}: ${v} ms`);
        }
        console.log('\n2. TỐC ĐỘ KÝ (Signing Time):');
        for (const [k, v] of Object.entries(data.signing)) {
            console.log(`   - ${k.padEnd(42)}: ${v} ms`);
        }
        console.log('\n3. TỐC ĐỘ XÁC THỰC (Verification Time):');
        for (const [k, v] of Object.entries(data.verification)) {
            console.log(`   - ${k.padEnd(42)}: ${v} ms`);
        }
        console.log('\n4. KÍCH THƯỚC KHÓA & CHỮ KÝ (Bytes):');
        for (const [k, v] of Object.entries(data.sizes)) {
            console.log(`   - ${k.padEnd(16)}: PubKey = ${String(v.publicKeyBytes).padStart(4)} B, PrivKey = ${String(v.privateKeyBytes).padStart(4)} B, Chữ ký = ${String(v.signatureBytes).padStart(4)} B`);
        }
        console.log('================================================================\n');
        break;
    }

    default:
        printUsage();
        break;
}
