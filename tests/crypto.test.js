/**
 * crypto.test.js - Bộ kiểm thử tự động toàn diện cho các module Mật mã ECC
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');

const KeyManager = require('../src/crypto/keyManager');
const ECDHExchange = require('../src/crypto/ecdhExchange');
const ECIESHybrid = require('../src/crypto/eciesHybrid');
const DigitalSignature = require('../src/crypto/digitalSignature');
const JwtECC = require('../src/crypto/jwtEcc');
const AttackSimulator = require('../src/crypto/attackSimulator');

describe('ECC Core Cryptography Suite', () => {

    test('1. Keypair generation across all supported curves', () => {
        const curves = ['prime256v1', 'secp384r1', 'secp256k1', 'ed25519', 'x25519'];
        for (const curve of curves) {
            const pair = KeyManager.generateKeyPair(curve);
            assert.ok(pair.pem.publicKey.includes('PUBLIC KEY'), `Public key of ${curve} should be in PEM format`);
            assert.ok(pair.pem.privateKey.includes('PRIVATE KEY'), `Private key of ${curve} should be in PEM format`);
            assert.ok(pair.fingerprint.startsWith('SHA256:'), `Fingerprint of ${curve} should start with SHA256`);
        }
    });

    test('2. ECDHE Key Exchange (X25519) with Perfect Forward Secrecy', () => {
        const handshake = ECDHExchange.simulateFullHandshake('x25519');
        assert.strictEqual(handshake.success, true, 'Client and Server must derive identical Shared Secret');
        assert.strictEqual(handshake.derivedAesKeyHex.length, 64, 'Derived AES-256 key must be 32 bytes (64 hex chars)');
        assert.ok(handshake.handshakeTimeMs < 50, 'X25519 handshake should complete rapidly (< 50ms)');
    });

    test('3. ECDHE Key Exchange (NIST P-256)', () => {
        const handshake = ECDHExchange.simulateFullHandshake('prime256v1');
        assert.strictEqual(handshake.success, true, 'ECDH on P-256 must derive identical Shared Secret');
    });

    test('4. ECIES Hybrid Encryption (X25519 + HKDF + AES-256-GCM) Encrypt/Decrypt', () => {
        const recipient = KeyManager.generateKeyPair('x25519');
        const secretMessage = 'Top secret coordinates and system parameters 2026';
        const aad = 'doc_classification=TOP_SECRET';

        // Mã hóa
        const envelope = ECIESHybrid.encrypt(recipient.pem.publicKey, secretMessage, aad, 'x25519');
        assert.ok(envelope.ciphertextBase64, 'Ciphertext must exist');
        assert.strictEqual(envelope.curve, 'x25519');
        assert.strictEqual(envelope.ivHex.length, 24, 'AES-GCM IV must be 12 bytes (24 hex)');
        assert.strictEqual(envelope.authTagHex.length, 32, 'AES-GCM Auth Tag must be 16 bytes (32 hex)');

        // Giải mã thành công
        const decrypted = ECIESHybrid.decrypt(recipient.pem.privateKey, envelope, aad);
        assert.strictEqual(decrypted.plaintext, secretMessage, 'Decrypted plaintext must match original');

        // Thử giả mạo bản mã -> phát hiện lỗi xác thực
        const corruptedEnvelope = JSON.parse(JSON.stringify(envelope));
        corruptedEnvelope.ciphertextBase64 = Buffer.from('corrupted ciphertext payload').toString('base64');
        assert.throws(() => {
            ECIESHybrid.decrypt(recipient.pem.privateKey, corruptedEnvelope, aad);
        }, /Xác thực gói tin thất bại/);
    });

    test('5. Ed25519 Digital Signatures: Sign, verify and tamper detection', () => {
        const signer = KeyManager.generateKeyPair('ed25519');
        const document = 'Electronic contract transfer $5,000,000 USD';

        // Ký
        const signResult = DigitalSignature.signEd25519(signer.pem.privateKey, document);
        assert.strictEqual(signResult.algorithm, 'Ed25519');
        assert.strictEqual(signResult.signatureLengthBytes, 64, 'Ed25519 signature must always be exactly 64 bytes');

        // Xác thực hợp lệ
        const verifySuccess = DigitalSignature.verifyEd25519(signer.pem.publicKey, signResult.signatureHex, document);
        assert.strictEqual(verifySuccess.valid, true, 'Original document signature must verify');

        // Xác thực khi tài liệu bị sửa đổi (Tampered)
        const tamperedDocument = document + ' (MODIFIED TO $50,000,000 USD)';
        const verifyTampered = DigitalSignature.verifyEd25519(signer.pem.publicKey, signResult.signatureHex, tamperedDocument);
        assert.strictEqual(verifyTampered.valid, false, 'Tampered document must fail verification');
        assert.strictEqual(verifyTampered.tampered, true);
    });

    test('6. ECDSA NIST P-256 (Deterministic Nonce RFC 6979)', () => {
        const signer = KeyManager.generateKeyPair('prime256v1');
        const data = 'Electronic banking transaction record';

        const sig1 = DigitalSignature.signECDSA(signer.pem.privateKey, data);
        assert.ok(sig1.signatureHex.length > 100, 'Valid DER ASN.1 ECDSA signature');

        const verify = DigitalSignature.verifyECDSA(signer.pem.publicKey, sig1.signatureHex, data);
        assert.strictEqual(verify.valid, true, 'ECDSA P-256 signature must verify');
    });

    test('7. ECC-JWT Authentication (ES256 & EdDSA)', () => {
        const p256Signer = KeyManager.generateKeyPair('prime256v1');
        const edSigner = KeyManager.generateKeyPair('ed25519');

        const userPayload = { userId: 'u_101', role: 'admin', username: 'antigravity' };

        // 7.1 ES256 Token
        const es256Token = JwtECC.sign(userPayload, p256Signer.pem.privateKey, 'ES256', 3600);
        assert.strictEqual(es256Token.split('.').length, 3, 'JWT must have 3 parts: header.payload.signature');
        const es256Verified = JwtECC.verify(es256Token, p256Signer.pem.publicKey);
        assert.strictEqual(es256Verified.valid, true);
        assert.strictEqual(es256Verified.payload.username, 'antigravity');

        // 7.2 EdDSA Token
        const edToken = JwtECC.sign(userPayload, edSigner.pem.privateKey, 'EdDSA', 3600);
        const edVerified = JwtECC.verify(edToken, edSigner.pem.publicKey);
        assert.strictEqual(edVerified.valid, true);
        assert.strictEqual(edVerified.payload.role, 'admin');

        // 7.3 Token tampering
        const forgedToken = es256Token.substring(0, es256Token.length - 5) + 'AAAAA';
        assert.throws(() => {
            JwtECC.verify(forgedToken, p256Signer.pem.publicKey);
        }, /Chữ ký số của Token không hợp lệ/);
    });

    test('8. Security Attacks Lab: Nonce Reuse Attack in ECDSA', () => {
        const sim = AttackSimulator.simulateNonceReuseAttack();
        assert.strictEqual(sim.compromiseResult.success, true, 'Attacker must recover private key when nonce is reused');
        assert.strictEqual(
            sim.compromiseResult.originalPrivateKey,
            sim.compromiseResult.recoveredPrivateKey,
            'Recovered private key must match original private key'
        );
    });
});
