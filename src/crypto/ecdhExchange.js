/**
 * ecdhExchange.js - Triển khai giao thức trao đổi khóa Diffie-Hellman đường cong Elliptic (ECDH & X25519)
 * Có tích hợp HKDF-SHA256 để dẫn xuất khóa phiên an toàn (PFS - Perfect Forward Secrecy)
 */

const crypto = require('crypto');
const KeyManager = require('./keyManager');

class ECDHExchange {
    /**
     * Khởi tạo phiên đàm phán bắt tay phía Client hoặc Server
     * @param {'x25519' | 'prime256v1'} algorithm 
     */
    static initiateSession(algorithm = 'x25519') {
        const keypair = KeyManager.generateKeyPair(algorithm);
        return {
            sessionId: crypto.randomBytes(16).toString('hex'),
            algorithm,
            privateKey: keypair.keyObjects.privateKey,
            publicKeyPem: keypair.pem.publicKey,
            createdAt: Date.now()
        };
    }

    /**
     * Tính toán khóa bí mật chung (Shared Secret) giữa khóa riêng của bên A và khóa công khai của bên B
     * @param {crypto.KeyObject} myPrivateKey 
     * @param {crypto.KeyObject | string} peerPublicKey 
     * @param {string} infoContext - Thông tin ngữ cảnh để HKDF phân tách không gian khóa
     */
    static computeSharedSecret(myPrivateKey, peerPublicKey, infoContext = 'ecc-session-key-v1') {
        let peerKeyObj = peerPublicKey;
        if (typeof peerPublicKey === 'string') {
            peerKeyObj = KeyManager.importPublicKeyPem(peerPublicKey);
        }

        // Thực hiện phép nhân vô hướng ECDH: S = a * B
        const rawSharedSecret = crypto.diffieHellman({
            privateKey: myPrivateKey,
            publicKey: peerKeyObj
        });

        // Áp dụng chuẩn HKDF (RFC 5869) với SHA-256 để tạo khóa phiên AES-256 đối xứng
        const salt = crypto.createHash('sha256').update('ecc-secure-salt-2026').digest();
        const derivedKey = crypto.hkdfSync(
            'sha256',
            rawSharedSecret,
            salt,
            Buffer.from(infoContext, 'utf8'),
            32 // 32 bytes = 256 bits cho AES-256
        );

        return {
            rawSecretHex: rawSharedSecret.toString('hex'),
            derivedKeyHex: Buffer.from(derivedKey).toString('hex'),
            derivedKeyBuffer: Buffer.from(derivedKey)
        };
    }

    /**
     * Mô phỏng quy trình bắt tay ECDHE 3 bước hoàn chỉnh giữa Client và Server
     */
    static simulateFullHandshake(algorithm = 'x25519') {
        const startTime = process.hrtime.bigint();

        // Bước 1: Client sinh Ephemeral Keypair (a, A = a*G)
        const client = this.initiateSession(algorithm);

        // Bước 2: Server sinh Ephemeral Keypair (b, B = b*G)
        const server = this.initiateSession(algorithm);

        // Bước 3: Trao đổi khóa công khai và tính Shared Secret
        // Client tính: S_client = a * B
        const clientDerived = this.computeSharedSecret(client.privateKey, server.publicKeyPem, 'handshake-test');

        // Server tính: S_server = b * A
        const serverDerived = this.computeSharedSecret(server.privateKey, client.publicKeyPem, 'handshake-test');

        const endTime = process.hrtime.bigint();
        const durationMs = Number(endTime - startTime) / 1_000_000;

        const isIdentical = clientDerived.derivedKeyHex === serverDerived.derivedKeyHex;

        return {
            success: isIdentical,
            algorithm,
            clientPublicKeyPreview: client.publicKeyPem.split('\n')[1],
            serverPublicKeyPreview: server.publicKeyPem.split('\n')[1],
            sharedSecretHex: clientDerived.rawSecretHex,
            derivedAesKeyHex: clientDerived.derivedKeyHex,
            handshakeTimeMs: Number(durationMs.toFixed(3)),
            perfectForwardSecrecy: true
        };
    }
}

module.exports = ECDHExchange;
