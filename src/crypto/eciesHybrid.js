/**
 * eciesHybrid.js - Triển khai chuẩn Mã Hóa Lai ECIES (Elliptic Curve Integrated Encryption Scheme)
 * KEM: X25519 / NIST P-256
 * KDF: HKDF-SHA256
 * DEM: AES-256-GCM (AEAD với 96-bit IV và 128-bit Authentication Tag)
 */

const crypto = require('crypto');
const KeyManager = require('./keyManager');
const ECDHExchange = require('./ecdhExchange');

class ECIESHybrid {
    /**
     * Mã hóa thông điệp hoặc tài liệu bằng khóa công khai người nhận
     * @param {string | crypto.KeyObject} recipientPublicKeyPem 
     * @param {string | Buffer} plaintext 
     * @param {string | Buffer} associatedData - Dữ liệu xác thực đi kèm (AAD) không bị mã hóa nhưng được bảo vệ tính toàn vẹn
     * @param {'x25519' | 'prime256v1'} curve
     */
    static encrypt(recipientPublicKeyPem, plaintext, associatedData = '', curve = 'x25519') {
        const plaintextBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
        const aadBuf = Buffer.isBuffer(associatedData) ? associatedData : Buffer.from(associatedData, 'utf8');

        // 1. Sinh cặp khóa tạm thời (Ephemeral Keypair) của người gửi
        const ephemeralKey = KeyManager.generateKeyPair(curve);

        // 2. Tính Shared Secret và rút trích khóa đối xứng AES-256 thông qua HKDF
        const { derivedKeyBuffer } = ECDHExchange.computeSharedSecret(
            ephemeralKey.keyObjects.privateKey,
            recipientPublicKeyPem,
            'ecies-hybrid-encryption-v1'
        );

        // 3. Khởi tạo mã hóa đối xứng AES-256-GCM
        const iv = crypto.randomBytes(12); // Chuẩn NIST SP 800-38D: 12 bytes IV
        const cipher = crypto.createCipheriv('aes-256-gcm', derivedKeyBuffer, iv);

        if (aadBuf.length > 0) {
            cipher.setAAD(aadBuf);
        }

        const encrypted = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
        const authTag = cipher.getAuthTag(); // 16 bytes Authentication Tag chống giả mạo

        return {
            version: 'ECIES-AES256-GCM-v1',
            curve,
            ephemeralPublicKeyPem: ephemeralKey.pem.publicKey,
            ivHex: iv.toString('hex'),
            authTagHex: authTag.toString('hex'),
            ciphertextBase64: encrypted.toString('base64'),
            aadString: aadBuf.toString('utf8'),
            metadata: {
                plaintextSizeBytes: plaintextBuf.length,
                ciphertextSizeBytes: encrypted.length,
                encryptedAt: new Date().toISOString()
            }
        };
    }

    /**
     * Giải mã thông điệp bằng khóa riêng của người nhận
     * @param {string | crypto.KeyObject} recipientPrivateKeyPem 
     * @param {object} encryptedEnvelope 
     * @param {string | Buffer} associatedData 
     */
    static decrypt(recipientPrivateKeyPem, encryptedEnvelope, associatedData = null) {
        let privKeyObj = recipientPrivateKeyPem;
        if (typeof recipientPrivateKeyPem === 'string') {
            privKeyObj = KeyManager.importPrivateKeyPem(recipientPrivateKeyPem);
        }

        const ephemeralPublicKeyPem = encryptedEnvelope.ephemeralPublicKeyPem;
        const iv = Buffer.from(encryptedEnvelope.ivHex, 'hex');
        const authTag = Buffer.from(encryptedEnvelope.authTagHex, 'hex');
        const ciphertext = Buffer.from(encryptedEnvelope.ciphertextBase64, 'base64');
        
        // Sử dụng AAD từ envelope nếu không truyền vào riêng
        const aadString = associatedData !== null ? associatedData : (encryptedEnvelope.aadString || '');
        const aadBuf = Buffer.isBuffer(aadString) ? aadString : Buffer.from(aadString, 'utf8');

        // 1. Tái tạo Shared Secret từ Ephemeral Public Key nhận được
        const { derivedKeyBuffer } = ECDHExchange.computeSharedSecret(
            privKeyObj,
            ephemeralPublicKeyPem,
            'ecies-hybrid-encryption-v1'
        );

        // 2. Thiết lập bộ giải mã AES-256-GCM
        const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKeyBuffer, iv);
        decipher.setAuthTag(authTag);

        if (aadBuf.length > 0) {
            decipher.setAAD(aadBuf);
        }

        // 3. Giải mã và kiểm tra tính toàn vẹn (Authentication Tag)
        try {
            const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            return {
                success: true,
                plaintext: decrypted.toString('utf8'),
                plaintextBuffer: decrypted
            };
        } catch (err) {
            throw new Error(`Xác thực gói tin thất bại! Dữ liệu đã bị giả mạo hoặc khóa giải mã không hợp lệ (AEAD Tag Mismatch): ${err.message}`);
        }
    }
}

module.exports = ECIESHybrid;
