const crypto = require('crypto');
const KeyManager = require('./keyManager');
const ECDHExchange = require('./ecdhExchange');

class ECIESHybrid {
    static encrypt(recipientPublicKeyPem, plaintext, associatedData = '', curve = 'x25519') {
        const plaintextBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
        const aadBuf = Buffer.isBuffer(associatedData) ? associatedData : Buffer.from(associatedData, 'utf8');

        const ephemeralKey = KeyManager.generateKeyPair(curve);

        const { derivedKeyBuffer } = ECDHExchange.computeSharedSecret(
            ephemeralKey.keyObjects.privateKey,
            recipientPublicKeyPem,
            'ecies-hybrid-encryption-v1'
        );

        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', derivedKeyBuffer, iv);

        if (aadBuf.length > 0) {
            cipher.setAAD(aadBuf);
        }

        const encrypted = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
        const authTag = cipher.getAuthTag();

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

    static decrypt(recipientPrivateKeyPem, encryptedEnvelope, associatedData = null) {
        let privKeyObj = recipientPrivateKeyPem;
        if (typeof recipientPrivateKeyPem === 'string') {
            privKeyObj = KeyManager.importPrivateKeyPem(recipientPrivateKeyPem);
        }

        const ephemeralPublicKeyPem = encryptedEnvelope.ephemeralPublicKeyPem;
        const iv = Buffer.from(encryptedEnvelope.ivHex, 'hex');
        const authTag = Buffer.from(encryptedEnvelope.authTagHex, 'hex');
        const ciphertext = Buffer.from(encryptedEnvelope.ciphertextBase64, 'base64');
        
        const aadString = associatedData !== null ? associatedData : (encryptedEnvelope.aadString || '');
        const aadBuf = Buffer.isBuffer(aadString) ? aadString : Buffer.from(aadString, 'utf8');

        const { derivedKeyBuffer } = ECDHExchange.computeSharedSecret(
            privKeyObj,
            ephemeralPublicKeyPem,
            'ecies-hybrid-encryption-v1'
        );

        const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKeyBuffer, iv);
        decipher.setAuthTag(authTag);

        if (aadBuf.length > 0) {
            decipher.setAAD(aadBuf);
        }

        try {
            const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            return {
                success: true,
                plaintext: decrypted.toString('utf8'),
                plaintextBuffer: decrypted
            };
        } catch (err) {
            throw new Error(`Xác thực gói tin thất bại! Dữ liệu đã bị giả mạo hoặc khóa giải mã không hợp lệ: ${err.message}`);
        }
    }
}

module.exports = ECIESHybrid;
