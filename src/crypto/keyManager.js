/**
 * keyManager.js - Module quản lý vòng đời khóa ECC (Generation, Export, Import, Fingerprint)
 */

const crypto = require('crypto');
const { SUPPORTED_CURVES } = require('./curves');

class KeyManager {
    /**
     * Sinh cặp khóa ECC dựa theo tên đường cong hoặc thuật toán
     * @param {string} curveName - 'prime256v1', 'secp384r1', 'secp256k1', 'ed25519', 'x25519'
     */
    static generateKeyPair(curveName = 'prime256v1') {
        const normalized = curveName.toLowerCase();

        let privateKey, publicKey;

        if (normalized === 'ed25519') {
            const pair = crypto.generateKeyPairSync('ed25519');
            privateKey = pair.privateKey;
            publicKey = pair.publicKey;
        } else if (normalized === 'x25519') {
            const pair = crypto.generateKeyPairSync('x25519');
            privateKey = pair.privateKey;
            publicKey = pair.publicKey;
        } else if (['prime256v1', 'secp256r1', 'p-256', 'secp384r1', 'p-384', 'secp256k1'].includes(normalized)) {
            let actualNamedCurve = normalized;
            if (normalized === 'p-256' || normalized === 'secp256r1') actualNamedCurve = 'prime256v1';
            if (normalized === 'p-384') actualNamedCurve = 'secp384r1';

            const pair = crypto.generateKeyPairSync('ec', {
                namedCurve: actualNamedCurve
            });
            privateKey = pair.privateKey;
            publicKey = pair.publicKey;
        } else {
            throw new Error(`Đường cong '${curveName}' không được hỗ trợ. Các lựa chọn: prime256v1, secp384r1, secp256k1, ed25519, x25519`);
        }

        const pemPublic = publicKey.export({ type: 'spki', format: 'pem' });
        const pemPrivate = privateKey.export({ type: 'pkcs8', format: 'pem' });
        const derPublic = publicKey.export({ type: 'spki', format: 'der' });
        const fingerprint = crypto.createHash('sha256').update(derPublic).digest('hex');

        // JWK export nếu là Node v18+
        let jwkPublic = null;
        try {
            jwkPublic = publicKey.export({ format: 'jwk' });
        } catch (e) {
            jwkPublic = null;
        }

        return {
            curve: curveName,
            keyObjects: { privateKey, publicKey },
            pem: {
                publicKey: pemPublic,
                privateKey: pemPrivate
            },
            raw: {
                publicKeyHex: derPublic.toString('hex')
            },
            jwk: jwkPublic,
            fingerprint: `SHA256:${fingerprint.substring(0, 32)}...`,
            fullFingerprint: fingerprint,
            createdAt: new Date().toISOString()
        };
    }

    /**
     * Nhập khóa công khai từ chuỗi PEM
     */
    static importPublicKeyPem(pemString) {
        return crypto.createPublicKey(pemString);
    }

    /**
     * Nhập khóa riêng từ chuỗi PEM
     */
    static importPrivateKeyPem(pemString) {
        return crypto.createPrivateKey(pemString);
    }

    /**
     * Tính toán Fingerprint chuẩn SHA-256 cho bất kỳ Public Key nào
     */
    static getPublicKeyFingerprint(publicKey) {
        const der = publicKey.export({ type: 'spki', format: 'der' });
        return crypto.createHash('sha256').update(der).digest('hex');
    }
}

module.exports = KeyManager;
