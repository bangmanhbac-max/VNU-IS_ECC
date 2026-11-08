/**
 * digitalSignature.js - Module Ký và Xác thực Chữ Ký Số ECC (Ed25519 & ECDSA P-256)
 */

const crypto = require('crypto');
const KeyManager = require('./keyManager');

class DigitalSignature {
    /**
     * Ký số thông điệp hoặc tài liệu bằng Ed25519
     * @param {crypto.KeyObject | string} privateKey - Khóa riêng Ed25519
     * @param {string | Buffer} data 
     */
    static signEd25519(privateKey, data) {
        let privKeyObj = privateKey;
        if (typeof privateKey === 'string') {
            privKeyObj = KeyManager.importPrivateKeyPem(privateKey);
        }

        const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');

        // Ed25519 ký trực tiếp trên dữ liệu (bên trong tự băm bằng SHA-512 theo RFC 8032)
        const signature = crypto.sign(null, dataBuffer, privKeyObj);

        return {
            algorithm: 'Ed25519',
            signatureHex: signature.toString('hex'),
            signatureBase64: signature.toString('base64'),
            signatureLengthBytes: signature.length, // Chuẩn 64 bytes
            signedAt: new Date().toISOString()
        };
    }

    /**
     * Xác thực chữ ký Ed25519
     */
    static verifyEd25519(publicKey, signature, data) {
        let pubKeyObj = publicKey;
        if (typeof publicKey === 'string') {
            pubKeyObj = KeyManager.importPublicKeyPem(publicKey);
        }

        const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
        const sigBuffer = Buffer.isBuffer(signature) 
            ? signature 
            : (signature.length === 128 ? Buffer.from(signature, 'hex') : Buffer.from(signature, 'base64'));

        try {
            const isValid = crypto.verify(null, dataBuffer, pubKeyObj, sigBuffer);
            return {
                valid: isValid,
                algorithm: 'Ed25519',
                tampered: !isValid
            };
        } catch (err) {
            return {
                valid: false,
                algorithm: 'Ed25519',
                tampered: true,
                error: err.message
            };
        }
    }

    /**
     * Ký số bằng ECDSA (NIST P-256 / prime256v1) sử dụng chuẩn SHA-256
     * Node.js OpenSSL 3.x sử dụng Deterministic Nonce (RFC 6979) để chống tấn công rò rỉ khóa do lặp nonce
     */
    static signECDSA(privateKey, data, curve = 'prime256v1') {
        let privKeyObj = privateKey;
        if (typeof privateKey === 'string') {
            privKeyObj = KeyManager.importPrivateKeyPem(privateKey);
        }

        const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
        const hashAlgo = curve === 'secp384r1' ? 'SHA384' : 'SHA256';

        const signer = crypto.createSign(hashAlgo);
        signer.update(dataBuffer);
        signer.end();

        // Chữ ký trả về định dạng chuẩn DER-encoded ASN.1 (r, s)
        const signatureDer = signer.sign({
            key: privKeyObj,
            dsaEncoding: 'der'
        });

        // Hashing checksum của tài liệu
        const dataHash = crypto.createHash(hashAlgo.toLowerCase()).update(dataBuffer).digest('hex');

        return {
            algorithm: `ECDSA-${hashAlgo}`,
            curve,
            documentHash: dataHash,
            signatureHex: signatureDer.toString('hex'),
            signatureBase64: signatureDer.toString('base64'),
            derLengthBytes: signatureDer.length,
            rfc6979Deterministic: true,
            signedAt: new Date().toISOString()
        };
    }

    /**
     * Xác thực chữ ký ECDSA
     */
    static verifyECDSA(publicKey, signature, data, curve = 'prime256v1') {
        let pubKeyObj = publicKey;
        if (typeof publicKey === 'string') {
            pubKeyObj = KeyManager.importPublicKeyPem(publicKey);
        }

        const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
        const sigBuffer = Buffer.isBuffer(signature) 
            ? signature 
            : (signature.length > 100 && !signature.includes('=') ? Buffer.from(signature, 'hex') : Buffer.from(signature, 'base64'));

        const hashAlgo = curve === 'secp384r1' ? 'SHA384' : 'SHA256';

        try {
            const verifier = crypto.createVerify(hashAlgo);
            verifier.update(dataBuffer);
            verifier.end();

            const isValid = verifier.verify({
                key: pubKeyObj,
                dsaEncoding: 'der'
            }, sigBuffer);

            return {
                valid: isValid,
                algorithm: `ECDSA-${hashAlgo}`,
                curve,
                tampered: !isValid
            };
        } catch (err) {
            return {
                valid: false,
                algorithm: `ECDSA-${hashAlgo}`,
                curve,
                tampered: true,
                error: err.message
            };
        }
    }
}

module.exports = DigitalSignature;
