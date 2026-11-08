/**
 * jwtEcc.js - Triển khai chuẩn JSON Web Token (JWT - RFC 7519) sử dụng thuật toán ECC (ES256 & EdDSA)
 */

const crypto = require('crypto');
const KeyManager = require('./keyManager');

class JwtECC {
    static base64UrlEncode(strOrBuffer) {
        const buf = Buffer.isBuffer(strOrBuffer) ? strOrBuffer : Buffer.from(strOrBuffer, 'utf8');
        return buf.toString('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
    }

    static base64UrlDecode(str) {
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        return Buffer.from(base64, 'base64');
    }

    /**
     * Tạo JWT ký bằng thuật toán ES256 (NIST P-256) hoặc EdDSA (Ed25519)
     * @param {object} payload - Dữ liệu xác thực người dùng
     * @param {crypto.KeyObject | string} privateKey - Khóa riêng ECC
     * @param {'ES256' | 'EdDSA'} algorithm 
     * @param {number} expiresInSeconds - Thời gian sống của token
     */
    static sign(payload, privateKey, algorithm = 'ES256', expiresInSeconds = 3600) {
        let privKeyObj = privateKey;
        if (typeof privateKey === 'string') {
            privKeyObj = KeyManager.importPrivateKeyPem(privateKey);
        }

        const now = Math.floor(Date.now() / 1000);
        const fullPayload = {
            ...payload,
            iat: now,
            exp: now + expiresInSeconds,
            iss: 'ecc-secureguard-auth-system'
        };

        const header = {
            alg: algorithm,
            typ: 'JWT'
        };

        const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
        const encodedPayload = this.base64UrlEncode(JSON.stringify(fullPayload));
        const signingInput = `${encodedHeader}.${encodedPayload}`;

        let signatureBuffer;
        if (algorithm === 'EdDSA') {
            signatureBuffer = crypto.sign(null, Buffer.from(signingInput), privKeyObj);
        } else if (algorithm === 'ES256') {
            // Chuẩn JWA (RFC 7518): Chữ ký ES256 trong JWT phải là 64 bytes IEEE P1363 (r || s), không phải DER ASN.1
            signatureBuffer = crypto.sign('SHA256', Buffer.from(signingInput), {
                key: privKeyObj,
                dsaEncoding: 'ieee-p1363'
            });
        } else {
            throw new Error(`Thuật toán ${algorithm} không được hỗ trợ cho ECC-JWT`);
        }

        const encodedSignature = this.base64UrlEncode(signatureBuffer);
        return `${signingInput}.${encodedSignature}`;
    }

    /**
     * Xác thực và giải mã JWT
     * @param {string} token 
     * @param {crypto.KeyObject | string} publicKey 
     */
    static verify(token, publicKey) {
        let pubKeyObj = publicKey;
        if (typeof publicKey === 'string') {
            pubKeyObj = KeyManager.importPublicKeyPem(publicKey);
        }

        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Token JWT không đúng định dạng 3 phần.');
        }

        const [encodedHeader, encodedPayload, encodedSignature] = parts;
        const signingInput = `${encodedHeader}.${encodedPayload}`;
        const signatureBuffer = this.base64UrlDecode(encodedSignature);

        const header = JSON.parse(this.base64UrlDecode(encodedHeader).toString('utf8'));
        const payload = JSON.parse(this.base64UrlDecode(encodedPayload).toString('utf8'));

        // 1. Kiểm tra chữ ký mật mã
        let isValid = false;
        if (header.alg === 'EdDSA') {
            isValid = crypto.verify(null, Buffer.from(signingInput), pubKeyObj, signatureBuffer);
        } else if (header.alg === 'ES256') {
            isValid = crypto.verify('SHA256', Buffer.from(signingInput), {
                key: pubKeyObj,
                dsaEncoding: 'ieee-p1363'
            }, signatureBuffer);
        } else {
            throw new Error(`Thuật toán header.alg ${header.alg} không được hỗ trợ`);
        }

        if (!isValid) {
            throw new Error('Chữ ký số của Token không hợp lệ! Token có thể đã bị giả mạo.');
        }

        // 2. Kiểm tra thời hạn (exp)
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) {
            throw new Error('Token JWT đã hết hạn sử dụng (Expired Token).');
        }

        return {
            valid: true,
            header,
            payload
        };
    }
}

module.exports = JwtECC;
