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
            iss: 'vnu-is-ecc-auth-system'
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
            signatureBuffer = crypto.sign('SHA256', Buffer.from(signingInput), {
                key: privKeyObj,
                dsaEncoding: 'ieee-p1363'
            });
        } else {
            throw new Error(`Thuật toán ${algorithm} không được hỗ trợ`);
        }

        const encodedSignature = this.base64UrlEncode(signatureBuffer);
        return `${signingInput}.${encodedSignature}`;
    }

    static verify(token, publicKey) {
        let pubKeyObj = publicKey;
        if (typeof publicKey === 'string') {
            pubKeyObj = KeyManager.importPublicKeyPem(publicKey);
        }

        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Token JWT không đúng định dạng');
        }

        const [encodedHeader, encodedPayload, encodedSignature] = parts;
        const signingInput = `${encodedHeader}.${encodedPayload}`;
        const signatureBuffer = this.base64UrlDecode(encodedSignature);

        const header = JSON.parse(this.base64UrlDecode(encodedHeader).toString('utf8'));
        const payload = JSON.parse(this.base64UrlDecode(encodedPayload).toString('utf8'));

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
            throw new Error('Chữ ký số của Token không hợp lệ');
        }

        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) {
            throw new Error('Token JWT đã hết hạn sử dụng');
        }

        return {
            valid: true,
            header,
            payload
        };
    }
}

module.exports = JwtECC;
