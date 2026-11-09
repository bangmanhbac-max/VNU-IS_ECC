const crypto = require('crypto');
const KeyManager = require('./keyManager');

class DigitalSignature {
    static signEd25519(privateKey, data) {
        let privKeyObj = privateKey;
        if (typeof privateKey === 'string') {
            privKeyObj = KeyManager.importPrivateKeyPem(privateKey);
        }

        const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
        const signature = crypto.sign(null, dataBuffer, privKeyObj);

        return {
            algorithm: 'Ed25519',
            signatureHex: signature.toString('hex'),
            signatureBase64: signature.toString('base64'),
            signatureLengthBytes: signature.length,
            signedAt: new Date().toISOString()
        };
    }

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

        const signatureDer = signer.sign({
            key: privKeyObj,
            dsaEncoding: 'der'
        });

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
