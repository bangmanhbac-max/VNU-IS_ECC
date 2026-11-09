const crypto = require('crypto');
const KeyManager = require('./keyManager');

class ECDHExchange {
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

    static computeSharedSecret(myPrivateKey, peerPublicKey, infoContext = 'ecc-session-key-v1') {
        let peerKeyObj = peerPublicKey;
        if (typeof peerPublicKey === 'string') {
            peerKeyObj = KeyManager.importPublicKeyPem(peerPublicKey);
        }

        const rawSharedSecret = crypto.diffieHellman({
            privateKey: myPrivateKey,
            publicKey: peerKeyObj
        });

        const salt = crypto.createHash('sha256').update('ecc-secure-salt-2026').digest();
        const derivedKey = crypto.hkdfSync(
            'sha256',
            rawSharedSecret,
            salt,
            Buffer.from(infoContext, 'utf8'),
            32
        );

        return {
            rawSecretHex: rawSharedSecret.toString('hex'),
            derivedKeyHex: Buffer.from(derivedKey).toString('hex'),
            derivedKeyBuffer: Buffer.from(derivedKey)
        };
    }

    static simulateFullHandshake(algorithm = 'x25519') {
        const startTime = process.hrtime.bigint();

        const client = this.initiateSession(algorithm);
        const server = this.initiateSession(algorithm);

        const clientDerived = this.computeSharedSecret(client.privateKey, server.publicKeyPem, 'handshake-test');
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
