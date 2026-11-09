const express = require('express');
const router = express.Router();

const { SUPPORTED_CURVES } = require('../crypto/curves');
const KeyManager = require('../crypto/keyManager');
const ECDHExchange = require('../crypto/ecdhExchange');
const ECIESHybrid = require('../crypto/eciesHybrid');
const DigitalSignature = require('../crypto/digitalSignature');
const AttackSimulator = require('../crypto/attackSimulator');
const CryptoBenchmark = require('../crypto/benchmark');

const authService = require('../services/authService');
const vaultService = require('../services/vaultService');
const auditService = require('../services/auditService');

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Yêu cầu Token Authorization (Bearer <token>)' });

    try {
        const decoded = authService.verifyToken(token);
        req.user = decoded.payload;
        next();
    } catch (err) {
        return res.status(403).json({ error: err.message });
    }
}

router.get('/system/status', (req, res) => {
    res.json({
        system: 'VNU-IS ECC Information System',
        status: 'ONLINE',
        nodeVersion: process.version,
        engine: 'OpenSSL 3.x Hardware Accelerated Cryptography',
        supportedCurvesCount: Object.keys(SUPPORTED_CURVES).length,
        authors: ['Bùi Kim Ngân', 'Nguyễn Tuấn Minh'],
        organization: 'AIVN',
        timestamp: new Date().toISOString()
    });
});

router.get('/curves', (req, res) => {
    res.json(SUPPORTED_CURVES);
});

router.post('/keys/generate', (req, res) => {
    try {
        const { curve = 'prime256v1' } = req.body;
        const keypair = KeyManager.generateKeyPair(curve);
        res.json({
            curve: keypair.curve,
            fingerprint: keypair.fingerprint,
            fullFingerprint: keypair.fullFingerprint,
            publicKeyPem: keypair.pem.publicKey,
            privateKeyPem: keypair.pem.privateKey,
            publicKeyHex: keypair.raw.publicKeyHex,
            jwk: keypair.jwk,
            createdAt: keypair.createdAt
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/ecdh/handshake-simulation', (req, res) => {
    try {
        const { algorithm = 'x25519' } = req.body;
        const result = ECDHExchange.simulateFullHandshake(algorithm);
        res.json(result);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/ecdh/compute-secret', (req, res) => {
    try {
        const { privateKeyPem, peerPublicKeyPem, context = 'api-key-exchange' } = req.body;
        if (!privateKeyPem || !peerPublicKeyPem) {
            return res.status(400).json({ error: 'Cần cung cấp đủ privateKeyPem và peerPublicKeyPem' });
        }
        const secret = ECDHExchange.computeSharedSecret(privateKeyPem, peerPublicKeyPem, context);
        res.json(secret);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/ecies/encrypt', (req, res) => {
    try {
        const { recipientPublicKeyPem, plaintext, associatedData = '', curve = 'x25519' } = req.body;
        if (!recipientPublicKeyPem || !plaintext) {
            return res.status(400).json({ error: 'Cần recipientPublicKeyPem và plaintext' });
        }
        const envelope = ECIESHybrid.encrypt(recipientPublicKeyPem, plaintext, associatedData, curve);
        res.json(envelope);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/ecies/decrypt', (req, res) => {
    try {
        const { recipientPrivateKeyPem, envelope, associatedData } = req.body;
        if (!recipientPrivateKeyPem || !envelope) {
            return res.status(400).json({ error: 'Cần recipientPrivateKeyPem và envelope' });
        }
        const result = ECIESHybrid.decrypt(recipientPrivateKeyPem, envelope, associatedData);
        res.json(result);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/signature/sign', (req, res) => {
    try {
        const { privateKeyPem, data, algorithm = 'ed25519' } = req.body;
        if (!privateKeyPem || !data) {
            return res.status(400).json({ error: 'Cần privateKeyPem và data' });
        }

        let result;
        if (algorithm.toLowerCase() === 'ed25519') {
            result = DigitalSignature.signEd25519(privateKeyPem, data);
        } else {
            result = DigitalSignature.signECDSA(privateKeyPem, data, 'prime256v1');
        }
        res.json(result);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/signature/verify', (req, res) => {
    try {
        const { publicKeyPem, signature, data, algorithm = 'ed25519' } = req.body;
        if (!publicKeyPem || !signature || !data) {
            return res.status(400).json({ error: 'Cần publicKeyPem, signature và data' });
        }

        let result;
        if (algorithm.toLowerCase() === 'ed25519') {
            result = DigitalSignature.verifyEd25519(publicKeyPem, signature, data);
        } else {
            result = DigitalSignature.verifyECDSA(publicKeyPem, signature, data, 'prime256v1');
        }
        res.json(result);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/auth/register', (req, res) => {
    try {
        const { username, password, fullName, role = 'user', preferredCurve = 'ed25519' } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Thiếu username hoặc password' });
        const user = authService.registerUser(username, password, fullName, role, preferredCurve);
        res.status(201).json(user);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/auth/login', (req, res) => {
    try {
        const { username, password, jwtAlgorithm = 'ES256' } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Thiếu username hoặc password' });
        const loginData = authService.login(username, password, jwtAlgorithm);
        res.json(loginData);
    } catch (err) {
        res.status(401).json({ error: err.message });
    }
});

router.get('/vault/documents', (req, res) => {
    res.json(vaultService.getAllDocumentsSummary());
});

router.post('/vault/documents', (req, res) => {
    try {
        const { title, content, classification = 'CONFIDENTIAL', authorUsername, recipientPublicKeyPem } = req.body;
        if (!title || !content || !authorUsername) {
            return res.status(400).json({ error: 'Thiếu thông tin tài liệu bắt buộc' });
        }

        const authorUser = authService.getUser(authorUsername);
        if (!authorUser) {
            return res.status(404).json({ error: `Không tìm thấy tác giả ${authorUsername}` });
        }

        const targetPubKey = recipientPublicKeyPem || authorUser.keys.encryption.publicKeyPem;

        const storedDoc = vaultService.storeDocument(
            title,
            content,
            classification,
            { username: authorUser.username, signingPrivateKeyPem: authorUser.keys.signing.privateKeyPem },
            targetPubKey
        );

        res.status(201).json(storedDoc);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/vault/documents/decrypt', (req, res) => {
    try {
        const { docId, recipientPrivateKeyPem, authorUsername, actorUsername = 'system' } = req.body;
        if (!docId || !recipientPrivateKeyPem) {
            return res.status(400).json({ error: 'Thiếu docId hoặc recipientPrivateKeyPem' });
        }

        let authorPubKey = null;
        if (authorUsername) {
            const author = authService.getUser(authorUsername);
            if (author) authorPubKey = author.keys.signing.publicKeyPem;
        }

        const decryptedDoc = vaultService.retrieveAndDecrypt(
            docId,
            recipientPrivateKeyPem,
            authorPubKey,
            actorUsername
        );

        res.json(decryptedDoc);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.get('/audit/logs', (req, res) => {
    res.json(auditService.getAllLogs());
});

router.post('/audit/verify', (req, res) => {
    const report = auditService.verifyChainIntegrity();
    res.json(report);
});

router.post('/attacks/nonce-reuse', (req, res) => {
    try {
        const result = AttackSimulator.simulateNonceReuseAttack();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.post('/attacks/invalid-curve', (req, res) => {
    try {
        const { pointHex = 'deadbeef12345678', curve = 'prime256v1' } = req.body;
        const result = AttackSimulator.validateCurvePoint(pointHex, curve);
        res.json(result);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.get('/benchmark', (req, res) => {
    try {
        const iterations = parseInt(req.query.iterations) || 30;
        const benchmarkData = CryptoBenchmark.runComparison(iterations);
        res.json(benchmarkData);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
