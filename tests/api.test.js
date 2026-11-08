/**
 * api.test.js - Kiểm thử tích hợp toàn bộ REST API của Hệ thống ECC (In-Memory Sandbox Friendly)
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { Readable } = require('stream');
const { app } = require('../server');

// Bộ giả lập HTTP Request/Response in-memory không cần mở Socket TCP
function callApi(method, url, body = null, headers = {}) {
    return new Promise((resolve, reject) => {
        const bodyStr = body ? JSON.stringify(body) : null;
        const req = new Readable({
            read() {}
        });

        if (bodyStr) {
            req.push(bodyStr);
        }
        req.push(null);

        req.method = method.toUpperCase();
        req.url = url;
        req.headers = {
            'content-type': 'application/json',
            'content-length': bodyStr ? Buffer.byteLength(bodyStr) : 0,
            'host': 'localhost',
            ...headers
        };

        const res = {
            statusCode: 200,
            _headers: {},
            setHeader(k, v) { this._headers[k.toLowerCase()] = v; },
            getHeader(k) { return this._headers[k.toLowerCase()]; },
            status(code) { this.statusCode = code; return this; },
            json(data) {
                resolve({ status: this.statusCode, data });
            },
            send(data) {
                let parsed = data;
                try { parsed = JSON.parse(data); } catch(e) {}
                resolve({ status: this.statusCode, data: parsed });
            },
            end(data) {
                if (data) {
                    try { resolve({ status: this.statusCode, data: JSON.parse(data) }); }
                    catch(e) { resolve({ status: this.statusCode, data }); }
                } else {
                    resolve({ status: this.statusCode, data: null });
                }
            }
        };

        app(req, res);
    });
}

describe('ECC REST API In-Memory Integration Suite', () => {

    test('1. GET /api/system/status returns ONLINE and active curves', async () => {
        const { status, data } = await callApi('GET', '/api/system/status');
        assert.strictEqual(status, 200);
        assert.strictEqual(data.status, 'ONLINE');
        assert.ok(data.supportedCurvesCount >= 5);
    });

    test('2. POST /api/keys/generate creates valid keypairs', async () => {
        const { status, data } = await callApi('POST', '/api/keys/generate', { curve: 'ed25519' });
        assert.strictEqual(status, 200);
        assert.strictEqual(data.curve, 'ed25519');
        assert.ok(data.publicKeyPem.includes('PUBLIC KEY'));
        assert.ok(data.fingerprint.startsWith('SHA256:'));
    });

    test('3. POST /api/ecdh/handshake-simulation completes ECDHE handshake', async () => {
        const { status, data } = await callApi('POST', '/api/ecdh/handshake-simulation', { algorithm: 'x25519' });
        assert.strictEqual(status, 200);
        assert.strictEqual(data.success, true);
        assert.strictEqual(data.perfectForwardSecrecy, true);
        assert.strictEqual(data.derivedAesKeyHex.length, 64);
    });

    test('4. POST /api/ecies/encrypt and /decrypt flow', async () => {
        // Sinh khóa người nhận
        const keyGen = await callApi('POST', '/api/keys/generate', { curve: 'x25519' });
        const pubPem = keyGen.data.publicKeyPem;
        const privPem = keyGen.data.privateKeyPem;

        // Mã hóa
        const plain = 'Testing API ECIES Hybrid Payload 2026';
        const encRes = await callApi('POST', '/api/ecies/encrypt', {
            recipientPublicKeyPem: pubPem,
            plaintext: plain,
            curve: 'x25519'
        });
        assert.strictEqual(encRes.status, 200);

        // Giải mã
        const decRes = await callApi('POST', '/api/ecies/decrypt', {
            recipientPrivateKeyPem: privPem,
            envelope: encRes.data
        });
        assert.strictEqual(decRes.status, 200);
        assert.strictEqual(decRes.data.plaintext, plain);
    });

    test('5. POST /api/auth/login with seed account succeeds', async () => {
        const { status, data } = await callApi('POST', '/api/auth/login', {
            username: 'admin',
            password: 'Admin@SecSys2026!',
            jwtAlgorithm: 'ES256'
        });
        assert.strictEqual(status, 200);
        assert.ok(data.token);
        assert.strictEqual(data.user.role, 'admin');
    });

    test('6. POST /api/audit/verify checks audit hash chain', async () => {
        const { status, data } = await callApi('POST', '/api/audit/verify', {});
        assert.strictEqual(status, 200);
        assert.strictEqual(data.valid, true);
        assert.ok(data.totalRecords >= 1);
    });

    test('7. POST /api/attacks/nonce-reuse simulates exploit', async () => {
        const { status, data } = await callApi('POST', '/api/attacks/nonce-reuse', {});
        assert.strictEqual(status, 200);
        assert.strictEqual(data.compromiseResult.success, true);
        assert.ok(data.mitigation.solution2.includes('Ed25519'));
    });
});
