const crypto = require('crypto');
const KeyManager = require('../crypto/keyManager');
const DigitalSignature = require('../crypto/digitalSignature');

class AuditService {
    constructor() {
        this.logs = [];
        this.systemSigner = KeyManager.generateKeyPair('ed25519');
        this.lastBlockHash = '0000000000000000000000000000000000000000000000000000000000000000';
    }

    logEvent(action, actor, details = {}) {
        const timestamp = new Date().toISOString();
        const eventIndex = this.logs.length;

        const eventData = {
            index: eventIndex,
            previousHash: this.lastBlockHash,
            timestamp,
            action,
            actor,
            details
        };

        const payloadToSign = JSON.stringify(eventData);
        const currentHash = crypto.createHash('sha256').update(payloadToSign).digest('hex');

        const signature = DigitalSignature.signEd25519(this.systemSigner.keyObjects.privateKey, payloadToSign);

        const auditEntry = {
            ...eventData,
            eventHash: currentHash,
            signatureHex: signature.signatureHex,
            signerPublicKeyFingerprint: this.systemSigner.fingerprint
        };

        this.logs.push(auditEntry);
        this.lastBlockHash = currentHash;

        return auditEntry;
    }

    verifyChainIntegrity() {
        let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';

        for (let i = 0; i < this.logs.length; i++) {
            const entry = this.logs[i];

            if (entry.previousHash !== prevHash) {
                return {
                    valid: false,
                    corruptedAtIndex: i,
                    reason: `Đứt gãy chuỗi băm tại bản ghi #${i}: previousHash không khớp!`
                };
            }

            const originalData = {
                index: entry.index,
                previousHash: entry.previousHash,
                timestamp: entry.timestamp,
                action: entry.action,
                actor: entry.actor,
                details: entry.details
            };

            const payloadToVerify = JSON.stringify(originalData);
            const recalculatedHash = crypto.createHash('sha256').update(payloadToVerify).digest('hex');

            if (recalculatedHash !== entry.eventHash) {
                return {
                    valid: false,
                    corruptedAtIndex: i,
                    reason: `Dữ liệu tại bản ghi #${i} đã bị sửa đổi trái phép!`
                };
            }

            const sigVerification = DigitalSignature.verifyEd25519(
                this.systemSigner.keyObjects.publicKey,
                entry.signatureHex,
                payloadToVerify
            );

            if (!sigVerification.valid) {
                return {
                    valid: false,
                    corruptedAtIndex: i,
                    reason: `Chữ ký số Ed25519 tại bản ghi #${i} không hợp lệ!`
                };
            }

            prevHash = entry.eventHash;
        }

        return {
            valid: true,
            totalRecords: this.logs.length,
            chainStatus: 'Chuỗi nhật ký hoàn toàn nguyên vẹn, được bảo chứng bằng chữ ký Ed25519.',
            systemSignerFingerprint: this.systemSigner.fingerprint
        };
    }

    getAllLogs() {
        return this.logs;
    }
}

module.exports = new AuditService();
