/**
 * auditService.js - Dịch vụ nhật ký kiểm toán bất biến (Tamper-evident Audit Trail)
 * Áp dụng chuỗi băm (Hash-chaining) và Chữ ký số Ed25519 cho mọi sự kiện bảo mật
 */

const crypto = require('crypto');
const KeyManager = require('../crypto/keyManager');
const DigitalSignature = require('../crypto/digitalSignature');

class AuditService {
    constructor() {
        this.logs = [];
        this.systemSigner = KeyManager.generateKeyPair('ed25519');
        this.lastBlockHash = '0000000000000000000000000000000000000000000000000000000000000000';
    }

    /**
     * Ghi nhận một sự kiện bảo mật vào nhật ký
     */
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

        // Ký số sự kiện bằng khóa Ed25519 của hệ thống
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

    /**
     * Kiểm tra tính toàn vẹn của toàn bộ chuỗi nhật ký (Auditing & Tamper Verification)
     */
    verifyChainIntegrity() {
        let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';

        for (let i = 0; i < this.logs.length; i++) {
            const entry = this.logs[i];

            // 1. Kiểm tra liên kết Hash Chain
            if (entry.previousHash !== prevHash) {
                return {
                    valid: false,
                    corruptedAtIndex: i,
                    reason: `Đứt gãy chuỗi băm tại bản ghi #${i}: previousHash không khớp!`
                };
            }

            // 2. Tái tạo dữ liệu gốc để kiểm tra chữ ký
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
                    reason: `Dữ liệu tại bản ghi #${i} đã bị sửa đổi trái phép (Hash mismatch)!`
                };
            }

            // 3. Xác thực chữ ký số Ed25519
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

// Singleton audit service
module.exports = new AuditService();
