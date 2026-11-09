const crypto = require('crypto');
const ECIESHybrid = require('../crypto/eciesHybrid');
const DigitalSignature = require('../crypto/digitalSignature');
const auditService = require('./auditService');

class VaultService {
    constructor() {
        this.documents = new Map();
    }

    storeDocument(title, content, classification, author, recipientPublicKeyPem) {
        const docId = `DOC-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
        
        const signatureObj = DigitalSignature.signEd25519(author.signingPrivateKeyPem, content);

        const aad = JSON.stringify({ docId, title, classification, author: author.username });
        const encryptedEnvelope = ECIESHybrid.encrypt(recipientPublicKeyPem, content, aad, 'x25519');

        const docRecord = {
            id: docId,
            title,
            classification,
            author: author.username,
            authorSignature: signatureObj.signatureHex,
            authorSignatureAlgo: signatureObj.algorithm,
            aad,
            encryptedEnvelope,
            createdAt: new Date().toISOString()
        };

        this.documents.set(docId, docRecord);

        auditService.logEvent('DOCUMENT_STORED_ENCRYPTED', author.username, {
            docId,
            title,
            classification,
            ciphertextSize: encryptedEnvelope.metadata.ciphertextSizeBytes
        });

        return {
            id: docId,
            title,
            classification,
            author: author.username,
            encryptedSummary: {
                algorithm: encryptedEnvelope.version,
                curve: encryptedEnvelope.curve,
                ivHex: encryptedEnvelope.ivHex,
                authTagHex: encryptedEnvelope.authTagHex,
                ciphertextSizeBytes: encryptedEnvelope.metadata.ciphertextSizeBytes
            },
            signatureHex: signatureObj.signatureHex,
            createdAt: docRecord.createdAt
        };
    }

    retrieveAndDecrypt(docId, recipientPrivateKeyPem, authorPublicKeyPem, actorUsername) {
        const docRecord = this.documents.get(docId);
        if (!docRecord) {
            throw new Error(`Không tìm thấy tài liệu có mã: ${docId}`);
        }

        const decryptResult = ECIESHybrid.decrypt(
            recipientPrivateKeyPem,
            docRecord.encryptedEnvelope,
            docRecord.aad
        );

        let signatureValid = false;
        if (authorPublicKeyPem) {
            const sigCheck = DigitalSignature.verifyEd25519(
                authorPublicKeyPem,
                docRecord.authorSignature,
                decryptResult.plaintext
            );
            signatureValid = sigCheck.valid;
        }

        auditService.logEvent('DOCUMENT_DECRYPTED', actorUsername, {
            docId,
            title: docRecord.title,
            signatureValid
        });

        return {
            id: docRecord.id,
            title: docRecord.title,
            classification: docRecord.classification,
            author: docRecord.author,
            decryptedContent: decryptResult.plaintext,
            signatureValid,
            signatureHex: docRecord.authorSignature,
            decryptedAt: new Date().toISOString()
        };
    }

    getAllDocumentsSummary() {
        return Array.from(this.documents.values()).map(doc => ({
            id: doc.id,
            title: doc.title,
            classification: doc.classification,
            author: doc.author,
            signatureAlgo: doc.authorSignatureAlgo,
            encryptionAlgo: doc.encryptedEnvelope.version,
            createdAt: doc.createdAt
        }));
    }
}

module.exports = new VaultService();
