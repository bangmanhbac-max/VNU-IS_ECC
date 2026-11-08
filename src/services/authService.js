/**
 * authService.js - Dịch vụ xác thực người dùng và phân quyền RBAC dựa trên ECC
 */

const crypto = require('crypto');
const KeyManager = require('../crypto/keyManager');
const JwtECC = require('../crypto/jwtEcc');
const auditService = require('./auditService');

class AuthService {
    constructor() {
        this.users = new Map();
        
        // Khóa định danh của Authorization Server (dùng ký JWT)
        this.jwtSignerP256 = KeyManager.generateKeyPair('prime256v1');
        this.jwtSignerEd25519 = KeyManager.generateKeyPair('ed25519');

        // Khởi tạo một tài khoản Quản trị viên mặc định
        this.seedInitialUsers();
    }

    seedInitialUsers() {
        this.registerUser('admin', 'Admin@SecSys2026!', 'Quản Trị Viên Hệ Thống', 'admin');
        this.registerUser('sec_officer', 'Officer@SecSys2026!', 'Cán Bộ An Toàn Thông Tin', 'officer');
        this.registerUser('alice', 'Alice@Secure2026!', 'Alice Specialist', 'user');
    }

    hashPassword(password, salt = null) {
        const actualSalt = salt || crypto.randomBytes(16).toString('hex');
        const hash = crypto.pbkdf2Sync(password, actualSalt, 100000, 64, 'sha512').toString('hex');
        return { hash, salt: actualSalt };
    }

    /**
     * Đăng ký người dùng mới, tự động sinh cặp khóa riêng / khóa công khai ECC cho người dùng
     */
    registerUser(username, password, fullName = '', role = 'user', preferredCurve = 'ed25519') {
        if (this.users.has(username)) {
            throw new Error(`Tên đăng nhập '${username}' đã tồn tại trong hệ thống.`);
        }

        const { hash, salt } = this.hashPassword(password);

        // Sinh cặp khóa định danh cá nhân cho người dùng (để ký và nhận tài liệu mã hóa ECIES)
        const userSigningKey = KeyManager.generateKeyPair(preferredCurve);
        const userEncryptionKey = KeyManager.generateKeyPair('x25519');

        const user = {
            id: `usr_${crypto.randomBytes(6).toString('hex')}`,
            username,
            passwordHash: hash,
            passwordSalt: salt,
            fullName: fullName || username,
            role,
            keys: {
                signing: {
                    curve: preferredCurve,
                    publicKeyPem: userSigningKey.pem.publicKey,
                    privateKeyPem: userSigningKey.pem.privateKey,
                    fingerprint: userSigningKey.fingerprint
                },
                encryption: {
                    curve: 'x25519',
                    publicKeyPem: userEncryptionKey.pem.publicKey,
                    privateKeyPem: userEncryptionKey.pem.privateKey,
                    fingerprint: userEncryptionKey.fingerprint
                }
            },
            createdAt: new Date().toISOString()
        };

        this.users.set(username, user);

        auditService.logEvent('USER_REGISTERED', username, {
            role,
            signingCurve: preferredCurve,
            encryptionCurve: 'x25519',
            fingerprint: userSigningKey.fingerprint
        });

        return {
            id: user.id,
            username: user.username,
            fullName: user.fullName,
            role: user.role,
            keys: {
                signingPublicKeyPem: user.keys.signing.publicKeyPem,
                signingFingerprint: user.keys.signing.fingerprint,
                encryptionPublicKeyPem: user.keys.encryption.publicKeyPem,
                encryptionFingerprint: user.keys.encryption.fingerprint
            }
        };
    }

    /**
     * Đăng nhập và cấp phát JWT ký bằng ES256 hoặc EdDSA
     */
    login(username, password, jwtAlgorithm = 'ES256') {
        const user = this.users.get(username);
        if (!user) {
            auditService.logEvent('LOGIN_FAILED', username, { reason: 'User not found' });
            throw new Error('Tài khoản hoặc mật khẩu không chính xác.');
        }

        const { hash } = this.hashPassword(password, user.passwordSalt);
        if (hash !== user.passwordHash) {
            auditService.logEvent('LOGIN_FAILED', username, { reason: 'Invalid password' });
            throw new Error('Tài khoản hoặc mật khẩu không chính xác.');
        }

        // Tạo JWT ký bằng khóa ECC của Server
        const payload = {
            sub: user.id,
            username: user.username,
            fullName: user.fullName,
            role: user.role,
            userSigningFingerprint: user.keys.signing.fingerprint
        };

        let token;
        if (jwtAlgorithm === 'EdDSA') {
            token = JwtECC.sign(payload, this.jwtSignerEd25519.keyObjects.privateKey, 'EdDSA', 3600);
        } else {
            token = JwtECC.sign(payload, this.jwtSignerP256.keyObjects.privateKey, 'ES256', 3600);
        }

        auditService.logEvent('LOGIN_SUCCESS', username, {
            jwtAlgorithm,
            role: user.role
        });

        return {
            token,
            algorithm: jwtAlgorithm,
            expiresIn: 3600,
            user: {
                id: user.id,
                username: user.username,
                fullName: user.fullName,
                role: user.role,
                signingKeys: user.keys.signing,
                encryptionKeys: user.keys.encryption
            }
        };
    }

    /**
     * Xác thực Token gửi lên từ Client
     */
    verifyToken(token) {
        try {
            // Thử xác thực với ES256 trước, nếu không được thử EdDSA
            try {
                return JwtECC.verify(token, this.jwtSignerP256.keyObjects.publicKey);
            } catch (e1) {
                return JwtECC.verify(token, this.jwtSignerEd25519.keyObjects.publicKey);
            }
        } catch (err) {
            throw new Error(`Token không hợp lệ: ${err.message}`);
        }
    }

    getUser(username) {
        return this.users.get(username);
    }
}

module.exports = new AuthService();
