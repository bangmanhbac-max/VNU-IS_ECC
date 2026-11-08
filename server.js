/**
 * server.js - Điểm khởi chạy chính của Hệ Thống Thông Tin An Toàn ECC (ECC-SecureGuard)
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const apiRoutes = require('./src/routes/api');

const app = express();
const PORT = process.env.PORT || 3000;

// Cấu hình Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Phục vụ giao diện Web Dashboard trực quan
app.use(express.static(path.join(__dirname, 'public')));

// Gắn các API endpoints
app.use('/api', apiRoutes);

// Fallback phục vụ SPA Dashboard
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Khởi động Server khi chạy trực tiếp
if (require.main === module) {
    const server = app.listen(PORT, () => {
        console.log('================================================================');
        console.log('   🛡️  ECC-SECUREGUARD: HỆ THỐNG THÔNG TIN AN TOÀN ECC v1.0.0');
        console.log('================================================================');
        console.log(`[+] Web Dashboard UI:    http://localhost:${PORT}`);
        console.log(`[+] API Base URL:        http://localhost:${PORT}/api`);
        console.log(`[+] System Status API:   http://localhost:${PORT}/api/system/status`);
        console.log(`[+] Benchmark API:       http://localhost:${PORT}/api/benchmark`);
        console.log(`[+] Node.js Crypto:      OpenSSL 3.x Hardware Acceleration Active`);
        console.log(`[+] Hỗ trợ đường cong:   NIST P-256, P-384, secp256k1, Ed25519, X25519`);
        console.log('================================================================');
    });
}

module.exports = { app };
