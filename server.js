const express = require('express');
const cors = require('cors');
const path = require('path');
const apiRoutes = require('./src/routes/api');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(express.static(path.join(__dirname, 'public')));

app.use('/api', apiRoutes);

app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log('================================================================');
        console.log('   🛡️  VNU-IS ECC: HỆ THỐNG THÔNG TIN AN TOÀN ECC v1.0.0');
        console.log('   Tác giả: Nguyễn Tuấn Minh (AIVN)');
        console.log('================================================================');
        console.log(`[+] Web Dashboard UI:    http://localhost:${PORT}`);
        console.log(`[+] API Base URL:        http://localhost:${PORT}/api`);
        console.log(`[+] System Status API:   http://localhost:${PORT}/api/system/status`);
        console.log(`[+] Benchmark API:       http://localhost:${PORT}/api/benchmark`);
        console.log('================================================================');
    });
}

module.exports = { app };
