/**
 * app.js - Xử lý logic tương tác trên Web Dashboard ECC-SecureGuard
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. TABS NAVIGATION
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');

            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const content = document.getElementById(targetTab);
            if (content) content.classList.add('active');

            // Nạp dữ liệu khi chuyển tab nếu cần
            if (targetTab === 'audit') loadAuditLogs();
            if (targetTab === 'vault') loadVaultDocuments();
        });
    });

    // 2. KHỞI TẠO HỆ THỐNG
    initSystemStatus();
    loadCurvesReference();

    // Biến lưu trữ cặp khóa tạm thời trong phiên làm việc của giao diện
    let activeKeyPair = null;
    let lastSignedData = null;
    let lastSignature = null;
    let lastSigningKey = null;

    // --- TAB 1: SYSTEM STATUS & CURVES ---
    async function initSystemStatus() {
        try {
            const res = await fetch('/api/system/status');
            const data = await res.json();
            const badge = document.getElementById('systemStatusText');
            badge.textContent = `HỆ THỐNG TRỰC TUYẾN (${data.engine})`;
        } catch (err) {
            document.getElementById('systemStatusText').textContent = 'MẤT KẾT NỐI API';
            document.getElementById('systemStatusBadge').style.borderColor = 'var(--danger)';
        }
    }

    async function loadCurvesReference() {
        try {
            const res = await fetch('/api/curves');
            const curves = await res.json();
            const container = document.getElementById('curvesTableContainer');

            let html = `<table>
                <thead>
                    <tr>
                        <th>Đường Cong</th>
                        <th>Chuẩn Quy Định</th>
                        <th>Độ Dài Khóa</th>
                        <th>Mức Bảo Mật</th>
                        <th>Mô Tả & Khuyến Nghị</th>
                    </tr>
                </thead>
                <tbody>`;

            for (const [name, meta] of Object.entries(curves)) {
                html += `<tr>
                    <td><strong style="color: var(--primary);">${name}</strong><br><small style="color: var(--text-muted);">${meta.aliases.join(', ')}</small></td>
                    <td>${meta.standard}</td>
                    <td><code>${meta.keySizeBits} bits</code></td>
                    <td><span class="sys-badge" style="padding: 2px 8px; font-size: 0.75rem;">${meta.securityLevelBits}-bit</span></td>
                    <td style="font-size: 0.85rem;">
                        ${meta.description}
                        <div style="margin-top: 4px; color: var(--accent);"><strong>Ưu tiên:</strong> ${meta.recommendedFor.join(', ')}</div>
                    </td>
                </tr>`;
            }

            html += `</tbody></table>`;
            container.innerHTML = html;
        } catch (e) {
            console.error(e);
        }
    }

    // --- TAB 2: KEY STUDIO ---
    const btnGenerateKey = document.getElementById('btnGenerateKey');
    btnGenerateKey.addEventListener('click', async () => {
        const curve = document.getElementById('curveSelect').value;
        btnGenerateKey.textContent = '⏳ Đang sinh khóa...';
        btnGenerateKey.disabled = true;

        try {
            const res = await fetch('/api/keys/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ curve })
            });
            const data = await res.json();

            activeKeyPair = data;

            document.getElementById('keyGenResult').style.display = 'block';
            document.getElementById('resCurveName').textContent = data.curve;
            document.getElementById('resPubKeyPem').textContent = data.publicKeyPem;
            document.getElementById('resPrivKeyPem').textContent = data.privateKeyPem;
            document.getElementById('resFingerprint').textContent = data.fingerprint;
        } catch (err) {
            alert('Lỗi khi sinh khóa: ' + err.message);
        } finally {
            btnGenerateKey.textContent = '✨ Sinh Cặp Khóa ECC';
            btnGenerateKey.disabled = false;
        }
    });

    // --- TAB 3: ECDHE HANDSHAKE ---
    const btnRunHandshake = document.getElementById('btnRunHandshake');
    btnRunHandshake.addEventListener('click', async () => {
        const algorithm = document.getElementById('handshakeAlgoSelect').value;
        btnRunHandshake.textContent = '⏳ Đang bắt tay...';
        btnRunHandshake.disabled = true;

        try {
            const res = await fetch('/api/ecdh/handshake-simulation', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ algorithm })
            });
            const data = await res.json();

            document.getElementById('handshakeVisual').style.display = 'block';
            document.getElementById('hsClientPub').textContent = data.clientPublicKeyPreview;
            document.getElementById('hsServerPub').textContent = data.serverPublicKeyPreview;
            document.getElementById('hsSharedSecret').textContent = data.sharedSecretHex;
            document.getElementById('hsDerivedKey').textContent = data.derivedAesKeyHex;
            document.getElementById('hsTime').textContent = data.handshakeTimeMs;
        } catch (err) {
            alert('Lỗi bắt tay: ' + err.message);
        } finally {
            btnRunHandshake.textContent = '🚀 Bắt Đầu Bắt Tay ECDHE';
            btnRunHandshake.disabled = false;
        }
    });

    // --- TAB 4: DIGITAL SIGNATURES ---
    const btnSignData = document.getElementById('btnSignData');
    btnSignData.addEventListener('click', async () => {
        const data = document.getElementById('sigPayloadInput').value;
        const algorithm = document.getElementById('sigAlgoSelect').value;

        // Sinh cặp khóa ký tạm cho demo nếu chưa có
        btnSignData.textContent = '⏳ Đang ký...';
        btnSignData.disabled = true;

        try {
            const keyRes = await fetch('/api/keys/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ curve: algorithm })
            });
            lastSigningKey = await keyRes.json();

            const signRes = await fetch('/api/signature/sign', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    privateKeyPem: lastSigningKey.privateKeyPem,
                    data,
                    algorithm
                })
            });
            const sigResult = await signRes.json();

            lastSignedData = data;
            lastSignature = sigResult.signatureHex;

            document.getElementById('sigResultBox').style.display = 'block';
            document.getElementById('sigOutputHex').textContent = sigResult.signatureHex;
            document.getElementById('sigLength').textContent = sigResult.signatureLengthBytes || sigResult.derLengthBytes;

            // Đưa dữ liệu sang ô xác thực
            document.getElementById('verifyPayloadInput').value = data;
            document.getElementById('verifyResultAlert').style.display = 'none';
        } catch (err) {
            alert('Lỗi ký số: ' + err.message);
        } finally {
            btnSignData.textContent = '🖋️ Ký Số Ngay';
            btnSignData.disabled = false;
        }
    });

    const btnVerifySig = document.getElementById('btnVerifySig');
    btnVerifySig.addEventListener('click', async () => {
        if (!lastSignature || !lastSigningKey) {
            alert('Vui lòng thực hiện ký số trước khi xác thực!');
            return;
        }

        const data = document.getElementById('verifyPayloadInput').value;
        const algorithm = document.getElementById('sigAlgoSelect').value;

        try {
            const res = await fetch('/api/signature/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    publicKeyPem: lastSigningKey.publicKeyPem,
                    signature: lastSignature,
                    data,
                    algorithm
                })
            });
            const result = await res.json();

            const alertBox = document.getElementById('verifyResultAlert');
            alertBox.style.display = 'block';

            if (result.valid) {
                alertBox.className = 'alert alert-success';
                alertBox.innerHTML = `<span><strong>✓ XÁC THỰC THÀNH CÔNG!</strong> Chữ ký hợp lệ 100%. Dữ liệu nguyên vẹn tuyệt đối từ người ký.</span>`;
            } else {
                alertBox.className = 'alert alert-danger';
                alertBox.innerHTML = `<span><strong>✕ XÁC THỰC THẤT BẠI!</strong> Dữ liệu đã bị can thiệp hoặc chữ ký không khớp.</span>`;
            }
        } catch (err) {
            alert('Lỗi xác thực: ' + err.message);
        }
    });

    const btnTamperData = document.getElementById('btnTamperData');
    btnTamperData.addEventListener('click', () => {
        const input = document.getElementById('verifyPayloadInput');
        input.value += ' [ĐÃ BỊ HACKER SỬA ĐỔI TỌA ĐỘ VÀ SỐ TIỀN]';
        btnVerifySig.click();
    });

    // --- TAB 5: SECURE VAULT ---
    const btnStoreDoc = document.getElementById('btnStoreDoc');
    btnStoreDoc.addEventListener('click', async () => {
        const title = document.getElementById('docTitle').value;
        const classification = document.getElementById('docClassification').value;
        const content = document.getElementById('docContent').value;

        btnStoreDoc.textContent = '🔒 Đang mã hóa ECIES...';
        btnStoreDoc.disabled = true;

        try {
            const res = await fetch('/api/vault/documents', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title,
                    classification,
                    content,
                    authorUsername: 'admin'
                })
            });
            const data = await res.json();

            document.getElementById('docStoreResult').style.display = 'block';
            document.getElementById('docStoreJson').textContent = JSON.stringify(data, null, 2);

            loadVaultDocuments();
        } catch (err) {
            alert('Lỗi lưu trữ: ' + err.message);
        } finally {
            btnStoreDoc.textContent = '🔒 Mã Hóa ECIES & Lưu Trữ Vào Vault';
            btnStoreDoc.disabled = false;
        }
    });

    async function loadVaultDocuments() {
        try {
            const res = await fetch('/api/vault/documents');
            const docs = await res.json();
            const list = document.getElementById('vaultDocsList');

            if (docs.length === 0) {
                list.innerHTML = '<p style="color: var(--text-muted); font-size: 0.85rem;">Chưa có tài liệu nào trong kho.</p>';
                return;
            }

            let html = '';
            docs.forEach(doc => {
                html += `
                <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--border-color); border-radius: 8px; padding: 1rem; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-weight: 600; color: var(--text-main);">${doc.title}</div>
                        <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem;">
                            Mã: <code>${doc.id}</code> | Tác giả: <strong>${doc.author}</strong> | Phân loại: <span style="color: var(--warning);">${doc.classification}</span>
                        </div>
                    </div>
                    <button class="btn btn-secondary btn-decrypt" data-id="${doc.id}" style="padding: 0.4rem 0.85rem; font-size: 0.8rem;">
                        🔓 Giải Mã & Đọc
                    </button>
                </div>`;
            });

            list.innerHTML = html;

            document.querySelectorAll('.btn-decrypt').forEach(b => {
                b.addEventListener('click', async (e) => {
                    const docId = b.getAttribute('data-id');
                    decryptDocument(docId);
                });
            });
        } catch (e) {
            console.error(e);
        }
    }

    async function decryptDocument(docId) {
        try {
            // Lấy khóa riêng của user admin mặc định từ backend
            const loginRes = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: 'admin', password: 'Admin@SecSys2026!' })
            });
            const loginData = await loginRes.json();
            const privKeyPem = loginData.user.encryptionKeys.privateKeyPem;

            const res = await fetch('/api/vault/documents/decrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    docId,
                    recipientPrivateKeyPem: privKeyPem,
                    authorUsername: 'admin'
                })
            });
            const data = await res.json();

            const box = document.getElementById('decryptResultBox');
            box.style.display = 'block';
            document.getElementById('decryptedTitle').textContent = `📄 ${data.title} (${data.classification})`;
            document.getElementById('decryptedText').textContent = data.decryptedContent;
            document.getElementById('decryptedSigStatus').innerHTML = data.signatureValid 
                ? '<span style="color: var(--accent);">✓ Chữ ký số tác giả Ed25519 được xác thực hợp lệ!</span>'
                : '<span style="color: var(--danger);">✕ Cảnh báo: Chữ ký tác giả không hợp lệ!</span>';
        } catch (err) {
            alert('Lỗi giải mã: ' + err.message);
        }
    }

    // --- TAB 6: ATTACKS LAB ---
    const btnRunNonceAttack = document.getElementById('btnRunNonceAttack');
    btnRunNonceAttack.addEventListener('click', async () => {
        btnRunNonceAttack.textContent = '⏳ Đang giải toán khôi phục khóa...';
        btnRunNonceAttack.disabled = true;

        try {
            const res = await fetch('/api/attacks/nonce-reuse', { method: 'POST' });
            const data = await res.json();

            document.getElementById('nonceAttackResult').style.display = 'block';
            document.getElementById('atkTime').textContent = data.compromiseResult.timeTakenMicroseconds;
            document.getElementById('atkOriginalKey').textContent = data.compromiseResult.originalPrivateKey;
            document.getElementById('atkRecoveredKey').textContent = data.compromiseResult.recoveredPrivateKey;
        } catch (err) {
            alert('Lỗi mô phỏng: ' + err.message);
        } finally {
            btnRunNonceAttack.textContent = '⚡ Khởi Chạy Tấn Công Khôi Phục Private Key';
            btnRunNonceAttack.disabled = false;
        }
    });

    const btnTestPointValidation = document.getElementById('btnTestPointValidation');
    btnTestPointValidation.addEventListener('click', async () => {
        const pointHex = document.getElementById('pointInput').value;
        try {
            const res = await fetch('/api/attacks/invalid-curve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pointHex, curve: 'prime256v1' })
            });
            const data = await res.json();

            const alertBox = document.getElementById('pointValidationAlert');
            alertBox.style.display = 'block';

            if (data.isValid) {
                alertBox.className = 'alert alert-success';
                alertBox.textContent = '✓ ' + data.status;
            } else {
                alertBox.className = 'alert alert-danger';
                alertBox.textContent = '🛡️ ' + data.reason;
            }
        } catch (e) {
            alert(e.message);
        }
    });

    // --- TAB 7: BENCHMARK ---
    const btnRunBenchmark = document.getElementById('btnRunBenchmark');
    btnRunBenchmark.addEventListener('click', async () => {
        const iters = document.getElementById('benchIters').value;
        const loading = document.getElementById('benchLoading');
        const view = document.getElementById('benchResultsView');

        loading.style.display = 'block';
        view.style.display = 'none';
        btnRunBenchmark.disabled = true;

        try {
            const res = await fetch(`/api/benchmark?iterations=${iters}`);
            const data = await res.json();

            renderBenchmarkBars('chartKeyGen', data.keyGeneration, 'ms', true);
            renderBenchmarkBars('chartSigning', data.signing, 'ms', true);
            renderBenchmarkBars('chartVerify', data.verification, 'ms', true);
            renderSizesBars('chartSizes', data.sizes);

            loading.style.display = 'none';
            view.style.display = 'block';
        } catch (err) {
            alert('Lỗi benchmark: ' + err.message);
            loading.style.display = 'none';
        } finally {
            btnRunBenchmark.disabled = false;
        }
    });

    function renderBenchmarkBars(elementId, dataset, unit, isTime = true) {
        const el = document.getElementById(elementId);
        const values = Object.values(dataset);
        const maxVal = Math.max(...values, 0.001);

        let html = '';
        for (const [algo, val] of Object.entries(dataset)) {
            const pct = Math.max(2, (val / maxVal) * 100);
            const isEcc = algo.toLowerCase().includes('25519') || algo.toLowerCase().includes('p-256') || algo.toLowerCase().includes('ecdsa');
            const fillClass = isEcc ? 'fill-ecc' : 'fill-rsa';

            html += `
            <div class="bench-bar-container">
                <div class="bench-bar-label">
                    <span>${algo}</span>
                    <strong>${val} ${unit}</strong>
                </div>
                <div class="bench-bar-track">
                    <div class="bench-bar-fill ${fillClass}" style="width: ${pct}%;"></div>
                </div>
            </div>`;
        }
        el.innerHTML = html;
    }

    function renderSizesBars(elementId, sizesData) {
        const el = document.getElementById(elementId);
        let html = '';

        for (const [algo, sz] of Object.entries(sizesData)) {
            const isEcc = algo.toLowerCase().includes('25519') || algo.toLowerCase().includes('p-256');
            const badgeColor = isEcc ? 'var(--accent)' : 'var(--warning)';

            html += `
            <div style="background: rgba(255,255,255,0.03); border-radius: 6px; padding: 0.6rem; margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center; font-size: 0.85rem;">
                <div><strong>${algo}</strong></div>
                <div>
                    <span style="color: ${badgeColor};">Khóa: ${sz.publicKeyBytes} B</span> | 
                    <span style="color: var(--primary);">Chữ ký: ${sz.signatureBytes} B</span>
                </div>
            </div>`;
        }
        el.innerHTML = html;
    }

    // --- TAB 8: AUDIT TRAIL ---
    async function loadAuditLogs() {
        try {
            const res = await fetch('/api/audit/logs');
            const logs = await res.json();
            const tbody = document.getElementById('auditTableBody');

            if (logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">Chưa có bản ghi nhật ký nào.</td></tr>';
                return;
            }

            let html = '';
            logs.forEach(log => {
                html += `<tr>
                    <td><code>#${log.index}</code></td>
                    <td style="font-size: 0.8rem; color: var(--text-muted);">${log.timestamp.replace('T', ' ').substring(0, 19)}</td>
                    <td><strong style="color: var(--primary);">${log.action}</strong></td>
                    <td><code>${log.actor}</code></td>
                    <td><code style="font-size: 0.75rem;">${log.previousHash.substring(0, 16)}...</code></td>
                    <td><code style="font-size: 0.75rem; color: var(--accent);">${log.eventHash.substring(0, 16)}...</code></td>
                    <td><code style="font-size: 0.75rem; color: #a855f7;">${log.signatureHex.substring(0, 16)}...</code></td>
                </tr>`;
            });

            tbody.innerHTML = html;
        } catch (e) {
            console.error(e);
        }
    }

    const btnVerifyAuditChain = document.getElementById('btnVerifyAuditChain');
    btnVerifyAuditChain.addEventListener('click', async () => {
        try {
            const res = await fetch('/api/audit/verify', { method: 'POST' });
            const data = await res.json();

            const statusBox = document.getElementById('auditVerifyStatus');
            statusBox.style.display = 'block';

            if (data.valid) {
                statusBox.className = 'alert alert-success';
                statusBox.innerHTML = `<span><strong>✓ TOÀN VẸN 100%!</strong> ${data.chainStatus} (Đã xác minh ${data.totalRecords} bản ghi).</span>`;
            } else {
                statusBox.className = 'alert alert-danger';
                statusBox.innerHTML = `<span><strong>✕ PHÁT HIỆN CAN THIỆP!</strong> ${data.reason}</span>`;
            }
        } catch (err) {
            alert('Lỗi kiểm tra: ' + err.message);
        }
    });
});
