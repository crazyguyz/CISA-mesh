/* GIAM-SAT v5.0.4 (Phase3 improvements): UI cho Watchlist IOC + Syslog device
   mapping/correlation + MITRE navigator export. Depends on dashboard.js helpers
   (showDetailModal, escapeHtml, showToast, t, escJs). */

// ================= WATCHLIST MANAGER =================
var _watchItems = [];

function openWatchlistManager() {
    showDetailModal('🛡 Watchlist (theo dõi IOC tự động → IOC-WATCH-001)',
        '<div style="font-size:12px;min-width:760px;" id="watchlistRoot"></div>');
    fetch('/api/watchlist').then(function (r) { return r.json(); }).then(function (d) {
        _watchItems = d.items || [];
        renderWatchlistManager();
    }).catch(function () {
        var r = document.getElementById('watchlistRoot');
        if (r) r.innerHTML = '<div class="text-danger">Lỗi tải watchlist.</div>';
    });
}

function renderWatchlistManager() {
    var r = document.getElementById('watchlistRoot');
    if (!r) return;
    r.innerHTML =
        '<div class="row g-2 mb-2">' +
        '<div class="col-md-3"><input class="search-box" id="wlInd" placeholder="IOC: 1.2.3.4 / evil.com / sha256" style="width:100%;"></div>' +
        '<div class="col-md-1"><select id="wlType" style="background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);width:100%;font-size:11px;"><option>ip</option><option>domain</option><option>hash</option><option>url</option></select></div>' +
        '<div class="col-md-2"><input class="search-box" id="wlLabel" placeholder="Ghi chú" style="width:100%;"></div>' +
        '<div class="col-md-2"><select id="wlSev" style="background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);width:100%;font-size:11px;"><option>HIGH</option><option>CRITICAL</option><option>MEDIUM</option><option>LOW</option></select></div>' +
        '<div class="col-md-2"><button class="btn btn-sm btn-success w-100" onclick="addWatchItem()">+ Thêm</button></div>' +
        '<div class="col-md-2"><button class="btn btn-sm btn-warning w-100" onclick="toggleWatchImportBox()">Import text</button></div>' +
        '</div>' +
        '<textarea id="wlImportBox" style="display:none;width:100%;height:90px;background:#0a0f14;color:#d0d8e0;border:1px solid var(--border-color);" placeholder="Mỗi dòng 1 IOC (dòng # là comment)"></textarea>' +
        '<div class="mt-1 mb-2">' +
        '<button class="btn btn-sm btn-outline-light me-2" id="wlImportGo" style="display:none;" onclick="doWatchImport()">Nạp danh sách</button>' +
        '<button class="btn btn-sm btn-outline-warning" id="wlPush" style="display:none;" onclick="pushWatchIntel()">↧ Push vào intel file</button>' +
        '</div>' +
        '<table class="table table-sm table-striped" style="font-size:11px;"><thead><tr><th>Type</th><th>Indicator</th><th>Label</th><th>Severity</th><th>Source</th><th>Action</th></tr></thead><tbody id="wlBody"></tbody></table>' +
        '<div class="text-muted" style="font-size:10px;">Matcher quét events/network_inspection/sysmon mỗi 30s; mỗi IOC cảnh báo tối đa 1 lần/giờ (rule IOC-WATCH-001).</div>';
    renderWatchRows();
}

function renderWatchRows() {
    var b = document.getElementById('wlBody');
    if (!b) return;
    b.innerHTML = _watchItems.map(function (w) {
        var tcls = w.type === 'ip' ? 'bg-primary' : w.type === 'domain' ? 'bg-info' : w.type === 'hash' ? 'bg-secondary' : 'bg-dark';
        var scls = w.severity === 'CRITICAL' ? 'bg-danger' : w.severity === 'HIGH' ? 'bg-warning text-dark' : 'bg-secondary';
        return '<tr><td><span class="badge ' + tcls + '">' + escapeHtml(w.type) + '</span></td>' +
            '<td><code style="color:#88dd99;">' + escapeHtml(w.indicator) + '</code></td>' +
            '<td>' + escapeHtml(w.label || '') + '</td>' +
            '<td><span class="badge ' + scls + '">' + escapeHtml(w.severity || 'HIGH') + '</span></td>' +
            '<td>' + escapeHtml(w.source || '') + '</td>' +
            '<td><button class="btn btn-sm btn-outline-' + (w.enabled ? 'success' : 'secondary') + '" onclick="toggleWatchItem(' + w.id + ',' + (w.enabled ? 'false' : 'true') + ')">' + (w.enabled ? 'ON' : 'OFF') + '</button> ' +
            '<button class="btn btn-sm btn-outline-danger" onclick="deleteWatchItem(' + w.id + ')">✕</button></td></tr>';
    }).join('') || '<tr><td colspan="6" class="text-center text-muted">Chưa có IOC trong watchlist.</td></tr>';
}

function fetchWatchItems() {
    fetch('/api/watchlist').then(function (r) { return r.json(); }).then(function (d) {
        _watchItems = d.items || [];
        renderWatchRows();
    }).catch(function () {});
}

function addWatchItem() {
    var ind = (document.getElementById('wlInd').value || '').trim();
    if (!ind) { showToast('Nhập indicator'); return; }
    fetch('/api/watchlist', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            indicator: ind, type: document.getElementById('wlType').value,
            label: document.getElementById('wlLabel').value,
            severity: document.getElementById('wlSev').value
        })
    }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.success) { showToast('✅ Đã thêm ' + d.type + ':' + ind); fetchWatchItems(); }
        else showToast('❌ ' + (d.error || 'Lỗi'));
    }).catch(function () { showToast('❌ ' + t('ui.connErrShort')); });
}


function toggleWatchImportBox() {
    var box = document.getElementById('wlImportBox');
    var go = document.getElementById('wlImportGo');
    var push = document.getElementById('wlPush');
    if (!box) return;
    var show = box.style.display === 'none';
    box.style.display = show ? '' : 'none';
    go.style.display = show ? '' : 'none';
    push.style.display = show ? '' : 'none';
}

function doWatchImport() {
    var text = document.getElementById('wlImportBox').value || '';
    if (!text.trim()) return;
    fetch('/api/watchlist/import', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text })
    }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.success) { showToast('✅ Import: ' + d.added + ' mới, ' + d.updated + ' đã có'); fetchWatchItems(); }
        else showToast('❌ ' + (d.error || ''));
    }).catch(function () { showToast('❌ ' + t('ui.connErrShort')); });
}

function toggleWatchItem(id, enabled) {
    fetch('/api/watchlist/' + id + '/toggle', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: enabled })
    }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.success) fetchWatchItems(); else showToast('❌ Lỗi cập nhật');
    });
}

function deleteWatchItem(id) {
    if (!confirm('Xóa IOC #' + id + '?')) return;
    fetch('/api/watchlist/' + id, { method: 'DELETE' }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.success) fetchWatchItems(); else showToast('❌ Lỗi xóa');
    });
}

function pushWatchIntel() {
    fetch('/api/watchlist/push-intel', { method: 'POST' }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.success) showToast('✅ Đã push: ' + d.ips + ' IP, ' + d.domains + ' domain → intel file');
        else showToast('❌ ' + (d.error || ''));
    }).catch(function () { showToast('❌ ' + t('ui.connErrShort')); });
}


// ================= SYSLOG SOURCES + CORRELATION =================
var _syslogSrcData = null;

function openSyslogSources() {
    showDetailModal('🛜 Nguồn Syslog → Asset (UDP :514 / TCP :6514)',
        '<div style="font-size:12px;min-width:780px;" id="syslogSrcRoot"></div>');
    fetch('/api/syslog/sources').then(function (r) { return r.json(); }).then(function (d) {
        _syslogSrcData = d;
        renderSyslogSources();
    }).catch(function () {
        var r = document.getElementById('syslogSrcRoot');
        if (r) r.innerHTML = '<div class="text-danger">Lỗi tải nguồn syslog.</div>';
    });
}

function renderSyslogSources() {
    var r = document.getElementById('syslogSrcRoot');
    if (!r || !_syslogSrcData) return;
    var machines = _syslogSrcData.machines || [];
    var rows = (_syslogSrcData.sources || []).map(function (s) {
        var opts = '<option value="">— không map —</option>' + machines.map(function (m) {
            var sel = String(s.machine_id || '') === String(m.machine_id || '') ? ' selected' : '';
            return '<option value="' + escJs(m.machine_id) + '"' + sel + '>' + escapeHtml(m.hostname) + '</option>';
        }).join('');
        var selOpts = '<select class="form-select form-select-sm wl-asset" style="background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);font-size:10px;">' + opts + '</select>';
        return '<tr><td><code>' + escapeHtml(s.source_ip) + '</code></td>' +
            '<td>' + escapeHtml(s.hostname || '') + '</td>' +
            '<td>' + escapeHtml(s.device_type || '') + '</td>' +
            '<td>' + selOpts + '</td>' +
            '<td>' + escapeHtml(s.last_seen || '') + '</td>' +
            '<td><button class="btn btn-sm btn-outline-success" onclick="saveSyslogAsset(\'' + escJs(s.source_ip) + '\', this)">Lưu</button> ' +
            '<button class="btn btn-sm btn-outline-danger" onclick="deleteSyslogSource(\'' + escJs(s.source_ip) + '\')">✕</button></td></tr>';
    }).join('') || '<tr><td colspan="6" class="text-center text-muted">Chưa có thiết bị nào gửi syslog. Cấu hình chúng gửi tới UDP :514 hoặc TCP :6514.</td></tr>';

    var mac = machines;
    var mopts = '<option value="">Chọn máy...</option>' + mac.map(function (m) {
        return '<option value="' + escJs(m.machine_id) + '">' + escapeHtml(m.hostname) + '</option>';
    }).join('');

    r.innerHTML =
        '<div class="alert alert-info py-2 mb-2" style="background:#1a3a5a;color:#88ccff;font-size:11px;">' +
        'Map IP thiết bị mạng với máy quản lý (agent) để FW-block đối chiếu được với sự kiện agent cùng IP. TLS cho TCP: set <code>GIAMSAT_SYSLOG_TLS_CERT/KEY</code> trong .env.</div>' +
        '<table class="table table-sm table-striped" style="font-size:11px;"><thead><tr><th>Source IP</th><th>Hostname</th><th>Loại</th><th>Asset (machine)</th><th>Last seen</th><th>Action</th></tr></thead><tbody>' + rows + '</tbody></table>' +
        '<hr><div class="mb-1"><b>Đối chiếu Firewall-block ↔ Agent (lateral movement)</b></div>' +
        '<div class="row g-2"><div class="col-md-4"><select id="corrMachine" style="background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);font-size:12px;width:100%;">' + mopts + '</select></div>' +
        '<div class="col-md-2"><button class="btn btn-sm btn-outline-info" onclick="runSyslogCorrelation()">Đối chiếu</button></div>' +
        '<div class="col-md-6"><span class="text-muted" style="font-size:11px;">cửa sổ:</span> <input class="search-box" id="corrHours" type="number" value="6" min="1" max="72" style="width:70px;"> giờ</div></div>' +
        '<div id="corrResult" class="mt-2"></div>';
}


function saveSyslogAsset(ip, btn) {
    var sel = btn.closest('tr').querySelector('.wl-asset');
    var machine = sel ? sel.value : '';
    fetch('/api/syslog/sources/' + encodeURIComponent(ip) + '/asset', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ machine_id: machine })
    }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.success) showToast('✅ Đã map ' + ip + (machine ? ' → ' + machine : ' (bỏ map)'));
        else showToast('❌ ' + (d.error || ''));
    });
}

function deleteSyslogSource(ip) {
    if (!confirm('Xóa nguồn ' + ip + '?')) return;
    fetch('/api/syslog/sources/' + encodeURIComponent(ip), { method: 'DELETE' })
        .then(function (r) { return r.json(); }).then(function (d) {
            if (d.success) { showToast('✅ Đã xóa'); openSyslogSources(); }
        });
}

function runSyslogCorrelation() {
    var machine = document.getElementById('corrMachine').value;
    var hours = document.getElementById('corrHours').value || 6;
    var el = document.getElementById('corrResult');
    if (!machine) { showToast('Chọn máy cần đối chiếu'); return; }
    el.innerHTML = '<span class="text-muted">Đang đối chiếu...</span>';
    fetch('/api/syslog/correlation?machine_id=' + encodeURIComponent(machine) + '&hours=' + encodeURIComponent(hours))
        .then(function (r) { return r.json(); }).then(function (d) {
            if (d.error) { el.innerHTML = '<span class="text-danger">' + escapeHtml(d.error) + '</span>'; return; }
            var blk = (d.firewall_blocks || []).map(function (b) {
                return '<div style="border-bottom:1px solid #1e2a3a;padding:2px 0;"><span class="badge bg-warning text-dark">' + escapeHtml(b.rule_id) + '</span> <small>' + escapeHtml((b.description || '').substring(0, 160)) + ' · ' + escapeHtml((b.timestamp || '').substring(0, 19)) + '</small></div>';
            }).join('') || '<div class="text-muted">Không có FW-block nào về IP này trong cửa sổ.</div>';
            var ev = (d.agent_events || []).slice(0, 30).map(function (e) {
                return '<div style="border-bottom:1px solid #1e2a3a;padding:2px 0;font-size:10px;">[' + escapeHtml(e.subtype || e.event_id || '?') + '] ' + escapeHtml((e.description || '').substring(0, 140)) + '</div>';
            }).join('') || '<div class="text-muted">Không có sự kiện agent trong cửa sổ.</div>';
            el.innerHTML = '<div class="row g-2"><div class="col-md-6"><b style="color:#ffcc66;">🧱 Firewall blocks (' + (d.firewall_blocks || []).length + ')</b>' + blk + '</div>' +
                '<div class="col-md-6"><b style="color:#88dd99;">🖥 Agent events máy (' + (d.agent_events || []).length + ', hiện 30)</b>' + ev + '</div></div>';
        }).catch(function () { el.innerHTML = '<span class="text-danger">Lỗi kết nối.</span>'; });
}

// ================= MITRE NAVIGATOR EXPORT =================
function exportMitreNavigator() {
    var hours = prompt('Cửa sổ giờ (mặc định 168 = 7 ngày):', '168');
    if (hours === null) return;
    fetch('/api/mitre/export/navigator?since_hours=' + encodeURIComponent(hours || 168))
        .then(function (r) { return r.json(); }).then(function (layer) {
            if (layer.error) { showToast('❌ ' + layer.error); return; }
            var blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'giamsat-mitre-navigator-layer.json';
            document.body.appendChild(a);
            a.click();
            setTimeout(function () { URL.revokeObjectURL(a.href); }, 1500);
            var blind = layer.techniques.filter(function (x) { return x.score === 0; }).length;
            showToast('✅ Đã xuất layer: ' + layer.techniques.length + ' techniques (' + blind + ' blind). Import vào attack-navigator.');
        }).catch(function () { showToast('❌ ' + t('ui.connErrShort')); });
}
