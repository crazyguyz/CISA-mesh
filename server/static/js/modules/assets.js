/**
 * GIAM-SAT v4.4: Asset Management Frontend
 * Quản lý danh sách tài sản (máy tính, màn hình) và cảnh báo thay đổi.
 */
var Assets = {
    init: function() {
        document.querySelectorAll('[data-tab-as]').forEach(function(tab) {
            tab.addEventListener('click', function() {
                var tabName = this.getAttribute('data-tab-as');
                document.querySelectorAll('[data-tab-as]').forEach(function(t) { t.classList.remove('active'); });
                this.classList.add('active');
                document.querySelectorAll('.tab-as-content').forEach(function(c) { c.style.display = 'none'; });
                var target = document.getElementById('tabAs' + tabName.charAt(0).toUpperCase() + tabName.slice(1));
                if (target) target.style.display = 'block';
                if (tabName === 'computers') Assets.loadComputers();
                else if (tabName === 'monitors') Assets.loadMonitors();
                else if (tabName === 'changes') Assets.loadChanges();
            });
        });
        Assets.loadComputers();
        Assets.updateBadges();
        setInterval(Assets.updateBadges, 60000);
    },

    updateBadges: function() {
        fetch('/api/assets/unresolved_count')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var count = data.count || 0;
                var badge = document.getElementById('assetsBadge');
                var changeBadge = document.getElementById('assetChangeBadge');
                if (badge) {
                    badge.textContent = count;
                    badge.style.display = count > 0 ? 'inline' : 'none';
                }
                if (changeBadge) changeBadge.textContent = count;
            })
            .catch(function() {});
    },

    loadComputers: function() {
        var search = document.getElementById('assetComputerSearch');
        var q = search ? search.value.trim() : '';
        var container = document.getElementById('assetComputersTable');
        if (!container) return;
        container.innerHTML = '<div class="text-center text-muted py-3"><div class="spinner-border spinner-border-sm" role="status"></div> ' + t('common.loading') + '</div>';

        fetch('/api/assets/computers?search=' + encodeURIComponent(q) + '&limit=200')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var computers = data.computers || [];
                if (computers.length === 0) {
                    container.innerHTML = '<div class="text-center text-muted py-4">' + t('assets.noComputers') + '</div>';
                    return;
                }
                var html = '<table class="table-data table table-sm mb-0"><thead><tr>' +
                    '<th>' + t('assets.assetId') + '</th><th>' + t('assets.computer') + '</th><th>' + t('assets.user') + '</th><th>Mainboard</th>' +
                    '<th>CPU</th><th>RAM</th><th>' + t('assets.disk') + '</th><th>GPU</th>' +
                    '<th>' + t('assets.monitor') + '</th><th>Online</th><th>' + t('assets.updated') + '</th></tr></thead><tbody>';

                computers.forEach(function(c) {
                    var disks = c.disks_json;
                    if (typeof disks === 'string') { try { disks = JSON.parse(disks); } catch(e) { disks = []; } }
                    var gpus = c.gpu_json;
                    if (typeof gpus === 'string') { try { gpus = JSON.parse(gpus); } catch(e) { gpus = []; } }
                    var monitors = c.monitors_json;
                    if (typeof monitors === 'string') { try { monitors = JSON.parse(monitors); } catch(e) { monitors = []; } }

                    var diskInfo = disks.map(function(d) { return (d.model || '?') + ' (' + (d.size_gb || '?') + 'GB)'; }).join('<br>') || '-';
                    var gpuInfo = gpus.map(function(g) { return (g.name || '?') + ' (' + (g.ram_gb || '?') + 'GB)'; }).join('<br>') || '-';
                    var monitorInfo = monitors.map(function(m) { return (m.manufacturer || '') + ' ' + (m.name || ''); }).join('<br>') || '-';

                    var mbInfo = (c.motherboard_manufacturer || '') + ' ' + (c.motherboard_product || '');
                    if (!mbInfo.trim()) mbInfo = '-';
                    var displayId = c.display_id || c.asset_id || '-';
                    var onlineDot = c.is_online ? '<span class="online-dot online"></span>' : '<span class="online-dot offline"></span>';
                    var updated = c.updated_at ? c.updated_at.substring(0, 16) : '-';

                    html += '<tr>' +
                        '<td><code style="font-size:11px;font-weight:bold;color:#00d4aa;">' + displayId + '</code></td>' +
                        '<td><strong>' + Assets.esc(c.hostname || c.machine_id || '-') + '</strong><br><small class="text-muted">' + Assets.esc(c.os_name || '') + ' ' + Assets.esc(c.os_version || '') + '</small></td>' +
                        '<td><strong>' + Assets.esc(c.user_name || '-') + '</strong><br><small>' + Assets.esc(c.employee_id || '') + '</small></td>' +
                        '<td style="font-size:10px;">' + Assets.esc(mbInfo) + '</td>' +
                        '<td style="font-size:11px;">' + Assets.esc(c.cpu_name || '-') + '<br><small>' + (c.cpu_cores || 0) + ' cores, ' + (c.cpu_max_clock_mhz || 0) + ' MHz</small></td>' +
                        '<td>' + (c.ram_total_gb || 0) + ' GB</td>' +
                        '<td style="font-size:10px;">' + diskInfo + '</td>' +
                        '<td style="font-size:10px;">' + gpuInfo + '</td>' +
                        '<td style="font-size:10px;">' + monitorInfo + '</td>' +
                        '<td>' + onlineDot + '</td>' +
                        '<td><small>' + updated + '</small></td>' +
                        '</tr>';
                });

                html += '</tbody></table>';
                container.innerHTML = html;
            })
            .catch(function(err) {
                container.innerHTML = '<div class="text-center text-danger py-3">' + t('assets.loadErr', [err]) + '</div>';
            });
    },

    loadMonitors: function() {
        var search = document.getElementById('assetMonitorSearch');
        var q = search ? search.value.trim() : '';
        var container = document.getElementById('assetMonitorsTable');
        if (!container) return;
        container.innerHTML = '<div class="text-center text-muted py-3"><div class="spinner-border spinner-border-sm" role="status"></div> ' + t('common.loading') + '</div>';

        fetch('/api/assets/monitors?search=' + encodeURIComponent(q) + '&limit=200')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var monitors = data.monitors || [];
                if (monitors.length === 0) {
                    container.innerHTML = '<div class="text-center text-muted py-4">' + t('assets.noMonitors') + '</div>';
                    return;
                }
                var html = '<table class="table-data table table-sm mb-0"><thead><tr>' +
                    '<th>' + t('assets.assetId') + '</th><th>' + t('assets.monitorName') + '</th><th>' + t('assets.brand') + '</th><th>' + t('assets.resolution') + '</th>' +
                    '<th>' + t('assets.connectedComputer') + '</th><th>' + t('assets.user') + '</th><th>' + t('assets.updated') + '</th></tr></thead><tbody>';

                monitors.forEach(function(m) {
                    var updated = m.updated_at ? m.updated_at.substring(0, 16) : '-';
                    var displayId = m.display_id || m.asset_id || '-';
                    html += '<tr>' +
                        '<td><code style="font-size:11px;font-weight:bold;color:#00d4aa;">' + displayId + '</code></td>' +
                        '<td><strong>' + Assets.esc(m.name || '-') + '</strong><br><small class="text-muted">' + Assets.esc(m.model_type || 'Monitor') + '</small></td>' +
                        '<td>' + Assets.esc(m.manufacturer || '-') + '</td>' +
                        '<td>' + Assets.esc(m.resolution || '-') + '</td>' +
                        '<td>' + Assets.esc(m.computer_hostname || t('assets.unassigned')) + '</td>' +
                        '<td>' + Assets.esc(m.computer_user || '-') + '</td>' +
                        '<td><small>' + updated + '</small></td>' +
                        '</tr>';
                });

                html += '</tbody></table>';
                container.innerHTML = html;
            })
            .catch(function(err) {
                container.innerHTML = '<div class="text-center text-danger py-3">' + t('assets.loadErr', [err]) + '</div>';
            });
    },

    loadChanges: function() {
        var unresolvedOnly = document.getElementById('assetUnresolvedOnly');
        var unresolved = unresolvedOnly && unresolvedOnly.checked ? '1' : '0';
        var container = document.getElementById('assetChangesTable');
        if (!container) return;
        container.innerHTML = '<div class="text-center text-muted py-3"><div class="spinner-border spinner-border-sm" role="status"></div> ' + t('common.loading') + '</div>';

        fetch('/api/assets/changes?limit=100&unresolved=' + unresolved)
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var changes = data.changes || [];
                if (changes.length === 0) {
                    container.innerHTML = '<div class="text-center text-success py-4">' + t('assets.noChanges') + '</div>';
                    return;
                }
                var html = '<table class="table-data table table-sm mb-0"><thead><tr>' +
                    '<th>' + t('assets.time') + '</th><th>' + t('assets.type') + '</th><th>' + t('assets.object') + '</th><th>' + t('assets.detail') + '</th>' +
                    '<th>' + t('assets.status') + '</th><th>' + t('assets.action') + '</th></tr></thead><tbody>';

                changes.forEach(function(ch) {
                    var details = ch.details;
                    if (typeof details === 'string') { try { details = JSON.parse(details); } catch(e) { details = {}; } }

                    var typeBadge = '';
                    var typeLabel = '';
                    if (ch.change_type === 'hardware_changed') { typeBadge = 'bg-danger'; typeLabel = t('assets.hwChanged'); }
                    else if (ch.change_type === 'monitor_reassigned') { typeBadge = 'bg-warning text-dark'; typeLabel = t('assets.monitorMoved'); }
                    else if (ch.change_type === 'monitor_disconnected') { typeBadge = 'bg-secondary'; typeLabel = t('assets.monitorRemoved'); }
                    else { typeBadge = 'bg-info'; typeLabel = ch.change_type || '-'; }

                    var desc = '';
                    if (ch.change_type === 'hardware_changed') {
                        var parts = [];
                        if (details.cpu_changed) parts.push('CPU: ' + details.cpu_changed);
                        if (details.ram_changed) parts.push('RAM: ' + details.ram_changed);
                        if (details.disks_changed) parts.push(t('assets.diskChanged'));
                        if (details.old_hash) parts.push('Hash: ' + details.old_hash + ' → ' + details.new_hash);
                        desc = parts.join('; ') || t('assets.hwChangedDesc');
                    } else if (ch.change_type === 'monitor_reassigned') {
                        desc = details.monitor + ': ' + details.from_computer + ' → ' + details.to_computer;
                    } else if (ch.change_type === 'monitor_disconnected') {
                        desc = t('assets.disconnected', [details.computer, details.monitor]);
                    }

                    var statusHtml = ch.is_resolved ? '<span class="badge bg-success">' + t('assets.resolved') + '</span>' : '<span class="badge bg-danger">' + t('assets.unresolved') + '</span>';
                    var actionHtml = ch.is_resolved ? '<small class="text-muted">' + (ch.resolved_by || '') + '</small>' : '<button class="btn btn-sm btn-success py-0 px-1" onclick="Assets.resolveChange(' + ch.id + ')">' + t('assets.confirm') + '</button>';

                    html += '<tr>' +
                        '<td><small>' + (ch.created_at || '').substring(0, 16) + '</small></td>' +
                        '<td><span class="badge ' + typeBadge + '">' + typeLabel + '</span></td>' +
                        '<td><code style="font-size:10px;">' + (ch.asset_id || '-') + '</code><br><small>' + (ch.asset_type || '') + '</small></td>' +
                        '<td style="font-size:11px;">' + Assets.esc(desc) + '</td>' +
                        '<td>' + statusHtml + '</td>' +
                        '<td>' + actionHtml + '</td>' +
                        '</tr>';
                });

                html += '</tbody></table>';
                container.innerHTML = html;

                var unresolvedC = changes.filter(function(c) { return !c.is_resolved; }).length;
                var badge = document.getElementById('assetsBadge');
                if (badge) { badge.textContent = unresolvedC; badge.style.display = unresolvedC > 0 ? 'inline' : 'none'; }
                var changeBadge = document.getElementById('assetChangeBadge');
                if (changeBadge) changeBadge.textContent = unresolvedC;
            })
            .catch(function(err) {
                container.innerHTML = '<div class="text-center text-danger py-3">' + t('assets.loadErr', [err]) + '</div>';
            });
    },

    resolveChange: function(changeId) {
        if (!confirm(t('assets.confirmResolve'))) return;
        fetch('/api/assets/changes/' + changeId + '/resolve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ resolved_by: 'admin' })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.success) {
                Assets.loadChanges();
                Assets.updateBadges();
                if (typeof showToast === 'function') showToast(t('assets.resolvedToast'));
            }
        });
    },

    exportExcel: function() {
        window.open('/api/assets/export', '_blank');
        if (typeof showToast === 'function') showToast(t('assets.downloading'));
    },

    esc: function(s) {
        if (!s) return '';
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(s));
        return div.innerHTML;
    }
};

function refreshAssetComputers() { Assets.loadComputers(); }
function refreshAssetMonitors() { Assets.loadMonitors(); }
function refreshAssetChanges() { Assets.loadChanges(); }

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() { Assets.init(); });
} else {
    Assets.init();
}