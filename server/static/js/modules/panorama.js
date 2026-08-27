/**
 * GIAM-SAT Panoramic Dashboard - Server health + security overview + agent fleet.
 * v2.5.2
 */

window.loadPanorama = function() {
    var el = document.getElementById('panoramaContent');
    el.innerHTML = '<div class="text-center text-muted py-5"><div class="spinner-border text-success spinner-border-sm" role="status"></div> ' + t('pano.loading') + '</div>';
    fetch('/api/panorama').then(function(r) { return r.json(); }).then(function(data) {
        if (data.error) { el.innerHTML = '<div class="alert alert-danger m-3">' + escapeHtml(data.error) + '</div>'; return; }
        renderPanorama(data, el);
    }).catch(function(e) { el.innerHTML = '<div class="alert alert-danger m-3">' + t('pano.loadErr', [e.message]) + '</div>'; });
};

function renderPanorama(data, el) {
    var res = data.resources || {};
    var proc = data.process || {};
    var db = data.database || {};
    var att = data.attacks || {};
    var fleet = data.agent_fleet || {};

    var html = '';

    // === TOP STATS ROW ===
    html += '<div class="row g-2 mb-2">';
    html += panoStatCard('Server Uptime', formatUptime(res.uptime_seconds || 0), '#00d4aa', 'clock');
    html += panoStatCard('CPU', (res.cpu_percent || 0) + '%', cpuColor(res.cpu_percent), 'cpu');
    html += panoStatCard('RAM', (res.ram_used_gb || 0) + ' / ' + (res.ram_total_gb || 0) + ' GB', ramColor(res.ram_percent), 'memory');
    html += panoStatCard('Disk', (res.disk_used_gb || 0) + ' / ' + (res.disk_total_gb || 0) + ' GB', diskColor(res.disk_percent), 'hdd');
    html += panoStatCard('Network', (res.net_speed_mbps || 0).toFixed(1) + ' Mbps', '#3399ff', 'speedometer2');
    html += panoStatCard('Process', proc.memory_mb + ' MB (' + (proc.thread_count || 0) + ' threads)', '#8892a4', 'gear');
    html += '</div>';

    // === THREE COLUMN LAYOUT ===
    html += '<div class="row g-2">';

    // === COLUMN 1: SECURITY ===
    html += '<div class="col-md-4">';
    html += '<div class="card mb-2"><div class="card-header" style="font-size:12px;"><i class="bi bi-shield-shaded"></i> ' + t('pano.security24h') + '</div><div class="card-body p-2">';
    html += '<div class="row text-center">';
    html += '<div class="col-4"><div style="font-size:22px;color:#ff4444;font-weight:700;">' + (att.total_threats_24h || 0) + '</div><div style="font-size:9px;color:#8892a4;">' + t('pano.totalThreats') + '</div></div>';
    html += '<div class="col-4"><div style="font-size:22px;color:#ff4444;font-weight:700;">' + (att.critical_threats_24h || 0) + '</div><div style="font-size:9px;color:#8892a4;">CRITICAL</div></div>';
    html += '<div class="col-4"><div style="font-size:22px;color:#ff9966;font-weight:700;">' + (att.server_self_attacks || 0) + '</div><div style="font-size:9px;color:#8892a4;">' + t('pano.serverAttacks') + '</div></div>';
    html += '</div></div></div>';

    // Attackers
    html += '<div class="card mb-2"><div class="card-header" style="font-size:12px;"><i class="bi bi-crosshair"></i> ' + t('pano.topAttackers') + '</div><div class="card-body p-1" style="max-height:200px;overflow-y:auto;">';
    if (att.top_attackers && att.top_attackers.length > 0) {
        att.top_attackers.slice(0, 8).forEach(function(a) {
            html += '<div style="display:flex;justify-content:space-between;padding:3px 8px;font-size:11px;border-bottom:1px solid #1a2a3a;">';
            html += '<span style="color:#ff9966;font-family:monospace;">' + escapeHtml(a.ip) + '</span>';
            html += '<span class="badge bg-danger" style="font-size:9px;">' + a.count + '</span></div>';
        });
    } else { html += '<div class="text-muted text-center py-2" style="font-size:11px;">' + t('pano.noData') + '</div>'; }
    html += '</div></div>';

    // Rule types
    html += '<div class="card mb-2"><div class="card-header" style="font-size:12px;"><i class="bi bi-tags"></i> ' + t('pano.ruleTypes') + '</div><div class="card-body p-1" style="max-height:200px;overflow-y:auto;">';
    if (att.top_rule_types && att.top_rule_types.length > 0) {
        att.top_rule_types.forEach(function(r) {
            var pct = att.total_threats_24h > 0 ? Math.round(r.count / att.total_threats_24h * 100) : 0;
            html += '<div style="padding:3px 8px;font-size:10px;">';
            html += '<div style="display:flex;justify-content:space-between;margin-bottom:2px;"><span style="color:#c8d8e8;">' + escapeHtml(r.rule) + '</span><span style="color:#8892a4;">' + r.count + '</span></div>';
            html += '<div style="background:#1a2a3a;height:4px;border-radius:2px;"><div style="background:#3399ff;height:4px;border-radius:2px;width:' + pct + '%;"></div></div></div>';
        });
    } else { html += '<div class="text-muted text-center py-2" style="font-size:11px;">' + t('pano.noData') + '</div>'; }
    html += '</div></div>';
    html += '</div>'; // end col 1

    // === COLUMN 2: AGENT FLEET ===
    html += '<div class="col-md-4">';
    html += '<div class="card mb-2"><div class="card-header" style="font-size:12px;"><i class="bi bi-pc-display"></i> ' + t('pano.agentFleet') + '</div><div class="card-body p-2">';
    html += '<div class="row text-center">';
    html += '<div class="col-3"><div style="font-size:20px;color:#c8d8e8;font-weight:700;">' + (fleet.total_agents || 0) + '</div><div style="font-size:9px;color:#8892a4;">' + t('pano.total') + '</div></div>';
    html += '<div class="col-3"><div style="font-size:20px;color:#00d4aa;font-weight:700;">' + (fleet.online_agents || 0) + '</div><div style="font-size:9px;color:#8892a4;">Online</div></div>';
    html += '<div class="col-3"><div style="font-size:20px;color:#ff4444;font-weight:700;">' + (fleet.offline_agents || 0) + '</div><div style="font-size:9px;color:#8892a4;">Offline</div></div>';
    html += '<div class="col-3"><div style="font-size:20px;color:#ffcc66;font-weight:700;">' + (fleet.needs_update || 0) + '</div><div style="font-size:9px;color:#8892a4;">' + t('pano.needsUpdate') + '</div></div>';
    html += '</div></div></div>';

    // Version distribution
    html += '<div class="card mb-2"><div class="card-header" style="font-size:12px;"><i class="bi bi-pie-chart"></i> ' + t('pano.agentVersions') + '</div><div class="card-body p-2" style="max-height:180px;overflow-y:auto;">';
    var verDist = fleet.version_distribution || {};
    var verKeys = Object.keys(verDist);
    if (verKeys.length > 0) {
        verKeys.forEach(function(v) {
            html += '<div style="display:flex;justify-content:space-between;padding:3px 8px;font-size:11px;border-bottom:1px solid #1a2a3a;">';
            html += '<span style="color:#c8d8e8;">' + escapeHtml(v) + '</span>';
            html += '<span class="badge bg-info" style="font-size:9px;">' + verDist[v] + '</span></div>';
        });
    } else { html += '<div class="text-muted text-center py-2" style="font-size:11px;">' + t('pano.noData') + '</div>'; }
    html += '</div></div>';

    // Top alerted agents
    html += '<div class="card mb-2"><div class="card-header" style="font-size:12px;"><i class="bi bi-exclamation-triangle"></i> ' + t('pano.topAlerted') + '</div><div class="card-body p-1" style="max-height:200px;overflow-y:auto;">';
    if (fleet.top_alerted && fleet.top_alerted.length > 0) {
        fleet.top_alerted.slice(0, 8).forEach(function(a) {
            html += '<div style="display:flex;justify-content:space-between;padding:3px 8px;font-size:10px;border-bottom:1px solid #1a2a3a;">';
            html += '<span style="color:#ff9966;">' + escapeHtml(a.hostname || a.machine_id) + '</span>';
            html += '<span class="badge bg-danger" style="font-size:9px;">' + a.count + '</span></div>';
        });
    } else { html += '<div class="text-muted text-center py-2" style="font-size:11px;">' + t('pano.noData') + '</div>'; }
    html += '</div></div>';
    html += '</div>'; // end col 2

    // === COLUMN 3: DATABASE ===
    html += '<div class="col-md-4">';
    html += '<div class="card mb-2"><div class="card-header" style="font-size:12px;"><i class="bi bi-database"></i> ' + t('pano.database') + '</div><div class="card-body p-2">';
    html += '<div style="font-size:11px;color:#8892a4;margin-bottom:4px;">Backend: <strong style="color:#c8d8e8;">' + escapeHtml(db.backend || 'unknown') + '</strong> | Size: <strong style="color:#00d4aa;">' + (db.total_size_mb || 0) + ' MB</strong></div>';
    var tables = db.tables || {};
    var tableKeys = Object.keys(tables);
    if (tableKeys.length > 0) {
        tableKeys.forEach(function(t) {
            var count = tables[t];
            html += '<div style="display:flex;justify-content:space-between;padding:2px 8px;font-size:10px;border-bottom:1px solid #1a2a3a;">';
            html += '<span style="color:#c8d8e8;">' + escapeHtml(t) + '</span>';
            html += '<span style="color:#8892a4;font-family:monospace;">' + (count || 0).toLocaleString() + ' rows</span></div>';
        });
    }
    html += '</div></div>';

    // Process info
    html += '<div class="card mb-2"><div class="card-header" style="font-size:12px;"><i class="bi bi-cpu"></i> Process Info</div><div class="card-body p-2" style="font-size:11px;">';
    html += '<div>PID: <strong style="color:#00d4aa;">' + (proc.pid || 0) + '</strong></div>';
    html += '<div>Connections: <strong style="color:#3399ff;">' + (proc.connections || 0) + '</strong></div>';
    html += '<div>Open Files: <strong style="color:#ffcc66;">' + (proc.open_files || 0) + '</strong></div>';
    html += '</div></div>';
    html += '</div>'; // end col 3

    html += '</div>'; // end row
    html += '<div class="text-end" style="font-size:9px;color:#5a6a7a;">' + t('pano.updated', [data.timestamp || '']) + '</div>';

    el.innerHTML = html;
}

function panoStatCard(label, value, color, icon) {
    return '<div class="col-md-2"><div class="card stat-card" style="padding:10px 4px;">' +
        '<div class="value" style="font-size:18px;color:' + color + ';">' + value + '</div>' +
        '<div class="label" style="font-size:9px;">' + label + '</div></div></div>';
}

function formatUptime(seconds) {
    var d = Math.floor(seconds / 86400);
    var h = Math.floor((seconds % 86400) / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm';
}

function cpuColor(v) { return v > 80 ? '#ff4444' : v > 50 ? '#ff9966' : '#00d4aa'; }
function ramColor(v) { return v > 90 ? '#ff4444' : v > 60 ? '#ff9966' : '#00d4aa'; }
function diskColor(v) { return v > 90 ? '#ff4444' : v > 70 ? '#ff9966' : '#00d4aa'; }