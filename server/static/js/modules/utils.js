/**
 * GIAM-SAT Dashboard - Utility Functions
 * Pure helpers with no external dependencies.
 */

function escapeHtml(s) {
    return String(s).replace(/&/g, '&').replace(/</g, '<').replace(/>/g, '>').replace(/"/g, '"').replace(/'/g, '&#39;');
}

function showToast(msg) {
    document.getElementById('toastMessage').textContent = msg;
    const toast = new bootstrap.Toast(document.getElementById('liveToast'));
    toast.show();
}

function tableWrap(headers, rows) {
    return '<table class="table table-data table-hover"><thead><tr>'
        + headers.map(function(h) { return '<th>' + h + '</th>'; }).join('')
        + '</tr></thead><tbody>' + rows.join('') + '</tbody></table>';
}

function getQueryParams(type, machineId) {
    var qs = machineId && machineId !== 'all' ? 'machine_id=' + machineId + '&' : '';
    var lim = type === 'events' || type === 'inspection' || type === 'sca' ? 300 : (type === 'network' ? 200 : 200);
    return qs + 'limit=' + lim;
}

function downloadJSON(data, filename) {
    window.lastExportedData = data;
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'giamsat_' + filename + '_' + new Date().toISOString().slice(0, 10) + '.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('\u2705 Đã xuất ' + (Array.isArray(data) ? data.length : 1) + ' records ra file JSON');
}

function exportToJSON(type, machineId, filename) {
    var apiMap = {
        events: '/api/events', fim: '/api/fim', syslog: '/api/syslog', responses: '/api/responses',
        network: '/api/network', inspection: '/api/inspection', threats: '/api/threats', vulns: '/api/vulns',
        yara: '/api/yara', sca: '/api/sca', agentless: '/api/agentless', overview: '/api/stats'
    };
    var url = apiMap[type] || apiMap['events'];
    var qs = getQueryParams(type, machineId);
    fetch(url + '?' + qs).then(function(r) { return r.json(); }).then(function(data) {
        if (type === 'overview') {
            Promise.all([
                fetch('/api/machines').then(function(r) { return r.json(); }),
                fetch('/api/event_types').then(function(r) { return r.json(); }),
                fetch('/api/stats').then(function(r) { return r.json(); })
            ]).then(function(results) {
                downloadJSON({ machines: results[0], event_types: results[1], stats: results[2] }, filename);
            });
        } else {
            downloadJSON(data, filename);
        }
    });
}