/**
 * GIAM-SAT Machine Control Panel v2.5.2
 * Creates tab "Kiem soat" content in machine detail view.
 * Tab span is already in HTML (renamed from "Nguoi dung").
 */
(function() {
    function init() {
        // Don't create tab span - HTML already has it. Just create content div.
        var lastTab = document.querySelector('#viewMachine #tabCommand');
        if (!lastTab) return;

        var tabContent = document.createElement('div');
        tabContent.className = 'tab-content';
        tabContent.id = 'tabControl';
        tabContent.style.display = 'none';
        tabContent.innerHTML =
            '<div class="card"><div class="card-header"><i class="bi bi-sliders"></i> ' + t('mc.title') + '</div>' +
            '<div class="card-body p-2">' +
            '<div class="row g-1 mb-3">' +
            '<div class="col"><button class="btn btn-sm export-btn w-100" onclick="window.machineControlAction(\'get_processes\')">' + t('mc.processes') + '</button></div>' +
            '<div class="col"><button class="btn btn-sm export-btn w-100" onclick="window.machineControlAction(\'get_services\')">' + t('mc.services') + '</button></div>' +
            '<div class="col"><button class="btn btn-sm export-btn w-100" onclick="window.machineControlAction(\'get_connections\')">' + t('mc.connections') + '</button></div>' +
            '<div class="col"><button class="btn btn-sm export-btn w-100" onclick="window.machineControlAction(\'get_scheduled_tasks\')">Scheduled Tasks</button></div>' +
            '<div class="col"><button class="btn btn-sm export-btn w-100" onclick="window.machineControlAction(\'get_startup_programs\')">' + t('mc.startup') + '</button></div>' +
            '</div>' +
            '<div id="controlResult" style="max-height:500px;overflow-y:auto;background:#0a0f14;border-radius:4px;padding:8px;font-family:Consolas,monospace;font-size:10px;color:#c8d8e8;white-space:pre-wrap;">' +
            '<div class="text-muted">' + t('mc.hint') + '</div>' +
            '</div></div></div>';

        lastTab.parentNode.insertBefore(tabContent, lastTab.nextSibling);
    }

    window.machineControlAction = function(action) {
        if (!window.selectedMachine) {
            if (window.showToast) window.showToast(t('mc.selectFirst'));
            return;
        }
        var resultEl = document.getElementById('controlResult');
        if (!resultEl) return;
        resultEl.innerHTML = '<span style="color:#ffcc66;">' + t('mc.sending', [action]) + '</span>';

        var execId = 'ctrl_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5);

        fetch('/api/command', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                machine_id: window.selectedMachine,
                action: action,
                command: '',
                exec_id: execId
            })
        }).then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) {
                resultEl.innerHTML = '<span style="color:#00d4aa;">' + t('mc.sent') + '</span>';
                pollControlResult(execId, resultEl, 0);
            } else {
                resultEl.innerHTML = '<span style="color:#ff4444;">' + t('mc.sendFail') + '</span>';
            }
        }).catch(function(e) {
            resultEl.innerHTML = '<span style="color:#ff4444;">' + t('mc.connErr', [e.message]) + '</span>';
        });
    };

    function pollControlResult(execId, resultEl, attempt) {
        if (attempt >= 45) {
            resultEl.innerHTML = '<span style="color:#ff8844;">' + t('mc.timeout') + '</span>';
            return;
        }
        setTimeout(function() {
            if (!window.selectedMachine) return;
            fetch('/api/responses?machine_id=' + window.selectedMachine + '&limit=20')
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    var found = null;
                    if (Array.isArray(data)) {
                        for (var i = 0; i < data.length; i++) {
                            if (data[i].exec_id === execId) { found = data[i]; break; }
                        }
                    }
                    if (found) {
                        var output = found.output || found.error || t('mc.empty');
                        try {
                            var parsed = JSON.parse(output);
                            resultEl.innerHTML = '<div style="color:#00d4aa;margin-bottom:6px;">' + t('mc.result', [found.action]) + '</div>' +
                                '<pre style="font-size:9px;max-height:450px;overflow-y:auto;">' + escapeHtml(JSON.stringify(parsed, null, 2)) + '</pre>';
                        } catch(e2) {
                            resultEl.innerHTML = '<div style="color:#00d4aa;margin-bottom:6px;">' + t('mc.result', [found.action]) + '</div>' +
                                '<pre style="font-size:10px;max-height:450px;overflow-y:auto;">' + escapeHtml(output) + '</pre>';
                        }
                    } else {
                        pollControlResult(execId, resultEl, attempt + 1);
                    }
                }).catch(function() {
                    pollControlResult(execId, resultEl, attempt + 1);
                });
        }, 2000);
    }

    function escapeHtml(s) {
        return String(s).replace(/&/g, '&').replace(/</g, '<').replace(/>/g, '>').replace(/"/g, '"');
    }

    // Initialize on load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();