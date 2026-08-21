function escapeHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function fmtBytes(b){b=parseInt(b)||0;if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';if(b<1073741824)return (b/1048576).toFixed(1)+' MB';return (b/1073741824).toFixed(2)+' GB';}

var selectedMachine = null;
var configCache = {};
var configLoadedFor = null;
const toast = new bootstrap.Toast(document.getElementById('liveToast'));
function showToast(msg) { document.getElementById('toastMessage').textContent = msg; toast.show(); }
let pendingExecs = {};
let lastExportedData = null;
let attackData = null;
let attackMapCanvas = null;
let attackMapCtx = null;
let attackMapNodes = [];
let attackMapAnimId = null;

document.querySelectorAll('.nav-link[data-view]').forEach(el => {
    el.addEventListener('click', function(e) {
        e.preventDefault();
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        this.classList.add('active');
        const view = this.dataset.view;
        document.querySelectorAll('[id^="view"]').forEach(v => v.style.display = 'none');
        if (view === 'overview') document.getElementById('viewOverview').style.display = '';
        // v2.5.22: Lazy-load - show loading skeleton first, then load data
        const loadingVD = '<div class="text-center py-5"><div class="spinner-border text-success" role="status"></div><p class="text-muted mt-2" style="font-size:13px;">' + t('dash.loadingData') + '</p></div>';
        var viewMap = {
            events: { el: 'viewEvents', container: 'allEventList', load: function() { loadAllEvents(); } },
            fim: { el: 'viewFim', container: 'allFimList', load: function() { loadAllFim(); } },
            syslog: { el: 'viewSyslog', container: 'syslogList', load: function() { loadSyslog(); } },
            response: { el: 'viewResponse', container: 'allResponseList', load: function() { loadAllResponses(); } },
            network: { el: 'viewNetwork', container: 'networkList', load: function() { loadNetwork(); } },
            netflow: { el: 'viewNetflow', load: function() { loadNetflow(); } },
            threats: { el: 'viewThreats', container: 'threatList', load: function() { loadThreats(); } },
            vulns: { el: 'viewVulns', container: 'vulnList', load: function() { loadVulns(); } },
            yara: { el: 'viewYara', container: 'yaraList', load: function() { loadYara(); } },
            sca: { el: 'viewSca', container: 'scaList', load: function() { loadSca(); } },
            agentless: { el: 'viewAgentless', container: 'agentlessList', load: function() { loadAgentless(); } },
            attack: { el: 'viewAttack', container: 'attackContent', load: function() { loadAttackOverview(); } },
            assistant: { el: 'viewAssistant', container: null, load: function() { loadAssistScope(); loadAiStatus(); } },
            groups: { el: 'viewGroups', container: 'groupsContent', load: function() { loadGroups(); } },
            fimbaseline: { el: 'viewFimBaseline', container: 'fimBaselineMachineList', load: function() { loadFimBaselineMachines(); } },
            rules: { el: 'viewRules', container: 'rulesList', load: function() { loadRules(); } },
            suppression: { el: 'viewSuppression', container: 'supList', load: function() { loadSuppressions(); populateSuppressionForm(); } },
            agentupdate: { el: 'viewAgentUpdate', container: 'agentUpdateGroups', load: function() { loadAgentUpdateView(); } },
            messages: { el: 'viewMessages', container: null, load: function() { if (window.messageChat) messageChat.init(); } },
            email: { el: 'viewEmail', container: null, load: function() { loadEmailView(); } },
            sysmon: { el: 'viewSysmon', container: 'sysmonList', load: function() { loadSysmon(); } },
            memory: { el: 'viewMemory', container: 'memoryList', load: function() { loadMemory(); } },
            hunting: { el: 'viewHunting', container: null, load: function() {} },
            anomaly: { el: 'viewAnomaly', container: 'anomalyList', load: function() { loadAnomaly(); } },
            ioc: { el: 'viewIoc', container: null, load: function() {} },
            incident: { el: 'viewIncident', container: 'incidentSidebar', load: function() { loadIncidentView(); } },
            mitre: { el: 'viewMitre', container: 'mitre-matrix-container', load: function() { if (window.loadMITREMatrix) loadMITREMatrix('mitre-matrix-container'); } },
            cleanup: { el: 'viewCleanup', container: 'cleanupContent', load: function() { loadCleanupSummary(); } },
            audit: { el: 'viewAudit', container: 'auditList', load: function() { loadAudit(); } },
            cluster: { el: 'viewCluster', container: 'clusterContent', load: function() { loadCluster(); } },
            dashboards: { el: 'viewDashboards', container: null, load: function() { if (typeof DbBuilder !== 'undefined') DbBuilder.init(); else setTimeout(function() { DbBuilder.init(); }, 200); } },
            assets: { el: 'viewAssets', container: null, load: function() { if (typeof Assets !== 'undefined') Assets.init(); else setTimeout(function() { Assets.init(); }, 200); } },
            'report-asset': { el: 'viewReportAsset', container: null, load: function() {} },
            'report-summary': { el: 'viewReportSummary', container: null, load: function() {} },
            users: { el: 'viewUsers', container: null, load: function() { loadUsers(); } }
        };
        var v = viewMap[view];
        if (v) {
            document.getElementById(v.el).style.display = '';
            if (v.container) {
                var cEl = document.getElementById(v.container);
                if (cEl && (cEl.innerHTML.indexOf(t('ui.loading')) < 0 && cEl.innerHTML.indexOf(t('ui.noData')) < 0 && cEl.innerHTML.indexOf('spinner') < 0)) {
                    cEl.innerHTML = loadingVD;
                }
            }
            setTimeout(function() { if (v.load) v.load(); }, 50);
        }
        if (view === "email") { document.getElementById("viewEmail").style.display = ""; loadEmailView(); }
        if (view === "agentupdate") { document.getElementById("viewAgentUpdate").style.display = ""; loadAgentUpdateView(); }
        if (view === "messages") { document.getElementById("viewMessages").style.display = ""; if (window.messageChat) messageChat.init(); }
        currentView = view;
        const iconMap = {'overview':'speedometer2','report-asset':'clipboard-data','report-summary':'bar-chart','events':'list-ul','fim':'folder2-open','syslog':'router','response':'arrow-return-right','network':'diagram-3','threats':'shield-exclamation','vulns':'bug','yara':'virus','sca':'clipboard-check','agentless':'wifi','assistant':'robot','groups':'people','fimbaseline':'shield-check','rules':'file-earmark-code','suppression':'funnel','audit':'journal-text','cluster':'diagram-2','agentupdate':'cloud-download','attack':'crosshair','messages':'chat-dots','hunting':'search','anomaly':'activity','ioc':'bullseye','incident':'zoom-in','cleanup':'trash3','users':'person-gear'};
        document.getElementById('pageTitle').innerHTML = `<i class="bi bi-${iconMap[view]||'speedometer2'}"></i> ${this.textContent.trim()}`;
    });
});

document.querySelectorAll('.panel-tab').forEach(el => {
    el.addEventListener('click', function() {
        document.querySelectorAll('.panel-tab').forEach(t => t.classList.remove('active'));
        this.classList.add('active');
        const tab = this.dataset.tab;
        document.querySelectorAll('.tab-content').forEach(t => t.style.display = 'none');
        document.getElementById('tab' + tab.charAt(0).toUpperCase() + tab.slice(1)).style.display = '';
        if (selectedMachine) {
        if (tab === 'events') loadMachineEvents(selectedMachine);
            else if (tab === 'fim') loadMachineFim(selectedMachine);
            else if (tab === 'response') loadMachineResponses(selectedMachine);
            else if (tab === 'config') loadMachineConfig(selectedMachine);
            else if (tab === 'control') { /* machine-control.js handles this */ }
        }
    });
});

function selectMachine(machineId) {
    const prevMachine = selectedMachine;
    selectedMachine = machineId;
    // v2.5.19: Sync dropdown
    const sel = document.getElementById('machineSelect');
    if (sel && sel.value !== machineId) {
        sel.value = machineId;
    }
    document.getElementById('viewOverview').style.display = 'none';
    document.getElementById('viewEvents').style.display = 'none';
    document.getElementById('viewFim').style.display = 'none';
    document.getElementById('viewSyslog').style.display = 'none';
    document.getElementById('viewResponse').style.display = 'none';
    document.getElementById('viewMachine').style.display = '';
    // Get hostname from selected option
    const option = sel ? sel.options[sel.selectedIndex] : null;
    const hostname = (option && option.dataset.hostname) ? option.dataset.hostname : machineId;
    document.getElementById('pageTitle').innerHTML = `<i class="bi bi-pc-display"></i> ${escapeHtml(hostname)}`;
    updateSSHTitle(hostname);
    loadMachineDetails(machineId);
    loadMachineEvents(machineId);
    loadMachineFim(machineId);
    loadMachineResponses(machineId);
    if (machineId !== prevMachine) { configLoadedFor = null; }
    loadMachineConfig(machineId);
}

function updateSSHTitle(hostname) {
    const headerEl = document.querySelector('#tabCommand .card-header');
    if (headerEl) { headerEl.innerHTML = `<i class="bi bi-terminal"></i> SSH Remote Shell → <strong style="color:#ffcc66;">${escapeHtml(hostname)}</strong> (${t('ssh.toMachine')})`; }
    const outputEl = document.getElementById('cmdOutput');
    if (outputEl && outputEl.innerHTML.indexOf('GIAM-SAT Remote Shell v1.0') === 0) {
        outputEl.innerHTML = `GIAM-SAT Remote Shell v1.0<br>================================<br>${t('ssh.machineLabel')}<strong style="color:#ffcc66;">${escapeHtml(hostname)}</strong><br>${t('ssh.typeCommand')}<br>${t('ssh.resultDelay')}<br>================================<br>`;
    }
}

function loadMachineDetails(machineId) {
    fetch(`/api/stats?machine_id=${machineId}`).then(r => r.json()).then(s => {
        document.getElementById('detailStatEvents').textContent = s.events || 0;
        document.getElementById('detailStatFim').textContent = s.fim_events || 0;
        document.getElementById('detailStatResponses').textContent = s.responses || 0;
    });
    fetch('/api/machines').then(r => r.json()).then(ms => {
        const m = ms.find(x => x.machine_id === machineId);
        if (m) {
            document.getElementById('detailMachineName').textContent = m.hostname || machineId;
            document.getElementById('detailMachineIP').textContent = m.ip_address || '-';
            const online = m.is_online == 1;
            document.getElementById('detailOnlineDot').className = `online-dot ${online ? 'online' : 'offline'}`;
            document.getElementById('detailMachineStatus').textContent = online ? 'Online' : 'Offline';
            // v2.2.0: Show user info in detail card
            if (m.user_name) {
                document.getElementById('detailUserName').textContent = escapeHtml(m.user_name);
                document.getElementById('detailUserEmpId').textContent = m.employee_id || '-';
                document.getElementById('detailUserEmail').textContent = m.email || '-';
                document.getElementById('detailUserInfo').style.display = '';
            } else {
                document.getElementById('detailUserInfo').style.display = 'none';
            }
            // v2.5.12: Show notes
            if (m.notes) {
                document.getElementById('detailNotesText').textContent = m.notes;
                document.getElementById('detailNotes').style.display = '';
            } else {
                document.getElementById('detailNotes').style.display = 'none';
            }
            document.getElementById('detailNotesEdit').style.display = 'none';
        }
    });
}


// v2.5.12: Machine notes functions
function editMachineNotes() {
    if (!selectedMachine) return;
    var notesEl = document.getElementById('detailNotes');
    var editEl = document.getElementById('detailNotesEdit');
    if (notesEl && editEl) {
        document.getElementById('detailNotesInput').value = document.getElementById('detailNotesText').textContent || '';
        notesEl.style.display = 'none';
        editEl.style.display = '';
    }
}

function saveMachineNotes() {
    if (!selectedMachine) return;
    var notes = document.getElementById('detailNotesInput').value.trim().substring(0, 500);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/machine/' + selectedMachine + '/notes', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.withCredentials = true;
    xhr.onload = function() {
        try {
            var data = JSON.parse(xhr.responseText);
            if (data.success) {
                if (notes) {
                    document.getElementById('detailNotesText').textContent = notes;
                    document.getElementById('detailNotes').style.display = '';
                } else {
                    document.getElementById('detailNotes').style.display = 'none';
                }
                document.getElementById('detailNotesEdit').style.display = 'none';
                showToast(t('dash.noteSaved'));
            } else {
                showToast('Lỗi: ' + (data.error || 'Không lưu được'));
            }
        } catch(e) { showToast('Lỗi phân tích phản hồi'); }
    };
    xhr.onerror = function() { showToast('Lỗi kết nối'); };
    xhr.send(JSON.stringify({notes: notes}));
}

function cancelEditNotes() {
    document.getElementById('detailNotesEdit').style.display = 'none';
    if (document.getElementById('detailNotesText').textContent) {
        document.getElementById('detailNotes').style.display = '';
    }
}

function tableWrap(headers, rows) { return '<table class="table table-data table-hover"><thead><tr>' + headers.map(h => '<th>' + h + '</th>').join('') + '</tr></thead><tbody>' + rows.join('') + '</tbody></table>'; }

// ===== EXPORT FUNCTIONS =====
function getQueryParams(type, machineId) {
    const qs = machineId && machineId !== 'all' ? `machine_id=${machineId}&` : '';
    const lim = type === 'events' || type === 'inspection' || type === 'sca' ? 300 : type === 'network' ? 200 : 200;
    return `${qs}limit=${lim}`;
}

function exportToJSON(type, machineId, filename) {
    const apiMap = { events:'/api/events', fim:'/api/fim', syslog:'/api/syslog', responses:'/api/responses',
        network:'/api/network', inspection:'/api/inspection', threats:'/api/threats', vulns:'/api/vulns',
        yara:'/api/yara', sca:'/api/sca', agentless:'/api/agentless', overview:'/api/stats' };
    const url = apiMap[type] || apiMap['events'];
    const qs = getQueryParams(type, machineId);
    fetch(`${url}?${qs}`).then(r => r.json()).then(data => {
        if (type === 'overview') {
            Promise.all([
                fetch('/api/machines').then(r => r.json()),
                fetch('/api/event_types').then(r => r.json()),
                fetch('/api/stats').then(r => r.json())
            ]).then(([machines, evtTypes, stats]) => {
                downloadJSON({ machines, event_types: evtTypes, stats }, filename);
            });
        } else {
            downloadJSON(data, filename);
        }
    });
}

function downloadJSON(data, filename) {
    lastExportedData = data;
    const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `giamsat_${filename}_${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(t('dash.exported', [Array.isArray(data) ? data.length : 1]));
}

// ===== AI ASSISTANT - Log Type Toggle =====
function toggleAllLogTypes(el) {
    document.querySelectorAll('.assistLogChk').forEach(cb => { cb.checked = el.checked; cb.disabled = el.checked; });
}

// ===== AI ASSISTANT - Auto fetch all + export =====
function autoFetchAndExportAssistContext() {
    const types = getSelectedLogTypes();
    if (types.length === 0) { showToast('⚠ Chọn ít nhất một loại log!'); return; }
    showToast('⏳ Đang thu thập dữ liệu...');
    let completed = 0;
    const allData = {};

    const apiMap = { events:'/api/events', fim:'/api/fim', network:'/api/network',
        threats:'/api/threats', vulns:'/api/vulns', yara:'/api/yara',
        sca:'/api/sca', inspection:'/api/inspection', agentless:'/api/agentless', syslog:'/api/syslog',
        fimbaseline:'/api/fim/baseline', attackoverview:'/api/attack/overview' };
    const machineId = document.getElementById('assistScope').value;

    types.forEach(t => {
        if (t === 'fimbaseline') {
            // FIM Baseline needs machine_id param
            fetch(`/api/machines`).then(r => r.json()).then(machines => {
                const promises = machines.map(m =>
                    fetch(`/api/fim/baseline/${m.machine_id}`).then(r => r.json()).catch(() => ({}))
                );
                Promise.all(promises).then(results => {
                    // Combine all machines' baseline into one object
                    const combined = {};
                    machines.forEach((m, i) => {
                        combined[m.machine_id] = results[i] || {};
                    });
                    allData[t] = { machines: combined, count: machines.length };
                    completed++;
                    checkDone();
                }).catch(() => { completed++; checkDone(); });
            }).catch(() => { completed++; checkDone(); });
            return;
        }
        const url = apiMap[t] || `/api/${t}`;
        const qs = getQueryParams(t, machineId);
        fetch(`${url}?${qs}`).then(r => r.json()).then(data => {
            allData[t] = data;
            completed++;
            checkDone();
        }).catch(() => { completed++; checkDone(); });
    });

    function checkDone() {
        if (completed >= types.length) {
            lastExportedData = allData;
            downloadJSON(allData, 'assist_context');
            showToast(t('dash.jsonExported', [types.length]));
        }
    }
}

function getSelectedLogTypes() {
    const allChk = document.getElementById('assistLogType_all');
    if (allChk && allChk.checked) { return ['events','fim','network','threats','vulns','yara','sca','inspection','agentless','syslog','fimbaseline','attackoverview']; }
    return Array.from(document.querySelectorAll('.assistLogChk:checked')).map(cb => cb.value);
}

function downloadAssistContextFile(fullReport) {
    const types = getSelectedLogTypes();
    if (types.length === 0) { showToast('⚠ Chọn ít nhất một loại log!'); return; }
    if (lastExportedData) {
        if (fullReport) downloadJSON(lastExportedData, 'full_report');
        else downloadJSON(lastExportedData, 'assist_context');
        return;
    }
    autoFetchAndExportAssistContext();
}

// ===== ALL VIEWS =====
function loadAllEvents() {
    const el = document.getElementById('allEventList');
    fetch('/api/events?limit=300').then(r => r.json()).then(events => {
        if (!events.length) { el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noEvents') + '</div>'; return; }
        el.innerHTML = tableWrap([t('dash.time'),t('dash.machine'),t('ui.type')+' / '+t('ui.channel'),'ID',t('dash.source'),t('ui.detail')],
            events.map(e => {
                const cat = e.event_category || '';
                const catBadge = cat ? `<span class="badge bg-secondary me-1" style="font-size:9px;">${escapeHtml(cat)}</span>` : '';
                const targetUser = e.target_username ? `<span style="color:#3399ff;">👤${escapeHtml(e.target_username)}</span> ` : '';
                const srcIp = e.source_ip ? `<span style="color:#ff9966;">🌐${escapeHtml(e.source_ip)}</span> ` : '';
                const procName = e.process_name ? `<span style="color:#88ccff;">⚙${escapeHtml(e.process_name.split('\\').pop())}</span> ` : '';
                const cmdLine = e.command_line ? `<span style="color:#ffcc66;font-size:9px;">${escapeHtml((e.command_line||'').substring(0,40))}</span>` : '';
                var desc = escapeHtml(e.description||'');
                var extraInfo = targetUser + srcIp + procName + cmdLine;
                return `<tr data-row='${JSON.stringify(e).replace(/'/g,"&#39;")}' style="cursor:pointer;"><td style="font-family:monospace;font-size:11px;color:#666!important;white-space:nowrap;">${escapeHtml((e.time||'').substring(0,19))}</td><td>${escapeHtml(e.hostname||e.machine_id||'-')}</td><td>${catBadge}<span class="log-type event">${escapeHtml((e.subtype||'').split('/').pop())}</span></td><td>${escapeHtml(e.event_id||'-')}</td><td>${escapeHtml(e.source||'-')}</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${extraInfo}${desc.substring(0,50)}</td></tr>`;
            }));
        document.getElementById('allEventSearch').oninput = function() { const q = this.value.toLowerCase(); el.querySelectorAll('tbody tr').forEach(r => r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none'); };
    });
}

function loadMachineEvents(machineId) {
    const el = document.getElementById('eventList');
    fetch(`/api/events?machine_id=${machineId}&limit=200`).then(r => r.json()).then(events => {
        if (!events.length) { el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noEvents') + '</div>'; return; }
        el.innerHTML = tableWrap([t('dash.time'),t('dash.type'),'ID',t('dash.source'),t('dash.desc')], events.map(e => `<tr data-row='${JSON.stringify(e).replace(/'/g,"&#39;")}' style="cursor:pointer;"><td style="font-family:monospace;font-size:11px;color:#666!important;white-space:nowrap;">${escapeHtml(e.time||'-')}</td><td><span class="log-type event">${escapeHtml(e.subtype||'?')}</span></td><td>${escapeHtml(e.event_id||'-')}</td><td>${escapeHtml(e.source||'-')}</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml((e.description||'').substring(0,80))}</td></tr>`));
        document.getElementById('eventSearch').oninput = function() { const q = this.value.toLowerCase(); el.querySelectorAll('tbody tr').forEach(r => r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none'); };
    }).catch(() => el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErr')+'</div>');
}

function loadAllFim() {
    const el = document.getElementById('allFimList');
    fetch('/api/fim?limit=200').then(r => r.json()).then(events => {
        if (!events.length) { el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noFimEvents') + '</div>'; return; }
        el.innerHTML = tableWrap([t('dash.time'),t('dash.machine'),t('dash.action'),t('dash.path')], events.map(e => `<tr data-row='${JSON.stringify(e).replace(/'/g,"&#39;")}' style="cursor:pointer;"><td style="font-family:monospace;font-size:11px;color:#666!important;white-space:nowrap;">${escapeHtml((e.time||'').substring(0,19))}</td><td>${escapeHtml(e.hostname||e.machine_id||'-')}</td><td><span class="log-type fim">${escapeHtml(e.action||'?')}</span></td><td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(e.path||'-')}</td></tr>`));
    });
}

function loadMachineFim(machineId) {
    const el = document.getElementById('fimList');
    fetch(`/api/fim?machine_id=${machineId}&limit=200`).then(r => r.json()).then(events => {
        if (!events.length) { el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noFimEvents') + '</div>'; return; }
        el.innerHTML = tableWrap([t('dash.time'),t('dash.action'),t('dash.path')], events.map(e => `<tr data-row='${JSON.stringify(e).replace(/'/g,"&#39;")}' style="cursor:pointer;"><td style="font-family:monospace;font-size:11px;color:#666!important;white-space:nowrap;">${escapeHtml(e.time||'-')}</td><td><span class="log-type fim">${escapeHtml(e.action||'?')}</span></td><td style="max-width:500px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(e.path||'-')}</td></tr>`));
    }).catch(() => el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErr')+'</div>');
}

function loadMachineResponses(machineId) {
    const el = document.getElementById('responseList');
    fetch(`/api/responses?machine_id=${machineId}&limit=50`).then(r => r.json()).then(data => {
        if (!data.length) { el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noResponseResults') + '</div>'; return; }
        el.innerHTML = tableWrap([t('dash.time'),t('dash.status'),'Output'], data.map(e => `<tr><td style="font-family:monospace;font-size:11px;color:#666!important;white-space:nowrap;">${escapeHtml((e.timestamp||'').substring(0,19))}</td><td><span class="badge ${e.status==='completed'?'bg-success':e.status==='error'?'bg-danger':'bg-warning text-dark'}">${escapeHtml(e.status||'?')}</span></td><td style="max-width:500px;font-family:monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;">${escapeHtml((e.output||e.error||'-').substring(0,200))}</td></tr>`));
    }).catch(() => el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErr')+'</div>');
}

function loadSyslog() {
    var el = document.getElementById('syslogList');
    var facility = document.getElementById('syslogFacility') ? document.getElementById('syslogFacility').value : '';
    var severity = document.getElementById('syslogSeverity') ? document.getElementById('syslogSeverity').value : '';
    var sourceIp = document.getElementById('syslogSourceIp') ? document.getElementById('syslogSourceIp').value.trim() : '';
    var search = document.getElementById('syslogSearch') ? document.getElementById('syslogSearch').value.trim() : '';
    var params = 'limit=300';
    if(facility) params += '&facility=' + encodeURIComponent(facility);
    if(severity) params += '&severity=' + encodeURIComponent(severity);
    if(sourceIp) params += '&source_ip=' + encodeURIComponent(sourceIp);
    if(search) params += '&search=' + encodeURIComponent(search);
    fetch('/api/syslog?'+params).then(function(r){
        if(!r.ok) throw new Error('HTTP '+r.status);
        return r.json();
    }).then(function(data){
        if(!Array.isArray(data)){ el.innerHTML='<div class="text-center text-muted py-3">'+t('ui.badData')+'</div>'; return; }
        var total = data.length;
        if (!total) { el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-info-circle"></i> ' + t('dash.noSyslog') + (search||facility||severity||sourceIp?'<br><small style="font-size:11px;color:#6a8aaa;">' + t('dash.clearFilter') + '</small>':'<br><small style="font-size:11px;color:#6a8aaa;">' + t('dash.syslogHint') + '</small>') + '</div>'; return; }
        el.innerHTML = '<div class="text-muted mb-1" style="font-size:11px;">' + t('dash.foundRecords', [total]) + (search||facility||severity||sourceIp?t('dash.filtered'):'') + '</div>' +
            tableWrap([t('dash.time'),t('dash.source'),'Facility',t('dash.severity'),t('dash.content')], data.map(function(e){ return '<tr><td style="font-family:monospace;font-size:11px;color:#666!important;white-space:nowrap;">'+escapeHtml((e.timestamp||'').substring(0,19))+'</td><td>'+escapeHtml(e.hostname||e.source_ip||'-')+'</td><td><span class="badge bg-dark" style="font-size:9px;">'+escapeHtml(e.facility||'?')+'</span></td><td><span class="badge '+(e.severity==='error'||e.severity==='critical'?'bg-danger':e.severity==='warning'?'bg-warning text-dark':'bg-secondary')+'">'+escapeHtml(e.severity||'?')+'</span></td><td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="'+escapeHtml(e.message||'')+'">'+escapeHtml((e.message||'').substring(0,120))+'</td></tr>'; }));
    }).catch(function(e){
        el.innerHTML='<div class="text-center text-muted py-3">⚠ '+t('ui.loadSyslogErr')+''+e.message+'<br><small style="font-size:11px;color:#6a8aaa;">'+t('ui.syslogHint')+'</small></div>';
    });
}

function loadAllResponses() {
    const el = document.getElementById('allResponseList');
    fetch('/api/responses?limit=200').then(r => r.json()).then(data => {
        if (!data.length) { el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noResults') + '</div>'; return; }
        el.innerHTML = tableWrap([t('dash.time'),t('dash.machine'),'Action',t('dash.status'),'Output'], data.map(e => `<tr><td style="font-family:monospace;font-size:11px;color:#666!important;white-space:nowrap;">${escapeHtml((e.timestamp||'').substring(0,19))}</td><td>${escapeHtml(e.hostname||e.machine_id||'-')}</td><td><span class="log-type response">${escapeHtml(e.action||'?')}</span></td><td><span class="badge ${e.status==='completed'?'bg-success':e.status==='error'?'bg-danger':'bg-warning text-dark'}">${escapeHtml(e.status||'?')}</span></td><td style="max-width:300px;font-family:monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;">${escapeHtml((e.output||e.error||'-').substring(0,150))}</td></tr>`));
    });
}

function loadNetflow() {
    const tbody = document.querySelector('#netflowTable tbody');
    const statsRow = document.getElementById('netflowStatsRow');
    const beaconBody = document.getElementById('netflowBeaconBody');
    const updatedEl = document.getElementById('netflowUpdated');
    if (tbody) tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted py-3"><div class="spinner-border spinner-border-sm text-success"></div> ' + t('ui.loading') + '</td></tr>';

    // Stats
    fetch('/api/netflow/stats').then(r => r.json()).then(st => {
        if (statsRow && st) {
            const cards = [
                { icon: 'bi-broadcast', label: t('netflow.pkts'), val: st.packets || 0 },
                { icon: 'bi-arrow-left-right', label: t('netflow.flows'), val: st.flows || 0 },
                { icon: 'bi-activity', label: 'NetFlow v5', val: st.v5 || 0 },
                { icon: 'bi-activity', label: 'NetFlow v9', val: st.v9 || 0 }
            ];
            statsRow.innerHTML = cards.map(c => `<div class="col-md-3 col-6"><div class="card"><div class="card-body py-2 d-flex align-items-center justify-content-between"><div><div class="text-muted" style="font-size:11px;">${c.label}</div><div style="font-size:20px;font-weight:600;color:#8ee6a8;">${c.val}</div></div><i class="bi ${c.icon} text-success" style="font-size:22px;opacity:.7;"></i></div></div></div>`).join('');
        }
    }).catch(() => {});

    // Beaconing
    const protoName = p => p === 6 ? 'TCP' : p === 17 ? 'UDP' : p === 1 ? 'ICMP' : (p === 0 || p == null ? '?' : String(p));
    fetch('/api/netflow/beaconing').then(r => r.json()).then(data => {
        if (!beaconBody) return;
        const arr = Array.isArray(data) ? data : (data.beacons || data.suspects || []);
        if (!arr.length) { beaconBody.innerHTML = '<div class="text-muted">' + t('netflow.noBeacon') + '</div>'; return; }
        beaconBody.innerHTML = arr.map(b => {
            const interval = b.span_seconds && b.flow_count > 1 ? Math.round(b.span_seconds / (b.flow_count - 1)) : '-';
            return `<div style="background:#2a0e0e;border-left:4px solid #ff5555;padding:8px 12px;margin-bottom:5px;border-radius:4px;"><div class="d-flex justify-content-between align-items-center flex-wrap"><span><span class="badge bg-danger">⚠ C2?</span> <strong style="color:#ffb3b3;">${escapeHtml(b.src_ip||'?')}</strong> → <strong style="color:#ffb3b3;">${escapeHtml(b.dst_ip||'?')}</strong> <span class="text-muted">:${escapeHtml(b.dst_port||'-')} ${protoName(b.protocol)}</span></span><small class="text-muted">${b.flow_count||0} flows · ${t('ssh.period')} ~${interval}s · ${b.span_seconds||0}s</small></div></div>`;
        }).join('');
    }).catch(() => {});

    // Flows
    fetch('/api/netflow?limit=200').then(r => r.json()).then(data => {
        const list = Array.isArray(data) ? data : (data.flows || []);
        if (tbody) {
            if (!list.length) { tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted py-3">' + t('dash.noNetworkTraffic') + '</td></tr>'; }
            else {
                tbody.innerHTML = list.map(e => {
                    const sp = e.src_port || '-', dp = e.dst_port || '-';
                    const proto = protoName(e.protocol);
                    return `<tr style="font-family:monospace;font-size:11px;"><td style="white-space:nowrap;">${escapeHtml((e.received_at||'').substring(0,19))}</td><td>${escapeHtml(e.src_ip||'-')}</td><td>${escapeHtml(sp)}</td><td>${escapeHtml(e.dst_ip||'-')}</td><td>${escapeHtml(dp)}</td><td><span class="badge ${proto==='TCP'?'bg-info':proto==='UDP'?'bg-warning text-dark':'bg-secondary'}">${proto}</span></td><td>${fmtBytes(e.bytes||0)}</td><td>${e.packets||0}</td><td>${escapeHtml(e.exporter_ip||'-')}</td></tr>`;
                }).join('');
            }
        }
        if (updatedEl) updatedEl.textContent = t('netflow.updated') + ': ' + new Date().toLocaleTimeString();
    }).catch(() => { if (tbody) tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted py-3">⚠ ' + t('ui.error') + '</td></tr>'; });
}
function loadNetwork() {
    const el = document.getElementById('networkList');
    fetch('/api/network?limit=200').then(r => r.json()).then(data => {
        let html = '';
        if (!data.length) { html += '<div class="text-center text-muted py-2">' + t('dash.noNetworkTraffic') + '</div>'; }
        else {
            html += '<h6 class="px-2 pt-2" style="font-size:12px;color:#88ccff;"><i class="bi bi-diagram-3"></i> '+t('ui.networkTraffic')+'</h6>';
            html += tableWrap([t('dash.time'),t('dash.machine'),t('dash.source'),t('dash.dest'),t('dash.protocol'),'Port','Size',t('dash.app')],
                data.map(e => {
                    const row = Object.assign({}, e, {type: 'network_traffic'});
                    if (e.raw_data) { try {
                        const rd = typeof e.raw_data === 'string' ? JSON.parse(e.raw_data) : e.raw_data;
                        if (rd.ip) { row.src_ip = row.src_ip || rd.ip.src; row.dst_ip = row.dst_ip || rd.ip.dst; row.ip_version = rd.ip.version; row.ip_ihl = rd.ip.ihl; row.ip_tos = rd.ip.tos; row.ip_len = rd.ip.total_len; row.ip_id = rd.ip.identification; row.ip_flags = rd.ip.flags; row.ip_frag_offset = rd.ip.frag_offset; row.ip_ttl = rd.ip.ttl; row.ip_proto = rd.ip.protocol; row.ip_checksum = rd.ip.checksum; }
                        if (rd.tcp) { row.src_port = row.src_port || rd.tcp.sport; row.dst_port = row.dst_port || rd.tcp.dport; row.tcp_seq = rd.tcp.seq; row.tcp_ack = rd.tcp.ack; row.tcp_data_offset = rd.tcp.hdr_len; var fv=0; if(rd.tcp.flags){rd.tcp.flags.forEach(function(f){if(f==='FIN')fv|=1;if(f==='SYN')fv|=2;if(f==='RST')fv|=4;if(f==='PSH')fv|=8;if(f==='ACK')fv|=16;if(f==='URG')fv|=32;if(f==='ECE')fv|=64;if(f==='CWR')fv|=128;if(f==='NS')fv|=256;});} row.tcp_flags_hex = '0x' + fv.toString(16).padStart(3,'0'); row.tcp_flags_detail = (rd.tcp.flags||[]).join(', '); row.tcp_window = rd.tcp.window; row.tcp_checksum = rd.tcp.checksum; row.tcp_urg_ptr = rd.tcp.urg_ptr; row.protocol = 'TCP'; }
                        if (rd.udp) { row.src_port = row.src_port || rd.udp.sport; row.dst_port = row.dst_port || rd.udp.dport; row.udp_len = rd.udp.len; row.udp_checksum = rd.udp.checksum; row.protocol = 'UDP'; }
                        if (rd.payload) { row.payload_size = rd.payload.size; row.payload_hex = rd.payload.hex; row.full_payload_hex_dump = rd.payload.full_hex_dump || row.full_payload_hex_dump || ''; }
                        if (rd.eth) { row.src_mac = rd.eth.src; row.dst_mac = rd.eth.dst; }
                    } catch(ex) {} }
                    // Parse IP từ raw_data để hiển thị (DB có thể lưu sai)
                    const displaySrc = row.src_ip && row.src_ip !== '0.0.0.0' ? row.src_ip : (row.dst_ip && row.dst_ip !== '0.0.0.0' ? (row.protocol === 'TCP' ? 'Local' : '-') : '-');
                    const displayDst = row.dst_ip && row.dst_ip !== '0.0.0.0' ? row.dst_ip : '-';
                    const displayPort = row.dst_port || row.src_port || '-';
                    // App protocol badge (v1.12.0)
                    let appBadge = '';
                    if (row.protocol_app === 'DNS') {
                        const dns = row.dns_info || {};
                        const nxdomain = dns.is_nxdomain ? ' ❌' : '';
                        appBadge = `<span class="badge bg-info" title="${escapeHtml((dns.qtype_name||'?') + ' rcode:' + (dns.rcode_name||'?'))}">🌐 DNS${nxdomain}</span>`;
                    } else if (row.protocol_app === 'HTTP') {
                        const http = row.http_info || {};
                        appBadge = `<span class="badge bg-warning text-dark" title="${escapeHtml((http.method||'GET') + ' ' + (http.uri||'/'))}">📄 ${escapeHtml(http.host||'HTTP')}</span>`;
                    } else {
                        appBadge = '<span class="text-muted" style="font-size:10px;">-</span>';
                    }
                    return `<tr data-row='${JSON.stringify(row).replace(/'/g,"&#39;")}' style="cursor:pointer;"><td style="font-family:monospace;font-size:11px;color:#666!important;white-space:nowrap;">${escapeHtml((e.timestamp||'').substring(0,19))}</td><td>${escapeHtml(e.hostname||e.machine_id||'-')}</td><td style="font-family:monospace;font-size:10px;">${escapeHtml(displaySrc)}</td><td style="font-family:monospace;font-size:10px;">${escapeHtml(displayDst)}</td><td><span class="badge ${e.protocol==='TCP'?'bg-info':e.protocol==='UDP'?'bg-warning text-dark':'bg-secondary'}">${escapeHtml(e.protocol||'?')}</span></td><td style="font-family:monospace;font-size:10px;">${escapeHtml(displayPort)}</td><td>${escapeHtml(e.size||0)}</td><td>${appBadge}</td></tr>`})
            );
        }
        fetch('/api/inspection?limit=100').then(r2 => r2.json()).then(inspData => {
            if (inspData.length) {
                html += '<hr style="border-color:#2a3a4a;margin:8px 0;"><h6 class="px-2" style="font-size:12px;color:#88ccff;"><i class="bi bi-search"></i> Deep Packet Inspection (DNS / TLS / HTTP / Beaconing)</h6>';
                html += inspData.map(e => `<div style="background:#1a1a2a;border-left:4px solid #3399ff;padding:6px 10px;margin-bottom:3px;border-radius:4px;"><div class="d-flex justify-content-between align-items-center"><span><span class="badge ${e.subtype==='dns_query'?'bg-info':e.subtype==='tls_sni'?'bg-success':e.subtype==='http_host'?'bg-warning text-dark':e.subtype==='beaconing'?'bg-danger':'bg-secondary'}">${escapeHtml(e.subtype||'?')}</span> <strong style="color:#d0d8e0;">${escapeHtml(e.domain||e.dst_ip||'-')}</strong>${e.subtype==='beaconing'?` (${t('ssh.period')} ${escapeHtml(e.avg_interval_sec)}s)`:''}</span><small class="text-muted">${escapeHtml((e.timestamp||'').substring(0,19))}</small></div></div>`).join('');
            }
            el.innerHTML = html;
        });
    });
}

function loadInspection() {
    const el = document.getElementById('inspectionList');
    fetch('/api/inspection?limit=300').then(r => r.json()).then(data => {
        if (!data.length) { el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noDpiData') + '</div>'; return; }
        el.innerHTML = data.map(e => `<div style="background:#1a1a2a;border-left:4px solid #3399ff;padding:8px 12px;margin-bottom:4px;border-radius:4px;"><div class="d-flex justify-content-between align-items-center"><span><span class="badge ${e.subtype==='dns_query'?'bg-info':e.subtype==='tls_sni'?'bg-success':e.subtype==='http_host'?'bg-warning text-dark':e.subtype==='beaconing'?'bg-danger':'bg-secondary'}">${escapeHtml(e.subtype||'?')}</span> <strong style="color:#d0d8e0;">${escapeHtml(e.domain||e.dst_ip||'-')}</strong></span><small class="text-muted">${escapeHtml((e.timestamp||'').substring(0,19))}</small></div></div>`).join('');
    });
}

function loadYara() {
    const el = document.getElementById('yaraList');
    fetch('/api/yara?limit=500').then(r => r.json()).then(data => {
        if (!data.length) { el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-check-circle text-success"></i> '+t('ui.noMalware')+'</div>'; return; }
        // v2.6.5: Highlight Binary_Padding_Evasion alerts
        const paddingAlerts = data.filter(e => e.rule_name === 'Binary_Padding_Evasion');
        let html = '';
        if (paddingAlerts.length > 0) {
            html += '<div class="p-2 mb-2" style="background:#1a1000;border:1px solid #ffcc66;border-radius:6px;">';
            html += '<strong style="color:#ffcc66;">⚠ Binary Padding Evasion Detected (' + paddingAlerts.length + ' files)</strong>';
            html += '<div style="font-size:11px;color:#ffaa44;margin-top:4px;">'+t('ui.lowEntropyHint')+'</div>';
            html += '</div>';
        }
        html += buildGroupedByMachine(data, 'yara', '🦠 YARA/Pattern Scan');
        el.innerHTML = html;
    });
}

function statusOptions(cur) {
    var st = cur || 'new';
    var opts = [['new', t('tr.new')], ['in_progress', t('tr.inProgress')], ['resolved', t('tr.resolved')], ['false_positive', t('tr.fp')]];
    return opts.map(function(o) { return '<option value="' + o[0] + '"' + (st === o[0] ? ' selected' : '') + '>' + o[1] + '</option>'; }).join('');
}

function setThreatStatus(id, status) {
    fetch('/api/threats/' + id + '/status', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({status: status})})
        .then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) { showToast('✅ ' + t('tr.updated')); }
            else { showToast('❌ ' + (d.error || '')); }
        }).catch(function() { showToast('❌ ' + t('ui.connErrShort')); });
}

function loadThreats() {
    const el = document.getElementById('threatList');
    fetch('/api/threats?limit=500').then(r => r.json()).then(data => {
        if (!data.length) { el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-check-circle text-success"></i> ' + t('dash.noCriticalAlerts') + '</div>'; return; }
        el.innerHTML = buildGroupedByMachine(data, 'threats', '⚠ Threat Alerts');
    });
}

function loadVulns() {
    const el = document.getElementById('vulnList');
    fetch('/api/vulns?limit=500').then(r => r.json()).then(data => {
        if (!data.length) { el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-check-circle text-success"></i> ' + t('dash.noVulns') + '</div>'; return; }
        el.innerHTML = buildGroupedByMachine(data, 'vulns', '🐞 Vulnerability Alerts (CVE)');
    }).catch(() => { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErrX')+'</div>'; });
}

function loadSca() {
    const el = document.getElementById('scaList');
    fetch('/api/sca?limit=500').then(r => r.json()).then(data => {
        if (!data.length) { el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noScaData') + '</div>'; return; }
        el.innerHTML = buildGroupedByMachine(data, 'sca', '📋 SCA Compliance');
    }).catch(() => { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErrX')+'</div>'; });
}

// ===== v2.6.2: SYSMON + MEMORY SCANNER =====
function loadSysmon() {
    const el = document.getElementById('sysmonList');
    const sysmonTab = document.getElementById('sysmonTabContent');
    if (!el) return;
    el.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-success" role="status"></div><p class="text-muted mt-2" style="font-size:13px;">' + t('dash.loadingSysmon') + '</p></div>';
    fetch('/api/sysmon?limit=500').then(r => r.json()).then(data => {
        if (!data.length) {
            el.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-info-circle"></i><p class="mt-2">' + t('dash.noSysmonEvents') + '</p><p style="font-size:11px;color:#5a6a7a;">Cần Sysmon64 cài trên máy trạm + Agent v2.6.1+</p></div>';
            return;
        }
        // Stats bar
        const critical = data.filter(e => e.severity === 'CRITICAL').length;
        const high = data.filter(e => e.severity === 'HIGH').length;
        const medium = data.filter(e => e.severity === 'MEDIUM').length;
        const credDump = data.filter(e => e.credential_dumping == 1).length;
        const persistence = data.filter(e => e.persistence_detected == 1).length;
        const injection = data.filter(e => e.sysmon_event_id == 8).length;
        const lsassAccess = data.filter(e => e.sysmon_event_id == 10 && e.target_process && e.target_process.toLowerCase().includes('lsass')).length;

        let html = '<div class="p-2">';
        html += '<div class="row text-center mb-3" style="position:sticky;top:0;z-index:10;background:var(--bg-dark);padding-top:8px;padding-bottom:8px;border-bottom:1px solid var(--border-color);">';
        html += '<div class="col-3"><div class="stat-card" style="background:#1a1a2a;"><div class="value" style="color:#00d4aa;">' + data.length + '</div><div class="label">'+t('ui.totalEvents')+'</div></div></div>';
        html += '<div class="col-3"><div class="stat-card" style="background:#3a1a1a;"><div class="value" style="color:#ff4444;">' + critical + '</div><div class="label">Critical</div></div></div>';
        html += '<div class="col-3"><div class="stat-card" style="background:#1a2a3a;"><div class="value" style="color:#ffcc66;">' + high + '</div><div class="label">High</div></div></div>';
        html += '<div class="col-3"><div class="stat-card" style="background:#1a1a2a;"><div class="value" style="color:#8888ff;">' + medium + '</div><div class="label">Medium</div></div></div>';
        html += '</div>';

        // Detection summary
        if (credDump > 0 || persistence > 0 || injection > 0 || lsassAccess > 0) {
            html += '<div class="mb-3 p-2" style="background:#1a0a0a;border:1px solid #ff4444;border-radius:6px;">';
            html += '<strong style="color:#ff6666;">'+t('ui.dangerDetected')+'</strong> ';
            const alerts = [];
            if (credDump > 0) alerts.push('<span class="badge bg-danger">' + credDump + ' Credential Dumping</span>');
            if (lsassAccess > 0) alerts.push('<span class="badge bg-danger">' + lsassAccess + ' LSASS Access</span>');
            if (injection > 0) alerts.push('<span class="badge bg-warning text-dark">' + injection + ' Process Injection</span>');
            if (persistence > 0) alerts.push('<span class="badge bg-warning text-dark">' + persistence + ' Persistence</span>');
            html += alerts.join(' ');
            html += '</div>';
        }

        // Event table
        html += '<div style="max-height:600px;overflow-y:auto;">';
        html += '<table class="table table-data table-hover"><thead><tr>';
        html += '<th style="width:100px;">Time</th><th style="width:40px;">EID</th><th>Process</th><th style="width:150px;">Type</th><th>Detail</th><th style="width:60px;">Sev</th>';
        html += '</tr></thead><tbody>';

        data.forEach(e => {
            const ts = (e.timestamp || '').substring(0, 19);
            const eid = e.sysmon_event_id || 0;
            const procName = escapeHtml(e.process_name || '');
            const evtType = escapeHtml(e.event_type || '');
            const sev = escapeHtml(e.severity || 'INFO');
            const sevColor = sev === 'CRITICAL' ? '#ff4444' : sev === 'HIGH' ? '#ffcc66' : sev === 'MEDIUM' ? '#8888ff' : '#8892a4';

            // Build detail column
            let detail = '';
            if (eid === 1) {
                detail = (e.command_line || '').substring(0, 80);
                if (e.parent_process) detail += '<br><small style="color:#666;">Parent: ' + escapeHtml(e.parent_process) + '</small>';
            } else if (eid === 3) {
                detail = (e.src_ip || '?') + ':' + (e.src_port || '?') + ' → ' + (e.dst_ip || '?') + ':' + (e.dst_port || '?');
            } else if (eid === 7) {
                detail = (e.dll_name || e.image_loaded || '').substring(0, 80);
                if (e.signed) detail += ' <span class="badge ' + (e.signed === 'true' ? 'bg-success' : 'bg-warning') + '" style="font-size:9px;">signed:' + e.signed + '</span>';
            } else if (eid === 8) {
                detail = '→ ' + escapeHtml(e.target_process || '');
                if (e.injection_type) detail += ' (' + escapeHtml(e.injection_type) + ')';
            } else if (eid === 10) {
                detail = '→ ' + escapeHtml(e.target_process || '');
                if (e.granted_access) detail += ' <small style="color:#666;">Access:' + escapeHtml(e.granted_access) + '</small>';
            } else if (eid === 11) {
                detail = escapeHtml(e.file_name || e.file_path || '');
            } else if (eid === 22) {
                detail = escapeHtml(e.dns_query || '');
            } else {
                detail = escapeHtml(e.description || e.suspicion_reason || '');
            }

            const rowColor = sev === 'CRITICAL' ? 'background:#1a0000!important;' : sev === 'HIGH' ? 'background:#1a1000!important;' : '';
            html += '<tr style="' + rowColor + 'cursor:pointer;" onclick="showSysmonDetail(' + JSON.stringify(e).replace(/"/g, '"') + ')">';
            html += '<td style="font-size:10px;color:#666;white-space:nowrap;">' + ts + '</td>';
            html += '<td><span class="badge bg-dark" style="font-size:9px;">' + eid + '</span></td>';
            html += '<td style="font-size:12px;">' + procName + '<br><small style="color:#555;font-size:9px;">PID:' + (e.pid || '?') + ' | ' + escapeHtml(e.hostname || '') + '</small></td>';
            html += '<td><span class="log-type event" style="font-size:9px;">' + evtType + '</span></td>';
            html += '<td style="font-size:11px;">' + detail + '</td>';
            html += '<td><span style="color:' + sevColor + ';font-weight:bold;font-size:10px;">' + sev + '</span></td>';
            html += '</tr>';
        });

        html += '</tbody></table></div></div>';
        el.innerHTML = html;
    }).catch(e => { el.innerHTML = '<div class="text-center text-muted py-3">❌ '+t('ui.loadSysmonErr')+'' + escapeHtml(e.message) + '</div>'; });
}

function loadMemory() {
    const el = document.getElementById('memoryList');
    if (!el) return;
    el.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-success" role="status"></div><p class="text-muted mt-2" style="font-size:13px;">' + t('dash.loadingMemory') + '</p></div>';
    fetch('/api/memory?limit=200').then(r => r.json()).then(data => {
        if (!data.length) {
            el.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-check-circle text-success"></i><p class="mt-2" style="font-size:16px;">'+t('ui.noMemAnomaly')+'</p><p style="font-size:11px;color:#5a6a7a;">'+t('ui.memScannerOk')+'</p></div>';
            return;
        }
        // v2.6.5: Count by alert type
        const sysProcAlerts = data.filter(e => e.alert_type === 'system_process_injection');
        const hollowingAlerts = data.filter(e => e.alert_type === 'suspicious_memory');
        const spoofAlerts = data.filter(e => e.alert_type === 'spoofed_process_name');

        let html = '<div class="p-2">';
        html += '<div class="mb-3 p-2" style="background:#1a0a0a;border:1px solid #ff4444;border-radius:6px;">';
        html += '<strong style="color:#ff6666;">⚠ Memory Anomalies Detected: ' + data.length + '</strong>';
        if (sysProcAlerts.length > 0) html += ' <span class="badge bg-danger">' + sysProcAlerts.length + ' System Process Injection</span>';
        if (hollowingAlerts.length > 0) html += ' <span class="badge bg-warning text-dark">' + hollowingAlerts.length + ' Process Hollowing</span>';
        if (spoofAlerts.length > 0) html += ' <span class="badge bg-info">' + spoofAlerts.length + ' Name Spoofing</span>';
        html += '</div>';
        html += '<table class="table table-data table-hover"><thead><tr><th>Time</th><th>Type</th><th>Process</th><th>Detail</th><th>Sev</th></tr></thead><tbody>';
        data.forEach(e => {
            const ts = (e.timestamp || '').substring(0, 19);
            const proc = escapeHtml(e.process_name || '');
            const alertType = escapeHtml(e.alert_type || 'unknown');
            const typeLabel = alertType === 'system_process_injection' ? '🔴 System Injection' :
                              alertType === 'suspicious_memory' ? '🟠 Process Hollowing' :
                              alertType === 'spoofed_process_name' ? '🟡 Name Spoofing' : alertType;
            const sev = escapeHtml(e.severity || 'HIGH');
            const sevColor = sev === 'CRITICAL' ? '#ff4444' : sev === 'HIGH' ? '#ffcc66' : '#8888ff';

            // Build detail with module info for system process injections
            let detail = escapeHtml(e.description || e.suspicion_reason || '');
            if (e.alert_type === 'system_process_injection') {
                if (e.module_name) detail += '<br><small style="color:#888;">Module: ' + escapeHtml(e.module_name) + '</small>';
                if (e.module_path) detail += '<br><small style="color:#666;font-family:monospace;font-size:9px;">' + escapeHtml(e.module_path) + '</small>';
                if (e.signed !== undefined) {
                    const signBadge = e.signed ? '<span class="badge bg-success" style="font-size:8px;">Signed</span>' : '<span class="badge bg-danger" style="font-size:8px;">Unsigned</span>';
                    const signerInfo = e.signer ? ' <small style="color:#888;">by ' + escapeHtml(e.signer).substring(0, 40) + '</small>' : '';
                    detail += '<br>' + signBadge + signerInfo;
                }
            }
            if (e.pid) detail += '<br><small style="color:#555;font-size:9px;">PID:' + e.pid + '</small>';

            const rowColor = sev === 'CRITICAL' ? 'background:#1a0000!important;' : sev === 'HIGH' ? 'background:#1a1000!important;' : '';
            html += '<tr style="' + rowColor + 'cursor:pointer;"><td style="font-size:10px;color:#666;white-space:nowrap;">' + ts + '</td>';
            html += '<td><span style="font-size:10px;">' + typeLabel + '</span></td>';
            html += '<td>' + proc + '</td>';
            html += '<td style="font-size:11px;">' + detail + '</td>';
            html += '<td><span style="color:' + sevColor + ';font-weight:bold;font-size:10px;">' + sev + '</span></td></tr>';
        });
        html += '</tbody></table></div>';
        el.innerHTML = html;
    }).catch(e => { el.innerHTML = '<div class="text-center text-muted py-3">❌ '+t('ui.loadMemErr')+'' + escapeHtml(e.message) + '</div>'; });
}

// v2.6.2: Sysmon detail popup
function showSysmonDetail(event) {
    let detailHtml = '<div style="max-height:500px;overflow-y:auto;font-size:12px;">';
    detailHtml += '<table class="table table-sm table-dark">';
    for (const [key, val] of Object.entries(event)) {
        if (key === 'raw_data') continue;
        const v = val !== null && val !== undefined ? String(val).substring(0, 200) : '-';
        detailHtml += '<tr><td style="color:#8892a4;white-space:nowrap;">' + escapeHtml(key) + '</td><td style="word-break:break-all;">' + escapeHtml(v) + '</td></tr>';
    }
    detailHtml += '</table></div>';
    const popup = window.open('', '_blank', 'width=700,height=600,scrollbars=yes');
    if (popup) {
        popup.document.write('<html><head><title>Sysmon Event Detail</title><style>body{background:#0d1117;color:#e4e7eb;font-family:monospace;padding:16px;}table{width:100%;border-collapse:collapse;}td{padding:4px 8px;border-bottom:1px solid #1e2a3a;}h3{color:#00d4aa;}<\/style><style>.modal-body { max-height: 70vh !important; overflow-y: auto !important; }<\/style>\n<\/head><body><h3>Sysmon Event Detail<\/h3>' + detailHtml + '<\/body><\/html>');
        popup.document.close();
    }
}

// ===== v2.0.2: Group alerts by machine with expand/collapse =====
function buildGroupedByMachine(data, type, title) {
    if (!data || !data.length) return '<div class="text-center text-muted py-3">' + t('dash.noData') + '</div>';

    // Group by machine_id
    const groups = {};
    data.forEach(item => {
        const mid = item.machine_id || item.hostname || 'Unknown';
        if (!groups[mid]) groups[mid] = { machine_id: mid, hostname: item.hostname || mid, items: [], latest: '', counts: { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, FAIL:0, PASS:0, WARN:0 } };
        groups[mid].items.push(item);
        const sev = item.severity || item.status || '';
        if (groups[mid].counts[sev] !== undefined) groups[mid].counts[sev]++;
        const ts = item.timestamp || item.time || item.received_at || '';
        if (ts > groups[mid].latest) {
            groups[mid].latest = ts;
            groups[mid].latestItem = item;
        }
    });

    // Sort groups by latest timestamp (newest first)
    const sorted = Object.values(groups).sort((a, b) => (b.latest || '').localeCompare(a.latest || ''));

    // Summary stats
    const totalMachines = sorted.length;
    const totalAlerts = data.length;
    const criticalCount = data.filter(e => (e.severity||'').toUpperCase() === 'CRITICAL' || (e.status||'').toUpperCase() === 'FAIL').length;

    // v2.0.2: Sticky stats bar + scrollable machine list
    let html = '<div class="p-2">';
    html += '<div class="row text-center mb-3" style="position:sticky;top:0;z-index:10;background:var(--bg-dark);padding-top:8px;padding-bottom:8px;border-bottom:1px solid var(--border-color);">';
    html += '<div class="col-3"><div class="stat-card" style="background:#1a1a2a;"><div class="value" style="color:#ffcc66;">' + totalMachines + '</div><div class="label">'+t('ui.machines')+'</div></div></div>';
    html += '<div class="col-3"><div class="stat-card" style="background:#1a1a2a;"><div class="value" style="color:#ff6666;">' + totalAlerts + '</div><div class="label">'+t('ui.totalAlerts')+'</div></div></div>';
    html += '<div class="col-3"><div class="stat-card" style="background:#3a1a1a;"><div class="value" style="color:#ff4444;">' + criticalCount + '</div><div class="label">'+t('ui.critical')+'</div></div></div>';
    html += '<div class="col-3"><div class="stat-card" style="background:#1a2a3a;"><div class="value" style="color:#00d4aa;">' + title + '</div><div class="label">'+t('ui.type')+'</div></div></div>';
    html += '</div>';

    sorted.forEach((group, idx) => {
        const mid = group.machine_id;
        const hostname = group.hostname || mid;
        const itemCount = group.items.length;
        const latest = group.latestItem;
        const c = group.counts;
        const sevBadges = [];
        if (c.CRITICAL > 0) sevBadges.push('<span class="badge bg-danger">' + c.CRITICAL + ' CRIT</span>');
        if (c.HIGH > 0) sevBadges.push('<span class="badge bg-warning text-dark">' + c.HIGH + ' HIGH</span>');
        if (c.MEDIUM > 0) sevBadges.push('<span class="badge bg-info">' + c.MEDIUM + ' MED</span>');
        if (c.LOW > 0) sevBadges.push('<span class="badge bg-secondary">' + c.LOW + ' LOW</span>');
        if (c.FAIL > 0) sevBadges.push('<span class="badge bg-danger">' + c.FAIL + ' FAIL</span>');
        if (c.PASS > 0) sevBadges.push('<span class="badge bg-success">' + c.PASS + ' PASS</span>');
        if (c.WARN > 0) sevBadges.push('<span class="badge bg-warning text-dark">' + c.WARN + ' WARN</span>');

        let latestSummary = '';
        if (latest) {
            if (type === 'threats') latestSummary = '<span style="color:#ff8888;">[' + (latest.severity||'?') + '] ' + (latest.rule_name||latest.rule_id||'?') + '</span> - ' + ((latest.description||'').substring(0, 80));
            else if (type === 'vulns') latestSummary = '<span style="color:#ff8888;">' + (latest.cve||'?') + '</span> ' + (latest.severity||'?') + ' - ' + (latest.software||'') + ' ' + (latest.version||'');
            else if (type === 'yara') latestSummary = '<span style="color:#ff6644;">' + (latest.rule_name||'?') + '</span> - ' + ((latest.description||'').substring(0, 80));
            else if (type === 'sca') latestSummary = '<span class="badge ' + (latest.status==='PASS'?'bg-success':latest.status==='FAIL'?'bg-danger':'bg-warning text-dark') + '">' + (latest.status||'?') + '</span> ' + (latest.title||latest.check_id||'?');
        }

        html += '<div style="background:#111827;border:1px solid #1e2a3a;border-radius:8px;margin-bottom:8px;cursor:pointer;" onclick="toggleMachineGroup(\'grp_' + type + '_' + idx + '\')">';
        html += '<div class="d-flex justify-content-between align-items-center p-3" style="border-bottom:1px solid #1e2a3a;">';
        html += '<div style="flex:1;">';
        html += '<strong style="color:#e4e7eb;font-size:14px;">🖥 ' + hostname + '</strong> ';
        html += '<small class="text-muted" style="font-size:10px;">(' + mid.substring(0,12) + '...)</small>';
        html += '<div style="margin-top:4px;">' + sevBadges.join(' ') + ' <span class="badge bg-dark">' + itemCount + ' alerts</span></div>';
        html += '<div style="margin-top:4px;font-size:11px;color:#8892a4;">'+t('ui.latest')+'' + latestSummary + '</div>';
        html += '<div style="margin-top:2px;font-size:10px;color:#5a6a7a;">⏱ ' + (group.latest ? group.latest.substring(0,19) : '-') + '</div>';
        html += '</div>';
        html += '<span id="grp_arrow_' + type + '_' + idx + '" style="color:#8892a4;font-size:14px;transition:transform 0.3s;">▼</span>';
        html += '</div>';

        // Expandable detail table
        html += '<div id="grp_' + type + '_' + idx + '" style="display:none;max-height:400px;overflow-y:auto;" onclick="event.stopPropagation();">';
        if (type === 'threats') {
            html += '<table class="table table-data" style="font-size:11px;margin:0;"><thead><tr><th>Thời gian</th><th>' + t('dash.severity') + '</th><th>Rule ID</th><th>Rule Name</th><th>' + t('dash.desc') + '</th><th>' + t('tr.status') + '</th><th style="width:50px;">🛡️</th></tr></thead><tbody>';
            group.items.sort((a,b) => (b.timestamp||'').localeCompare(a.timestamp||'')).forEach(e => {
                html += '<tr><td style="font-size:10px;white-space:nowrap;">' + (e.timestamp||'').substring(0,19) + '</td><td><span class="badge ' + (e.severity==='CRITICAL'?'bg-danger':e.severity==='HIGH'?'bg-warning text-dark':e.severity==='MEDIUM'?'bg-info':'bg-secondary') + '">' + (e.severity||'?') + '</span></td><td>' + (e.rule_id||'-') + '</td><td>' + (e.rule_name||'-') + '</td><td style="max-width:300px;">' + (e.description||'-').substring(0,120) + '</td><td><select style="font-size:9px;background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);padding:1px 2px;" onchange="setThreatStatus(' + e.id + ', this.value)">' + statusOptions(e.status) + '</select></td>' + _actionButtons('threats', e) + '</tr>';
            });
        } else if (type === 'vulns') {
            html += '<table class="table table-data" style="font-size:11px;margin:0;"><thead><tr><th>Thời gian</th><th>' + t('dash.severity') + '</th><th>CVE</th><th>' + t('dash.software') + '</th><th>' + t('dash.desc') + '</th><th style="width:50px;">🛡️</th></tr></thead><tbody>';
            group.items.sort((a,b) => (b.timestamp||'').localeCompare(a.timestamp||'')).forEach(e => {
                html += '<tr><td style="font-size:10px;white-space:nowrap;">' + (e.timestamp||'').substring(0,19) + '</td><td><span class="badge ' + (e.severity==='CRITICAL'?'bg-danger':e.severity==='HIGH'?'bg-warning text-dark':'bg-info') + '">' + (e.severity||'?') + '</span></td><td style="font-family:monospace;">' + (e.cve||'-') + '</td><td>' + (e.software||'-') + ' v' + (e.version||'?') + '</td><td style="max-width:300px;">' + (e.description||'-').substring(0,120) + '</td>' + _actionButtons('vulns', e) + '</tr>';
            });
        } else if (type === 'yara') {
            html += '<table class="table table-data" style="font-size:11px;margin:0;"><thead><tr><th>Thời gian</th><th>Rule Name</th><th>File</th><th>' + t('dash.desc') + '</th><th style="width:50px;">🛡️</th></tr></thead><tbody>';
            group.items.sort((a,b) => (b.timestamp||'').localeCompare(a.timestamp||'')).forEach(e => {
                html += '<tr><td style="font-size:10px;white-space:nowrap;">' + (e.timestamp||'').substring(0,19) + '</td><td style="color:#ff6644;font-weight:600;">' + (e.rule_name||'?') + '</td><td style="font-family:monospace;font-size:10px;">' + (e.file||'-') + '</td><td style="max-width:300px;">' + (e.description||'-').substring(0,120) + '</td>' + _actionButtons('yara', e) + '</tr>';
            });
        } else if (type === 'sca') {
            html += '<table class="table table-data" style="font-size:11px;margin:0;"><thead><tr><th>Thời gian</th><th>Trạng thái</th><th>Check ID</th><th>Tiêu đề</th><th>' + t('dash.desc') + '</th></tr></thead><tbody>';
            group.items.sort((a,b) => (b.timestamp||'').localeCompare(a.timestamp||'')).forEach(e => {
                html += '<tr><td style="font-size:10px;white-space:nowrap;">' + (e.timestamp||'').substring(0,19) + '</td><td><span class="badge ' + (e.status==='PASS'?'bg-success':e.status==='FAIL'?'bg-danger':'bg-warning text-dark') + '">' + (e.status||'?') + '</span></td><td>' + (e.check_id||'-') + '</td><td>' + (e.title||'-') + '</td><td style="max-width:300px;">' + (e.description||'-').substring(0,120) + '</td></tr>';
            });
        }
        html += '</tbody></table></div>';
        html += '</div>';
    });

    html += '<div class="text-muted mt-2" style="font-size:10px;text-align:center;">' + t('ui.showingAlerts',[totalAlerts,totalMachines]) + '</div>';
    html += '</div>';
    return html;
}

function toggleMachineGroup(groupId) {
    const el = document.getElementById(groupId);
    const arrowId = groupId.replace('grp_', 'grp_arrow_');
    const arrow = document.getElementById(arrowId);
    if (el) {
        const isVisible = el.style.display !== 'none';
        el.style.display = isVisible ? 'none' : 'block';
        if (arrow) arrow.style.transform = isVisible ? 'rotate(0deg)' : 'rotate(180deg)';
    }
}

function loadAgentless() {
    const el = document.getElementById('agentlessList');
    fetch('/api/agentless?limit=200').then(r => r.json()).then(data => {
        if (!data.length) { el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noAgentlessData') + '</div>'; return; }
        el.innerHTML = data.map(e => `<div style="background:#1a1a2a;padding:6px 10px;margin-bottom:3px;border-radius:4px;"><strong>${escapeHtml(e.device_name||e.ip||'?')}</strong> <small class="text-muted">${escapeHtml(e.timestamp||'')}</small><br><span style="font-size:11px;color:#999;">${escapeHtml((e.data_json||'').substring(0,120))}</span></div>`).join('');
    }).catch(() => { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErrX')+'</div>'; });
    // Load management tab lazily
    if (document.getElementById('tabAgManage') && document.getElementById('agentlessDeviceMgmt').innerHTML.indexOf(t('ui.loading')) > -1) {
        loadAgentlessDevices();
    }
}

// ===== AGENTLESS TAB SWITCHING =====
document.querySelectorAll('[data-tab-ag]').forEach(el => {
    el.addEventListener('click', function() {
        document.querySelectorAll('[data-tab-ag]').forEach(t => t.classList.remove('active'));
        this.classList.add('active');
        const tab = this.dataset.tabAg;
        document.querySelectorAll('.tab-ag-content').forEach(t => t.style.display = 'none');
        if (tab === 'monitor') document.getElementById('tabAgMonitor').style.display = '';
        if (tab === 'manage') { document.getElementById('tabAgManage').style.display = ''; loadAgentlessDevices(); }
    });
});

function loadAgentlessDevices() {
    const el = document.getElementById('agentlessDeviceMgmt');
    if (!el) return;
    fetch('/api/agentless/devices').then(r => r.json()).then(devices => {
        let html = '';
        if (devices && devices.length > 0) {
            html += tableWrap(['#',t('ui.name'),'IP',t('dash.type'),'Method','Interval(s)',t('ui.actions')],
                devices.map((d,i) => `<tr><td>${i+1}</td><td>${d.name||'-'}</td><td>${d.ip||'-'}</td><td>${d.device_type||'generic'}</td><td>${d.method||'ping'}</td><td>${d.interval_seconds||300}</td><td><button class="btn btn-del btn-sm py-0 px-1" onclick="deleteAgentlessDevice(${i})"><i class="bi bi-trash3"></i></button></td></tr>`)
            );
        } else {
            html += '<div class="text-center text-muted py-2">' + t('dash.noDevices') + '</div>';
        }
        // Add form
        html += '<div class="mt-2 p-2" style="background:#0a1a1a;border-radius:4px;"><strong style="font-size:11px;color:#ffcc66;">'+t('ui.addNewDevice')+'</strong>';
        html += '<div class="row g-1 mt-1">';
        html += '<div class="col-3"><input class="search-box" id="agName" placeholder="'+t('ph.deviceName')+'" style="width:100%;font-size:11px;"></div>';
        html += '<div class="col-2"><input class="search-box" id="agIp" placeholder="IP" style="width:100%;font-size:11px;"></div>';
        html += '<div class="col-2"><select class="form-select form-select-sm" id="agType" style="background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);font-size:11px;"><option value="generic">Generic</option><option value="router">Router</option><option value="switch">Switch</option><option value="server">Server</option><option value="printer">Printer</option></select></div>';
        html += '<div class="col-2"><select class="form-select form-select-sm" id="agMethod" style="background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);font-size:11px;"><option value="ping">Ping</option><option value="snmp">SNMP</option><option value="ssh">SSH</option></select></div>';
        html += '<div class="col-1"><input class="search-box" id="agInterval" placeholder="300" style="width:100%;font-size:11px;" value="300"></div>';
        html += '<div class="col-2"><button class="btn btn-sm export-btn" onclick="addAgentlessDevice()"><i class="bi bi-plus-circle"></i> '+t('btn.add')+'</button></div>';
        html += '</div></div>';
        el.innerHTML = html;
    }).catch(() => { el.innerHTML = '<div class="text-center text-muted py-2">'+t('ui.loadErrShort')+'</div>'; });
}

function addAgentlessDevice() {
    const name = document.getElementById('agName').value.trim();
    const ip = document.getElementById('agIp').value.trim();
    if (!name || !ip) { showToast('⚠ Nhập tên và IP!'); return; }
    const data = {
        name, ip,
        device_type: document.getElementById('agType').value,
        method: document.getElementById('agMethod').value,
        interval_seconds: parseInt(document.getElementById('agInterval').value) || 300
    };
    fetch('/api/agentless/devices', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)})
        .then(r => r.json()).then(d => {
            if (d.success) { showToast('✅ Đã thêm ' + name); loadAgentlessDevices(); }
            else { showToast('❌ Lỗi: ' + (d.error || 'Unknown')); }
        }).catch(() => showToast('❌ Lỗi kết nối'));
}

function deleteAgentlessDevice(index) {
    if (!confirm(t('ui.confirmDeleteDevice'))) return;
    fetch('/api/agentless/devices/' + index, {method:'DELETE'})
        .then(r => r.json()).then(d => {
            if (d.success) { showToast(t('dash.deleted')); loadAgentlessDevices(); }
            else { showToast('❌ Lỗi: ' + (d.error || 'Unknown')); }
        }).catch(() => showToast('❌ Lỗi kết nối'));
}

// ===== TOGGLE MACHINE TABLE =====
function toggleMachineTable() {
    const collapse = document.getElementById('machineTableCollapse');
    const arrow = document.getElementById('machineTableArrow');
    if (collapse.style.display === 'none' || !collapse.style.display) {
        collapse.style.display = 'block';
        arrow.style.transform = 'rotate(180deg)';
    } else {
        collapse.style.display = 'none';
        arrow.style.transform = 'rotate(0deg)';
    }
}

// ===== NEURAL NETWORK GRAPH (v1.12.0) =====
let networkGraphNodes = [];
let networkGraphAnimationId = null;
let networkGraphTime = 0;
// Zoom/Pan state
let _ng_zoom = 1.0;
let _ng_offsetX = 0;
let _ng_offsetY = 0;
let _ng_dragging = false;
let _ng_dragStartX = 0;
let _ng_dragStartY = 0;
let _ng_dragOffX = 0;
let _ng_dragOffY = 0;

async function drawNetworkGraph(machines) {
    const canvas = document.getElementById('networkCanvas');
    if (!canvas) return;
    const loadingEl = document.getElementById('networkGraphLoading');
    if (loadingEl) loadingEl.style.display = 'none';

    // v2.5.22: Use alert counts from /api/machines/summary (already fetched)
    // machines array now includes alert_threats, alert_vulns, alert_yara fields
    const alertCounts = {};
    if (machines && machines.length > 0) {
        machines.forEach(m => {
            if (m.alert_threats > 0 || m.alert_vulns > 0 || m.alert_yara > 0) {
                alertCounts[m.machine_id] = {
                    threats: m.alert_threats || 0,
                    vulns: m.alert_vulns || 0,
                    yara: m.alert_yara || 0
                };
            }
        });
    }

    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    const W = rect.width;
    const H = rect.height;

    // Reset zoom/pan on new data
    _ng_zoom = 1.0;
    _ng_offsetX = 0;
    _ng_offsetY = 0;

    // Build node list from machines
    const nodes = [];
    
    // Central server node
    nodes.push({
        id: 'server',
        label: 'SERVER',
        x: W / 2,
        y: H / 2,
        radius: 10,
        color: '#00d4aa',
        glowColor: 'rgba(0,212,170,0.6)',
        isServer: true,
        online: true
    });

    if (machines && machines.length > 0) {
        const onlineNodes = machines.filter(m => m.is_online == 1);
        const offlineNodes = machines.filter(m => m.is_online != 1);
        
        // Place online nodes in inner ring
        onlineNodes.forEach((m, i) => {
            const angle = (i / Math.max(onlineNodes.length, 1)) * Math.PI * 2 - Math.PI / 2;
            const dist = Math.min(W, H) * 0.3;
            nodes.push({
                id: m.machine_id,
                label: m.hostname || m.machine_id,
                ip: m.ip_address,
                x: W / 2 + Math.cos(angle) * dist,
                y: H / 2 + Math.sin(angle) * dist,
                radius: 6,
                color: '#3399ff',
                glowColor: 'rgba(51,153,255,0.6)',
                isServer: false,
                online: true,
                angle: angle,
                dist: dist,
                orbitSpeed: 0.0002 + Math.random() * 0.0003,
                alerts: alertCounts[m.machine_id] || { threats: 0, vulns: 0, yara: 0 }
            });
        });

        // Place offline nodes in outer ring
        offlineNodes.forEach((m, i) => {
            const angle = (i / Math.max(offlineNodes.length, 1)) * Math.PI * 2 + Math.PI / 3;
            const dist = Math.min(W, H) * 0.4;
            nodes.push({
                id: m.machine_id,
                label: m.hostname || m.machine_id,
                ip: m.ip_address,
                x: W / 2 + Math.cos(angle) * dist,
                y: H / 2 + Math.sin(angle) * dist,
                radius: 4,
                color: '#ff4444',
                glowColor: 'rgba(255,68,68,0.3)',
                isServer: false,
                online: false,
                angle: angle,
                dist: dist,
                orbitSpeed: 0.0001,
                alerts: alertCounts[m.machine_id] || { threats: 0, vulns: 0, yara: 0 }
            });
        });
    }

    networkGraphNodes = nodes;

    // Cancel previous animation
    if (networkGraphAnimationId) cancelAnimationFrame(networkGraphAnimationId);

    // Background stars
    const stars = [];
    for (let i = 0; i < 100; i++) {
        stars.push({
            x: Math.random() * W * 3 - W,
            y: Math.random() * H * 3 - H,
            r: Math.random() * 1.2 + 0.3,
            twinkle: Math.random() * Math.PI * 2,
            speed: 0.01 + Math.random() * 0.03
        });
    }

    // Particle connections
    const particles = [];
    for (let i = 0; i < 40; i++) {
        particles.push({
            angle: Math.random() * Math.PI * 2,
            dist: Math.random() * Math.min(W, H) * 0.4 + 10,
            speed: 0.003 + Math.random() * 0.008,
            size: Math.random() * 2 + 1
        });
    }

    function animate(ts) {
        networkGraphTime = ts * 0.001;
        
        // Save context and apply transform
        ctx.save();
        ctx.fillStyle = '#080e14';
        ctx.fillRect(0, 0, W, H);

        // Apply zoom + pan transform
        const cx = W / 2;
        const cy = H / 2;
        ctx.translate(cx, cy);
        ctx.scale(_ng_zoom, _ng_zoom);
        ctx.translate(-cx + _ng_offsetX / _ng_zoom, -cy + _ng_offsetY / _ng_zoom);

        // Draw background stars (kích thước tự scale theo canvas transform)
        stars.forEach(s => {
            const sx = ((s.x % (W * 3)) + W * 3) % (W * 3) - W;
            const sy = ((s.y % (H * 3)) + H * 3) % (H * 3) - H;
            s.twinkle += s.speed;
            const alpha = 0.3 + Math.sin(s.twinkle) * 0.4 + 0.4;
            ctx.beginPath();
            ctx.arc(sx, sy, s.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(255,255,255,${alpha})`;
            ctx.fill();
        });

        // Update orbiting particles
        particles.forEach(p => {
            p.angle += p.speed;
            p.x = W / 2 + Math.cos(p.angle) * p.dist;
            p.y = H / 2 + Math.sin(p.angle) * p.dist;
        });

        // Draw connection lines from server to each node
        const serverNode = nodes.find(n => n.isServer);
        if (serverNode) {
            nodes.forEach(node => {
                if (node.isServer) return;
                const alpha = node.online ? 0.25 : 0.08;
                ctx.beginPath();
                ctx.moveTo(serverNode.x, serverNode.y);
                ctx.lineTo(node.x, node.y);
                ctx.strokeStyle = node.online 
                    ? `rgba(51,153,255,${alpha})` 
                    : `rgba(255,68,68,${alpha})`;
                ctx.lineWidth = (node.online ? 1 : 0.5);
                ctx.setLineDash([4, 8]);
                ctx.stroke();
                ctx.setLineDash([]);
            });
        }

        // Draw floating particles along connections
        particles.forEach(p => {
            const serverNode = nodes.find(n => n.isServer);
            if (serverNode) {
                const dx = serverNode.x - p.x;
                const dy = serverNode.y - p.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < Math.min(W, H) * 0.45) {
                    const alpha = 0.4 + Math.sin(networkGraphTime * 2 + p.angle) * 0.3;
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                    ctx.fillStyle = `rgba(0,212,170,${alpha})`;
                    ctx.fill();
                    
                    const gradient = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.size * 4);
                    gradient.addColorStop(0, `rgba(0,212,170,${alpha * 0.8})`);
                    gradient.addColorStop(1, 'rgba(0,212,170,0)');
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, p.size * 4 / _ng_zoom, 0, Math.PI * 2);
                    ctx.fillStyle = gradient;
                    ctx.fill();
                }
            }
        });

        // Draw nodes (kích thước tự scale theo canvas transform)
        nodes.forEach(node => {
            const r = node.radius;
            
            // Glow
            const glowGradient = ctx.createRadialGradient(node.x, node.y, r * 0.3, node.x, node.y, r * 3.5);
            glowGradient.addColorStop(0, node.glowColor || 'rgba(0,212,170,0.4)');
            glowGradient.addColorStop(1, 'rgba(0,0,0,0)');
            ctx.beginPath();
            ctx.arc(node.x, node.y, r * 3.5, 0, Math.PI * 2);
            ctx.fillStyle = glowGradient;
            ctx.fill();

            // Inner glow ring
            const innerGlow = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r * 1.8);
            innerGlow.addColorStop(0, 'rgba(255,255,255,0.8)');
            innerGlow.addColorStop(0.3, node.color);
            innerGlow.addColorStop(1, 'rgba(0,0,0,0)');
            ctx.beginPath();
            ctx.arc(node.x, node.y, r * 1.8, 0, Math.PI * 2);
            ctx.fillStyle = innerGlow;
            ctx.fill();

            // Core circle
            ctx.beginPath();
            ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
            ctx.fillStyle = '#ffffff';
            ctx.fill();

            // Draw alert icons ABOVE node (v1.12.0)
            if (!node.isServer && node.alerts) {
                const alertTypes = [];
                if (node.alerts.threats > 0) alertTypes.push({ emoji: '⚠', label: 'Threats' });
                if (node.alerts.vulns > 0) alertTypes.push({ emoji: '🐞', label: 'Vulns' });
                if (node.alerts.yara > 0) alertTypes.push({ emoji: '🦠', label: 'YARA' });
                
                const iconCount = alertTypes.length;
                const iconSize = 10;
                const iconGap = 3;
                const totalWidth = iconCount * iconSize + (iconCount - 1) * iconGap;
                const startX = node.x - totalWidth / 2 + iconSize / 2;
                const iconY = node.y - r - 10;

                // Red glow background
                if (iconCount > 0) {
                    const glowW = totalWidth + 12;
                    const glowH = iconSize + 10;
                    const glowGrad = ctx.createRadialGradient(node.x, iconY, 2, node.x, iconY, glowW);
                    glowGrad.addColorStop(0, 'rgba(255,50,50,0.4)');
                    glowGrad.addColorStop(1, 'rgba(0,0,0,0)');
                    ctx.beginPath();
                    ctx.ellipse(node.x, iconY, glowW, glowH, 0, 0, Math.PI*2);
                    ctx.fillStyle = glowGrad;
                    ctx.fill();
                }

                alertTypes.forEach((at, i) => {
                    const ix = startX + i * (iconSize + iconGap);
                    // Red circle background
                    ctx.beginPath();
                    ctx.arc(ix, iconY, iconSize/2 + 2, 0, Math.PI*2);
                    ctx.fillStyle = 'rgba(220,40,40,0.85)';
                    ctx.fill();
                    ctx.strokeStyle = '#ff6666';
                    ctx.lineWidth = 1;
                    ctx.stroke();
                    // Emoji
                    ctx.font = `${iconSize - 2}px "Segoe UI Emoji", "Apple Color Emoji", sans-serif`;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(at.emoji, ix, iconY);
                });
            }

            // Label (kích thước tự scale theo canvas transform)
            if (node.isServer) {
                ctx.font = 'bold 11px "Segoe UI", sans-serif';
                ctx.fillStyle = '#00d4aa';
                ctx.textAlign = 'center';
                ctx.fillText(node.label, node.x, node.y + r + 16);
            } else if (node.online) {
                // Online nodes with full info
                ctx.font = '9px "Segoe UI", sans-serif';
                ctx.fillStyle = '#c8d8e8';
                ctx.textAlign = 'center';
                const shortLabel = node.label.length > 12 ? node.label.substring(0, 11) + '…' : node.label;
                ctx.fillText(shortLabel, node.x, node.y + r + 12);
                if (node.ip) {
                    ctx.font = '8px monospace';
                    ctx.fillStyle = '#6a8aaa';
                    ctx.fillText(node.ip, node.x, node.y + r + 22);
                }
            } else {
                // Offline nodes - show label in dim red
                ctx.font = '8px "Segoe UI", sans-serif';
                ctx.fillStyle = '#996666';
                ctx.textAlign = 'center';
                const shortLabel = node.label.length > 12 ? node.label.substring(0, 11) + '…' : node.label;
                ctx.fillText(shortLabel, node.x, node.y + r + 10);
            }

            node.clickRadius = r + 12;
        });

        networkGraphNodes = nodes;
        ctx.restore();

        networkGraphAnimationId = requestAnimationFrame(animate);
    }

    animate(0);

    // --- Zoom (mouse wheel) ---
    canvas.onwheel = function(e) {
        e.preventDefault();
        const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
        const newZoom = Math.max(0.3, Math.min(5.0, _ng_zoom * zoomFactor));
        // Zoom toward mouse position
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left - W / 2;
        const my = e.clientY - rect.top - H / 2;
        const scaleChange = newZoom / _ng_zoom;
        _ng_offsetX = mx - scaleChange * (mx - _ng_offsetX);
        _ng_offsetY = my - scaleChange * (my - _ng_offsetY);
        _ng_zoom = newZoom;
    };

    // --- Pan (mouse drag) ---
    canvas.onmousedown = function(e) {
        _ng_dragging = true;
        _ng_dragStartX = e.clientX;
        _ng_dragStartY = e.clientY;
        _ng_dragOffX = _ng_offsetX;
        _ng_dragOffY = _ng_offsetY;
        canvas.style.cursor = 'grabbing';
    };
    canvas.onmousemove = function(e) {
        if (!_ng_dragging) return;
        _ng_offsetX = _ng_dragOffX + (e.clientX - _ng_dragStartX);
        _ng_offsetY = _ng_dragOffY + (e.clientY - _ng_dragStartY);
    };
    canvas.onmouseup = function() {
        _ng_dragging = false;
        canvas.style.cursor = 'grab';
    };
    canvas.onmouseleave = function() {
        _ng_dragging = false;
        canvas.style.cursor = 'grab';
    };

    // Double-click to reset zoom
    canvas.ondblclick = function() {
        _ng_zoom = 1.0;
        _ng_offsetX = 0;
        _ng_offsetY = 0;
    };

    // Add click handler for node selection (transform-aware)
    canvas.onclick = function(e) {
        if (_ng_dragging) return;
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        // Convert screen coords to world coords
        const cx = W / 2;
        const cy = H / 2;
        const wx = cx + (mx - cx - _ng_offsetX) / _ng_zoom;
        const wy = cy + (my - cy - _ng_offsetY) / _ng_zoom;
        for (const node of networkGraphNodes) {
            if (node.isServer) continue;
            const dx = node.x - wx;
            const dy = node.y - wy;
            const dist = Math.sqrt(dx * dx + dy * dy);
            const hitRadius = node.clickRadius || (node.radius + 12);
            if (dist <= hitRadius) {
                selectMachine(node.id);
                return;
            }
        }
    };
}

// ===== MACHINE LIST (DROPDOWN) =====
function loadMachines() {
    fetch('/api/machines').then(r => r.json()).then(ms => {
        const sel = document.getElementById('machineSelect');
        if (!ms.length) { 
            if (sel) sel.innerHTML = '<option value="">-- ' + t('dash.noMachines') + ' --</option>';
            document.getElementById('machineCountBadge').textContent = '0';
            return; 
        }
        document.getElementById('machineCountBadge').textContent = ms.length;
        // v2.5.19: Dropdown thay vì div list tránh kéo dài sidebar
        const curVal = sel ? sel.value : '';
        if (sel) {
            sel.innerHTML = '<option value="">' + t('opt.selectMachineN',[ms.length]) + '</option>' +
                ms.map(m => {
                    const status = m.is_online == 1 ? '🟢' : '🔴';
                    const notesSuffix = m.notes ? ' - ' + m.notes.substring(0, 30) : '';
                    const userLabel = m.user_name ? '👤 ' + m.user_name + (m.email ? ' (' + m.email + ')' : '') : t('dash.noUser');
                    const label = status + ' ' + (m.hostname || m.machine_id) + ' — ID: ' + m.machine_id + ' — ' + userLabel + ' — ' + (m.ip_address || '?') + notesSuffix;
                    const selected = (selectedMachine === m.machine_id) ? ' selected' : '';
                    return '<option value="' + m.machine_id + '" data-hostname="' + escapeHtml(m.hostname || m.machine_id) + '"' + selected + '>' + label + '</option>';
                }).join('');
            // Restore selected value if still valid
            if (curVal && ms.find(m => m.machine_id === curVal)) {
                sel.value = curVal;
            }
        }
        document.getElementById('machineTableContainer').innerHTML = tableWrap([t('dash.status'),t('ui.hostname'),t('ui.user'),t('ui.uptime'),'IP',t('ui.machineId'),t('ui.online'),t('ui.actions')], ms.map(m => {
            const userCell = (m.user_name) ? `👤 ${escapeHtml(m.user_name)}${m.employee_id?'<br><small style="font-size:9px;">'+escapeHtml(m.employee_id)+'</small>':''}` : '-';
            const uptimeCell = (m.is_online==1 && m.uptime_hours > 0) ? `<span style="color:${m.uptime_alert_24h?'#ff4444':'#8892a4'};">⏱ ${m.uptime_hours.toFixed(1)}h${m.uptime_alert_24h?' ⚠':''}</span>` : '-';
            return `<tr><td><span class="online-dot ${m.is_online==1?'online':'offline'}"></span></td><td><strong>${m.hostname||'Unknown'}</strong></td><td style="font-size:11px;">${userCell}</td><td style="font-size:11px;">${uptimeCell}</td><td>${m.ip_address||'-'}</td><td style="font-family:monospace;font-size:11px;">${m.machine_id}</td><td>${m.is_online==1?'<span class="badge bg-success">Online</span>':'<span class="badge bg-secondary">Offline</span>'}</td><td class="text-nowrap"><button class="btn btn-stop btn-sm py-0 px-1" onclick="event.stopPropagation();stopMachineById('${m.machine_id}')"><i class="bi bi-stop-circle"></i></button><button class="btn btn-del btn-sm py-0 px-1 ms-1" onclick="event.stopPropagation();deleteMachineById('${m.machine_id}')"><i class="bi bi-trash3"></i></button></td></tr>`;
        }));
        
    });
}

// v2.5.19: Dropdown change handler
function onMachineDropdownChange() {
    const sel = document.getElementById('machineSelect');
    if (!sel || !sel.value) return;
    selectMachine(sel.value);
}

function clearAgentlessLogs(){
    if(!confirm(t('ui.confirmClearAgentless'))) return;
    fetch('/api/agentless/clear', {method:'POST'})
        .then(r => r.json()).then(d => {
            if(d.success) { showToast(t('dash.deletedLogs', [d.deleted])); loadAgentless(); }
            else { showToast('❌ Lỗi: ' + (d.error || 'Unknown')); }
        }).catch(() => showToast('❌ Lỗi kết nối'));
}

function stopMachineById(id) { if(confirm(t('ui.confirmStopMachine',[id]))) fetch(`/api/machine/${id}/stop`,{method:'POST'}).then(r=>r.json()).then(d=>showToast(d.message)).then(loadMachines); }
function deleteMachineById(id) { if(confirm(t('ui.confirmDeleteMachine',[id]))) fetch(`/api/machine/${id}/delete`,{method:'POST'}).then(r=>r.json()).then(d=>{showToast(d.message);if(selectedMachine===id){selectedMachine=null;document.getElementById('viewMachine').style.display='none';document.getElementById('viewOverview').style.display='';}loadMachines();loadStats();}); }
function stopMachine() { stopMachineById(selectedMachine); }
function deleteMachine() { deleteMachineById(selectedMachine); }
// ===== v2.5.0: ISOLATE MACHINE =====
function isolateMachine() {
    if (!selectedMachine) { showToast(t('mc.selectFirst')); return; }
    if (!confirm(t('ui.confirmIsolate',[selectedMachine]))) return;
    showToast(t('mc.isolating'));
    fetch('/api/machine/' + selectedMachine + '/isolate', {method: 'POST'})
        .then(r => r.json()).then(d => {
            if (d.success) {
                showToast(t('mc.isolated', [d.message || selectedMachine]));
                document.getElementById('btnUnisolate').style.display = '';
            } else {
                showToast('❌ ' + (d.message || t('mc.sendFail')));
            }
        }).catch(e => showToast(t('mc.connErr', [e.message])));
}

function unisolateMachine() {
    if (!selectedMachine) { showToast(t('mc.selectFirst')); return; }
    if (!confirm(t('mc.unIsolateConfirm', [selectedMachine]))) return;
    showToast(t('mc.unisolating'));
    fetch('/api/machine/' + selectedMachine + '/unisolate', {method: 'POST'})
        .then(r => r.json()).then(d => {
            if (d.success) {
                showToast(t('mc.unisolated', [d.message || selectedMachine]));
                document.getElementById('btnUnisolate').style.display = 'none';
            } else {
                showToast('❌ ' + (d.message || t('mc.sendFail')));
            }
        }).catch(e => showToast(t('mc.connErr', [e.message])));
}

function deleteOfflineMachines() {
    if(!confirm(t('ui.confirmDeleteOffline'))) return;
    fetch('/api/machines').then(r=>r.json()).then(ms=>{
        const offline = ms.filter(m=>m.is_online==0);
        if(!offline.length){showToast(t('dash.noOfflineMachines'));return;}
        let d=0;offline.forEach(m=>fetch(`/api/machine/${m.machine_id}/delete`,{method:'POST'}).then(()=>{d++;if(d===offline.length){loadMachines();loadStats();showToast(t('dash.deletedOfflineMachines', [d]));}}));
    });
}

// ===== LOAD OVERVIEW PANORAMA (Server Health & Security Overview) =====
function loadOverviewPanorama() {
    const el = document.getElementById('overviewPanoramaContent');
    if (!el) return;
    fetch('/api/panorama').then(r => r.json()).then(data => {
        if (!data || data.error) {
            el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noPanoramaData') + '</div>';
            return;
        }
        const res = data.resources || {};
        const proc = data.process || {};
        const db = data.database || {};
        const attacks = data.attacks || {};
        const fleet = data.agent_fleet || {};
        
        let html = '<div style="font-size:12px;">';
        
        // Row 1: Server Resources (CPU, RAM, Disk)
        html += '<div class="row text-center g-1 mb-2 p-2" style="background:#0f1923;border-bottom:1px solid #2a3a4a;">';
        const cpuUsage = res.cpu_percent || 0;
        const ramUsage = res.ram_percent || 0;
        const diskUsage = res.disk_percent || 0;
        html += '<div class="col-4"><div style="background:#111827;border-radius:4px;padding:6px;"><small class="text-muted"><i class="bi bi-cpu"></i> CPU</small><br><strong style="color:' + (cpuUsage > 80 ? '#ff4444' : '#00d4aa') + ';font-size:16px;">' + cpuUsage + '%</strong><br><small style="font-size:9px;color:#5a6a7a;">' + (res.cpu_count || '?') + ' cores</small></div></div>';
        html += '<div class="col-4"><div style="background:#111827;border-radius:4px;padding:6px;"><small class="text-muted"><i class="bi bi-memory"></i> RAM</small><br><strong style="color:' + (ramUsage > 80 ? '#ff4444' : '#00d4aa') + ';font-size:16px;">' + ramUsage + '%</strong><br><small style="font-size:9px;color:#5a6a7a;">' + (res.ram_used_gb || 0) + ' / ' + (res.ram_total_gb || '?') + ' GB</small></div></div>';
        html += '<div class="col-4"><div style="background:#111827;border-radius:4px;padding:6px;"><small class="text-muted"><i class="bi bi-hdd"></i> Disk</small><br><strong style="color:' + (diskUsage > 80 ? '#ff4444' : '#00d4aa') + ';font-size:16px;">' + diskUsage + '%</strong><br><small style="font-size:9px;color:#5a6a7a;">' + (res.disk_used_gb || 0) + ' / ' + (res.disk_total_gb || '?') + ' GB</small></div></div>';
        html += '</div>';
        
        // Row 2: Security + Agent Fleet
        html += '<div class="row text-center g-1 mb-2 p-2">';
        const criticalThreats = attacks.critical_threats_24h || 0;
        const totalThreats = attacks.total_threats_24h || 0;
        html += '<div class="col-3"><div style="background:#111827;border-radius:4px;padding:6px;"><small class="text-muted"><i class="bi bi-shield-exclamation"></i> Threats 24h</small><br><strong style="color:' + (criticalThreats > 0 ? '#ff4444' : '#00d4aa') + ';font-size:16px;">' + totalThreats + '</strong><br><small style="font-size:9px;color:#ff4444;">' + criticalThreats + ' CRITICAL</small></div></div>';
        html += '<div class="col-3"><div style="background:#111827;border-radius:4px;padding:6px;"><small class="text-muted"><i class="bi bi-pc-display"></i> Agents</small><br><strong style="color:#00d4aa;font-size:16px;">' + (fleet.online_agents || 0) + '</strong><br><small style="font-size:9px;color:#5a6a7a;">/' + (fleet.total_agents || 0) + ' online</small></div></div>';
        
        // Network speed
        const netSpeed = res.net_speed_mbps || 0;
        html += '<div class="col-3"><div style="background:#111827;border-radius:4px;padding:6px;"><small class="text-muted"><i class="bi bi-speedometer"></i> Network</small><br><strong style="color:#3399ff;font-size:16px;">' + netSpeed.toFixed(1) + '</strong><br><small style="font-size:9px;color:#5a6a7a;">Mbps</small></div></div>';
        
        // DB size
        html += '<div class="col-3"><div style="background:#111827;border-radius:4px;padding:6px;"><small class="text-muted"><i class="bi bi-database"></i> Database</small><br><strong style="color:#ffcc66;font-size:16px;">' + (db.db_size_mb ? db.db_size_mb.toFixed(0) + ' MB' : 'N/A') + '</strong><br><small style="font-size:9px;color:#5a6a7a;">' + (db.tables_count ? db.tables_count + ' tables' : '') + '</small></div></div>';
        html += '</div>';
        
        // Row 3: Server Process + Uptime
        html += '<div class="p-2" style="background:#0a0f14;border-radius:4px;margin-bottom:4px;">';
        html += '<div style="font-size:11px;color:#8892a4;display:flex;flex-wrap:wrap;gap:12px;">';
        html += '<span><strong style="color:#88ccff;">PID:</strong> ' + (proc.pid || '?') + '</span>';
        html += '<span><strong style="color:#88ccff;">Memory:</strong> ' + (proc.memory_mb ? proc.memory_mb.toFixed(1) + ' MB' : '?') + '</span>';
        html += '<span><strong style="color:#88ccff;">Threads:</strong> ' + (proc.thread_count || '?') + '</span>';
        html += '<span><strong style="color:#88ccff;">Connections:</strong> ' + (proc.connections || '0') + '</span>';
        html += '<span><strong style="color:#88ccff;">Uptime:</strong> ' + formatUptime(res.uptime_seconds || 0) + '</span>';
        html += '</div></div>';
        
        // Row 4: Top attackers
        const topAttackers = attacks.top_attackers || [];
        if (topAttackers.length > 0) {
            html += '<div class="p-2" style="background:#1a0a0a;border:1px solid #3a1a1a;border-radius:4px;margin-bottom:4px;">';
            html += '<div style="font-size:10px;color:#ff8888;margin-bottom:4px;"><strong>⚠ Top Attackers (24h):</strong></div>';
            html += '<div style="font-size:10px;color:#c0d4e0;">';
            topAttackers.slice(0, 5).forEach(a => {
                html += '<span style="display:inline-block;background:#2a1a1a;padding:2px 6px;border-radius:3px;margin:1px 3px;">' + escapeHtml(a.ip) + ' <span style="color:#ff6666;">(' + a.count + ')</span></span>';
            });
            html += '</div></div>';
        }
        
        html += '</div>';
        el.innerHTML = html;
        
        // Update refresh badge
        const badge = document.getElementById('panoramaRefreshBadge');
        if (badge) {
            const ts = new Date();
            badge.textContent = '🔄 Auto 15s (' + ts.getHours().toString().padStart(2,'0') + ':' + ts.getMinutes().toString().padStart(2,'0') + ':' + ts.getSeconds().toString().padStart(2,'0') + ')';
        }
    }).catch(() => {
        el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadPanoramaErr')+'</div>';
    });
}

function formatUptime(seconds) {
    if (!seconds || seconds < 0) return '0s';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    let parts = [];
    if (d > 0) parts.push(d + 'd');
    if (h > 0) parts.push(h + 'h');
    if (m > 0) parts.push(m + 'm');
    if (s > 0 || parts.length === 0) parts.push(s + 's');
    return parts.join(' ');
}

function loadStats() {
    fetch('/api/stats').then(r=>r.json()).then(s=>{document.getElementById('statTotalMachines').textContent=s.total_machines||0;document.getElementById('statOnlineMachines').textContent=s.online_machines||0;document.getElementById('statTotalEvents').textContent=s.events||0;document.getElementById('statSyslog').textContent=s.syslog||0;});
    fetch('/api/event_types').then(r=>r.json()).then(types=>{
        const el=document.getElementById('eventTypesChart');
        if(!types.length){el.innerHTML='<div class="text-center text-muted py-3">'+t('ui.noData')+'</div>';return;}
        const total=types.reduce((a,b)=>a+b.cnt,0);
        // v4.11 (UI fix): event-type names were squeezed into a fixed 120px span
        // and truncated ("Microsoft-Windows-PowerShell/Operational" -> "...Po").
        // Now the name uses the full row width (ellipsis + title tooltip for the
        // rest), count on the right, progress bar underneath. subtype is
        // HTML-escaped because it comes from event sources (arbitrary text).
        el.innerHTML=types.slice(0,8).map(t=>{
            const name=escapeHtml(t.subtype||'Unknown');
            return '<div class="mb-1">'+
                '<div class="d-flex justify-content-between align-items-center" style="font-size:11px;color:#d0d8e0;">'+
                '<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="'+name+'">'+name+'</span>'+
                '<span style="margin-left:8px;color:#8892a4;">'+escapeHtml(t.cnt)+'</span>'+
                '</div>'+
                '<div class="progress" style="height:8px;background:var(--bg-dark);">'+
                '<div class="progress-bar" style="width:'+(t.cnt/total*100).toFixed(1)+'%;background:var(--accent);"></div>'+
                '</div>'+
                '</div>';
        }).join('');
    });
}

// v4.10: Global unread-messages badge (nav "Tin nhắn") - polls independently of the
// Messages tab so other users see the badge without having to open the tab.
function refreshMessageBadge() {
    fetch('/api/message/unread-count')
        .then(function(r){return r.json();})
        .then(function(data){
            var badge = document.getElementById('msgBadge');
            if (!badge) return;
            var count = data.count || 0;
            badge.textContent = count;
            badge.style.display = count > 0 ? 'inline' : 'none';
        })
        .catch(function(){});
}

let currentView='overview';
// v2.5.22: Debounce heartbeat reload to avoid 10 agents triggering 10 reloads simultaneously
let _lastHeartbeatReload = 0;
const HEARTBEAT_RELOAD_COOLDOWN = 10000; // 10 seconds between reloads from heartbeats
function connectSSE() {
    const evtSource = new EventSource('/api/events/stream');
    // v4.10 FIX: the stream sends a JSON ARRAY of events (core.sse_queue slice);
    // the old handler parsed it as a single object so register/heartbeat/
    // response_result handling never fired. Iterate the array properly.
    evtSource.onmessage = function(e) {
      if (!e.data || e.data === ': keepalive') return;
      try {
        var events = JSON.parse(e.data);
        var list = Array.isArray(events) ? events : [events];
        for (var k = 0; k < list.length; k++) {
          var msg = list[k];
          if (!msg) continue;
          if (msg.type === 'agent_message') refreshMessageBadge(); // v4.10: workstation sent a message
          if (msg.type === 'register' || msg.type === 'heartbeat') {
            var now = Date.now();
            if (now - _lastHeartbeatReload > HEARTBEAT_RELOAD_COOLDOWN) {
              _lastHeartbeatReload = now;
              loadMachines();
            }
          }
          else if (msg.type === 'response_result') {
            // Always reload responses for selected machine
            if (selectedMachine && msg.machine_id === selectedMachine) loadMachineResponses(selectedMachine);
            // Show real-time toast for update/reset results
            var action = msg.action || '';
            if (action === 'agent_update') {
              if (msg.status === 'success') showToast('✅ '+(msg.hostname||msg.machine_id)+': Update thành công - '+(msg.output||''));
              else showToast('❌ '+(msg.hostname||msg.machine_id)+': Update thất bại - '+(msg.error||msg.output||'Lỗi'));
              // Refresh agent update view if open
              if (currentView === 'agentupdate') loadAgentUpdateView();
            }
            if (action === 'reset_user') {
              if (msg.status === 'completed') showToast('🔄 '+(msg.hostname||msg.machine_id)+': Reset user info thành công, agent đang restart...');
              else showToast('❌ '+(msg.hostname||msg.machine_id)+': Reset thất bại - '+(msg.error||''));
              if (currentView === 'agentupdate') loadAgentUpdateView();
            }
            // Refresh agent update log tab if currently visible
            if (document.getElementById('tabAuLog') && document.getElementById('tabAuLog').style.display !== 'none') {
              loadAgentUpdateLogs();
            }
          }
          else {
            if (currentView === 'events') loadAllEvents();
            if (currentView === 'fim') loadAllFim();
            if (currentView === 'network') loadNetwork();
            if (selectedMachine) { _debouncedReloadEvents(selectedMachine); _debouncedReloadFim(selectedMachine); }
          }
        }
        loadStats();
      } catch(err) {}
    };
    evtSource.onerror = function() { setTimeout(connectSSE, 3000); };
}

function reloadActiveView() {
    // v2.0.2 FIX: Only reload high-frequency views. Threats/Vulns/YARA/SCA are event-driven (SSE).
    if(currentView==='events')loadAllEvents();else if(currentView==='fim')loadAllFim();else if(currentView==='syslog')loadSyslog();
    else if(currentView==='response')loadAllResponses();else if(currentView==='network')loadNetwork();else if(currentView==='agentless')loadAgentless();
    if(selectedMachine){_debouncedReloadEvents(selectedMachine);_debouncedReloadFim(selectedMachine);}
}

const detailModal = new bootstrap.Modal(document.getElementById('detailModal'));
function showDetailModal(title, body) { document.getElementById('detailModalTitle').innerHTML = title; document.getElementById('detailModalBody').innerHTML = body; detailModal.show(); }

// ===== WIRESHARK DETAIL =====
document.addEventListener('click', function(e) {
    const row = e.target.closest('tr[data-row]');
    if (!row) return;
    try {
        const data = JSON.parse(row.getAttribute('data-row'));
        const typ = data.type || data.action || '-';
        if (typ === 'network_traffic') {
            // Parse raw_data to get accurate IPs (DB may have 0.0.0.0)
            let rd = null;
            try { rd = typeof data.raw_data === 'string' ? JSON.parse(data.raw_data) : data.raw_data; } catch(ex) {}
            const sIp = (data.src_ip && data.src_ip !== '0.0.0.0') ? data.src_ip : (rd && rd.ip ? rd.ip.src : '-');
            const dIp = (data.dst_ip && data.dst_ip !== '0.0.0.0') ? data.dst_ip : (rd && rd.ip ? rd.ip.dst : '-');
            const sPort = data.src_port || (rd && rd.tcp ? rd.tcp.sport : (rd && rd.udp ? rd.udp.sport : 0));
            const dPort = data.dst_port || (rd && rd.tcp ? rd.tcp.dport : (rd && rd.udp ? rd.udp.dport : 0));
            const title = '📡 Packet - '+(data.protocol||'?')+' '+sIp+':'+sPort+' → '+dIp+':'+dPort;

            let body = '<div style="font-family:Consolas,monospace;font-size:11px;">';
            // Frame
            body += '<div style="background:#1a1a2a;border:1px solid #2a3a4a;margin-bottom:6px;"><div style="background:#1a3a5a;padding:4px 8px;color:#88ccff;font-weight:bold;">Frame ' + (data.size||'?') + ' bytes on wire</div>';
            body += '<table class="table-data" style="font-size:10px;"><tbody>';
            body += '<tr><th style="width:160px;">Arrival Time</th><td>' + (data.timestamp||'-') + '</td></tr>';
            body += '<tr><th>Frame Length</th><td>' + (data.size||0) + ' bytes</td></tr>';
            body += '<tr><th>Capture Length</th><td>' + (data.size||0) + ' bytes</td></tr>';
            body += '</tbody></table></div>';

            // Ethernet
            body += '<div style="background:#1a1a2a;border:1px solid #2a3a4a;margin-bottom:6px;"><div style="background:#2a3a1a;padding:4px 8px;color:#88dd99;">Ethernet II, Src: '+(data.src_mac||(rd&&rd.eth?rd.eth.src:'-'))+', Dst: '+(data.dst_mac||(rd&&rd.eth?rd.eth.dst:'-'))+'</div>';
            body += '<table class="table-data" style="font-size:10px;"><tbody>';
            body += '<tr><th style="width:160px;">Source MAC</th><td>'+(data.src_mac||(rd&&rd.eth?rd.eth.src:'-'))+'</td></tr>';
            body += '<tr><th>Dest MAC</th><td>'+(data.dst_mac||(rd&&rd.eth?rd.eth.dst:'-'))+'</td></tr>';
            body += '</tbody></table></div>';

            // IP
            const ipVer = data.ip_version || (rd&&rd.ip?rd.ip.version:4);
            const ipHdrLen = data.ip_ihl || (rd&&rd.ip?rd.ip.ihl:20);
            const ipTotalLen = data.ip_len || (rd&&rd.ip?rd.ip.total_len:'?');
            const ipId = data.ip_id || (rd&&rd.ip?rd.ip.identification:'?');
            const ipFlags = data.ip_flags || (rd&&rd.ip?rd.ip.flags:'');
            const ipFrag = data.ip_frag_offset || (rd&&rd.ip?rd.ip.frag_offset:'0');
            const ipTtl = data.ip_ttl || (rd&&rd.ip?rd.ip.ttl:'?');
            const ipProto = data.ip_proto || (rd&&rd.ip?rd.ip.protocol:'?');
            const ipChk = data.ip_checksum || (rd&&rd.ip?rd.ip.checksum:'-');
            body += '<div style="background:#1a1a2a;border:1px solid #2a3a4a;margin-bottom:6px;"><div style="background:#1a2a3a;padding:4px 8px;color:#3399ff;">Internet Protocol Version '+ipVer+', Src: '+sIp+', Dst: '+dIp+'</div>';
            body += '<table class="table-data" style="font-size:10px;"><tbody>';
            body += '<tr><th style="width:160px;">Version</th><td>'+ipVer+'</td></tr>';
            body += '<tr><th>Header Length</th><td>'+ipHdrLen+' bytes</td></tr>';
            body += '<tr><th>Total Length</th><td>'+ipTotalLen+'</td></tr>';
            body += '<tr><th>Identification</th><td>'+ipId+'</td></tr>';
            body += '<tr><th>Flags</th><td>'+ipFlags+'</td></tr>';
            body += '<tr><th>Fragment Offset</th><td>'+ipFrag+'</td></tr>';
            body += '<tr><th>TTL</th><td>'+ipTtl+'</td></tr>';
            body += '<tr><th>Protocol</th><td>'+ipProto+' ('+(data.protocol||'?')+')</td></tr>';
            body += '<tr><th>Header Checksum</th><td>'+ipChk+'</td></tr>';
            body += '<tr><th>Source IP</th><td style="color:#3399ff;">'+sIp+'</td></tr>';
            body += '<tr><th>Dest IP</th><td style="color:#ff9966;">'+dIp+'</td></tr>';
            body += '</tbody></table></div>';

            if (data.protocol === 'TCP') {
                const tcpFlags = data.tcp_flags_hex || '-';
                const tcpFlagsDetail = data.tcp_flags_detail || '';
                body += '<div style="background:#1a1a2a;border:1px solid #2a3a4a;margin-bottom:6px;"><div style="background:#3a1a1a;padding:4px 8px;color:#ff8888;">Transmission Control Protocol, Src Port: '+sPort+', Dst Port: '+dPort+', Seq: '+(data.tcp_seq||0)+', Ack: '+(data.tcp_ack||0)+', Len: '+(data.tcp_payload_len||0)+'</div>';
                body += '<table class="table-data" style="font-size:10px;"><tbody>';
                body += '<tr><th style="width:160px;">Source Port</th><td>'+sPort+'</td></tr>';
                body += '<tr><th>Dest Port</th><td>'+dPort+'</td></tr>';
                body += '<tr><th>Seq Number</th><td>'+(data.tcp_seq||0)+'</td></tr>';
                body += '<tr><th>Ack Number</th><td>'+(data.tcp_ack||0)+'</td></tr>';
                body += '<tr><th>Header Length</th><td>'+(data.tcp_data_offset||20)+' bytes</td></tr>';
                body += '<tr><th>Flags</th><td>'+tcpFlags+' ['+tcpFlagsDetail+']</td></tr>';
                body += '<tr><th>Window</th><td>'+(data.tcp_window||0)+'</td></tr>';
                body += '<tr><th>Checksum</th><td>'+(data.tcp_checksum||'-')+'</td></tr>';
                body += '<tr><th>Urgent Pointer</th><td>'+(data.tcp_urg_ptr||0)+'</td></tr>';
                body += '<tr><th>TCP Payload Len</th><td>'+(data.tcp_payload_len||0)+' bytes</td></tr>';
                body += '</tbody></table></div>';
            } else if (data.protocol === 'UDP') {
                body += '<div style="background:#1a1a2a;border:1px solid #2a3a4a;margin-bottom:6px;"><div style="background:#3a2a1a;padding:4px 8px;color:#ffcc66;">User Datagram Protocol, Src Port: '+sPort+', Dst Port: '+dPort+'</div>';
                body += '<table class="table-data" style="font-size:10px;"><tbody>';
                body += '<tr><th style="width:160px;">Source Port</th><td>'+sPort+'</td></tr>';
                body += '<tr><th>Dest Port</th><td>'+dPort+'</td></tr>';
                body += '<tr><th>Length</th><td>'+(data.udp_len||0)+'</td></tr>';
                body += '<tr><th>Checksum</th><td>'+(data.udp_checksum||'-')+'</td></tr>';
                body += '</tbody></table></div>';
            } else {
                body += '<div style="background:#1a1a2a;border:1px solid #2a3a4a;margin-bottom:6px;"><div style="background:#3a3a1a;padding:4px 8px;color:#ffcc66;">OTHER Protocol</div><table class="table-data" style="font-size:10px;"><tbody><tr><th style="width:160px;">Protocol</th><td>'+(data.protocol||'?')+'</td></tr></tbody></table></div>';
            }

            // ---- v1.12.0: Application Layer (DNS/HTTP) ----
            if (data.protocol_app === 'DNS' && data.dns_info) {
                const dns = data.dns_info;
                const nxIcon = dns.is_nxdomain ? ' ❌ NXDOMAIN' : '';
                body += '<div style="background:#1a1a2a;border:1px solid #2a3a4a;margin-bottom:6px;">';
                body += '<div style="background:'+(dns.is_nxdomain?'#3a1a1a':'#1a3a5a')+';padding:4px 8px;color:'+(dns.is_nxdomain?'#ff8888':'#88ccff')+';font-weight:bold;">🌐 Domain Name System (DNS)'+nxIcon+'</div>';
                body += '<table class="table-data" style="font-size:10px;"><tbody>';
                body += '<tr><th style="width:160px;">Query Name</th><td style="color:#3399ff;font-weight:bold;">'+dns.qname+'</td></tr>';
                body += '<tr><th>Query Type</th><td>'+dns.qtype_name+' ('+dns.qtype+')</td></tr>';
                body += '<tr><th>Response Code</th><td style="color:'+(dns.is_nxdomain?'#ff4444':'#88dd99')+';">'+dns.rcode_name+' ('+dns.rcode+')</td></tr>';
                body += '<tr><th>Direction</th><td>'+(dns.is_response ? 'Response ←' : 'Query →')+'</td></tr>';
                body += '</tbody></table></div>';
            } else if (data.protocol_app === 'HTTP' && data.http_info) {
                const http = data.http_info;
                body += '<div style="background:#1a1a2a;border:1px solid #2a3a4a;margin-bottom:6px;">';
                body += '<div style="background:#3a2a1a;padding:4px 8px;color:#ffcc66;font-weight:bold;">📄 Hypertext Transfer Protocol (HTTP)</div>';
                body += '<table class="table-data" style="font-size:10px;"><tbody>';
                body += '<tr><th style="width:160px;">Method</th><td style="color:#ffcc66;font-weight:bold;">'+http.method+'</td></tr>';
                body += '<tr><th>Request URI</th><td style="color:#d0d8e0;">'+http.uri+'</td></tr>';
                body += '<tr><th>Host</th><td style="color:#88dd99;">'+http.host+'</td></tr>';
                body += '<tr><th>Request Line</th><td style="font-size:9px;color:#999;">'+http.request_line+'</td></tr>';
                body += '</tbody></table></div>';
            }

            if (data.full_payload_hex_dump) {
                body += '<div style="background:#1a1a2a;border:1px solid #2a3a4a;margin-bottom:6px;"><div style="background:#1a2a2a;padding:4px 8px;color:#88dddd;">Payload ('+(data.payload_size||0)+' bytes)</div><div style="background:#0a0a0a;padding:8px;font-size:10px;color:#0f0;white-space:pre;max-height:300px;overflow-y:auto;">'+data.full_payload_hex_dump+'</div></div>';
            }
            body += '</div>';
            showDetailModal(title, body);
            return;
        }
        let b = ''; if(data.description) b += '<div class="card mb-2" style="background:#0f1923;border-color:#2a3a4a;"><div class="card-header py-1" style="font-size:11px;">'+t('ui.description')+'</div><div class="card-body py-2" style="font-size:11px;color:#d0d8e0;">'+(data.description||'-')+'</div></div>';
        if(data.raw_data) b += '<div class="card mb-2" style="background:#0f1923;border-color:#2a3a4a;"><div class="card-header py-1" style="font-size:11px;">Raw Data</div><div class="card-body py-2" style="font-family:monospace;font-size:10px;color:#888;word-break:break-all;">'+String(data.raw_data).substring(0,2000)+'</div></div>';
        showDetailModal(t('dash.details') + ' - '+typ+' ('+(data.hostname||data.machine_id||'?')+')', b+'<table class="table table-data" style="font-size:11px;"><tbody>'+Object.entries(data).filter(([k])=>!['raw_data','data_json','fingerprint','rendered_at'].includes(k)).map(([k,v])=>'<tr><th style="width:180px;">'+k+'</th><td>'+(typeof v==='object'?JSON.stringify(v,null,2):String(v||'-'))+'</td></tr>').join('')+'</tbody></table>');
    } catch(ex) {}
});

document.addEventListener('click', function(e) {
    const card = e.target.closest('div[data-threat]'); if(!card) return;
    try { const d=JSON.parse(card.getAttribute('data-threat')); showDetailModal(t('dash.alert') + ': '+(d.rule_name||d.rule_id)+' ['+(d.severity||'?')+']','<table class="table table-data" style="font-size:11px;"><tbody><tr><th>Rule ID</th><td>'+d.rule_id+'</td></tr><tr><th>' + t('dash.name') + '</th><td>'+d.rule_name+'</td></tr><tr><th>' + t('dash.severity') + '</th><td>'+d.severity+'</td></tr><tr><th>' + t('dash.desc') + '</th><td>'+d.description+'</td></tr><tr><th>' + t('dash.machine') + '</th><td>'+(d.hostname||d.machine_id||'-')+'</td></tr></tbody></table>'); } catch(ex) {}
});
document.addEventListener('click', function(e) {
    const card = e.target.closest('div[data-vuln]'); if(!card) return;
    try { const d=JSON.parse(card.getAttribute('data-vuln')); showDetailModal('CVE: '+(d.cve||'?')+' ['+(d.severity||'?')+']','<table class="table table-data" style="font-size:11px;"><tbody><tr><th>CVE</th><td>'+d.cve+'</td></tr><tr><th>' + t('dash.severity') + '</th><td>'+d.severity+'</td></tr><tr><th>' + t('dash.software') + '</th><td>'+(d.software||'-')+' v'+(d.version||'?')+'</td></tr><tr><th>' + t('dash.desc') + '</th><td>'+d.description+'</td></tr></tbody></table>'); } catch(ex) {}
});

// ===== SEND COMMAND =====
function sendCommand() {
    if(!selectedMachine){showToast('⚠ Chọn máy trạm trước!');return;}
    const action=document.getElementById('cmdAction').value;
    const command=document.getElementById('cmdInput').value.trim();
    if(!command){showToast('⚠ Nhập lệnh!');return;}
    const output=document.getElementById('cmdOutput');
    const exec_id='cmd_'+Date.now()+'_'+Math.random().toString(36).substr(2,5);
    const ts=new Date().toLocaleTimeString();
    output.innerHTML+=`\n${escapeHtml(ts)} [${escapeHtml(selectedMachine)}] $ ${escapeHtml(command)}\n`;
    output.scrollTop=output.scrollHeight;
    document.getElementById('cmdInput').value='';
    pendingExecs[exec_id]=true;
    fetch('/api/command',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({machine_id:selectedMachine,action,command,exec_id})
    }).then(r=>r.json()).then(d=>{
        if(d.success){
            output.innerHTML+=t('ssh.sentWaiting')+'\n';
            pollCommandResult(exec_id,output,0);
        }else{
            delete pendingExecs[exec_id];
            output.innerHTML+=t('ssh.sendFailed')+(d.error||t('ssh.offlineAuth'))+'\n────────────────────────────────────\n';
        }
        output.scrollTop=output.scrollHeight;
    }).catch(err=>{
        delete pendingExecs[exec_id];
        output.innerHTML+=t('ui.connErr')+err.message+'\n────────────────────────────────────\n';
        output.scrollTop=output.scrollHeight;
    });
}
function pollCommandResult(exec_id,output,attempt){
    if(attempt>=90){ // 90 x 2s = 3 phút
        if(pendingExecs[exec_id]){
            delete pendingExecs[exec_id];
            output.innerHTML+=t('ssh.timeout')+'\n────────────────────────────────────\n';
            output.scrollTop=output.scrollHeight;
        }
        return;
    }
    if(!pendingExecs[exec_id])return;
    // Check every 2s
    setTimeout(()=>{
        if(!pendingExecs[exec_id])return;
        fetch(`/api/responses?machine_id=${selectedMachine}&limit=20`)
            .then(r=>{
                if(!r.ok) throw new Error('HTTP '+r.status);
                return r.json();
            }).then(data=>{
                const found=Array.isArray(data)?data.find(r=>r.exec_id===exec_id):null;
                if(found){
                    delete pendingExecs[exec_id];
                    const result = found.output || found.error || ''+t('ui.empty')+'';
                    output.innerHTML+=`\n${t('ssh.resultPrefix')}${escapeHtml(found.status||'completed')}):\n${escapeHtml(result)}\n────────────────────────────────────\n`;
                    output.scrollTop=output.scrollHeight;
                }else{
                    pollCommandResult(exec_id,output,attempt+1);
                }
            }).catch(err=>{
                // Retry on network error
                pollCommandResult(exec_id,output,attempt+1);
            });
    },2000);
}

// ===== AI ASSISTANT =====
const assistHistoryList=[];
const ASSIST_MODELS={deepseek:['deepseek-chat (V3)','deepseek-reasoner (R1)'],openai:['gpt-4o','gpt-4o-mini','gpt-4-turbo'],gemini:['gemini-2.0-flash','gemini-2.0-pro'],groq:['llama-3.3-70b-versatile','mixtral-8x7b-32768'],xai:['grok-2-latest','grok-2-vision-latest']};
function updateAssistModel(){const p=document.getElementById('assistProvider').value;document.getElementById('assistModel').innerHTML=(ASSIST_MODELS[p]||['default']).map(m=>`<option value="${m}">${m}</option>`).join('');}
updateAssistModel();
function toggleApiKey(){document.getElementById('assistApiKey').type=document.getElementById('assistApiKey').type==='password'?'text':'password';}
function loadAssistScope(){fetch('/api/machines').then(r=>r.json()).then(ms=>{document.getElementById('assistScope').innerHTML='<option value="all">'+t('assist.allSystem')+'</option>'+ms.map(m=>`<option value="${m.machine_id}">${m.hostname||m.machine_id}</option>`).join('');});}

function runAssistant(){
    const provider=document.getElementById('assistProvider').value;
    const model=document.getElementById('assistModel').value;
    const api_key=document.getElementById('assistApiKey').value.trim();
    const machine_id=document.getElementById('assistScope').value;
    const custom_prompt=document.getElementById('assistCustomPrompt').value.trim();
    const fileInput=document.getElementById('assistFileInput');
    if(!api_key){showToast('Vui lòng nhập API Key!');return;}
    if(!custom_prompt){showToast('Vui lòng nhập prompt / yêu cầu phân tích!');return;}
    document.getElementById('assistResult').style.display='none';
    document.getElementById('assistError').style.display='none';
    document.getElementById('assistLoading').style.display='';
    showToast('⏳ Đang thu thập dữ liệu và gửi AI...');

    // Check if user uploaded file first
    if(fileInput&&fileInput.files&&fileInput.files.length>0){
        const reader=new FileReader();
        reader.onload=function(e){
            sendToAssistant(e.target.result);
        };
        reader.readAsText(fileInput.files[0]);
    }else{
        // Auto-fetch selected log types
        const types=getSelectedLogTypes();
        const apiMap={events:'/api/events',fim:'/api/fim',network:'/api/network',
            threats:'/api/threats',vulns:'/api/vulns',yara:'/api/yara',
            sca:'/api/sca',inspection:'/api/inspection',agentless:'/api/agentless',syslog:'/api/syslog'};
        let completed=0;const allData={};
        types.forEach(t=>{
            const url=apiMap[t]||`/api/${t}`;
            const qs=getQueryParams(t,machine_id);
            fetch(`${url}?${qs}`).then(r=>r.json()).then(data=>{
                allData[t]=data;completed++;
                if(completed>=types.length){sendToAssistant(JSON.stringify(allData));}
            }).catch(()=>{completed++;if(completed>=types.length){sendToAssistant(JSON.stringify(allData));}});
        });
    }
}

function sendToAssistant(contextData){
    const provider=document.getElementById('assistProvider').value;
    const model=document.getElementById('assistModel').value;
    const api_key=document.getElementById('assistApiKey').value.trim();
    const custom_prompt=document.getElementById('assistCustomPrompt').value.trim();
    const machine_id=document.getElementById('assistScope').value;
    fetch('/api/assistant',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({provider,model,api_key,machine_id,question:custom_prompt,context_data:contextData})})
    .then(r=>r.json()).then(data=>{
        document.getElementById('assistLoading').style.display='none';
        if(data.error){document.getElementById('assistError').textContent='⚠ '+data.error;document.getElementById('assistError').style.display='';return;}
        document.getElementById('assistResponse').textContent=data.response;
        document.getElementById('assistContextSize').textContent=`📊 ${data.context_size||0} bytes`;
        document.getElementById('assistResult').style.display='';
        const hEl=document.getElementById('assistHistory'),ts=new Date().toLocaleString();
        assistHistoryList.unshift({ts,provider,model,question:custom_prompt,fullResponse:data.response});
        hEl.innerHTML=assistHistoryList.map((h,i)=>`<div class="card mb-1" style="background:var(--bg-dark);border-color:var(--border-color);"><div class="card-body py-2 px-3" style="font-size:11px;cursor:pointer;" onclick="showHistoryDetail(${i})"><span class="text-muted">${escapeHtml(h.ts)}</span> <span class="badge bg-info" style="font-size:9px;">${escapeHtml(h.provider)}</span> <span style="color:#d0d8e0;"> - ${escapeHtml(h.question.substring(0,80))}...</span></div></div>`).join('');
        showToast('✅ Phân tích hoàn tất');
    }).catch(err=>{document.getElementById('assistLoading').style.display='none';document.getElementById('assistError').textContent=''+t('ui.errPrefix')+''+err.message;document.getElementById('assistError').style.display='';});
}
function showHistoryDetail(i){const h=assistHistoryList[i];if(!h)return;showDetailModal(t('ui.history'),`<div style="white-space:pre-wrap;color:#d0e8d8;font-size:12px;"><strong>❓</strong> ${escapeHtml(h.question)}\n\n<strong>🤖</strong> ${escapeHtml(h.fullResponse||t('ui.empty'))}</div>`);}

// ===== DEBOUNCE =====
let _lastEventRefresh=0,_lastFimRefresh=0;
const REFRESH_COOLDOWN=5000;
function _debouncedReloadEvents(mid){const n=Date.now();if(n-_lastEventRefresh<REFRESH_COOLDOWN){setTimeout(()=>{loadMachineEvents(mid);_lastEventRefresh=Date.now();},REFRESH_COOLDOWN-(n-_lastEventRefresh));return;}_lastEventRefresh=n;loadMachineEvents(mid);}
function _debouncedReloadFim(mid){const n=Date.now();if(n-_lastFimRefresh<REFRESH_COOLDOWN){setTimeout(()=>{loadMachineFim(mid);_lastFimRefresh=Date.now();},REFRESH_COOLDOWN-(n-_lastFimRefresh));return;}_lastFimRefresh=n;loadMachineFim(mid);}

// ===== MACHINE CONFIG =====
function loadMachineConfig(mid){
    const el=document.getElementById('configContent');
    if(mid!==selectedMachine)return;
    // Use cache if available
    if(configCache[mid]){
        el.innerHTML=configCache[mid];
        return;
    }
    if(configLoadedFor===mid&&el.innerHTML.indexOf('Loading')===-1&&el.innerHTML.indexOf(t('ui.loading'))===-1)return;
    el.innerHTML='<div class="text-center text-muted py-3"><i class="bi bi-hourglass-split"></i> '+t('ui.loading')+'</div>';
    fetch(`/api/machine/${mid}/config`).then(r=>r.json()).then(data=>{
        if(mid!==selectedMachine)return;if(!data||!data.data){el.innerHTML='<div class="text-center text-muted py-3">⏳ ' + t('dash.noConfig') + '</div>';configLoadedFor=null;return;}
        configLoadedFor=mid;const cfg=data.data,diffs=data.diffs||[],baselineTs=data.baseline_saved_at;
        // Build diff lookup map: path -> diff object
        const diffMap={};
        diffs.forEach(function(d){diffMap[d.path]=d;});
        // Helper: return warning icon + tooltip if field has diff
        function _diffIcon(path,label){
            var d=diffMap[path];
            if(!d)return'';
            var oldV=d.baseline_value||'-',newV=d.current_value||'-';
            return' <span title="'+t('ui.changed')+''+label+'\n'+t('ui.before')+''+oldV+'\n'+t('ui.current')+''+newV+'" style="cursor:help;color:#ffcc66;font-size:14px;">⚠️</span>';
        }
        // Helper: check if any sub-path under prefix has diff
        function _hasDiff(prefix){
            for(var k in diffMap){if(k.indexOf(prefix)===0)return true;}
            return false;
        }
        // Helper: build diff detail list for a section
        function _diffDetails(prefix){
            var items=[];
            for(var k in diffMap){
                if(k.indexOf(prefix)===0){
                    var d=diffMap[k];
                    items.push('<div style="font-size:10px;color:#ffcc66;padding:1px 0;">⚠ <b>'+d.field+'</b>: <span style="text-decoration:line-through;color:#ff8888;">'+(d.baseline_value||'-')+'</span> → <span style="color:#88ff88;">'+(d.current_value||'-')+'</span></div>');
                }
            }
            return items.join('');
        }
        let html='<div style="font-size:12px;padding:8px;">';
        if(diffs.length>0){
            html+='<div class="alert alert-warning py-2 mb-3" style="font-size:12px;background:#3a2a1a;color:#ffcc66;">⚠ <b>' + t('dash.changes', [diffs.length]) + '</b>' + t('dash.vsBaseline')+ (baselineTs?baselineTs:'') +'</div>';
            html+='<div class="mb-3 p-2" style="background:#1a1410;border:1px solid #3a2a1a;border-radius:4px;">';
            html+='<div style="font-size:11px;color:#ffcc66;margin-bottom:4px;">'+t('ui.changeDetails')+'</div>';
            diffs.forEach(function(d){
                html+='<div style="font-size:10px;padding:2px 0;border-bottom:1px solid #2a1a0a;">';
                html+='<span style="color:#ffaa44;">📌 '+d.path+'</span><br>';
                html+='<span style="color:#ff8888;text-decoration:line-through;">'+t('ui.before')+''+(d.baseline_value||'-')+'</span> → ';
                html+='<span style="color:#88ff88;">'+t('ui.current')+''+(d.current_value||'-')+'</span>';
                html+='</div>';
            });
            html+='</div>';
        }else if(baselineTs)html+='<div class="alert alert-success py-2 mb-3" style="font-size:12px;background:#1a3a2a;color:#88dd99;">'+t('ui.noChangeBaseline')+''+baselineTs+')</div>';
        // OS
        if(cfg.os){
            var osChanged=_hasDiff('os.');
            html+='<div class="mb-3" style="'+(osChanged?'border-left:3px solid #ffcc66;padding-left:8px;':'')+'">';
            html+='<h6 class="text-info"><i class="bi bi-windows"></i> ' + t('dash.os') + (osChanged?' <span style="color:#ffcc66;font-size:11px;">' + t('dash.changed') + '</span>':'')+'</h6>';
            html+='<table class="table table-data"><tbody>';
            html+='<tr><th>' + t('dash.osShort') + '</th><td>'+_diffIcon('os.name', t('dash.osShort'))+' '+(cfg.os.name||'-')+' '+(cfg.os.release||'')+' (Build '+(cfg.os.build||'?')+')</td></tr>';
            html+='<tr><th>Phiên bản</th><td>'+_diffIcon('os.version',t('cfg.version'))+' '+(cfg.os.version||'-')+'</td></tr>';
            html+='</tbody></table>';
            if(osChanged)html+=_diffDetails('os.');
            html+='</div>';
        }
        // Motherboard + BIOS
        if(cfg.motherboard&&(cfg.motherboard.manufacturer||cfg.motherboard.product)){
            var mbChanged=_hasDiff('motherboard.');
            html+='<div class="mb-3" style="'+(mbChanged?'border-left:3px solid #ffcc66;padding-left:8px;':'')+'">';
            html+='<h6 class="text-info"><i class="bi bi-motherboard"></i> Mainboard'+(mbChanged?' <span style="color:#ffcc66;font-size:11px;">' + t('dash.changed') + '</span>':'')+'</h6>';
            html+='<table class="table table-data"><tbody>';
            html+='<tr><th>Hãng</th><td>'+_diffIcon('motherboard.manufacturer',t('cfg.mainboard'))+' '+(cfg.motherboard.manufacturer||'-')+'</td></tr>';
            html+='<tr><th>Model</th><td>'+_diffIcon('motherboard.product','Model Mainboard')+' '+(cfg.motherboard.product||'-')+'</td></tr>';
            if(cfg.motherboard.version)html+='<tr><th>Version</th><td>'+_diffIcon('motherboard.version','Version Mainboard')+' '+(cfg.motherboard.version)+'</td></tr>';
            if(cfg.motherboard.serial)html+='<tr><th>Serial</th><td style="font-family:monospace;">'+_diffIcon('motherboard.serial','Serial Mainboard')+' '+(cfg.motherboard.serial)+'</td></tr>';
            html+='</tbody></table>';
            if(mbChanged)html+=_diffDetails('motherboard.');
            html+='</div>';
        }
        if(cfg.bios&&cfg.bios.name){
            var biosChanged=_hasDiff('bios.');
            html+='<div class="mb-3" style="'+(biosChanged?'border-left:3px solid #ffcc66;padding-left:8px;':'')+'">';
            html+='<h6 class="text-info"><i class="bi bi-cpu"></i> BIOS'+(biosChanged?' <span style="color:#ffcc66;font-size:11px;">' + t('dash.changed') + '</span>':'')+'</h6>';
            html+='<table class="table table-data"><tbody>';
            html+='<tr><th>Hãng</th><td>'+_diffIcon('bios.manufacturer',t('cfg.biosMaker'))+' '+(cfg.bios.manufacturer||'-')+'</td></tr>';
            html+='<tr><th>Version</th><td>'+_diffIcon('bios.name',t('cfg.biosName'))+' '+(cfg.bios.name||'-')+' v'+(cfg.bios.version||'')+'</td></tr>';
            if(cfg.bios.release_date)html+='<tr><th>Ngày phát hành</th><td>'+_diffIcon('bios.release_date',t('cfg.biosRelease'))+' '+(cfg.bios.release_date)+'</td></tr>';
            if(cfg.bios.serial)html+='<tr><th>Serial</th><td style="font-family:monospace;">'+_diffIcon('bios.serial','Serial BIOS')+' '+(cfg.bios.serial)+'</td></tr>';
            html+='</tbody></table>';
            if(biosChanged)html+=_diffDetails('bios.');
            html+='</div>';
        }
        // CPU
        if(cfg.cpu){
            var cpuChanged=_hasDiff('cpu.');
            html+='<div class="mb-3" style="'+(cpuChanged?'border-left:3px solid #ffcc66;padding-left:8px;':'')+'">';
            html+='<h6 class="text-info"><i class="bi bi-cpu-fill"></i> CPU'+(cpuChanged?' <span style="color:#ffcc66;font-size:11px;">' + t('dash.changed') + '</span>':'')+'</h6>';
            html+='<table class="table table-data"><tbody>';
            html+='<tr><th>' + t('dash.name') + '</th><td>'+_diffIcon('cpu.name','Tên CPU')+' '+(cfg.cpu.name||'-')+'</td></tr>';
            html+='<tr><th>' + t('dash.clockSpeed') + '</th><td>'+_diffIcon('cpu.max_clock_speed_mhz', t('dash.cpuClock'))+' '+(cfg.cpu.max_clock_speed_mhz?Math.round(cfg.cpu.max_clock_speed_mhz/1000*10)/10+' GHz':'-')+'</td></tr>';
            html+='<tr><th>Số nhân</th><td>'+_diffIcon('cpu.cores',t('cfg.cpuCores'))+' '+(cfg.cpu.cores||'-')+' cores / '+(cfg.cpu.logical_processors||'-')+' threads</td></tr>';
            html+='</tbody></table>';
            if(cpuChanged)html+=_diffDetails('cpu.');
            html+='</div>';
        }
        // RAM
        if(cfg.ram){
            var ramChanged=_hasDiff('ram.');
            html+='<div class="mb-3" style="'+(ramChanged?'border-left:3px solid #ffcc66;padding-left:8px;':'')+'">';
            html+='<h6 class="text-info"><i class="bi bi-memory"></i> RAM'+(ramChanged?' <span style="color:#ffcc66;font-size:11px;">' + t('dash.changed') + '</span>':'')+'</h6>';
            html+='<table class="table table-data"><tbody><tr><th>Tổng</th><td>'+_diffIcon('ram.total_gb',t('cfg.totalRam'))+' <strong>'+(cfg.ram.total_gb||0)+' GB</strong></td></tr></tbody></table>';
            if(cfg.ram.sticks&&cfg.ram.sticks.length){
                html+='<table class="table table-data mt-1"><thead><tr><th>#</th><th>'+t('cfg.manufacturer')+'</th><th>'+t('cfg.capacity')+'</th><th>Bus</th><th>'+t('cfg.kind')+'</th><th>Form</th><th>Part Number</th></tr></thead><tbody>';
                cfg.ram.sticks.forEach(function(s,i){
                    var bus=cfg.ram.sticks.length>0?((s.configured_speed_mhz||s.speed_mhz||'?')+(s.configured_speed_mhz&&s.speed_mhz&&s.configured_speed_mhz!==s.speed_mhz?' (Max: '+s.speed_mhz+' MHz)':(s.speed_mhz?' MHz':''))):'-';
                    var rowStyle='';
                    if(_hasDiff('ram.sticks['+i+']'))rowStyle=' style="background:rgba(255,200,50,0.08);"';
                    html+='<tr'+rowStyle+'><td>'+_diffIcon('ram.sticks['+i+'] (số lượng)',t('cfg.ramQty'))+' '+(i+1)+'</td>';
                    html+='<td>'+_diffIcon('ram.sticks['+i+'].manufacturer',t('cfg.ramMaker',[i+1]))+' '+(s.manufacturer||'-')+'</td>';
                    html+='<td>'+_diffIcon('ram.sticks['+i+'].capacity_gb',t('cfg.ramCapacity',[i+1]))+' '+(s.capacity_gb||0)+' GB</td>';
                    html+='<td>'+_diffIcon('ram.sticks['+i+'].speed_mhz','Bus RAM #'+(i+1))+' '+bus+'</td>';
                    html+='<td>'+_diffIcon('ram.sticks['+i+'].memory_type',t('cfg.ramType',[i+1]))+' '+(s.memory_type||'-')+'</td>';
                    html+='<td>'+_diffIcon('ram.sticks['+i+'].form_factor','Form RAM #'+(i+1))+' '+(s.form_factor||'-')+'</td>';
                    html+='<td style="font-family:monospace;font-size:10px;">'+_diffIcon('ram.sticks['+i+'].part_number','Part Number RAM #'+(i+1))+' '+(s.part_number||'-')+'</td></tr>';
                });
                html+='</tbody></table>';
            }
            if(ramChanged)html+=_diffDetails('ram.');
            html+='</div>';
        }
        // Disks
        if(cfg.disks&&cfg.disks.length){
            var diskChanged=_hasDiff('disks.');
            html+='<div class="mb-3" style="'+(diskChanged?'border-left:3px solid #ffcc66;padding-left:8px;':'')+'">';
            html+='<h6 class="text-info"><i class="bi bi-device-hdd"></i> ' + t('dash.disk') + (diskChanged?' <span style="color:#ffcc66;font-size:11px;">' + t('dash.changed') + '</span>':'')+'</h6>';
            html+='<table class="table table-data"><thead><tr><th>#</th><th>'+t('cfg.model')+'</th><th>'+t('cfg.capacity')+'</th><th>'+t('cfg.standard')+'</th><th>'+t('cfg.kind')+'</th></tr></thead><tbody>';
            cfg.disks.forEach(function(d,i){
                var rowStyle='';
                if(_hasDiff('disks['+i+']'))rowStyle=' style="background:rgba(255,200,50,0.08);"';
                html+='<tr'+rowStyle+'><td>'+_diffIcon('disks['+i+'] (số lượng)',t('cfg.diskQty'))+' '+(i+1)+'</td>';
                html+='<td>'+_diffIcon('disks['+i+'].model',t('cfg.diskModel',[i+1]))+' '+(d.model||'-')+'</td>';
                html+='<td>'+_diffIcon('disks['+i+'].size_gb',t('cfg.diskCapacity',[i+1]))+' '+(d.size_gb||0)+' GB</td>';
                html+='<td>'+_diffIcon('disks['+i+'].interface',t('cfg.diskStd',[i+1]))+' '+(d.interface||'-')+'</td>';
                html+='<td>'+_diffIcon('disks['+i+'].media_type',t('cfg.diskType',[i+1]))+' '+(d.media_type||'-')+'</td></tr>';
            });
            html+='</tbody></table>';
            if(diskChanged)html+=_diffDetails('disks.');
            html+='</div>';
        }
        // GPU
        if(cfg.gpu&&cfg.gpu.length){
            var gpuChanged=_hasDiff('gpu.');
            html+='<div class="mb-3" style="'+(gpuChanged?'border-left:3px solid #ffcc66;padding-left:8px;':'')+'">';
            html+='<h6 class="text-info"><i class="bi bi-gpu-card"></i> ' + t('dash.gpuCard') + (gpuChanged?' <span style="color:#ffcc66;font-size:11px;">' + t('dash.changed') + '</span>':'')+'</h6>';
            html+='<table class="table table-data"><thead><tr><th>#</th><th>' + t('dash.name') + '</th><th>VRAM</th><th>Driver</th><th>GPU Chip</th></tr></thead><tbody>';
            cfg.gpu.forEach(function(g,i){
                var rowStyle='';
                if(_hasDiff('gpu['+i+']'))rowStyle=' style="background:rgba(255,200,50,0.08);"';
                html+='<tr'+rowStyle+'><td>'+_diffIcon('gpu['+i+'] (số lượng)',t('cfg.gpuQty'))+' '+(i+1)+'</td>';
                html+='<td>'+_diffIcon('gpu['+i+'].name',t('cfg.gpuName',[i+1]))+' '+(g.name||'-')+'</td>';
                html+='<td>'+_diffIcon('gpu['+i+'].ram_gb', t('dash.gpuVram', [i+1]))+' '+(g.ram_gb>0?g.ram_gb+' GB':'-')+'</td>';
                html+='<td>'+_diffIcon('gpu['+i+'].driver_version','Driver GPU #'+(i+1))+' '+(g.driver_version||'-')+'</td>';
                html+='<td>'+_diffIcon('gpu['+i+'].video_processor','GPU Chip #'+(i+1))+' '+(g.video_processor||'-')+'</td></tr>';
            });
            html+='</tbody></table>';
            if(gpuChanged)html+=_diffDetails('gpu.');
            html+='</div>';
        }
        // Monitors
        if(cfg.monitors&&cfg.monitors.length){
            var monChanged=_hasDiff('monitors.');
            html+='<div class="mb-3" style="'+(monChanged?'border-left:3px solid #ffcc66;padding-left:8px;':'')+'">';
            html+='<h6 class="text-info"><i class="bi bi-display"></i> ' + t('dash.monitor') + (monChanged?' <span style="color:#ffcc66;font-size:11px;">' + t('dash.changed') + '</span>':'')+'</h6>';
            html+='<table class="table table-data"><thead><tr><th>#</th><th>' + t('dash.name') + '</th><th>Hãng</th><th>Độ phân giải</th><th>'+t('ui.type')+'</th></tr></thead><tbody>';
            cfg.monitors.forEach(function(m,i){
                var rowStyle='';
                if(_hasDiff('monitors['+i+']'))rowStyle=' style="background:rgba(255,200,50,0.08);"';
                html+='<tr'+rowStyle+'><td>'+_diffIcon('monitors['+i+'] (số lượng)',t('cfg.monQty'))+' '+(i+1)+'</td>';
                html+='<td>'+_diffIcon('monitors['+i+'].name',t('cfg.monName',[i+1]))+' '+(m.name||'-')+'</td>';
                html+='<td>'+_diffIcon('monitors['+i+'].manufacturer',t('cfg.monMaker',[i+1]))+' '+(m.manufacturer||'-')+'</td>';
                html+='<td>'+_diffIcon('monitors['+i+'].resolution',t('cfg.monRes',[i+1]))+' '+(m.resolution||'-')+'</td>';
                html+='<td>'+_diffIcon('monitors['+i+'].type',t('cfg.monType',[i+1]))+' '+(m.type||'-')+'</td></tr>';
            });
            html+='</tbody></table>';
            if(monChanged)html+=_diffDetails('monitors.');
            html+='</div>';
        }
        // Installed Software
        if(cfg.installed_software&&cfg.installed_software.length){
            var swChanged=_hasDiff('installed_software.');
            html+='<div class="mb-3" style="'+(swChanged?'border-left:3px solid #ffcc66;padding-left:8px;':'')+'">';
            html+='<h6 class="text-info"><i class="bi bi-boxes"></i> ' + t('dash.installedSoftware') + ' ('+cfg.installed_software.length+')'+(swChanged?' <span style="color:#ffcc66;font-size:11px;">' + t('dash.changed') + '</span>':'')+'</h6>';
            html+='<table class="table table-data"><thead><tr><th>#</th><th>'+t('cfg.swName')+'</th><th>'+t('cfg.version')+'</th><th>'+t('cfg.publisher')+'</th><th>'+t('cfg.installDate')+'</th></tr></thead><tbody>';
            cfg.installed_software.forEach(function(sw,i){
                var rowStyle='';
                if(_hasDiff('installed_software['+i+']'))rowStyle=' style="background:rgba(255,200,50,0.08);"';
                html+='<tr'+rowStyle+'><td>'+_diffIcon('installed_software['+i+'] (số lượng)',t('cfg.swQty'))+' '+(i+1)+'</td>';
                html+='<td>'+_diffIcon('installed_software['+i+'].name',t('cfg.swNameN',[i+1]))+' '+(sw.name||'-')+'</td>';
                html+='<td>'+_diffIcon('installed_software['+i+'].version',t('cfg.swVerN',[i+1]))+' '+(sw.version||'-')+'</td>';
                html+='<td>'+_diffIcon('installed_software['+i+'].publisher','NXB PM #'+(i+1))+' '+(sw.publisher||'-')+'</td>';
                html+='<td>'+_diffIcon('installed_software['+i+'].install_date',t('cfg.swDateN',[i+1]))+' '+(sw.install_date||'-')+'</td></tr>';
            });
            html+='</tbody></table>';
            if(swChanged)html+=_diffDetails('installed_software.');
            html+='</div>';
        }
        html+='<div class="text-muted mt-2" style="font-size:11px;">'+t('cfg.updated')+''+(data.received_at||'-')+'</div></div>';
        el.innerHTML=html;
        // Cache the rendered config
        configCache[mid]=html;
    }).catch(function(){if(mid!==selectedMachine)return;el.innerHTML='<div class="text-center text-muted py-3">❌ '+t('ui.loadConfigErr')+'</div>';configLoadedFor=null;});
}

// ===== CLEANUP =====
function cleanupOldLogs(){var d=prompt(t('dash.cleanupPrompt'), "30");if(!d)return;if(!confirm(t('dash.cleanupConfirm', [d])))return;fetch('/api/cleanup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days:parseInt(d),keep_threats:true})}).then(function(r){return r.json();}).then(function(r){showToast(t('dash.cleanupDone', [(r.total||0).toLocaleString()]));loadStats();loadMachines();}).catch(function(){showToast(t('dash.cleanupErr'));});}

// ===== v2.1.0: AGENT GROUPS =====
function loadGroups(){
    const el = document.getElementById('groupsContent');
    fetch('/api/groups').then(r => r.json()).then(data => {
        const groups = data.groups || [];
        if (!groups.length) {
            el.innerHTML = '<div class="p-3"><div class="text-center text-muted py-2">' + t('dash.noGroups') + '</div><div class="mt-2 p-2" style="background:#0a1a1a;border-radius:4px;"><strong style="font-size:11px;color:#ffcc66;">' + t('dash.createGroup') + '</strong><div class="row g-1 mt-1"><div class="col-4"><input class="search-box" id="grpName" placeholder="' + t('dash.groupName') + '" style="width:100%;font-size:11px;"></div><div class="col-6"><input class="search-box" id="grpDesc" placeholder="' + t('dash.groupDesc') + '" style="width:100%;font-size:11px;"></div><div class="col-2"><button class="btn btn-sm export-btn" onclick="createGroup()"><i class="bi bi-plus-circle"></i> Tạo</button></div></div></div></div>';
            loadMachinesForGroupSelect();
            return;
        }
        let html = '';
        groups.forEach(g => {
            html += '<div style="background:#111827;border:1px solid #1e2a3a;border-radius:8px;margin-bottom:8px;padding:12px;">';
            html += '<div class="d-flex justify-content-between align-items-center mb-2">';
            html += '<strong style="color:#e4e7eb;">📁 ' + g.name + '</strong>';
            html += '<div><button class="btn btn-del btn-sm py-0 px-1" onclick="deleteGroup(' + g.id + ')"><i class="bi bi-trash3"></i></button></div>';
            html += '</div>';
            html += '<small class="text-muted">' + (g.description || '') + ' | ' + t('ui.groupsMembers',[g.members ? g.members.length : 0]) + '</small>';
            if (g.members && g.members.length) {
                html += '<div style="margin-top:4px;">' + g.members.map(m => '<span class="badge bg-info me-1" style="cursor:pointer;" onclick="removeFromGroup(\'' + m.machine_id + '\',' + g.id + ')" title="' + t('ui.remFromGroupTitle') + '">' + (m.hostname || m.machine_id) + ' ✕</span>').join('') + '</div>';
            }
            html += '<div class="mt-2"><select class="form-select form-select-sm d-inline-block" id="addMachSelect_' + g.id + '" style="width:auto;background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);font-size:11px;"><option value="">'+t('ui.addMachineHint')+'</option></select>';
            html += '<button class="btn btn-sm export-btn ms-1" onclick="addToGroup(' + g.id + ')" style="font-size:10px;">'+t('btn.add')+'</button></div>';
            html += '</div>';
        });
        html += '<div class="mt-2 p-2" style="background:#0a1a1a;border-radius:4px;"><strong style="font-size:11px;color:#ffcc66;">' + t('dash.createGroup') + '</strong><div class="row g-1 mt-1"><div class="col-4"><input class="search-box" id="grpName" placeholder="' + t('dash.groupName') + '" style="width:100%;font-size:11px;"></div><div class="col-6"><input class="search-box" id="grpDesc" placeholder="' + t('dash.groupDesc') + '" style="width:100%;font-size:11px;"></div><div class="col-2"><button class="btn btn-sm export-btn" onclick="createGroup()"><i class="bi bi-plus-circle"></i> Tạo</button></div></div></div>';
        el.innerHTML = html;
        loadMachinesForGroupSelect();
    });
}

function loadMachinesForGroupSelect(){
    Promise.all([
        fetch('/api/machines').then(r => r.json()),
        fetch('/api/groups').then(r => r.json())
    ]).then(([ms, groupData]) => {
        const groups = groupData.groups || [];
        // Collect ALL machine_ids already assigned to any group
        const assignedIds = new Set();
        groups.forEach(g => {
            if (g.members) {
                g.members.forEach(m => assignedIds.add(m.machine_id));
            }
        });
        // Only show machines NOT already in any group
        const available = ms.filter(m => !assignedIds.has(m.machine_id));
        const opts = available.map(m => {
            const status = m.is_online == 1 ? '🟢' : '🔴';
            const userLabel = m.user_name ? '👤 ' + m.user_name + (m.email ? ' (' + m.email + ')' : '') : t('dash.noUser');
            const label = status + ' ' + (m.hostname || m.machine_id) + ' — ID: ' + m.machine_id + ' — ' + userLabel + ' — ' + (m.ip_address || '?');
            return '<option value="' + m.machine_id + '">' + label + '</option>';
        }).join('');
        document.querySelectorAll('[id^="addMachSelect_"]').forEach(sel => {
            sel.innerHTML = '<option value="">' + t('ui.availableMachines',[available.length]) + '</option>' + opts;
        });
    });
}

function createGroup(){
    const name = document.getElementById('grpName').value.trim();
    if (!name) { showToast('⚠ Nhập tên group!'); return; }
    const desc = document.getElementById('grpDesc').value.trim();
    fetch('/api/groups', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name, description: desc, config:{}})})
        .then(r => r.json()).then(d => {
            if (d.success) { showToast('✅ Đã tạo group: ' + name); loadGroups(); }
            else { showToast('❌ ' + (d.error || 'Lỗi')); }
        }).catch(() => showToast('❌ Lỗi kết nối'));
}

function deleteGroup(id){
    if (!confirm(t('ui.confirmDelGroup'))) return;
    fetch('/api/groups/' + id, {method:'DELETE'}).then(r => r.json()).then(d => {
        if (d.success) { showToast(t('dash.deleteGroup')); loadGroups(); }
        else { showToast('❌ Lỗi'); }
    }).catch(() => showToast('❌ Lỗi kết nối'));
}

function addToGroup(groupId){
    const sel = document.getElementById('addMachSelect_' + groupId);
    const machineId = sel ? sel.value : '';
    if (!machineId) { showToast('⚠ Chọn máy!'); return; }
    fetch('/api/groups/' + groupId + '/members', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({machine_id: machineId})})
        .then(r => r.json()).then(d => {
            if (d.success) { showToast(t('ui.machineAdded')); loadGroups(); }
            else { showToast('❌ Lỗi'); }
        }).catch(() => showToast('❌ Lỗi kết nối'));
}

function executeResponseAction(machineId, hostname, action, paramValue) {
    if (!confirm(t('ui.confirmExec',[action, hostname || machineId]))) return;
    var params = {};
    if (typeof paramValue === 'object') {
        params = paramValue;
    } else if (paramValue) {
        if (action === 'kill_process') {
            params = isNaN(parseInt(paramValue)) ? {name: paramValue} : {pid: paramValue};
        } else if (action === 'firewall_block' || action === 'firewall_unblock') {
            params = {ip: paramValue};
        } else if (action === 'disable_account') {
            params = {username: paramValue};
        } else if (action === 'quarantine_file') {
            params = {file_path: paramValue};
        }
    }
    showToast('\u23f3 Đang gửi lệnh ' + action + '...');
    fetch('/api/response/execute', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({machine_id: machineId, action: action, params: params})
    }).then(r => r.json()).then(d => {
        if (d.success) {
            showToast('✅ ' + d.message);
        } else {
            showToast('❌ Lỗi: ' + (d.error || 'Unknown'));
        }
    }).catch(() => showToast('❌ Lỗi kết nối'));
}

function _actionButtons(type, item) {
    var mid = item.machine_id || '';
    var host = item.hostname || '';
    if (!mid) return '';
    var h = '<td style="white-space:nowrap;text-align:center;">';
    // Forensic snapshot - always available
    h += '<button class="btn btn-xs btn-outline-info py-0 px-1" style="font-size:9px;margin:1px;" onclick="event.stopPropagation();executeResponseAction(\'' + mid + '\',\'' + host + '\',\'forensic_snapshot\',\'\')" title="Forensic Snapshot">&#128269;</button>';
    if (type === 'threats') {
        if (item.pid || item.process_name) {
            var pv = item.pid || item.process_name || '';
            h += '<button class="btn btn-xs btn-outline-danger py-0 px-1" style="font-size:9px;margin:1px;" onclick="event.stopPropagation();executeResponseAction(\'' + mid + '\',\'' + host + '\',\'kill_process\',\'' + pv + '\')" title="Kill Process">&#128298;</button>';
        }
        if (item.source_ip || item.dst_ip) {
            var ip = item.source_ip || item.dst_ip || '';
            h += '<button class="btn btn-xs btn-outline-warning py-0 px-1" style="font-size:9px;margin:1px;" onclick="event.stopPropagation();executeResponseAction(\'' + mid + '\',\'' + host + '\',\'firewall_block\',\'' + ip + '\')" title="Block IP">&#128683;</button>';
        }
    } else if (type === 'yara') {
        if (item.file) {
            h += '<button class="btn btn-xs btn-outline-danger py-0 px-1" style="font-size:9px;margin:1px;" onclick="event.stopPropagation();executeResponseAction(\'' + mid + '\',\'' + host + '\',\'quarantine_file\',\'' + (item.file||'') + '\')" title="Quarantine File">&#128230;</button>';
        }
    }
    h += '</td>';
    return h;
}

function removeFromGroup(machineId, groupId){
    if (!confirm(t('ui.confirmRemoveFromGroup'))) return;
    fetch('/api/groups/' + groupId + '/members/' + machineId, {method:'DELETE'})
        .then(r => r.json()).then(d => {
            if (d.success) { showToast(t('dash.deleted')); loadGroups(); }
            else { showToast('❌ Lỗi'); }
        }).catch(() => showToast('❌ Lỗi kết nối'));
}

// ===== v2.5.1: FIM BASELINE REDESIGN =====
// Machine summary rows with risk counts, click to expand detail table
let _fimBaselineSelectedMachine = null;

function loadFimBaselineMachines(){
    const el = document.getElementById('fimBaselineMachineList');
    el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-hourglass-split"></i> '+t('ui.loading')+'</div>';
    fetch('/api/fim/baseline/summary').then(r => r.json()).then(data => {
        const machines = data.machines || [];
        if (!machines.length) {
            el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noFimBaseline') + '</div>';
            return;
        }
        // Sort: most critical first, then by total
        machines.sort((a,b) => (b.critical*4 + b.high*3 + b.medium*2 + b.low) - (a.critical*4 + a.high*3 + a.medium*2 + a.low) || b.total - a.total);

        let html = '';
        // Legend header
        html += '<div style="display:flex;align-items:center;padding:10px 14px;background:#0f1923;border-bottom:1px solid var(--border-color);font-size:11px;color:#b0c8e0;">';
        html += '<div style="flex:2;">'+t('ui.machineCol')+'</div>';
        html += '<div style="flex:1;text-align:center;">📁 Files</div>';
        html += '<div style="flex:0.7;text-align:center;" title="Critical">🔴</div>';
        html += '<div style="flex:0.7;text-align:center;" title="High">🟠</div>';
        html += '<div style="flex:0.7;text-align:center;" title="Medium">🟡</div>';
        html += '<div style="flex:0.7;text-align:center;" title="Low">🟢</div>';
        html += '</div>';

        machines.forEach(m => {
            const isOnline = m.is_online === 1;
            const hasIssues = m.critical > 0 || m.high > 0;
            const rowBg = hasIssues ? 'rgba(255,51,51,0.06)' : (m.total > 0 ? 'rgba(0,212,170,0.04)' : '');
            const borderL = m.critical > 0 ? '3px solid #ff3333' : m.high > 0 ? '3px solid #ff8844' : '3px solid transparent';
            html += '<div class="fim-machine-row" data-machine-id="' + m.machine_id + '" style="display:flex;align-items:center;padding:10px 14px;border-bottom:1px solid var(--border-color);border-left:' + borderL + ';background:' + rowBg + ';cursor:pointer;transition:background 0.2s;" onclick="expandFimBaselineMachine(\'' + m.machine_id + '\',\'' + (m.hostname || m.machine_id).replace(/'/g,"\\'") + '\')" onmouseover="this.style.background=\'rgba(255,255,255,0.05)\'" onmouseout="this.style.background=\'' + rowBg + '\'">';
            html += '<div style="flex:2;display:flex;flex-direction:column;gap:2px;">';
            html += '<span style="font-weight:600;font-size:12px;color:#eef4f8;">' + (m.hostname || m.machine_id) + '</span>';
            html += '<span style="font-size:10px;color:#8892a4;">' + (isOnline ? '🟢 Online' : '⚫ Offline') + ' · <span style="font-family:monospace;font-size:9px;">' + m.machine_id.substring(0,8) + '</span></span>';
            html += '</div>';
            html += '<div style="flex:1;text-align:center;font-size:13px;font-weight:600;color:#00d4aa;">' + (m.total_files || 0) + '</div>';
            html += '<div style="flex:0.7;text-align:center;font-size:13px;font-weight:bold;color:' + (m.critical > 0 ? '#ff3333' : '#444') + ';">' + (m.critical || 0) + '</div>';
            html += '<div style="flex:0.7;text-align:center;font-size:13px;font-weight:bold;color:' + (m.high > 0 ? '#ff8844' : '#444') + ';">' + (m.high || 0) + '</div>';
            html += '<div style="flex:0.7;text-align:center;font-size:13px;font-weight:bold;color:' + (m.medium > 0 ? '#ffcc66' : '#444') + ';">' + (m.medium || 0) + '</div>';
            html += '<div style="flex:0.7;text-align:center;font-size:13px;font-weight:bold;color:' + (m.low > 0 ? '#00d4aa' : '#444') + ';">' + (m.low || 0) + '</div>';
            html += '</div>';
        });
        el.innerHTML = html;
    }).catch(e => {
        el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErrX')+': ' + e.message + '</div>';
    });
}

function expandFimBaselineMachine(machineId, hostname) {
    _fimBaselineSelectedMachine = machineId;
    // Highlight selected row
    document.querySelectorAll('.fim-machine-row').forEach(r => r.style.background = r.style.background.replace('rgba(0,212,170,0.12)','').replace('rgba(255,255,255,0.05)',''));
    const row = document.querySelector('.fim-machine-row[data-machine-id="' + machineId + '"]');
    if (row) row.style.background = 'rgba(0,212,170,0.12)';

    const panel = document.getElementById('fimBaselineDetailPanel');
    const title = document.getElementById('fimBaselineDetailTitle');
    const content = document.getElementById('fimBaselineContent');

    panel.style.display = '';
    title.innerHTML = '<i class="bi bi-zoom-in"></i> FIM Baseline: <strong style="color:#00d4aa;">' + hostname + '</strong>';
    content.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-hourglass-split"></i> '+t('ui.loading')+'</div>';

    fetch('/api/fim/baseline/' + machineId).then(r => r.json()).then(data => {
        const baseline = data.baseline || [];
        const stats = data.stats || {};
        const threatsCount = data.threats_count || 0;
        if (!baseline.length) {
            content.innerHTML = '<div class="p-3"><div class="text-center text-muted">' + t('dash.noBaseline') + '</div></div>';
            return;
        }
        const changedCount = stats.changed_files || 0;
        let html = '<div class="p-2">';
        // Stats cards
        html += '<div class="row text-center mb-3 g-1">';
        html += '<div class="col"><div style="background:#111827;border-radius:6px;padding:6px 2px;"><span class="text-muted" style="font-size:10px;">📁 Tong file</span><br><strong style="color:#00d4aa;font-size:15px;">' + (stats.total_files || 0) + '</strong></div></div>';
        html += '<div class="col"><div style="background:#111827;border-radius:6px;padding:6px 2px;"><span class="text-muted" style="font-size:10px;">✅ Check 24h</span><br><strong style="color:#3399ff;font-size:15px;">' + (stats.checked_24h || 0) + '</strong></div></div>';
        html += '<div class="col"><div style="background:#111827;border-radius:6px;padding:6px 2px;"><span class="text-muted" style="font-size:10px;">🔄 Da doi</span><br><strong style="color:' + (changedCount > 0 ? '#ff6b6b' : '#00d4aa') + ';font-size:15px;">' + changedCount + '</strong></div></div>';
        html += '<div class="col"><div style="background:#111827;border-radius:6px;padding:6px 2px;"><span class="text-muted" style="font-size:10px;">⚠ Threats</span><br><strong style="color:' + (threatsCount > 0 ? '#ff6b6b' : '#00d4aa') + ';font-size:15px;">' + threatsCount + '</strong></div></div>';
        html += '</div>';
        // Legend
        html += '<div class="mb-2 p-2" style="background:#0a0f14;border-radius:4px;font-size:10px;line-height:1.6;">';
        html += '<strong style="color:#ffcc66;">🎯 FIM Suspicion Score:</strong> Danh gia muc do nghi ngo cho tung file.<br>';
        html += '<span style="background:#00d4aa;color:#000;padding:0 6px;border-radius:3px;margin-right:4px;">🟢 Low 0-25</span>';
        html += '<span style="background:#ffcc66;color:#000;padding:0 6px;border-radius:3px;margin:0 4px;">🟡 Medium 26-50</span>';
        html += '<span style="background:#ff8844;color:#fff;padding:0 6px;border-radius:3px;margin:0 4px;">🟠 High 51-80</span>';
        html += '<span style="background:#ff3333;color:#fff;padding:0 6px;border-radius:3px;margin-left:4px;">🔴 CRITICAL 81-100</span>';
        html += '</div>';
        // Table
        html += tableWrap(['Score','Duong dan','Hash (SHA256)','KT','Ly do',''],
            baseline.map(f => {
                const s = f.suspicion || {};
                const score = s.score || 0;
                const reasonsArr = s.reasons || [];
                const fhash = f.file_hash || '-';
                const scColor = score >= 80 ? '#ff3333' : score >= 50 ? '#ff8844' : score >= 25 ? '#ffcc66' : '#00d4aa';
                const scBg = score >= 80 ? 'rgba(255,51,51,0.2)' : score >= 50 ? 'rgba(255,136,68,0.15)' : score >= 25 ? 'rgba(255,204,102,0.1)' : 'rgba(0,212,170,0.08)';
                const shortPath = f.path.length > 35 ? '...' + f.path.substring(f.path.length - 32) : f.path;
                const sizeStr = f.file_size ? (f.file_size > 1024 ? (f.file_size/1024).toFixed(1)+'KB' : f.file_size+'B') : '-';
                const lastMod = (f.last_modified || f.last_checked || '-').substring(0,10);
                const fId = 'fim_' + Math.random().toString(36).substr(2,8);
                window['_fim_' + fId] = f;
                return '<tr style="background:' + scBg + ';cursor:pointer;" onclick="showFimBaselineDetail(\'' + fId + '\')">' +
                    '<td style="font-size:12px;font-weight:bold;text-align:center;color:' + scColor + ';">' + (score >= 80 ? '🔴' : score >= 50 ? '🟠' : score >= 25 ? '🟡' : '🟢') + ' ' + score + '</td>' +
                    '<td style="font-family:monospace;font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + f.path + '">' + shortPath + '</td>' +
                    '<td style="font-family:monospace;font-size:9px;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + fhash + '">' + fhash.substring(0,16) + '...</td>' +
                    '<td style="font-size:10px;">' + sizeStr + '</td>' +
                    '<td style="font-size:9px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#8892a4;">' + (reasonsArr.slice(0,2).join('; ') || '-') + '</td>' +
                    '<td style="font-size:9px;">' + lastMod + '</td>' +
                    '</tr>';
            })
        );
        content.innerHTML = html;
    }).catch(() => { content.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErrX')+'</div>'; });
}

// ===== FIM BASELINE DETAIL MODAL =====
function showFimBaselineDetail(fId) {
    const f = window['_fim_' + fId];
    if (!f) return;
    const s = f.suspicion || {};
    const score = s.score || 0;
    const reasonsArr = s.reasons || [];
    const level = s.risk_level || 'low';
    const levelLabel = level === 'critical' ? 'CRITICAL' : level === 'high' ? 'HIGH' : level === 'medium' ? 'MEDIUM' : 'LOW';
    const levelColor = level === 'critical' ? '#ff3333' : level === 'high' ? '#ff8844' : level === 'medium' ? '#ffcc66' : '#00d4aa';
    const levelBg = level === 'critical' ? '#3a1a1a' : level === 'high' ? '#3a2a1a' : level === 'medium' ? '#3a3a1a' : '#1a3a2a';
    const changed = (f.change_count || 0) > 0;
    
    let body = '<div style="font-size:12px;">';
    // Header with score
    body += '<div style="background:' + levelBg + ';border-left:4px solid ' + levelColor + ';padding:10px 14px;border-radius:6px;margin-bottom:12px;">';
    body += '<div style="font-size:18px;font-weight:700;color:' + levelColor + ';">Suspicion Score: ' + score + '/100 <span style="font-size:13px;">(' + levelLabel + ')</span></div>';
    body += '<div style="font-size:11px;color:#8892a4;margin-top:4px;">' + (reasonsArr.length ? reasonsArr.map(function(r){return '\u2022 ' + r;}).join('<br>') : 'Khong co ly do dac biet') + '</div>';
    body += '</div>';
    
    // File details table
    body += '<table class="table table-data" style="font-size:11px;margin-bottom:0;">';
    body += '<tr><th style="width:130px;">Duong dan day du</th><td style="font-family:monospace;font-size:10px;word-break:break-all;color:#e4e7eb;">' + (f.path || '-') + '</td></tr>';
    body += '<tr><th>Hash (SHA256)</th><td style="font-family:monospace;font-size:9px;word-break:break-all;color:#00d4aa;">' + (f.file_hash || '-') + '</td></tr>';
    if (changed && f.file_hash_old) {
        body += '<tr><th>Hash cu (truoc khi doi)</th><td style="font-family:monospace;font-size:9px;word-break:break-all;color:#ff8844;">' + (f.file_hash_old || '-') + '</td></tr>';
    }
    body += '<tr><th>Kich thuoc</th><td>' + (f.file_size ? (f.file_size > 1024 ? (f.file_size/1024).toFixed(2)+' KB (' + f.file_size + ' bytes)' : f.file_size + ' bytes') : '-') + '</td></tr>';
    body += '<tr><th>Owner</th><td>' + (f.owner || '-') + '</td></tr>';
    body += '<tr><th>Quyen (Permissions)</th><td style="font-family:monospace;">' + (f.permissions || '-') + '</td></tr>';
    body += '<tr><th>Thay doi lan dau</th><td>' + (f.first_seen || '-') + '</td></tr>';
    body += '<tr><th>Kiem tra lan cuoi</th><td>' + (f.last_checked || '-') + '</td></tr>';
    body += '<tr><th>Sua doi gan nhat</th><td>' + (f.last_modified || '-') + '</td></tr>';
    body += '<tr><th>So lan thay doi</th><td style="color:' + (changed ? '#ff6b6b' : '#00d4aa') + ';font-weight:bold;">' + (f.change_count || 0) + ' lan</td></tr>';
    body += '</table>';
    body += '</div>';
    
    var modalTitle = 'File: ' + (f.path ? f.path.split('\\\\').pop() : 'File');
    showDetailModal('FIM Baseline: ' + modalTitle, body);
}


// ===== v2.1.0: RULES MANAGEMENT =====
function loadRules(){
    const el = document.getElementById('rulesList');
    fetch('/api/rules').then(r => r.json()).then(data => {
        const rules = data.rules || [];
        if (!rules.length) { el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noRules') + '</div>'; return; }
        window._cachedRules = rules;
        el.innerHTML = rules.map((r, i) => {
            return '<div style="background:#111827;border:1px solid #1e2a3a;border-radius:6px;margin-bottom:6px;padding:8px 12px;cursor:pointer;" data-rule-index="' + i + '"><strong style="color:#ffcc66;">' + r.id + '</strong> <span class="badge ' + (r.severity==='CRITICAL'?'bg-danger':r.severity==='HIGH'?'bg-warning text-dark':'bg-info') + '">' + (r.severity||'?') + '</span> <strong style="color:#e4e7eb;">' + (r.name||'?') + '</strong><br><small class="text-muted">' + (r.description||'') + '</small><div style="margin-top:3px;"><small style="color:#5a6a7a;">'+t('ui.conditions') + (r.conditions ? r.conditions.length : 0) + ' | MITRE: ' + (r.mitre||'?') + ' | Tactic: ' + (r.tactic||'?') + (r.logic ? ' | Logic: ' + r.logic : '') + (r.rule_type ? ' | Type: ' + r.rule_type : '') + '</small></div></div>';
        }).join('');
        // Add delegated click handler
        el.querySelectorAll('[data-rule-index]').forEach(div => {
            div.addEventListener('click', function() {
                const idx = parseInt(this.getAttribute('data-rule-index'));
                if (window._cachedRules && window._cachedRules[idx]) {
                    showDetailModal('📋 Rule ' + window._cachedRules[idx].id,
                        '<pre style="color:#d0e8d8;font-size:11px;white-space:pre-wrap;max-height:60vh;overflow-y:auto;">' + 
                        JSON.stringify(window._cachedRules[idx], null, 2).replace(/&/g,'&').replace(/</g,'<').replace(/>/g,'>') + 
                        '</pre>');
                }
            });
        });
    }).catch(() => { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErrShort')+' rules</div>'; });
}

function reloadRules(){
    if (!confirm(t('ui.confirmHotReload'))) return;
    fetch('/api/rules/reload', {method:'POST'}).then(r => r.json()).then(d => {
        if (d.success) { showToast('✅ Đã reload ' + d.agent_rules + ' agent rules + ' + d.cross_machine_rules + ' cross-machine rules'); loadRules(); }
        else { showToast('❌ ' + (d.error || 'Lỗi')); }
    }).catch(() => showToast('❌ Lỗi kết nối'));
}

function deployRules(){
    if (!confirm(t('ui.confirmDeploy'))) return;
    showToast('⏳ Đang deploy rules...');
    fetch('/api/rules/deploy', {method:'POST'}).then(r => r.json()).then(d => {
        if (d.success) { showToast('✅ Đã deploy rules đến ' + d.agents_notified + ' agent(s). Agent sẽ tự động reload.'); }
        else { showToast('❌ ' + (d.error || 'Lỗi')); }
    }).catch(() => showToast('❌ Lỗi kết nối'));
}

function newRuleTemplate(){
    const template = {
        "id": "THREAT-0XX",
        "name": "New Rule Name",
        "mitre": "TXXXX",
        "tactic": "Tactic Name",
        "severity": "MEDIUM",
        "description": "Rule description here",
        "conditions": [
            {
                "type": "windows_event",
                "event_id": "4688",
                "description_contains": ["example"],
                "threshold": 1,
                "within_seconds": 60
            }
        ]
    };
    document.getElementById('editRuleJson').value = JSON.stringify(template, null, 2);
}

function saveRule(){
    const jsonText = document.getElementById('editRuleJson').value.trim();
    if (!jsonText) { showToast('⚠ Nhập JSON rule vào editor!'); return; }
    let rule;
    try { rule = JSON.parse(jsonText); } catch(e) { showToast(''+t('ioc.jsonInvalid')+'' + e.message); return; }
    if (!rule.id) { showToast('⚠ Rule cần có trường "id"!'); return; }
    // Check if update or create
    const existing = window._cachedRules ? window._cachedRules.find(r => r.id === rule.id) : null;
    const method = existing ? 'PUT' : 'POST';
    const url = existing ? '/api/rules/' + rule.id : '/api/rules';
    fetch(url, {method, headers:{'Content-Type':'application/json'}, body:JSON.stringify({rule})})
        .then(r => r.json()).then(d => {
            if (d.success) {
                showToast(existing ? t('ui.ruleUpdated') + rule.id : t('ui.ruleCreated') + rule.id + ' (' + (d.rule_count || '') + t('ui.ruleCount'));
                loadRules();
            } else { showToast('❌ ' + (d.error || 'Lỗi')); }
        }).catch(() => showToast('❌ Lỗi kết nối'));
}

function testRule(){
    const ruleJson = document.getElementById('testRuleJson').value.trim();
    const eventJson = document.getElementById('testEventJson').value.trim();
    const resultEl = document.getElementById('testRuleResult');
    if (!ruleJson || !eventJson) { resultEl.innerHTML = '<div class="alert alert-warning py-1">'+t('ui.enterRuleEventJson')+'</div>'; return; }
    let rule, event;
    try { rule = JSON.parse(ruleJson); } catch(e) { resultEl.innerHTML = '<div class="alert alert-danger py-1">'+t('ui.ruleJsonInvalid') + e.message + '</div>'; return; }
    try { event = JSON.parse(eventJson); } catch(e) { resultEl.innerHTML = '<div class="alert alert-danger py-1">'+t('ui.eventJsonInvalid') + e.message + '</div>'; return; }
    resultEl.innerHTML = '<div class="text-muted"><i class="bi bi-hourglass-split"></i> '+t('ui.testing')+'</div>';
    fetch('/api/rules/test', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({rule, event})})
        .then(r => r.json()).then(d => {
            if (d.success) {
                if (d.triggered) {
                    resultEl.innerHTML = '<div class="alert alert-success py-1">✅ Rule TRIGGERED! ' + d.alerts.length + ' alert(s):<br>' + d.alerts.map(a => '<strong>' + a.rule_id + ': ' + a.rule_name + '</strong> [' + a.severity + ']').join('<br>') + '</div>';
                } else {
                    resultEl.innerHTML = '<div class="alert alert-info py-1">'+t('ui.notTriggered')+'</div>';
                }
            } else {
                resultEl.innerHTML = '<div class="alert alert-danger py-1">'+t('ui.errPrefix') + (d.error || t('ui.errGeneric')) + '</div>';
            }
        }).catch(() => { resultEl.innerHTML = '<div class="alert alert-danger py-1">'+t('ui.connErrShort')+'</div>'; });
}

// ===== ALERT SUPPRESSION (Global Whitelist for False Positive Tuning) =====
function loadSuppressions() {
    const el = document.getElementById('supList');
    if (!el) return;
    el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-hourglass-split"></i> '+t('ui.loading')+'</div>';
    fetch('/api/suppression/list').then(r => r.json()).then(data => {
        const items = data.suppressions || [];
        const cnt = document.getElementById('supCount');
        if (cnt) cnt.textContent = t('supp.count', [items.length]);
        if (!items.length) { el.innerHTML = '<div class="text-center text-muted py-3">'+t('supp.none')+'</div>'; return; }
        el.innerHTML = '<table class="table table-sm table-hover align-middle mb-0" style="font-size:11px;"><thead><tr><th>ID</th><th>'+t('supp.ruleId')+'</th><th>'+t('supp.machine')+'</th><th>'+t('supp.pathHash')+'</th><th>'+t('supp.reason')+'</th><th>'+t('supp.createdBy')+'</th><th>'+t('supp.createdAt')+'</th><th></th></tr></thead><tbody>'
            + items.map(function(s) {
                return '<tr><td>'+escapeHtml(s.id)+'</td><td><strong style="color:#ffcc66;">'+escapeHtml(s.rule_id||'-')+'</strong></td><td>'+escapeHtml(s.machine_id||t('supp.allMachines'))+'</td><td style="color:#8892a4;">'+escapeHtml((s.field_path||'')+(s.field_hash?' | '+s.field_hash:''))+'</td><td>'+escapeHtml(s.reason||'')+'</td><td>'+escapeHtml(s.created_by||'')+'</td><td style="white-space:nowrap;">'+escapeHtml(s.created_at||'')+'</td><td><button class="btn btn-sm btn-outline-danger" style="font-size:10px;padding:0 6px;" onclick="deleteSuppression('+s.id+')">'+t('btn.delete')+'</button></td></tr>';
            }).join('') + '</tbody></table>';
    }).catch(() => { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErr')+'</div>'; });
}

function populateSuppressionForm() {
    fetch('/api/machines').then(r => r.json()).then(ms => {
        const sel = document.getElementById('supMachine');
        if (!sel) return;
        const cur = sel.value;
        sel.innerHTML = '<option value="">'+t('supp.allMachines')+'</option>' + ms.map(m => '<option value="'+escapeHtml(m.machine_id)+'">'+escapeHtml(m.hostname||m.machine_id)+'</option>').join('');
        sel.value = cur;
    }).catch(function(){});
    fetch('/api/rules').then(r => r.json()).then(data => {
        const dl = document.getElementById('supRuleList');
        if (dl && data.rules) { dl.innerHTML = data.rules.map(function(r){ return '<option value="'+escapeHtml(r.id)+'"></option>'; }).join(''); }
    }).catch(function(){});
}

function addSuppression() {
    const rule_id = document.getElementById('supRuleId').value.trim();
    if (!rule_id) { showToast('⚠ ' + t('supp.enterRuleId')); return; }
    const machine_id = document.getElementById('supMachine').value || null;
    const reason = document.getElementById('supReason').value.trim();
    fetch('/api/suppression/add', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({rule_id: rule_id, machine_id: machine_id, reason: reason})})
        .then(r => r.json()).then(d => {
            if (d.success) { showToast('✅ '+t('supp.added')); document.getElementById('supReason').value=''; loadSuppressions(); }
            else { showToast('❌ ' + (d.error || '')); }
        }).catch(() => { showToast('❌ '+t('ui.connErrShort')); });
}

function deleteSuppression(id) {
    if (!confirm(t('supp.confirmDel'))) return;
    fetch('/api/suppression/remove/' + id, {method:'POST'}).then(r => r.json()).then(d => {
        if (d.success) { showToast('✅ '+t('supp.deleted')); loadSuppressions(); }
    }).catch(() => { showToast('❌ '+t('ui.connErrShort')); });
}

// ===== AUDIT LOG =====
let auditData = [];
function loadAudit() {
    const el = document.getElementById('auditList');
    if (!el) return;
    el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-hourglass-split"></i> '+t('ui.loading')+'</div>';
    const limit = document.getElementById('auditLimit') ? document.getElementById('auditLimit').value : 100;
    fetch('/api/audit?limit=' + limit).then(r => r.json()).then(data => {
        auditData = Array.isArray(data) ? data : [];
        renderAudit();
    }).catch(() => { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErr')+'</div>'; });
}

function renderAudit() {
    const el = document.getElementById('auditList');
    if (!el) return;
    const q = (document.getElementById('auditSearch') ? document.getElementById('auditSearch').value : '').toLowerCase();
    const items = auditData.filter(function(r) {
        if (!q) return true;
        return (r.username||'').toLowerCase().includes(q) || (r.action||'').toLowerCase().includes(q) || (r.details||'').toLowerCase().includes(q) || (r.ip_address||'').includes(q);
    });
    if (!items.length) { el.innerHTML = '<div class="text-center text-muted py-3">'+t('audit.none')+'</div>'; return; }
    el.innerHTML = '<table class="table table-sm table-hover align-middle mb-0" style="font-size:11px;"><thead><tr><th>'+t('audit.time')+'</th><th>'+t('audit.user')+'</th><th>'+t('audit.action')+'</th><th>'+t('audit.details')+'</th><th>IP</th></tr></thead><tbody>'
        + items.map(function(r) {
            return '<tr><td style="white-space:nowrap;">'+escapeHtml(r.timestamp||'')+'</td><td>'+escapeHtml(r.username||'')+'</td><td><span class="badge bg-info">'+escapeHtml(r.action||'')+'</span></td><td>'+escapeHtml(r.details||'')+'</td><td>'+escapeHtml(r.ip_address||'-')+'</td></tr>';
        }).join('') + '</tbody></table>';
}

// ===== CLUSTER STATUS =====
function loadCluster() {
    const el = document.getElementById('clusterContent');
    if (!el) return;
    el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-hourglass-split"></i> '+t('ui.loading')+'</div>';
    fetch('/api/cluster/nodes').then(r => r.json()).then(data => {
        // API returns nodes as an object keyed by node_id (cluster_manager.get_all_active_nodes)
        const nodes = Array.isArray(data.nodes) ? data.nodes : Object.values(data.nodes || {});
        let html = '';
        html += '<div class="row g-2 mb-3">';
        html += '<div class="col-md-4"><div class="stat-card"><div class="label">'+t('cluster.nodeId')+'</div><div class="value" style="font-size:14px;">'+escapeHtml(data.node_id||'-')+'</div></div></div>';
        html += '<div class="col-md-4"><div class="stat-card"><div class="label">'+t('cluster.role')+'</div><div class="value" style="font-size:14px;color:#00d4aa;">'+(data.is_master ? '👑 '+t('cluster.master') : t('cluster.slave'))+'</div></div></div>';
        html += '<div class="col-md-4"><div class="stat-card"><div class="label">'+t('cluster.nodes')+'</div><div class="value" style="font-size:14px;">'+nodes.length+'</div></div></div>';
        html += '</div>';
        if (!nodes.length) {
            html += '<div class="text-center text-muted py-3">'+t('cluster.noNodes')+'</div>';
        } else {
            html += '<table class="table table-sm table-hover align-middle mb-0" style="font-size:11px;"><thead><tr><th>'+t('cluster.nodeId')+'</th><th>IP</th><th>'+t('cluster.tcpPort')+'</th><th>'+t('cluster.webPort')+'</th><th>'+t('cluster.agentCount')+'</th><th>'+t('cluster.role')+'</th><th>'+t('cluster.status')+'</th><th>'+t('cluster.lastSeen')+'</th></tr></thead><tbody>';
            html += nodes.map(function(n) {
                return '<tr><td><strong style="color:#ffcc66;">'+escapeHtml(n.node_id||'')+'</strong></td><td>'+escapeHtml(n.ip||'-')+'</td><td>'+escapeHtml(n.tcp_port||'-')+'</td><td>'+escapeHtml(n.web_port||'-')+'</td><td>'+(n.agent_count||0)+'</td><td>'+(n.is_master ? '<span class="badge bg-warning text-dark">'+t('cluster.master')+'</span>' : '<span class="badge bg-secondary">'+t('cluster.slave')+'</span>')+'</td><td>'+escapeHtml(n.status||t('cluster.online'))+'</td><td style="white-space:nowrap;">'+escapeHtml(n.last_seen ? new Date(n.last_seen*1000).toLocaleString() : '-')+'</td></tr>';
            }).join('');
            html += '</tbody></table>';
        }
        el.innerHTML = html;
    }).catch(() => { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErr')+'</div>'; });
}

// ===== AI ENABLE/STATUS =====
function loadAiStatus() {
    fetch('/api/ai/status').then(r => r.json()).then(function(d) {
        const badge = document.getElementById('aiStatusBadge');
        if (!badge) return;
        if (d.ai_disabled) {
            badge.className = 'badge bg-danger me-2';
            badge.style.fontSize = '10px';
            badge.textContent = t('assist.disabled');
        } else {
            badge.className = 'badge bg-success me-2';
            badge.style.fontSize = '10px';
            badge.textContent = t('assist.enabled');
        }
    }).catch(function(){});
}

function toggleAi() {
    if (!confirm(t('assist.confirmToggle'))) return;
    const badge = document.getElementById('aiStatusBadge');
    const current = badge && badge.classList.contains('bg-danger');
    fetch('/api/ai/toggle', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({disabled: !current})})
        .then(r => r.json()).then(function(d) {
            if (d.success) { showToast(d.ai_disabled ? '⛔ ' + t('assist.disabled') : '✅ ' + t('assist.enabled')); loadAiStatus(); }
        }).catch(() => { showToast('❌ ' + t('ui.connErrShort')); });
}

// ===== TABLE SORT (Excel-style: date, number, text; persistent per-table per-column state) =====
let sortState={};
document.addEventListener('click',function(e){
    var th=e.target.closest('th');
    if(!th||!th.closest('table.table-data'))return;
    var table=th.closest('table');
    var tbody=table.querySelector('tbody');
    if(!tbody)return;
    var theadRow=table.querySelector('thead tr');
    if(!theadRow)return;
    // Use numeric index in the thead row to avoid text-content mismatch
    var colIdx=-1;
    for(var i=0;i<theadRow.children.length;i++){if(theadRow.children[i]===th){colIdx=i;break;}}
    if(colIdx<0)return;
    // Stable key from table's nearest id ancestor + column index
    var tableContainer=table.closest('[id]')||table;
    var tableId=(tableContainer.id||tableContainer.className||'tbl').toString().slice(0,30);
    var colKey=tableId+'_c'+colIdx;
    var dir;if(!sortState[colKey]){sortState[colKey]='asc';dir='asc';}else if(sortState[colKey]==='asc'){sortState[colKey]='desc';dir='desc';}else{sortState[colKey]='asc';dir='asc';}
    var rows=Array.prototype.slice.call(tbody.querySelectorAll('tr'));
    if(rows.length<2)return;
    rows.sort(function(a,b){
        var aV=(a.children[colIdx]?a.children[colIdx].textContent:'').trim();
        var bV=(b.children[colIdx]?b.children[colIdx].textContent:'').trim();
        // Try date parsing first (ISO/dd-mm/yyyy-mm-dd)
        var aDate=Date.parse(aV),bDate=Date.parse(bV);
        if(!isNaN(aDate)&&!isNaN(bDate))return(aDate-bDate)*(dir==='asc'?1:-1);
        // Try numeric
        var aNum=parseFloat(aV.replace(/,/g,'')),bNum=parseFloat(bV.replace(/,/g,''));
        if(!isNaN(aNum)&&!isNaN(bNum))return(aNum-bNum)*(dir==='asc'?1:-1);
        // Text (case-insensitive)
        var aLower=aV.toLowerCase(),bLower=bV.toLowerCase();
        if(aLower<bLower)return dir==='asc'?-1:1;
        if(aLower>bLower)return dir==='asc'?1:-1;
        return 0;
    });
    rows.forEach(function(r){tbody.appendChild(r);});
    // Clear old arrow indicators, set new
    Array.prototype.forEach.call(theadRow.querySelectorAll('th'),function(h){h.textContent=h.textContent.replace(/ [▲▼]$/,'');});
    th.textContent+=dir==='asc'?' ▲':' ▼';
});

loadMachines();
loadStats();
refreshMessageBadge();
loadOverviewPanorama();
connectSSE();
// v3.7.1: Performance optimized polling - drastically reduced intervals
// Overview stats (machines + counts): 2 minutes
setInterval(()=>{loadMachines();loadStats();},120000);
// Panorama (CPU/RAM/Disk): 60 seconds (was 15s)
setInterval(()=>{if(currentView==='overview')loadOverviewPanorama();},60000);
// v4.10: Unread messages badge - always poll (not just when Messages tab is open)
setInterval(refreshMessageBadge,30000);
// Active view + network: 5 minutes (was 60s)
setInterval(()=>{reloadActiveView();loadNetwork();},300000);
// Tránh reload khi tab không active (visibility API)
document.addEventListener('visibilitychange',()=>{if(!document.hidden){loadMachines();loadStats();refreshMessageBadge();}});

// ===== v2.4.0: AGENT UPDATE =====
function loadAgentUpdateView() {
    // Load server version
    fetch('/api/agent/version').then(r => r.json()).then(d => {
        document.getElementById('serverAgentVersion').textContent = d.version || '?';
    });
    // Load agent update status by groups
    loadAgentUpdateStatus();
    // Update log tab if active
    const logTab = document.getElementById('tabAuLog');
    if (logTab && logTab.style.display !== 'none') {
        loadAgentUpdateLogs();
    }
}

function loadAgentUpdateStatus() {
    const el = document.getElementById('agentUpdateGroups');
    Promise.all([
        fetch('/api/groups').then(r => r.json()),
        fetch('/api/machines').then(r => r.json()),
        fetch('/api/agent/version').then(r => r.json())
    ]).then(([groupsData, machines, versionData]) => {
        const groups = groupsData.groups || [];
        const serverVersion = versionData.version || '?';
        // Build map of machine_id -> machine info
        const machineMap = {};
        machines.forEach(m => { machineMap[m.machine_id] = m; });

        // Build map of group_id -> members
        const ungroupedMachines = new Set(machines.map(m => m.machine_id));
        const groupMachineMap = {};
        groups.forEach(g => {
            (g.members || []).forEach(m => {
                groupMachineMap[m.machine_id] = g;
                ungroupedMachines.delete(m.machine_id);
            });
        });

        let html = '';

        // Show machines grouped by agent groups
        if (groups.length > 0) {
            groups.forEach(g => {
                const members = g.members || [];
                html += '<div style="background:#111827;border:1px solid #1e2a3a;border-radius:8px;margin:8px;padding:12px;">';
                html += '<div class="d-flex justify-content-between align-items-center mb-2">';
                html += '<strong style="color:#e4e7eb;">📁 ' + g.name + '</strong>';
                html += '<button class="btn btn-sm btn-warning" onclick="pushUpdateToGroup(' + g.id + ')" style="font-size:10px;"><i class="bi bi-cloud-upload"></i> Push Update Group</button>';
                html += '</div>';
                html += '<small class="text-muted">' + t('ui.groupsMembers',[members.length]) + '</small>';

                if (members.length > 0) {
                    html += '<table class="table table-data" style="margin-top:4px;"><thead><tr><th>Hostname</th><th>Machine ID</th><th>'+t('ui.agentVersion')+'</th><th>Server</th><th>'+t('ui.status')+'</th><th>'+t('ui.actions')+'</th></tr></thead><tbody>';
                    members.forEach(m => {
                        const info = machineMap[m.machine_id] || {};
                        const agentVer = info.version || '?';
                        const needsUpdate = agentVer !== serverVersion;
                        const online = info.is_online == 1;
                        html += '<tr>';
                        html += '<td>' + (m.hostname || m.machine_id) + '</td>';
                        html += '<td style="font-family:monospace;font-size:10px;">' + (m.machine_id || '').substring(0, 12) + '...</td>';
                        html += '<td><span class="badge ' + (needsUpdate ? 'bg-warning text-dark' : 'bg-success') + '">' + agentVer + '</span>' + (needsUpdate ? ' <span style="color:#ff4444;">' + t('dash.needsUpdate') + '</span>' : '') + '</td>';
                        html += '<td><span class="badge bg-info">' + serverVersion + '</span></td>';
                        html += '<td>' + (online ? '<span class="badge bg-success">Online</span>' : '<span class="badge bg-secondary">Offline</span>') + '</td>';
                        html += '<td><button class="btn btn-sm btn-warning py-0 px-1" onclick="pushUpdateToMachine(\'' + m.machine_id + '\')" ' + (online ? '' : 'disabled') + '><i class="bi bi-cloud-upload"></i> Push</button><button class="btn btn-sm btn-danger py-0 px-1 ms-1" onclick="event.stopPropagation();resetUserInfoToMachine(\'' + m.machine_id + '\')" ' + (online ? '' : 'disabled') + ' title="Xoa thong tin nguoi dung & reset"><i class="bi bi-person-x"></i></button></td>';
                        html += '</tr>';
                    });
                    html += '</tbody></table>';
                } else {
                    html += '<div class="text-center text-muted py-2">'+t('ui.groupEmpty')+'</div>';
                }
                html += '</div>';
            });
        }

        // Show ungrouped machines
        const ungroupedList = Array.from(ungroupedMachines).map(mid => machineMap[mid]).filter(Boolean);
        if (ungroupedList.length > 0) {
            html += '<div style="background:#111827;border:1px solid #1e2a3a;border-radius:8px;margin:8px;padding:12px;">';
            html += '<strong style="color:#ffcc66;">'+t('ui.ungroupedTitle',[ungroupedList.length])+'</strong>';
            html += '<table class="table table-data" style="margin-top:4px;"><thead><tr><th>Hostname</th><th>Machine ID</th><th>'+t('ui.agentVersion')+'</th><th>Server</th><th>'+t('ui.status')+'</th><th>'+t('ui.actions')+'</th></tr></thead><tbody>';
            ungroupedList.forEach(info => {
                const agentVer = info.version || '?';
                const needsUpdate = agentVer !== serverVersion;
                const online = info.is_online == 1;
                html += '<tr>';
                html += '<td>' + (info.hostname || '?') + '</td>';
                html += '<td style="font-family:monospace;font-size:10px;">' + (info.machine_id || '').substring(0, 12) + '...</td>';
                html += '<td><span class="badge ' + (needsUpdate ? 'bg-warning text-dark' : 'bg-success') + '">' + agentVer + '</span>' + (needsUpdate ? ' <span style="color:#ff4444;">' + t('dash.needsUpdate') + '</span>' : '') + '</td>';
                html += '<td><span class="badge bg-info">' + serverVersion + '</span></td>';
                html += '<td>' + (online ? '<span class="badge bg-success">Online</span>' : '<span class="badge bg-secondary">Offline</span>') + '</td>';
                html += '<td><button class="btn btn-sm btn-warning py-0 px-1" onclick="pushUpdateToMachine(\'' + info.machine_id + '\')" ' + (online ? '' : 'disabled') + '><i class="bi bi-cloud-upload"></i> Push</button><button class="btn btn-sm btn-danger py-0 px-1 ms-1" onclick="event.stopPropagation();resetUserInfoToMachine(\'' + info.machine_id + '\')" ' + (online ? '' : 'disabled') + ' title="Xoa thong tin nguoi dung & reset"><i class="bi bi-person-x"></i></button></td>';
                html += '</tr>';
            });
            html += '</tbody></table></div>';
        }

    // Also add Reset User Info button per group
    if (groups.length > 0) {
        let foundGroups = el.querySelectorAll('[onclick*="pushUpdateToGroup"]');
        // Group-level reset is already available via resetUserInfoToGroup
    }

        if (html === '') {
            html = '<div class="text-center text-muted py-3">' + t('dash.noMachines') + '</div>';
        }
        el.innerHTML = html;
    }).catch(() => {
        el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErrX')+'</div>';
    });
}

function pushUpdateToMachine(machineId) {
    if (!confirm(t('dash.pushToMachine', [machineId]))) return;
    showToast('⏳ Đang push update đến ' + machineId + '...');
    fetch('/api/agent/push-update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ machine_id: machineId })
    }).then(r => r.json()).then(d => {
        if (d.success) {
            showToast(t('dash.pushedUpdate', [d.pushed, d.version]) + (d.failed > 0 ? ', ' + d.failed + t('dash.failed') : ''));
        } else {
            showToast('❌ ' + (d.error || 'Lỗi'));
        }
        loadAgentUpdateView();
    }).catch(() => showToast('❌ Lỗi kết nối'));
}

function pushUpdateToGroup(groupId) {
    if (!confirm(t('dash.pushToGroup'))) return;
    showToast('⏳ Đang push update group...');
    fetch('/api/agent/push-update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_id: groupId })
    }).then(r => r.json()).then(d => {
        if (d.success) {
            showToast('✅ Push update: ' + d.pushed + ' thành công, ' + d.failed + ' thất bại (version ' + d.version + ')');
        } else {
            showToast('❌ ' + (d.error || 'Lỗi'));
        }
        loadAgentUpdateView();
    }).catch(() => showToast('❌ Lỗi kết nối'));
}

function pushUpdateToAll() {
    if (!confirm(t('dash.pushToAll'))) return;
    showToast('⏳ Đang push update tất cả...');
    // Push to each online machine individually
    fetch('/api/machines').then(r => r.json()).then(ms => {
        const onlineMachines = ms.filter(m => m.is_online == 1);
        if (onlineMachines.length === 0) {
            showToast(t('dash.noOnlineMachines'));
            return;
        }
        let done = 0, success = 0, fail = 0;
        onlineMachines.forEach(m => {
            fetch('/api/agent/push-update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ machine_id: m.machine_id })
            }).then(r => r.json()).then(d => {
                done++;
                if (d.success) success += d.pushed;
                fail += d.failed || 0;
                if (done >= onlineMachines.length) {
                    showToast('✅ Push xong: ' + success + ' thành công, ' + fail + ' thất bại');
                    loadAgentUpdateView();
                }
            }).catch(() => {
                done++;
                fail++;
                if (done >= onlineMachines.length) {
                    showToast('✅ Push xong: ' + success + ' thành công, ' + fail + ' thất bại');
                    loadAgentUpdateView();
                }
            });
        });
    });
}

function loadAgentUpdateLogs() {
    const el = document.getElementById('agentUpdateLogList');
    fetch('/api/agent/update-log?limit=100').then(r => r.json()).then(logs => {
        if (!logs || !logs.length) {
            el.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.noUpdateLog') + '</div>';
            return;
        }
        el.innerHTML = tableWrap([t('dash.time'), t('dash.machine'), 'Từ phiên bản', 'Đến phiên bản', t('dash.status'), t('dash.source'), 'Thông báo'],
            logs.map(l => {
                let statusBadge = '';
                if (l.status === 'success') statusBadge = '<span class="badge bg-success">'+t('ui.success')+'</span>';
                else if (l.status === 'failed') statusBadge = '<span class="badge bg-danger">'+t('ui.failed')+'</span>';
                else if (l.status === 'pending') statusBadge = '<span class="badge bg-warning text-dark">'+t('ui.pending')+'</span>';
                else if (l.status === 'downloading') statusBadge = '<span class="badge bg-info">📥 ' + t('dash.downloading') + '</span>';
                else statusBadge = '<span class="badge bg-secondary">' + (l.status || '?') + '</span>';
                let sourceBadge = '';
                if (l.source === 'push') sourceBadge = '<span class="badge bg-warning text-dark">📤 Server Push</span>';
                else if (l.source === 'auto') sourceBadge = '<span class="badge bg-info">🔄 Auto Update</span>';
                else sourceBadge = '<span class="badge bg-secondary">' + (l.source || '?') + '</span>';
                return '<tr><td style="font-size:10px;white-space:nowrap;">' + (l.timestamp || '').substring(0, 19) + '</td><td>' + (l.hostname || l.machine_id || '?') + '</td><td>' + (l.from_version || '?') + '</td><td>' + (l.to_version || '?') + '</td><td>' + statusBadge + '</td><td>' + sourceBadge + '</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + (l.message || '-').substring(0, 60) + '</td></tr>';
            })
        );
    }).catch(() => {
        el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadLogErr')+'</div>';
    });
}

// ===== v2.5.1: USER INFO RESET =====
function resetUserInfoToMachine(machineId) {
    if (!confirm(t('dash.resetUser', [machineId]) + '?\n\nAgent sẽ xóa thông tin người dùng và hiển thị lại bảng nhập thông tin khi khởi động lại.\n\nThao tác này sẽ:\n1. Gửi lệnh reset_user qua TCP 6666\n2. Agent xóa file user_info.json + agent_config.json + boot_tracker.json\n3. Agent tự restart để hiển thị config dialog')) return;
    showToast(t('dash.sendingReset', [machineId]));
    fetch('/api/agent/reset-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ machine_id: machineId })
    }).then(r => r.json()).then(d => {
        if (d.success) {
            showToast('✅ Đã gửi lệnh reset: ' + (d.message || ''));
        } else {
            showToast('❌ ' + (d.error || 'Lỗi'));
        }
        loadAgentUpdateView();
    }).catch(() => showToast('❌ Lỗi kết nối'));
}

function resetUserInfoToGroup(groupId) {
    if (!confirm(t('dash.resetUserGroup') + '?\n\nAgent sẽ xóa thông tin và hiển thị lại bảng nhập thông tin khi khởi động lại.')) return;
    showToast('⏳ Đang gửi lệnh reset group...');
    fetch('/api/agent/reset-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_id: groupId })
    }).then(r => r.json()).then(d => {
        if (d.success) {
            showToast('✅ Reset: ' + d.pushed + ' thành công, ' + d.failed + ' thất bại');
        } else {
            showToast('❌ ' + (d.error || 'Lỗi'));
        }
        loadAgentUpdateView();
    }).catch(() => showToast('❌ Lỗi kết nối'));
}

function resetUserInfoAll() {
    if (!confirm(t('dash.resetUserAll') + '?\n\nAgent sẽ xóa thông tin và hiển thị lại bảng nhập thông tin khi khởi động lại.')) return;
    showToast('⏳ Đang gửi lệnh reset tất cả...');
    fetch('/api/machines').then(r => r.json()).then(ms => {
        const onlineMachines = ms.filter(m => m.is_online == 1);
        if (onlineMachines.length === 0) {
            showToast(t('dash.noOnlineMachines'));
            return;
        }
        let done = 0, success = 0, fail = 0;
        onlineMachines.forEach(m => {
            fetch('/api/agent/reset-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ machine_id: m.machine_id })
            }).then(r => r.json()).then(d => {
                done++;
                if (d.success) success++;
                else fail++;
                if (done >= onlineMachines.length) {
                    showToast('✅ Reset xong: ' + success + ' thành công, ' + fail + ' thất bại');
                    loadAgentUpdateView();
                }
            }).catch(() => {
                done++; fail++;
                if (done >= onlineMachines.length) {
                    showToast('✅ Reset xong: ' + success + ' thành công, ' + fail + ' thất bại');
                    loadAgentUpdateView();
                }
            });
        });
    });
}

// Agent Update tab switching
document.querySelectorAll('[data-tab-au]').forEach(el => {
    el.addEventListener('click', function() {
        document.querySelectorAll('[data-tab-au]').forEach(t => t.classList.remove('active'));
        this.classList.add('active');
        const tab = this.dataset.tabAu;
        document.querySelectorAll('.tab-au-content').forEach(t => t.style.display = 'none');
        if (tab === 'status') { document.getElementById('tabAuStatus').style.display = ''; loadAgentUpdateView(); }
        if (tab === 'log') { document.getElementById('tabAuLog').style.display = ''; loadAgentUpdateLogs(); }
    });
});

// ===== v2.4.0: EMAIL ALERTS =====
let emailTemplates = [];
function loadEmailView(){
    fetch('/api/email/templates').then(r=>r.json()).then(d=>{
        emailTemplates = d.templates || [];
        // Build inline template data for onEmailTemplateChange fallback
        var td = {};
        emailTemplates.forEach(function(t){ td[t.id] = {s: t.subject, b: t.body}; });
        var el = document.getElementById('emailTemplatesData');
        if(el) el.textContent = JSON.stringify(td);
    }).catch(function(){
        // Fallback: build from DOM select options
        var td = {};
        td['uptime_24h'] = {s: '⚠️ Cảnh báo: Máy {hostname} hoạt động liên tục quá 24 giờ', b: 'Kính gửi {user_name},\\n\\n'+t('ui.machines')+' {hostname} (MSNV: {employee_id}) đã hoạt động liên tục quá 24 giờ.\\n\\nĐề nghị kiểm tra và khởi động lại máy để đảm bảo hiệu suất và bảo mật.\\n\\nTrân trọng,\\nBộ phận IT'};
        td['brute_force'] = {s: '🚨 Cảnh báo: Phát hiện tấn công Brute Force trên máy {hostname}', b: 'Kính gửi {user_name},\\n\\nHệ thống GIAM-SAT đã phát hiện dấu hiệu tấn công Brute Force trên máy {hostname}.\\n\\nVui lòng ngắt kết nối mạng ngay lập tức và liên hệ bộ phận IT.\\n\\nTrân trọng,\\nBộ phận IT'};
        td['malware_detected'] = {s: '🦠 Cảnh báo: Phát hiện Malware/Virus trên máy {hostname}', b: 'Kính gửi {user_name},\\n\\nHệ thống GIAM-SAT đã phát hiện phần mềm độc hại trên máy {hostname}.\\n\\nVui lòng KHÔNG mở thêm bất kỳ file nào và liên hệ ngay bộ phận IT.\\n\\nTrân trọng,\\nBộ phận IT'};
        td['phishing_alert'] = {s: '🎣 Cảnh báo: Phát hiện tấn công Phishing trên máy {hostname}', b: 'Kính gửi {user_name},\\n\\nHệ thống GIAM-SAT đã phát hiện dấu hiệu tấn công Phishing trên máy {hostname}.\\n\\nVui lòng không click vào bất kỳ link đáng ngờ nào và báo cáo ngay cho bộ phận IT.\\n\\nTrân trọng,\\nBộ phận IT'};
        td['unauthorized_access'] = {s: '🔓 Cảnh báo: Truy cập trái phép trên máy {hostname}', b: 'Kính gửi {user_name},\\n\\nHệ thống GIAM-SAT đã phát hiện truy cập trái phép trên máy {hostname}.\\n\\nVui lòng xác nhận ngay với bộ phận IT nếu đây không phải là hành động của bạn.\\n\\nTrân trọng,\\nBộ phận IT'};
        td['vulnerability_found'] = {s: '🛡️ Cảnh báo: Lỗ hổng bảo mật trên máy {hostname}', b: 'Kính gửi {user_name},\\n\\nHệ thống GIAM-SAT đã phát hiện lỗ hổng bảo mật trên máy {hostname}.\\n\\nVui lòng cập nhật phần mềm và hệ điều hành lên phiên bản mới nhất.\\n\\nTrân trọng,\\nBộ phận IT'};
        td['suspicious_connection'] = {s: '🌐 Cảnh báo: Kết nối mạng đáng ngờ từ máy {hostname}', b: 'Kính gửi {user_name},\\n\\nHệ thống GIAM-SAT đã phát hiện kết nối mạng đáng ngờ từ máy {hostname}.\\n\\nVui lòng kiểm tra các ứng dụng đang chạy và liên hệ bộ phận IT.\\n\\nTrân trọng,\\nBộ phận IT'};
        td['fim_alert'] = {s: '📁 Cảnh báo: Thay đổi file hệ thống trên máy {hostname}', b: 'Kính gửi {user_name},\\n\\nHệ thống GIAM-SAT đã phát hiện thay đổi file hệ thống trên máy {hostname}.\\n\\nVui lòng xác nhận với bộ phận IT nếu bạn không thực hiện thay đổi này.\\n\\nTrân trọng,\\nBộ phận IT'};
        td['general_warning'] = {s: '⚠️ Cảnh báo bảo mật: Máy {hostname}', b: 'Kính gửi {user_name},\\n\\nHệ thống GIAM-SAT đã phát hiện hoạt động bất thường trên máy {hostname}.\\n\\nVui lòng liên hệ bộ phận IT để được hỗ trợ.\\n\\nTrân trọng,\\nBộ phận IT'};
        var el = document.getElementById('emailTemplatesData');
        if(el) el.textContent = JSON.stringify(td);
    });
    fetch('/api/machines').then(r=>r.json()).then(ms=>{
        const sel = document.getElementById('emailMachine');
        sel.innerHTML = '<option value="">'+t('opt.selectMachineEmail')+'</option>' + ms.map(m=>'<option value="'+m.machine_id+'">'+(m.hostname||m.machine_id)+' ('+(m.user_name||'?')+')</option>').join('');
    });
    // Email tabs
    document.querySelectorAll('[data-tab-em]').forEach(el=>{
        el.addEventListener('click', function(){
            document.querySelectorAll('[data-tab-em]').forEach(t=>t.classList.remove('active'));
            this.classList.add('active');
            document.querySelectorAll('.tab-em-content').forEach(t=>t.style.display='none');
            if(this.dataset.tabEm==='compose') document.getElementById('tabEmCompose').style.display='';
            if(this.dataset.tabEm==='config'){ document.getElementById('tabEmConfig').style.display=''; loadEmailConfig(); }
            if(this.dataset.tabEm==='log'){ document.getElementById('tabEmLog').style.display=''; loadEmailLog(); }
        });
    });
}


function onEmailTemplateChange(){
    var tid=document.getElementById('emailTemplate').value;
    if(!tid){updateEmailPreview();return;}
    // Try from loaded API data first
    var t = emailTemplates.find(function(t){return t.id===tid;});
    if(t){
        document.getElementById('emailSubject').value=t.subject||'';
        document.getElementById('emailBody').value=t.body||'';
        updateEmailPreview();
        return;
    }
    // Fallback: try emailTemplatesData DOM element
    try {
        var el=document.getElementById('emailTemplatesData');
        if(el){
            var data=JSON.parse(el.textContent);
            var x=data[tid];
            if(x){
                document.getElementById('emailSubject').value=x.s;
                document.getElementById('emailBody').value=x.b;
                updateEmailPreview();
            }
        }
    } catch(e) {}
}
function onEmailMachineChange(){
    const mid = document.getElementById('emailMachine').value;
    if(mid){
        fetch('/api/machines/'+mid+'/user').then(r=>r.json()).then(u=>{
            document.getElementById('emailTo').value = u.email || '';
            updateEmailPreview();
        });
    }
}
function updateEmailPreview(){
    const body = document.getElementById('emailBody').value;
    const mid = document.getElementById('emailMachine').value;
    const to = document.getElementById('emailTo').value;
    let preview = body;
    if(mid){
        fetch('/api/machines').then(r=>r.json()).then(ms=>{
            const m = ms.find(x=>x.machine_id===mid);
            if(m){
                preview = preview.replace(/{hostname}/g, m.hostname||mid);
                preview = preview.replace(/{user_name}/g, m.user_name||'');
                preview = preview.replace(/{employee_id}/g, m.employee_id||'');
            }
            document.getElementById('emailPreview').textContent = t('email.toLabel2')+to+'\n'+t('email.subjectLabel2')+document.getElementById('emailSubject').value+'\n\n'+preview;
        });
    } else {
        document.getElementById('emailPreview').textContent = t('email.toLabel2')+to+'\n'+t('email.subjectLabel2')+document.getElementById('emailSubject').value+'\n\n'+preview;
    }
}
document.getElementById('emailBody').addEventListener('input', updateEmailPreview);
document.getElementById('emailSubject').addEventListener('input', updateEmailPreview);
function sendEmailAlert(){
    const mid = document.getElementById('emailMachine').value;
    if(!mid){ showToast('⚠ Chọn máy trạm!'); return; }
    const tid = document.getElementById('emailTemplate').value;
    const subject = document.getElementById('emailSubject').value;
    const body = document.getElementById('emailBody').value;
    const to = document.getElementById('emailTo').value;
    if(!subject||!body){ showToast('⚠ Nhập tiêu đề và nội dung!'); return; }
    document.getElementById('emailSendStatus').textContent = t('ui.sendingEmail');
    fetch('/api/email/send', {method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({machine_id:mid, template_id:tid, subject, body, to_email:to})
    }).then(r=>r.json()).then(d=>{
        if(d.success){ document.getElementById('emailSendStatus').innerHTML = '<span style="color:#88dd99;">✅ '+d.message+'</span>'; showToast('✅ Đã gửi email!'); }
        else { document.getElementById('emailSendStatus').innerHTML = '<span style="color:#ff8888;">'+t('ui.errPrefix')+(d.error||t('ui.errGeneric'))+'</span>'; }
    }).catch(e=>{ document.getElementById('emailSendStatus').innerHTML = '<span style="color:#ff8888;">'+t('ui.connErrShort')+'</span>'; });
}
function loadEmailConfig(){
    fetch('/api/email/config').then(r=>r.json()).then(d=>{
        document.getElementById('smtpHost').value = d.smtp_host;
        document.getElementById('smtpPort').value = d.smtp_port;
        document.getElementById('smtpUser').value = d.smtp_user;
        document.getElementById('smtpStatus').textContent = d.smtp_configured ? t('dash.configured') : t('dash.notConfigured');
        document.getElementById('smtpStatus').className = 'badge '+(d.smtp_configured?'bg-success':'bg-danger');
    });
}
function testEmailConfig(){
    const to = document.getElementById('emailTestTo').value.trim() || 'it@example.com';
    document.getElementById('emailTestResult').innerHTML = '<span style="color:#ffcc66;">'+t('ui.sendingTestEmail')+'</span>';
    fetch('/api/email/test', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({to})})
        .then(r=>r.json()).then(d=>{
            if(d.success) document.getElementById('emailTestResult').innerHTML = '<span style="color:#88dd99;">✅ '+d.message+'</span>';
            else document.getElementById('emailTestResult').innerHTML = '<span style="color:#ff8888;">❌ '+d.error+'</span>';
        }).catch(e=>{ document.getElementById('emailTestResult').innerHTML = '<span style="color:#ff8888;">'+t('ui.connErrShort')+'</span>'; });
}

// ===== v4.10: MAIL ĐÃ GỬI (local sent-mail log on the GIAM-SAT server) =====
function loadEmailLog(){
    fetch('/api/email/sent?limit=200').then(r=>r.json()).then(d=>{
        const list = d.emails || [];
        const tb = document.getElementById('sentEmailList');
        if(!list.length){
            tb.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-3">'+t('ui.noSentEmail')+'</td></tr>';
            return;
        }
        tb.innerHTML = list.map(function(m){
            const st = m.status==='sent'
                ? '<span class="badge bg-success">'+t('ui.sentOk')+'</span>'
                : '<span class="badge bg-danger" title="'+escapeHtml(m.error||'')+'">'+t('ui.sentFail')+'</span>';
            return '<tr>' +
                '<td class="text-muted" style="white-space:nowrap;">'+escapeHtml(m.time)+'</td>' +
                '<td>'+escapeHtml(m.to)+'</td>' +
                '<td>'+escapeHtml(m.subject)+'</td>' +
                '<td>'+st+'</td>' +
                '<td><button class="btn btn-sm btn-outline-secondary" style="font-size:10px;padding:1px 6px;" onclick="toggleSentBody(\''+m.id+'\')" title='+t('tt.viewContent')+'>👁</button></td>' +
                '<td><button class="btn btn-sm btn-outline-danger" style="font-size:10px;padding:1px 6px;" onclick="deleteSentEmail(\''+m.id+'\')" title='+t('tt.deleteRecord')+'>🗑</button></td>' +
                '</tr>' +
                '<tr id="sentBody_'+m.id+'" style="display:none;"><td colspan="6" style="background:#0a0f14;border-top:none;white-space:pre-wrap;font-size:11px;color:#a8b4c0;">'+escapeHtml(m.body||'')+'</td></tr>';
        }).join('');
    }).catch(function(){
        document.getElementById('sentEmailList').innerHTML = '<tr><td colspan="6" class="text-center text-danger py-3">'+t('ui.loadSentErr')+'</td></tr>';
    });
}
function toggleSentBody(id){
    const el = document.getElementById('sentBody_'+id);
    if(el) el.style.display = (el.style.display==='none') ? '' : 'none';
}
function deleteSentEmail(id){
    if(!confirm(t('ui.confirmDelMailRecord'))) return;
    fetch('/api/email/sent/'+encodeURIComponent(id), {method:'DELETE'})
        .then(r=>r.json()).then(d=>{
            if(d.success){ showToast('🗑 Đã xóa bản ghi'); loadEmailLog(); }
            else showToast('❌ '+(d.error||'Lỗi xóa'));
        }).catch(function(){ showToast('❌ Lỗi kết nối'); });
}
function clearSentEmails(){
    if(!confirm(t('ui.confirmClearMailLog'))) return;
    fetch('/api/email/sent/clear', {method:'POST'})
        .then(r=>r.json()).then(d=>{
            if(d.success){ showToast('🗑 Đã xóa '+(d.deleted||0)+' bản ghi'); loadEmailLog(); }
            else showToast('❌ '+(d.error||'Lỗi xóa'));
        }).catch(function(){ showToast('❌ Lỗi kết nối'); });
}



// ===== v2.5.0: ATTACK OVERVIEW =====

function loadAttackOverview() {
    const el = document.getElementById("attackContent");
    el.innerHTML = '<div class="text-center text-muted py-3"><div class="spinner-border text-success spinner-border-sm" role="status"></div> ' + t('ao.analyzing') + '</div>';
    fetch("/api/attack/overview").then(r => r.json()).then(data => {
        if (data.error) { el.innerHTML = '<div class="alert alert-danger m-3">' + escapeHtml(data.error) + '</div>'; return; }
        attackData = data;
        // v4.13 (P2): kill-chain risk triage -> Incident jump (card rendered inside renderAttackOverview)
        fetch("/api/risk/killchain?since_hours=24&min_tactics=3").then(r => r.json()).then(kc => {
            _killchainData = kc && !kc.error ? kc : null;
            renderAttackOverview(data);
        }).catch(() => { _killchainData = null; renderAttackOverview(data); });
    }).catch(e => { el.innerHTML = '<div class="alert alert-danger m-3">' + t('ui.loadErr') + ': ' + escapeHtml(e.message) + '</div>'; });
}

function renderAttackOverview(data) {
    const el = document.getElementById("attackContent");
    const stats = data.stats || {};
    const chains = data.chains || [];
    const timeline = data.timeline || [];
    const nodes = data.nodes || [];
    const edges = data.edges || [];

    // Store globally for chain/timeline detail
    _attackData = data;
    _timelineData = timeline;

    // v4.13 (P2): kill-chain risk card (triage) - rendered even when no attack chains
    const kc = _killchainData || null;
    let kcHtml = '';
    if (kc) {
        const kcInc = kc.incidents || [];
        kcHtml += '<div style="background:#0d1117;border-bottom:1px solid #2a3a4a;padding:10px 12px;">';
        kcHtml += '<div style="display:flex;justify-content:space-between;align-items:center;">';
        kcHtml += '<h6 style="color:#ffcc66;font-size:12px;margin:0;"><i class="bi bi-diagram-3"></i> ' + t('kc.title') + '</h6>';
        kcHtml += '<span style="font-size:10px;color:#5a6a7a;">' + t('kc.window', [kc.since_hours || 24, kc.min_tactics || 3]) + '</span></div>';
        if (!kcInc.length) {
            kcHtml += '<div class="text-muted py-1" style="font-size:11px;"><i class="bi bi-check-circle text-success"></i> ' + t('kc.none') + '</div>';
        } else {
            kcInc.forEach(function(m) {
                kcHtml += '<div style="background:#2a1a1a;border:1px solid #5a2a2a;border-radius:4px;padding:6px 8px;margin-top:6px;display:flex;justify-content:space-between;align-items:center;">';
                kcHtml += '<div><strong style="color:#ff9966;">' + escapeHtml(m.hostname) + '</strong> <span class="badge bg-danger" style="font-size:9px;">' + t('kc.incident') + '</span>';
                kcHtml += '<div style="font-size:10px;color:#8892a4;margin-top:2px;">' + t('kc.tactics', [m.tactic_count]) + ': ' + m.tactics.map(escapeHtml).join(', ') + '</div></div>';
                kcHtml += '<div style="display:flex;align-items:center;gap:6px;"><span class="badge bg-danger" style="font-size:12px;">' + m.tactic_count + '</span>';
                kcHtml += '<button class="btn btn-sm btn-outline-danger" style="font-size:10px;padding:1px 8px;" onclick="openIncidentForMachine(\'' + escapeHtml(m.machine_id) + '\',\'' + escapeHtml(m.hostname) + '\')">🔍 ' + t('kc.investigate') + '</button></div></div>';
            });
        }
        kcHtml += '</div>';
    }

    if (!chains.length && !timeline.length) {
        el.innerHTML = kcHtml + '<div class="text-center py-5"><i class="bi bi-check-circle text-success" style="font-size:48px;"></i><h5 class="mt-2">' + t('ao.noAttack') + '</h5><p class="text-muted">' + t('ao.noAttackSub') + '</p></div>';
        return;
    }

    // Build layout: Stats bar + [Attack Map (left) | Chains (right)] + Timeline (bottom)
    let html = kcHtml;

    // === STATS BAR ===
    html += '<div class="row g-2 p-2 text-center" style="background:#0f1923;border-bottom:1px solid #2a3a4a;position:sticky;top:0;z-index:10;">';
    html += '<div class="col-2"><div style="background:#1a1a2a;border-radius:4px;padding:6px;"><span style="font-size:20px;color:#ff4444;font-weight:700;">' + (stats.total_chains || 0) + '</span><div style="font-size:9px;color:#888;">' + t('ao.chainsTitle') + '</div></div></div>';
    html += '<div class="col-2"><div style="background:#3a1a1a;border-radius:4px;padding:6px;"><span style="font-size:20px;color:#ff4444;font-weight:700;">' + (stats.critical_chains || 0) + '</span><div style="font-size:9px;color:#888;">CRITICAL</div></div></div>';
    html += '<div class="col-2"><div style="background:#1a1a2a;border-radius:4px;padding:6px;"><span style="font-size:20px;color:#ffcc66;font-weight:700;">' + (stats.compromised_count || 0) + '</span><div style="font-size:9px;color:#888;">' + t('ao.legendCompromised') + '</div></div></div>';
    html += '<div class="col-2"><div style="background:#1a1a2a;border-radius:4px;padding:6px;"><span style="font-size:20px;color:#888;font-weight:700;">' + (stats.c2_count || 0) + '</span><div style="font-size:9px;color:#888;">' + t('ao.legendC2') + '</div></div></div>';
    html += '<div class="col-4 text-end" style="font-size:9px;color:#5a6a7a;padding-top:8px;">' + (stats.generated_at || '') + '</div>';
    html += '</div>';

    // === MAIN CONTENT: Map + Chains ===
    html += '<div class="row g-0" style="min-height:500px;">';

    // Left: Attack Map Canvas
    html += '<div class="col-md-7 p-2 position-relative" style="background:#0a0f1a;">';
    html += '<canvas id="attackMapCanvas" style="width:100%;height:100%;min-height:480px;cursor:grab;"></canvas>';
    html += '<div style="position:absolute;top:8px;right:12px;font-size:9px;color:#5a6a7a;">' + t('ao.mapHint') + '</div>';
    html += '<div style="position:absolute;bottom:8px;left:12px;font-size:10px;">';
    html += '<span class="badge bg-danger" style="font-size:9px;">' + t('ao.legendCompromised') + '</span> ';
    html += '<span class="badge bg-info" style="font-size:9px;">' + t('ao.legendMachine') + '</span> ';
    html += '<span class="badge bg-dark" style="font-size:9px;">' + t('ao.legendC2') + '</span>';
    html += '</div>';
    html += '</div>';

    // Right: Attack Chains
    html += '<div class="col-md-5 p-2" style="background:#0d1117;max-height:520px;overflow-y:auto;">';
    html += '<h6 style="color:#ffcc66;font-size:12px;"><i class="bi bi-link-45deg"></i> ' + t('ao.chainsTitle') + '</h6>';
    if (chains.length === 0) {
        html += '<div class="text-muted py-2" style="font-size:11px;">' + t('dash.noChains') + '</div>';
    } else {
        chains.forEach((chain, idx) => {
            const sevColor = chain.severity === 'CRITICAL' ? '#ff4444' : '#ff9966';
            const sevBg = chain.severity === 'CRITICAL' ? '#3a1a1a' : '#3a2a1a';
            html += '<div style="background:' + sevBg + ';border-left:3px solid ' + sevColor + ';padding:8px 10px;margin-bottom:6px;border-radius:4px;cursor:pointer;" onclick="highlightChain(\'' + chain.id + '\')" ondblclick="showChainDetail(\'' + chain.id + '\')" title="' + t('ao.chainHint') + '">';
            html += '<div style="font-size:12px;color:' + sevColor + ';font-weight:600;">' + chain.id + ' - ' + chain.root_hostname + '</div>';
            html += '<div style="font-size:10px;color:#8892a4;margin-top:2px;">' + chain.steps.length + ' ' + t('ao.steps') + ' | ' + chain.severity + '</div>';
            // Steps preview
            chain.steps.slice(0, 4).forEach(step => {
                const icon = step.type === 'beaconing' ? '\\ud83d\\udce1' : '\\u26a0';
                html += '<div style="font-size:10px;color:#c0d4e0;margin-top:2px;">' + icon + ' ' + (step.command || step.rule_name || step.description || '').substring(0, 60) + '</div>';
            });
            if (chain.steps.length > 4) html += '<div style="font-size:9px;color:#5a6a7a;">' + t('ao.moreSteps', [chain.steps.length - 4]) + '</div>';
            html += '</div>';
        });
    }
    html += '</div>';
    html += '</div>';

    // === TIMELINE BAR ===
    html += '<div style="background:#0d1117;border-top:1px solid #2a3a4a;padding:8px 12px;overflow-x:auto;white-space:nowrap;">';
    html += '<h6 style="color:#ffcc66;font-size:11px;margin-bottom:6px;"><i class="bi bi-clock-history"></i> ' + t('ao.timelineTitle') + '</h6>';
    if (timeline.length === 0) {
        html += '<span class="text-muted" style="font-size:11px;">' + t('dash.noEventsAny') + '</span>';
    } else {
        html += '<div style="display:flex;gap:4px;align-items:center;min-height:40px;">';
        timeline.forEach((t, ti) => {
            const dotColor = t.severity === 'CRITICAL' ? '#ff4444' : t.severity === 'HIGH' ? '#ff9966' : '#ffcc66';
            const size = t.severity === 'CRITICAL' ? '14px' : '10px';
            html += '<div style="flex-shrink:0;text-align:center;cursor:pointer;" title="' + escapeHtml(t.label || '') + '\\n' + escapeHtml(t.hostname || '') + '\\n' + escapeHtml(t.time || '') + '" onclick="showTimelineDetail(' + ti + ')">';
            html += '<div style="width:' + size + ';height:' + size + ';border-radius:50%;background:' + dotColor + ';margin:0 auto 2px;box-shadow:0 0 6px ' + dotColor + ';"></div>';
            html += '<div style="font-size:9px;color:#5a6a7a;max-width:60px;overflow:hidden;text-overflow:ellipsis;">' + (t.time || '').substring(11, 16) + '</div>';
            html += '<div style="font-size:8px;color:#8892a4;max-width:60px;overflow:hidden;text-overflow:ellipsis;">' + escapeHtml((t.label || '').substring(0, 20)) + '</div>';
            html += '</div>';
        });
        html += '</div>';
    }
    html += '</div>';

    el.innerHTML = html;

    // Initialize Canvas
    setTimeout(function() { initAttackMap(data); }, 100);
}

// ===== CANVAS ATTACK MAP =====
function initAttackMap(data) {
    const canvas = document.getElementById("attackMapCanvas");
    if (!canvas) return;
    attackMapCanvas = canvas;
    attackMapCtx = canvas.getContext("2d");

    const container = canvas.parentElement;
    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight || 480;

    const nodes = data.nodes || [];
    const edges = data.edges || [];

    // Layout: simple circular placement
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    const radius = Math.min(cx, cy) * 0.7;

    attackMapNodes = nodes.map((n, i) => {
        // Compromised/C2 nodes in center, normal machines on outer ring
        let angle, r;
        const compromisedNodes = nodes.filter(nn => nn.type !== 'machine');
        const machineNodes = nodes.filter(nn => nn.type === 'machine');

        if (n.type !== 'machine' && compromisedNodes.length > 0) {
            const ci = compromisedNodes.indexOf(n);
            angle = (ci / compromisedNodes.length) * Math.PI * 2;
            r = radius * 0.3;
        } else if (n.type === 'machine' && machineNodes.length > 0) {
            const mi = machineNodes.indexOf(n);
            angle = (mi / machineNodes.length) * Math.PI * 2;
            r = radius * 0.8;
        } else {
            angle = (i / nodes.length) * Math.PI * 2;
            r = radius * 0.5;
        }

        return {
            ...n,
            x: cx + Math.cos(angle) * r,
            y: cy + Math.sin(angle) * r,
            vx: 0, vy: 0,
            radius: n.type === 'c2_server' ? 18 : n.type === 'compromised' ? 22 : 14,
            pulse: 0
        };
    });

    // Mouse interaction
    let dragging = false, dragNode = null, offsetX = 0, offsetY = 0;
    let panX = 0, panY = 0, panning = false, panStartX = 0, panStartY = 0;

    canvas.onmousedown = function(e) {
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left - panX;
        const my = e.clientY - rect.top - panY;

        const hit = attackMapNodes.find(n => {
            const dx = mx - n.x, dy = my - n.y;
            return Math.sqrt(dx*dx + dy*dy) < n.radius + 4;
        });

        if (hit) {
            dragNode = hit;
            offsetX = hit.x - mx;
            offsetY = hit.y - my;
            dragging = true;
        } else {
            panning = true;
            panStartX = e.clientX - panX;
            panStartY = e.clientY - panY;
        }
        canvas.style.cursor = dragging ? 'grabbing' : 'grabbing';
    };

    // onmousemove handled below (combined handler)

    canvas.onmouseup = function() {
        dragging = false; dragNode = null;
        panning = false;
        canvas.style.cursor = 'grab';
    };

    canvas.onwheel = function(e) {
        e.preventDefault();
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const zoom = e.deltaY < 0 ? 1.1 : 0.9;
        attackMapNodes.forEach(n => {
            n.x = mx + (n.x - mx) * zoom;
            n.y = my + (n.y - my) * zoom;
            n.radius *= zoom;
        });
    };

    // Combined mousemove: drag/pan + hover
    canvas.onmousemove = function(e) {
        const rect = canvas.getBoundingClientRect();
        // Handle drag/pan
        if (dragging && dragNode) {
            dragNode.x = e.clientX - rect.left + offsetX - panX;
            dragNode.y = e.clientY - rect.top + offsetY - panY;
            return;
        }
        if (panning) {
            panX = e.clientX - panStartX;
            panY = e.clientY - panStartY;
            return;
        }
        // Hover detection
        const mx = e.clientX - rect.left - panX;
        const my = e.clientY - rect.top - panY;
        let hovered = false;
        for (const n of attackMapNodes) {
            const dx = mx - n.x, dy = my - n.y;
            if (Math.sqrt(dx*dx + dy*dy) < n.radius + 4) {
                canvas.title = n.label + ' (' + n.type + ')';
                if (n.chain_id) canvas.style.cursor = 'pointer';
                hovered = true;
                break;
            }
        }
        if (!hovered) { canvas.title = ''; canvas.style.cursor = 'grab'; }
    };

    canvas.onclick = function(e) {
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left - panX;
        const my = e.clientY - rect.top - panY;
        for (const n of attackMapNodes) {
            const dx = mx - n.x, dy = my - n.y;
            if (Math.sqrt(dx*dx + dy*dy) < n.radius + 4 && n.chain_id) {
                highlightChain(n.chain_id);
                break;
            }
        }
    };

    // Start animation loop
    if (attackMapAnimId) cancelAnimationFrame(attackMapAnimId);
    function animate() {
        const ctx = attackMapCtx;
        const cw = attackMapCanvas.width;
        const ch = attackMapCanvas.height;
        ctx.clearRect(0, 0, cw, ch);

        // Background grid
        ctx.strokeStyle = '#1a2a3a';
        ctx.lineWidth = 0.5;
        for (let x = panX % 40; x < cw; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, ch); ctx.stroke(); }
        for (let y = panY % 40; y < ch; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(cw, y); ctx.stroke(); }

        ctx.save();
        ctx.translate(panX, panY);

        // Draw edges
        edges.forEach(edge => {
            const src = attackMapNodes.find(n => n.id === edge.source);
            const tgt = attackMapNodes.find(n => n.id === edge.target);
            if (src && tgt) {
                ctx.strokeStyle = edge.severity === 'CRITICAL' ? 'rgba(255,68,68,0.6)' : 'rgba(255,153,102,0.4)';
                ctx.lineWidth = 2;
                ctx.setLineDash([6, 3]);
                ctx.beginPath();
                ctx.moveTo(src.x, src.y);
                ctx.lineTo(tgt.x, tgt.y);
                ctx.stroke();
                ctx.setLineDash([]);

                // Arrow
                const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
                const ax = tgt.x - Math.cos(angle) * (tgt.radius + 4);
                const ay = tgt.y - Math.sin(angle) * (tgt.radius + 4);
                ctx.fillStyle = ctx.strokeStyle;
                ctx.beginPath();
                ctx.moveTo(ax, ay);
                ctx.lineTo(ax - 8 * Math.cos(angle - 0.5), ay - 8 * Math.sin(angle - 0.5));
                ctx.lineTo(ax - 8 * Math.cos(angle + 0.5), ay - 8 * Math.sin(angle + 0.5));
                ctx.fill();

                // Label
                ctx.fillStyle = '#8892a4';
                ctx.font = '9px Segoe UI';
                ctx.fillText(edge.label || '', (src.x + tgt.x) / 2, (src.y + tgt.y) / 2 - 6);
            }
        });

        // Draw nodes
        attackMapNodes.forEach(n => {
            n.pulse = (n.pulse + 0.03) % (Math.PI * 2);

            let color, glowColor;
            if (n.type === 'compromised') { color = '#ff6644'; glowColor = 'rgba(255,100,60,0.4)'; }
            else if (n.type === 'c2_server') { color = '#666'; glowColor = 'rgba(100,100,100,0.3)'; }
            else if (n.type === 'machine') { color = '#3399ff'; glowColor = 'rgba(50,150,255,0.2)'; }
            else { color = '#3399ff'; glowColor = 'rgba(50,150,255,0.2)'; }

            // Glow
            if (n.type === 'compromised' || n.type === 'c2_server') {
                const glowR = n.radius + 4 + Math.sin(n.pulse * 2) * 3;
                const grad = ctx.createRadialGradient(n.x, n.y, n.radius * 0.5, n.x, n.y, glowR);
                grad.addColorStop(0, glowColor);
                grad.addColorStop(1, 'transparent');
                ctx.fillStyle = grad;
                ctx.beginPath(); ctx.arc(n.x, n.y, glowR, 0, Math.PI * 2); ctx.fill();
            }

            // Node circle
            ctx.fillStyle = color;
            ctx.beginPath(); ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2); ctx.fill();
            ctx.strokeStyle = '#fff';
            ctx.lineWidth = 1.5;
            ctx.stroke();

            // Icon
            ctx.fillStyle = '#fff';
            ctx.font = (n.radius * 0.8) + 'px Segoe UI';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            const icon = n.type === 'c2_server' ? '\\u2601' : n.type === 'compromised' ? '!' : '\\u2699';
            ctx.fillText(icon, n.x, n.y);

            // Label
            ctx.fillStyle = '#c8d8e8';
            ctx.font = '10px Segoe UI';
            ctx.fillText(n.label, n.x, n.y + n.radius + 12);
        });

        ctx.restore();
        attackMapAnimId = requestAnimationFrame(animate);
    }
    animate();
}

// Store attack data globally for chain detail
let _attackData = null;
let _killchainData = null; // v4.13 (P2): /api/risk/killchain -> Incident jump

// ===== CHAIN HIGHLIGHT + CLICK FOR FULL DETAIL =====
function highlightChain(chainId) {
    const allChains = document.querySelectorAll('[onclick*="highlightChain"]');
    allChains.forEach(el => {
        el.style.opacity = el.getAttribute('onclick').includes(chainId) ? '1' : '0.4';
    });
    // Scroll to chain
    const target = Array.from(allChains).find(el => el.getAttribute('onclick').includes(chainId));
    if (target) target.scrollIntoView({behavior: 'smooth', block: 'center'});
}

function showChainDetail(chainId) {
    if (!_attackData) return;
    const chain = (_attackData.chains || []).find(c => c.id === chainId);
    if (!chain) return;
    const sevColor = chain.severity === 'CRITICAL' ? '#ff4444' : '#ff9966';
    const sevBg = chain.severity === 'CRITICAL' ? '#3a1a1a' : '#3a2a1a';
    let body = '<div style="background:' + sevBg + ';border-left:4px solid ' + sevColor + ';padding:12px;border-radius:6px;margin-bottom:12px;">';
    body += '<h5 style="color:' + sevColor + ';margin:0;">' + chain.id + '</h5>';
    body += '<div style="font-size:12px;color:#8892a4;">Root: ' + (chain.root_hostname || '-') + ' | ' + chain.steps.length + ' steps | ' + chain.severity + '</div>';
    body += '</div>';
    body += '<table class="table table-data" style="font-size:11px;"><thead><tr><th>#</th><th>Time</th><th>Machine</th><th>Type</th><th>Rule/Event</th><th>Severity</th><th>Command/Description</th></tr></thead><tbody>';
    chain.steps.forEach((step, i) => {
        const sColor = step.severity === 'CRITICAL' ? '#ff4444' : step.severity === 'HIGH' ? '#ff9966' : '#ffcc66';
        body += '<tr><td>' + (i+1) + '</td>';
        body += '<td style="font-size:10px;">' + (step.time || '-').substring(0,19) + '</td>';
        body += '<td>' + (step.hostname || step.machine_id || '-') + '</td>';
        body += '<td><span class="badge ' + (step.type === 'beaconing' ? 'bg-danger' : 'bg-warning text-dark') + '">' + (step.type || '?') + '</span></td>';
        body += '<td>' + (step.rule_id || step.rule_name || '-') + '</td>';
        body += '<td><span style="color:' + sColor + ';">' + (step.severity || '?') + '</span></td>';
        body += '<td style="max-width:300px;font-size:10px;">' + (step.command || step.description || '-').substring(0,120) + '</td></tr>';
    });
    body += '</tbody></table>';
    if (chain.beaconing_target) {
        body += '<div style="background:#3a1a1a;padding:8px;border-radius:4px;margin-top:8px;"><strong style="color:#ff8888;">\\ud83d\\udce1 Beaconing target:</strong> ' + chain.beaconing_target + '</div>';
    }
    showDetailModal('Attack Chain: ' + chain.id, body);
}

// ===== TIMELINE DETAIL (fixed) =====
let _timelineData = [];

function showTimelineDetail(idx) {
    const t = _timelineData[idx];
    if (!t) return;
    const sevBadge = t.severity === 'CRITICAL' ? '<span class="badge bg-danger">CRITICAL</span>' : 
                     t.severity === 'HIGH' ? '<span class="badge bg-warning text-dark">HIGH</span>' : 
                     t.severity === 'MEDIUM' ? '<span class="badge bg-info">MEDIUM</span>' :
                     '<span class="badge bg-secondary">' + (t.severity || '?') + '</span>';
    let detailHtml = '<table class="table table-data" style="font-size:11px;"><tbody>';
    detailHtml += '<tr><th style="width:120px;">Time</th><td>' + (t.time || '-') + '</td></tr>';
    detailHtml += '<tr><th>Machine</th><td>' + (t.hostname || t.machine_id || '-') + '</td></tr>';
    detailHtml += '<tr><th>Event</th><td>' + (t.label || t.type || '-') + '</td></tr>';
    detailHtml += '<tr><th>Severity</th><td>' + sevBadge + '</td></tr>';
    detailHtml += '<tr><th>Type</th><td>' + (t.type || '-') + '</td></tr>';
    if (t.rule_id) detailHtml += '<tr><th>Rule ID</th><td>' + t.rule_id + '</td></tr>';
    if (t.dst) detailHtml += '<tr><th>Destination</th><td>' + t.dst + '</td></tr>';
    if (t.command) detailHtml += '<tr><th>Command</th><td style="font-family:monospace;font-size:10px;">' + t.command + '</td></tr>';
    if (t.description) detailHtml += '<tr><th>Description</th><td>' + t.description + '</td></tr>';
    if (t.source_ip) detailHtml += '<tr><th>Source IP</th><td>' + t.source_ip + '</td></tr>';
    detailHtml += '</tbody></table>';
    showDetailModal('Attack Timeline: ' + (t.hostname || t.machine_id || 'Event'), detailHtml);
}
// ===== v2.5.1: REPORT EXPORT MODAL =====
function showReportModal() {
    const fmt = document.getElementById('reportFormat')?.value || 'xlsx';
    const fmtLabel = fmt === 'html' ? 'HTML (.html) - Interactive collapsible' : t('dash.excelRow');
    const fmtDesc = fmt === 'html'
        ? '<strong>HTML (.html)</strong> - ' + t('dash.htmlDesc')
        : t('dash.excelDesc');

    let body = '<div style="font-size:13px;">';
    body += '<p class="text-muted mb-3">' + t('dash.exportDesc', [fmtDesc]) + '</p>';
    body += '<div class="mb-3 p-2" style="background:#0a1a1a;border-radius:6px;">';
    body += '<div class="form-check mb-2">';
    body += '<input class="form-check-input" type="checkbox" id="rptConfig" checked>';
    body += '<label class="form-check-label" for="rptConfig"><strong>' + t('dash.machineConfig') + '</strong><br><small class="text-muted">' + t('dash.machineConfigSub') + '</small></label>';
    body += '</div>';
    body += '<div class="form-check mb-2">';
    body += '<input class="form-check-input" type="checkbox" id="rptSoftware" checked>';
    body += '<label class="form-check-label" for="rptSoftware"><strong>' + t('dash.softwareList') + '</strong><br><small class="text-muted">' + t('dash.softwareListSub') + '</small></label>';
    body += '</div>';
    body += '<div class="form-check">';
    body += '<input class="form-check-input" type="checkbox" id="rptUser" checked>';
    body += '<label class="form-check-label" for="rptUser"><strong>' + t('dash.userInfo') + '</strong><br><small class="text-muted">' + t('dash.userInfoSub') + '</small></label>';
    body += '</div>';
    body += '</div>';
    body += '<div class="alert alert-info py-2 mb-2" style="background:#1a3a5a;color:#88ccff;font-size:11px;"><i class="bi bi-info-circle"></i> '+t('ui.formatInfo',[fmtLabel])+'</div>';
    body += '<hr class="my-2">';
    body += '<div class="mb-2"><strong>'+t('reports.summaryTitle')+'</strong><br><small class="text-muted">'+t('reports.summarySub')+'</small></div>';
    body += '<div class="d-flex gap-2 mb-3">';
    body += '<button class="btn btn-sm btn-outline-info" onclick="generateSummaryReport(\'daily\')"><i class="bi bi-calendar-day"></i> '+t('reports.daily')+'</button>';
    body += '<button class="btn btn-sm btn-outline-info" onclick="generateSummaryReport(\'weekly\')"><i class="bi bi-calendar-week"></i> '+t('reports.weekly')+'</button>';
    body += '</div>';
    body += '<div class="text-end"><button class="btn btn-sm btn-success" onclick="exportReport()"><i class="bi bi-download"></i> ' + t('dash.downloadReport') + '</button></div>';
    body += '</div>';
    showDetailModal(t('dash.exportTitle'), body);
}

function generateSummaryReport(type) {
    if (!confirm(t('reports.confirmGen'))) return;
    fetch('/api/reports/generate', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({type: type})})
        .then(r => r.json()).then(d => {
            if (!d.success) { showToast('❌ ' + (d.error || t('ui.errGeneric'))); return; }
            const filename = String(d.path || '').split(/[\\/]/).pop();
            const a = document.createElement('a');
            a.href = '/api/reports/download/' + encodeURIComponent(filename);
            a.download = filename;
            document.body.appendChild(a); a.click(); a.remove();
            showToast('✅ ' + t('reports.done'));
        }).catch(() => { showToast('❌ ' + t('ui.connErrShort')); });
}

function exportReport(fmtId, cfgId, swId, uidId) {
    fmtId = fmtId || 'reportFormat';
    cfgId = cfgId || 'rptConfig';
    swId = swId || 'rptSoftware';
    uidId = uidId || 'rptUser';
    const btn = document.querySelector('#detailModal .btn-success');
    const fmt = document.getElementById(fmtId)?.value || 'xlsx';
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-hourglass-split"></i> ' + t('ao.generating') + ''; }

    const url = fmt === 'html' ? '/api/reports/machine-config-html' : '/api/reports/machine-config-export';

    fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            include_config: document.getElementById(cfgId)?.checked,
            include_software: document.getElementById(swId)?.checked,
            include_user: document.getElementById(uidId)?.checked
        })
    }).then(r => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const disposition = r.headers.get('Content-Disposition');
        let filename = fmt === 'html' ? 'GIAM-SAT_Config_Report.html' : 'GIAM-SAT_Config_Report.xlsx';
        if (disposition) {
            const match = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
            if (match && match[1]) filename = match[1].replace(/['"]/g, '');
        }
        return r.blob().then(blob => ({ blob, filename }));
    }).then(({ blob, filename }) => {
        const url2 = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url2; a.download = filename;
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        URL.revokeObjectURL(url2);
        showToast(t('dash.reportDownloaded', [filename]));
        const modal = bootstrap.Modal.getInstance(document.getElementById('detailModal'));
        if (modal && modal._isShown) modal.hide();
    }).catch(e => {
        showToast(t('dash.reportError', [e.message]));
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-download"></i> '+t('ui.downloadReport')+''; }
    });
}

// ===== FLOATING AI WIDGET =====
(function(){
  let autoMonitorInterval = null;
  let autoMonitorRunning = false;
  let lastAutoResponse = '';

  // Expose toggle function for onclick in HTML
  window.toggleFloatAiDialog = function(){
    const dlg=document.getElementById('floatAiDialog');
    dlg.classList.toggle('active');
    document.getElementById('floatAiHistoryMenu').classList.remove('active');
    if(dlg.classList.contains('active')&&document.getElementById('floatAiBody').children.length===0){
      addBotBubble(t('ui.greeting'));
    }
  };

  // Drag-to-move widget (simple mousedown/move/up, only on widget, zero impact on dialog)
  (function(){
    const widget = document.getElementById('floatAiWidget');
    if(!widget)return;
    let draggingWidget = false, startX, startY, origLeft, origTop;
    widget.addEventListener('mousedown', function(e){
      if(e.button!==0)return;
      if(!e.target.closest('#floatAiBtn'))return;
      e.stopPropagation();
      draggingWidget=true;
      startX=e.clientX; startY=e.clientY;
      const rect=widget.getBoundingClientRect();
      origLeft=rect.left; origTop=rect.top;
      widget.style.position='fixed'; widget.style.right='auto'; widget.style.bottom='auto';
      widget.style.left=origLeft+'px'; widget.style.top=origTop+'px';
    });
    widget.addEventListener('mousemove', function(e){
      if(!draggingWidget)return;
      widget.style.left=(origLeft+e.clientX-startX)+'px';
      widget.style.top=(origTop+e.clientY-startY)+'px';
    });
    widget.addEventListener('mouseup', function(){draggingWidget=false;});
    widget.addEventListener('mouseleave', function(){draggingWidget=false;});
  })();

  function addUserBubble(msg){
    const b=document.createElement('div');b.className='ai-bubble user';b.textContent=msg;
    document.getElementById('floatAiBody').appendChild(b);
    document.getElementById('floatAiBody').scrollTop=document.getElementById('floatAiBody').scrollHeight;
  }
  function addBotBubble(msg){
    const b=document.createElement('div');b.className='ai-bubble bot';b.textContent=msg;
    document.getElementById('floatAiBody').appendChild(b);
    document.getElementById('floatAiBody').scrollTop=document.getElementById('floatAiBody').scrollHeight;
  }
  function addSysBubble(msg){
    const b=document.createElement('div');b.className='ai-bubble system';b.textContent=msg;
    document.getElementById('floatAiBody').appendChild(b);
    document.getElementById('floatAiBody').scrollTop=document.getElementById('floatAiBody').scrollHeight;
  }

  window.sendFloatAiMsg = function(){
    const input=document.getElementById('floatAiInput');
    const msg=input.value.trim(); if(!msg)return;
    input.value='';
    addUserBubble(msg);
    addSysBubble(t('ai.thinking'));
    fetch('/api/float_ai_chat',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({messages:[{role:'system',content:'Ban la tro ly AI.'},{role:'user',content:msg}]})
    }).then(r=>r.json()).then(data=>{
      document.getElementById('floatAiBody').lastChild.remove();
      if(data.success){addBotBubble(data.content);}else{addBotBubble(t('ui.errPrefix')+(data.error||''));}
    }).catch(err=>{
      document.getElementById('floatAiBody').lastChild.remove();
      addBotBubble('⚠ Loi ket noi: '+err.message);
    });
  };

  window.onFloatAiFileSelected = function(){
    const input=document.getElementById('floatAiFileInput');
    if(!input||!input.files||!input.files.length)return;
    const file=input.files[0];
    const reader=new FileReader();
    reader.onload=function(e){
      const content=String(e.target.result||'');
      const snippet=content.length>4000?content.substring(0,4000)+'...\n['+t('ai.thinking')+']':content;
      addUserBubble('[📎 '+file.name+']\n'+snippet);
      addSysBubble(t('ai.thinking'));
      fetch('/api/float_ai_chat',{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({messages:[{role:'system',content:'Ban la tro ly AI.'},{role:'user',content:'File "'+file.name+'" noi dung:\n'+content}]})
      }).then(r=>r.json()).then(data=>{
        document.getElementById('floatAiBody').lastChild.remove();
        if(data.success){addBotBubble(data.content);}else{addBotBubble(t('ui.errPrefix')+(data.error||''));}
      }).catch(err=>{
        document.getElementById('floatAiBody').lastChild.remove();
        addBotBubble('⚠ '+t('ui.errPrefix')+err.message);
      });
    };
    reader.readAsText(file);
  };

  window.clearAiChat=function(){document.getElementById('floatAiBody').innerHTML='';addBotBubble(t('dash.clearHistory'));};
  window.openAiHistory=function(){document.getElementById('floatAiHistoryMenu').classList.toggle('active');};

  async function fetchAllLogs(minutes){
    const apiConfig={
      events:{url:'/api/events',limit:300,timeField:'time'},
      fim:{url:'/api/fim',limit:100,timeField:'time'},
      network:{url:'/api/network',limit:100,timeField:'timestamp'},
      threats:{url:'/api/threats',limit:500,timeField:'timestamp'},
      vulns:{url:'/api/vulns',limit:500,timeField:'timestamp'},
      yara:{url:'/api/yara',limit:500,timeField:'timestamp'},
      sca:{url:'/api/sca',limit:500,timeField:'timestamp'},
      inspection:{url:'/api/inspection',limit:100,timeField:'timestamp'},
      agentless:{url:'/api/agentless',limit:100,timeField:'timestamp'},
      syslog:{url:'/api/syslog',limit:100,timeField:'timestamp'},
      sysmon:{url:'/api/sysmon',limit:500,timeField:'timestamp'},
      memory:{url:'/api/memory',limit:200,timeField:'timestamp'}
    };
    const allData={};
    const cutoff = new Date(Date.now() - (minutes||30) * 60 * 1000);
    for(const[t,cfg]of Object.entries(apiConfig)){
      try{
        const r=await fetch(`${cfg.url}?limit=${cfg.limit}`);
        let data=await r.json();
        if(Array.isArray(data)){
          data=data.filter(item=>{const ts=item[cfg.timeField]||'';if(!ts)return true;try{return new Date(ts)>=cutoff}catch(e){return true}});
          if(data.length>cfg.limit)data=data.slice(0,cfg.limit);
        }
        allData[t]=data;
      }catch(e){allData[t]=[];}
    }
    try{const r=await fetch('/api/machines');allData['machines']=await r.json();}catch(e){allData['machines']=[];}
    try{const r=await fetch('/api/stats');allData['system_stats']=await r.json();}catch(e){allData['system_stats']={};}
    try{const r=await fetch('/api/attack/overview');allData['attack_overview']=await r.json();}catch(e){allData['attack_overview']={};}
    allData['_meta']={period_minutes:minutes||30,collected_at:new Date().toISOString(),total_machines:Array.isArray(allData['machines'])?allData['machines'].length:0,record_counts:Object.fromEntries(Object.entries(allData).filter(([k])=>!['_meta','machines','system_stats'].includes(k)).map(([k,v])=>[k,Array.isArray(v)?v.length:0]))};
    return JSON.stringify(allData,null,2);
  }

  async function sendToTelegram(result){
    try{
      const header='📊 <b>GIAM-SAT Auto-Monitor</b>\n'+new Date().toLocaleString('vi-VN','en')+'\n━━━━━━━━━━━━━━━━━━━━\n';
      const maxLen=3800;
      let msg=result;
      if(msg.length>maxLen)msg=msg.substring(0,maxLen)+'\n...(da cat bot)';
      await fetch('/api/telegram/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:header+msg})});
      addSysBubble(t('ai.sentToTelegram'));
    }catch(e){}
  }

  async function runAutoMonitor(){
    const mins=parseInt(document.getElementById('autoMonInterval').value)||30;
    addSysBubble(t('ai.collecting',[mins]));
    const loadingEl=document.getElementById('floatAiBody').lastChild;
    try{
      const logJson=await fetchAllLogs(mins);
      const filename='giamsat_auto_monitor_'+new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
      const blob=new Blob([logJson],{type:'application/json'});
      const url=URL.createObjectURL(blob);
      const a=document.createElement('a');a.href=url;a.download=filename+'.json';
      document.body.appendChild(a);a.click();document.body.removeChild(a);
      URL.revokeObjectURL(url);
      addSysBubble(t('ai.fileDownloaded',[filename,Math.round(logJson.length/1024)]));
      if(loadingEl&&loadingEl.parentNode)loadingEl.remove();
      addBotBubble(t('ai.fileSent',[Math.round(logJson.length/1024)]));
      const MAX_PROMPT=28000;
      const prompt='FILE ĐÍNH KÈM: '+filename+'.json (dữ liệu giám sát '+mins+' phút gần nhất). Hãy phân tích và đánh giá tình trạng bảo mật hệ thống. Đưa ra: 1. Danh gia tong quan; 2. Cac moi de doa va lo hong moi dang chu y; 3. De xuat cai thien cu the. DU LIEU:\n'+(logJson.length>MAX_PROMPT?logJson.substring(0,MAX_PROMPT)+'\n...(da cat bot)':logJson);
      fetch('/api/float_ai_chat',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({messages:[{role:'system',content:'Ban la tro ly bao mat GIAM-SAT. Phan tich du lieu giam sat JSON va dua ra danh gia + de xuat bang tieng Viet.'},{role:'user',content:prompt}],temperature:0.5})
      }).then(r=>r.json()).then(data=>{
        if(data.success){
          lastAutoResponse=data.content;
          addBotBubble(t('ai.evalResult')+'\n'+data.content);
          saveAutoToHistory('Auto-monitor: '+mins+' phut - '+Math.round(logJson.length/1024)+' KB - AI analyzed');
          sendToTelegram(data.content);
        }else{addBotBubble(t('dash.aiError', [data.error||t('dash.noResponse')]));}
      }).catch(err=>{addBotBubble(t('ai.aiConnErr')+err.message);});
    }catch(err){
      if(loadingEl&&loadingEl.parentNode)loadingEl.remove();
      addBotBubble(t('ai.collectErr')+err.message);
    }
  }

  function saveAutoToHistory(msg){
    const key='giamsat_float_ai_auto';
    let hist=JSON.parse(localStorage.getItem(key)||'[]');
    hist.push({msg,time:new Date().toISOString()});
    if(hist.length>100)hist=hist.slice(-100);
    localStorage.setItem(key,JSON.stringify(hist));
  }

  window.toggleAutoMonitor=function(){
    if(autoMonitorRunning){stopAutoMonitor();}else{startAutoMonitor();}
  };

  function startAutoMonitor(){
    autoMonitorRunning=true;
    document.getElementById('autoMonBtn').style.color='#ffcc66';
    document.getElementById('floatAiBadge').style.display='block';
    const mins=parseInt(document.getElementById('autoMonInterval').value)||30;
    showToast('✅ Da bat tu dong giam sat (moi '+mins+' phut)');
    addSysBubble('⏱ Da bat che do tu dong giam sat (moi '+mins+' phut)');
    runAutoMonitor();
    if(autoMonitorInterval)clearInterval(autoMonitorInterval);
    autoMonitorInterval=setInterval(runAutoMonitor,mins*60*1000);
  }

  function stopAutoMonitor(){
    autoMonitorRunning=false;
    document.getElementById('autoMonBtn').style.color='';
    document.getElementById('floatAiBadge').style.display='none';
    if(autoMonitorInterval){clearInterval(autoMonitorInterval);autoMonitorInterval=null;}
    lastAutoResponse='';
    showToast('⏸ Da tat tu dong giam sat');
    addSysBubble('⏸ Da tat che do tu dong giam sat');
  }
})();

// ===== v3.2: ANOMALY DETECTION =====
function loadAnomaly() {
    const el = document.getElementById('anomalyList');
    el.innerHTML = '<div class="text-center py-3"><div class="spinner-border text-success spinner-border-sm"></div> ' + t('dash.loadingAnomaly') + '</div>';

    fetch('/api/threats?limit=500').then(r => r.json()).then(data => {
        const anomalyAlerts = (data || []).filter(a => (a.rule_id || '').startsWith('ANOMALY-'));
        if (!anomalyAlerts.length) {
            el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-check-circle text-success"></i> ' + t('dash.noAnomaly') + '</div>';
            document.getElementById('anomalyTotalAlerts').textContent = '0';
            document.getElementById('anomalyHighAlerts').textContent = '0';
            document.getElementById('anomalyMedAlerts').textContent = '0';
            document.getElementById('anomalyFirstTime').textContent = '0';
            return;
        }

        const high = anomalyAlerts.filter(a => a.severity === 'HIGH').length;
        const med = anomalyAlerts.filter(a => a.severity === 'MEDIUM').length;
        const firstTime = anomalyAlerts.filter(a => (a.description || '').includes('First time')).length;

        document.getElementById('anomalyTotalAlerts').textContent = anomalyAlerts.length;
        document.getElementById('anomalyHighAlerts').textContent = high;
        document.getElementById('anomalyMedAlerts').textContent = med;
        document.getElementById('anomalyFirstTime').textContent = firstTime;

        el.innerHTML = tableWrap(['Time', 'Machine', 'Severity', 'Score', 'Reasons'],
            anomalyAlerts.map(a => {
                const sevColor = a.severity === 'HIGH' ? '#ff4444' : '#ffcc66';
                const score = a.anomaly_score || '?';
                const reasons = (a.description || '').substring(0, 200);
                return '<tr><td style="font-size:10px;">' + (a.timestamp || '').substring(0,19) + '</td><td>' + (a.hostname || '-') + '</td><td><span style="color:' + sevColor + ';font-weight:bold;">' + (a.severity || '?') + '</span></td><td><span class="badge bg-warning text-dark">' + score + '</span></td><td style="font-size:10px;">' + reasons + '</td></tr>';
            })
        );
    }).catch(() => { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErrX')+'</div>'; });
}

// ===== v3.2: IOC SWEEP =====
function loadIoc() {
    // Reload button: restore the default empty state (no scan history API)
    const res = document.getElementById('iocResults');
    const stats = document.getElementById('iocStats');
    if (res) res.innerHTML = '<div class="text-center text-muted py-3"><span>' + t('ioc.hint') + '</span></div>';
    if (stats) stats.textContent = '';
}

function sweepIoc() {
    const jsonText = document.getElementById('iocJsonInput').value.trim();
    const fileInput = document.getElementById('iocFileInput');
    const el = document.getElementById('iocResults');
    el.innerHTML = '<div class="text-center py-3"><div class="spinner-border text-success spinner-border-sm"></div> '+t('ioc.scanning')+'</div>';

    if (fileInput && fileInput.files && fileInput.files.length > 0) {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        fetch('/api/ioc/sweep', { method: 'POST', body: formData })
            .then(r => r.json()).then(d => renderIocResults(d))
            .catch(() => { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ioc.scanErr')+'</div>'; });
    } else if (jsonText) {
        try {
            const iocs = JSON.parse(jsonText);
            fetch('/api/ioc/sweep', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ iocs })
            }).then(r => r.json()).then(d => renderIocResults(d))
              .catch(() => { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ioc.scanErr')+'</div>'; });
        } catch(e) {
            el.innerHTML = '<div class="text-center text-muted py-3">'+t('ioc.jsonInvalid')+'' + e.message + '</div>';
        }
    } else {
        el.innerHTML = '<div class="text-center text-muted py-3">'+t('ioc.enterJson')+'</div>';
    }
}

function renderIocResults(data) {
    const el = document.getElementById('iocResults');
    document.getElementById('iocStats').textContent = data.matches ? data.matches + ' matches' : '';
    if (!data.results || !data.results.length) {
        el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-check-circle text-success"></i> '+t('ioc.noMatch')+'</div>';
        return;
    }
    el.innerHTML = tableWrap(['IOC Type', 'IOC Value', 'Table', 'Column', 'Matched', 'Time', 'Hostname', 'Confidence'],
        data.results.map(r => {
            const confidence = r.ioc_confidence || 70;
            const confColor = confidence >= 80 ? '#ff4444' : '#ffcc66';
            return '<tr><td><span class="badge bg-danger">' + (r.ioc_type || '?') + '</span></td><td style="font-family:monospace;font-size:10px;">' + (r.ioc_value || '') + '</td><td>' + (r.table || '?') + '</td><td>' + (r.column || '?') + '</td><td style="font-size:10px;">' + (r.matched_value || '').substring(0,80) + '</td><td style="font-size:10px;">' + (r.timestamp || '').substring(0,19) + '</td><td>' + (r.hostname || '-') + '</td><td><span style="color:' + confColor + ';font-weight:bold;">' + confidence + '%</span></td></tr>';
        })
    );
    showToast('✅ IOC Sweep: ' + data.matches + ' matches found');
}

// ===== v3.2: DATA CLEANUP =====
function loadCleanupSummary() {
    const el = document.getElementById('cleanupContent');
    el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-hourglass-split"></i> '+t('ui.loading')+'</div>';
    fetch('/api/cleanup/summary').then(r => r.json()).then(data => {
        if (!data.success) { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErr')+'</div>'; return; }
        const summary = data.data || {};
        let html = '<div class="p-3">';
        html += '<p class="text-muted mb-3" style="font-size:12px;"><i class="bi bi-info-circle"></i> '+t('cleanup.hint')+'</p>';
        
        // Config row
        html += '<div class="row g-2 mb-3">';
        html += '<div class="col-md-3"><label class="text-muted" style="font-size:11px;">'+t('cleanup.keepDays')+'</label><input class="search-box" type="number" id="cleanupDays" value="30" min="1" max="365" style="width:100%;"></div>';
        html += '<div class="col-md-3 d-flex align-items-end"><button class="btn btn-danger btn-sm" onclick="runCleanup()"><i class="bi bi-trash3"></i> '+t('cleanup.run')+'</button></div>';
        html += '<div class="col-md-6"></div>';
        html += '</div>';
        
        // Type checkboxes
        const typeLabels = {
            'events': '📋 Events', 'fim_events': '📁 FIM', 'network_traffic': '🌐 Network Traffic',
            'sysmon_events': '🖥 Sysmon', 'heartbeats': '💓 Heartbeats', 'syslog': '📡 Syslog',
            'yara_alerts': '🦠 YARA', 'sca_events': '✅ SCA', 'agentless_events': '📶 Agentless'
        };
        html += '<div style="background:#0a0f14;border-radius:6px;padding:8px 12px;margin-bottom:12px;">';
        html += '<div class="row g-2">';
        for (const [key, label] of Object.entries(typeLabels)) {
            const info = summary[key] || {count:0};
            html += '<div class="col-md-4"><div class="form-check">';
            html += '<input class="form-check-input cleanupTypeChk" type="checkbox" value="' + key + '" checked id="cc_' + key + '">';
            html += '<label class="form-check-label text-muted" for="cc_' + key + '" style="font-size:11px;">' + label + ' <span class="badge bg-dark">' + (info.count || 0).toLocaleString() + '</span></label>';
            html += '</div></div>';
        }
        html += '</div></div>';
        
        // Result area
        html += '<div id="cleanupResult"></div>';
        html += '</div>';
        el.innerHTML = html;
    }).catch(() => { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErr')+'</div>'; });
}

function runCleanup() {
    const days = parseInt(document.getElementById('cleanupDays').value) || 30;
    const types = Array.from(document.querySelectorAll('.cleanupTypeChk:checked')).map(cb => cb.value);
    const resultEl = document.getElementById('cleanupResult');
    
    if (types.length === 0) { showToast('⚠ Chọn ít nhất 1 loại dữ liệu'); return; }
    if (!confirm(t('dash.cleanupConfirm2', [days, types.length]))) return;
    
    resultEl.innerHTML = '<div class="text-center py-2"><div class="spinner-border text-warning spinner-border-sm"></div> '+t('cleanup.running')+'</div>';
    
    fetch('/api/cleanup', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ types: types, days: days, keep_threats: true })
    }).then(r => r.json()).then(data => {
        if (data.success) {
            let html = '<div class="alert alert-success py-2" style="background:#1a3a2a;color:#88dd99;">';
            html += '<strong>✅ ' + data.message + '</strong>';
            html += '<div style="font-size:11px;margin-top:4px;">';
            for (const [table, count] of Object.entries(data.deleted || {})) {
                var c = count || 0;
                if (c > 0) html += '<span class="badge bg-success me-1">' + table + ': ' + c.toLocaleString() + '</span> ';
            }
            html += '</div></div>';
            resultEl.innerHTML = html;
            showToast(t('dash.cleanupDone', [(data.total || 0).toLocaleString()]));
            // Refresh summary
            setTimeout(loadCleanupSummary, 2000);
        } else {
            resultEl.innerHTML = '<div class="alert alert-danger py-2">'+t('ui.errPrefix') + (data.error || t('ui.errGeneric')) + '</div>';
        }
    }).catch(e => { resultEl.innerHTML = '<div class="alert alert-danger py-2">'+t('ui.errPrefix') + e.message + '</div>'; });
}

// ===== v3.2: THREAT HUNTING (AI-Powered) =====
var huntPollInterval = null;

function startHunting() {
    const hypothesis = document.getElementById('huntHypothesis').value.trim();
    const tactic = document.getElementById('huntTactic').value;
    const sinceHours = parseInt(document.getElementById('huntSinceHours').value) || 168;
    const el = document.getElementById('huntResults');
    const campaignEl = document.getElementById('huntCampaignId');

    if (!hypothesis) { showToast('⚠ Vui lòng nhập giả thuyết săn mối nguy'); return; }

    el.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-success" role="status"></div><p class="text-muted mt-2" style="font-size:13px;">'+t('ai.investigating')+'<br><small style="font-size:11px;">'+t('ai.deepseekParsing')+'</small></p></div>';
    campaignEl.textContent = '';

    fetch('/api/hunt/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            hypothesis: hypothesis,
            tactic: tactic || null,
            since_hours: sinceHours,
            use_ai: true
        })
    }).then(r => r.json()).then(data => {
        if (data.error) {
            el.innerHTML = '<div class="text-center text-muted py-3">❌ ' + data.error + '</div>';
            return;
        }
        campaignEl.textContent = 'Campaign: ' + data.campaign_id + ' | ' + t('hunt.parsedStatus') + (data.parsed_query || t('hunt.parsing'));
        // Start polling for results
        if (huntPollInterval) clearInterval(huntPollInterval);
        huntPollInterval = setInterval(function() {
            loadHunting(data.campaign_id);
        }, 2000);
    }).catch(function(e) {
        el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.connErr')+'' + e.message + '</div>';
    });
}

function loadHunting(campaignId) {
    var el = document.getElementById('huntResults');
    var campaignEl = document.getElementById('huntCampaignId');

    fetch('/api/hunt/result/' + campaignId)
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (!data || data.error) {
                el.innerHTML = '<div class="text-center text-muted py-3">❌ ' + (data ? data.error : t('dash.noCampaign')) + '</div>';
                return;
            }
            if (data.status === 'running') {
                return; // Still running, keep polling
            }
            // Completed - stop polling
            if (huntPollInterval) { clearInterval(huntPollInterval); huntPollInterval = null; }
            campaignEl.textContent = 'Campaign: ' + data.id + ' | Matches: ' + data.match_count + ' | Status: ' + data.status;
            renderHuntResults(data);
        })
        .catch(function(e) {
            el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.errPrefix') + e.message + '</div>';
            if (huntPollInterval) { clearInterval(huntPollInterval); huntPollInterval = null; }
        });
}

// ===== v3.7.0: INCIDENT INVESTIGATION WORKSPACE =====

function loadIncidentView() {
    // Load sidebar list
    const sidebar = document.getElementById('incidentSidebar');
    if (!sidebar) return;
    sidebar.innerHTML = '<div class="text-center text-muted py-3"><div class="spinner-border spinner-border-sm text-success"></div> '+t('ui.loading')+'</div>';

    // v4.13 (P2): optional machine filter (kill-chain -> Incident jump)
    const mf = window._incidentMachineFilter || null;
    let url = '/api/incident/list?limit=100';
    let banner = '';
    if (mf) {
        url += '&machine_id=' + encodeURIComponent(mf);
        banner = '<div class="d-flex justify-content-between align-items-center p-2" style="background:#2a1a0a;border-bottom:1px solid #5a3a1a;">' +
            '<span style="font-size:11px;color:#ffcc66;"><i class="bi bi-filter"></i> ' + t('kc.filtering') + ': <strong>' + escapeHtml(window._incidentMachineName || mf) + '</strong></span>' +
            '<button class="btn btn-sm btn-outline-warning" style="font-size:10px;padding:0 8px;" onclick="window._incidentMachineFilter=null;window._incidentMachineName=null;loadIncidentView();loadIncidentTimeline(0);">✖ ' + t('kc.clearFilter') + '</button></div>';
    }

    fetch(url)
        .then(r => r.json())
        .then(data => {
            const incidents = data.incidents || [];
            if (!incidents.length) {
                sidebar.innerHTML = banner + '<div class="text-center text-muted py-3">' + (mf ? t('kc.noIncidentFor') + ' ' + escapeHtml(window._incidentMachineName || mf) : t('dash.noAlerts')) + '</div>';
                return;
            }

            let html = '';
            incidents.forEach(t => {
                const sev = (t.severity || 'INFO').toUpperCase();
                const sevColor = sev === 'CRITICAL' ? '#ff4444' :
                               sev === 'HIGH' ? '#ff8844' : sev === 'MEDIUM' ? '#ffcc66' : '#8892a4';
                const sevBg = sev === 'CRITICAL' ? 'rgba(255,68,68,0.1)' :
                             sev === 'HIGH' ? 'rgba(255,136,68,0.08)' : '';
                const ruleName = t.rule_name || t.rule_id || 'Unknown';
                const desc = (t.description || '').substring(0, 60);
                const ts = (t.timestamp || '').substring(0, 19);

                html += '<div class="p-2" style="border-bottom:1px solid #2a3a4a;cursor:pointer;background:' + sevBg + ';" onclick="loadIncidentTimeline(' + t.id + ')" onmouseover="this.style.background=\'rgba(255,255,255,0.04)\'" onmouseout="this.style.background=\'' + sevBg + '\'">';
                html += '<div style="font-size:11px;color:' + sevColor + ';font-weight:600;">' + ruleName + '</div>';
                html += '<div style="font-size:10px;color:#8892a4;">' + (t.hostname || '') + ' · ' + ts + '</div>';
                if (desc) html += '<div style="font-size:10px;color:#6a7a8a;">' + desc + '</div>';
                html += '</div>';
            });

            sidebar.innerHTML = banner + html;
        })
        .catch(() => {
            sidebar.innerHTML = '<div class="text-center text-muted py-3">' + t('dash.loadListErr') + '</div>';
        });
}

// v4.13 (P2): kill-chain card -> Incident view, filtered to one machine
window.openIncidentForMachine = function(machineId, hostname) {
    window._incidentMachineFilter = machineId;
    window._incidentMachineName = hostname || machineId;
    const nav = document.querySelector('a[data-view="incident"]');
    if (nav) nav.click();
    loadIncidentView();
};

function loadIncidentTimeline(threatId) {
    const timelineEl = document.getElementById('incidentTimeline');
    const titleEl = document.getElementById('incidentTitle');
    const timeWindowEl = document.getElementById('incidentTimeWindow');
    const countEl = document.getElementById('incidentEvidenceCount');

    timelineEl.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-success"></div><p class="text-muted mt-2">'+t('ui.loadingInvestigation')+'</p></div>';

    fetch('/api/incident/' + threatId)
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                timelineEl.innerHTML = '<div class="text-center text-muted py-5">❌ ' + data.error + '</div>';
                return;
            }

            const threat = data.threat || {};
            const events = data.timeline_events || [];
            const tw = data.timewindow || {};
            const evidence = data.evidence || {};
            const sev = (threat.severity || 'INFO').toUpperCase();
            const sevColor = sev === 'CRITICAL' ? '#ff4444' : sev === 'HIGH' ? '#ff8844' : '#ffcc66';

            // Update header
            titleEl.textContent = ' — ' + (threat.rule_name || threat.rule_id || 'Unknown');
            timeWindowEl.textContent = t('incident.minutes',[tw.minutes || 15]);
            countEl.textContent = t('incident.eventsCount', [data.total_events]);

            // Build evidence summary
            let evSummary = '';
            const evTypes = ['network', 'sysmon', 'events', 'fim', 'memory'];
            evTypes.forEach(t => {
                if (evidence[t] && evidence[t].count > 0) {
                    const icons = {'network': '🌐', 'sysmon': '🖥', 'events': '📋', 'fim': '📁', 'memory': '🧠'};
                    evSummary += '<span class="badge bg-dark me-1" style="font-size:10px;">' + (icons[t] || '') + ' ' + t + ': ' + evidence[t].count + '</span> ';
                }
            });

            // Build timeline HTML
            let html = '<div class="p-3">';

            // Alert header
            html += '<div style="background:rgba(255,68,68,0.1);border-left:4px solid ' + sevColor + ';padding:12px;border-radius:6px;margin-bottom:16px;">';
            html += '<div style="font-size:14px;color:' + sevColor + ';font-weight:700;">🔴 ' + (threat.rule_name || threat.rule_id || 'Unknown') + '</div>';
            html += '<div style="font-size:11px;color:#8892a4;">' + (threat.description || '') + '</div>';
            html += '<div style="font-size:10px;color:#6a7a8a;margin-top:4px;">🖥 ' + (threat.hostname || threat.machine_id || '') + ' · ⏱ ' + (threat.timestamp || '') + '</div>';
            html += '<div style="margin-top:6px;">' + evSummary + '</div>';
            html += '</div>';

            // Timeline
            if (events.length === 0) {
                html += '<div class="text-center text-muted py-3">' + t('dash.noEventsInRange') + '</div>';
            } else {
                html += '<div style="border-left:2px solid #2a3a4a;margin-left:20px;padding-left:20px;">';

                events.forEach(e => {
                    const icon = e.icon || '📋';
                    const type = e.type || 'unknown';
                    const title = e.title || '';
                    const desc = e.description || '';
                    const ts = (e.timestamp || '').substring(11, 19);
                    const fullTs = (e.timestamp || '').substring(0, 19);
                    const isAnchor = e.is_anchor;
                    const severity = (e.severity || 'INFO').toUpperCase();

                    let bg = '';
                    if (isAnchor) bg = 'background:rgba(255,68,68,0.1);border:1px solid rgba(255,68,68,0.3);';
                    else if (severity === 'HIGH') bg = 'background:rgba(255,136,68,0.05);';

                    const sourceBadge = e.source ? '<span class="badge bg-dark me-1" style="font-size:8px;">' + e.source + '</span>' : '';

                    html += '<div style="position:relative;padding:6px 10px;margin-bottom:8px;border-radius:4px;' + bg + '">';
                    html += '<div style="position:absolute;left:-27px;top:8px;font-size:14px;">' + icon + '</div>';
                    html += '<div style="display:flex;justify-content:space-between;align-items:start;">';
                    html += '<div style="flex:1;">';
                    html += '<div style="font-size:11px;color:#d0d8e0;">' + sourceBadge + title + '</div>';
                    if (desc) html += '<div style="font-size:10px;color:#6a7a8a;margin-top:2px;">' + desc + '</div>';
                    html += '</div>';
                    html += '<div style="font-size:9px;color:#5a6a7a;white-space:nowrap;min-width:50px;text-align:right;" title="' + fullTs + '">' + ts + '</div>';
                    html += '</div>';
                    html += '</div>';
                });

                html += '</div>';
            }

            html += '</div>';

            timelineEl.innerHTML = html;

            // Highlight sidebar item
            document.querySelectorAll('#incidentSidebar > div').forEach(d => d.style.background = d.style.background.replace('rgba(0,212,170,0.12)','').replace('rgba(255,255,255,0.04)',''));
        })
        .catch(e => {
            timelineEl.innerHTML = '<div class="text-center text-muted py-5">'+t('ui.errPrefix') + e.message + '</div>';
        });
}

function exportIncidentReport() {
    const timelineEl = document.getElementById('incidentTimeline');
    if (!timelineEl) return;

    // Get raw text from timeline
    const text = timelineEl.textContent || timelineEl.innerText || '';
    const title = document.getElementById('incidentTitle').textContent || 'incident';
    const blob = new Blob([text], {type: 'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'giamsat_incident_' + (title.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30) || 'report') + '_' + new Date().toISOString().slice(0, 10) + '.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(t('dash.investigationExported'));
}

function renderHuntResults(data) {
    var el = document.getElementById('huntResults');
    if (!data.results || data.results.length === 0) {
        el.innerHTML = '<div class="text-center text-muted py-4"><i class="bi bi-check-circle text-success" style="font-size:24px;"></i><p class="mt-2">' + t('dash.noHuntResults') + '<br><small>' + t('dash.systemClean') + '</small></p></div>';
        showToast('✅ Hunt hoàn tất: 0 matches - hệ thống sạch');
        return;
    }
    var results = data.results;
    var html = '<div style="background:rgba(0,212,170,0.08);border-radius:6px;padding:8px 12px;margin-bottom:10px;font-size:12px;">';
    html += '<strong>🎯 Hypothesis:</strong> ' + (data.hypothesis || '') + '<br>';
    html += '<strong>📊 Matches:</strong> <span style="color:#00d4aa;font-weight:bold;">' + data.match_count + '</span> | ';
    html += '<strong>⏱ Created:</strong> ' + (data.created_at || '') + ' | ';
    html += '<strong>✅ Completed:</strong> ' + (data.completed_at || '');
    html += '</div>';

    html += tableWrap(
        ['Table', 'Time', 'Machine', 'Details'],
        results.map(function(r) {
            var detail = '';
            if (r.description) detail = r.description;
            else if (r.raw_data) detail = String(r.raw_data);
            else detail = JSON.stringify(r).substring(0, 150);
            if (detail.length > 150) detail = detail.substring(0, 150) + '...';
            return '<tr><td><span class="log-type event">' + (r.table || '?') + '</span></td>' +
                   '<td style="font-size:10px;">' + (r.timestamp || '').substring(0,19) + '</td>' +
                   '<td>' + (r.machine_id || '-') + '</td>' +
                   '<td style="font-size:10px;max-width:400px;word-break:break-all;">' + detail + '</td></tr>';
        })
    );
    html += '<div class="text-center text-muted mt-1" style="font-size:10px;">' + t('ui.showingResults',[Math.min(results.length,100), data.match_count]) + '</div>';
    el.innerHTML = html;
    showToast('✅ Hunt hoàn tất: ' + data.match_count + ' matches');
}

// ===== v3.9.15: DASHBOARD TEMPLATE SYSTEM =====
function loadDashboardList() {
    fetch('/api/dashboard/list')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var sel = document.getElementById('dashTemplateSelect');
            if (!sel) return;
            var templates = data.templates || [];
            sel.innerHTML = '<option value="">'+t('ui.selectTemplate')+'</option>' +
                templates.map(function(t) {
                    return '<option value="' + t.name + '">' + t.name + ' (' + t.panel_count + ' panels, ' + t.refresh_interval + 's) - ' + (t.category || '') + '</option>';
                }).join('');
        })
        .catch(function() {});
}

function loadDashboardTemplate() {
    var sel = document.getElementById('dashTemplateSelect');
    var area = document.getElementById('dashboardRenderArea');
    if (!sel || !sel.value) return;

    area.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-success" role="status"></div><p class="text-muted mt-2">' + t('dash.loadingDashboard') + '</p></div>';

    fetch('/api/dashboard/render?name=' + encodeURIComponent(sel.value))
        .then(function(r) { return r.text(); })
        .then(function(html) {
            area.innerHTML = html;
        })
        .catch(function() {
            area.innerHTML = '<div class="alert alert-danger">'+t('ui.loadDashErr')+'</div>';
        });
}

// ======== v4.1: SOC Approval Pending Poll ========
var _pendingAlertsSeen = {};
var _pendingPollInterval = null;

function startPendingApprovalPoll() {
    if (_pendingPollInterval) return;
    _pendingPollInterval = setInterval(pollPendingApprovals, 30000);
    pollPendingApprovals();  // Initial poll
    console.log('[SOC APPROVAL] Started pending approval poll (30s interval)');
}

function pollPendingApprovals() {
    fetch('/api/alert/pending')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var pending = data.pending || [];
            // Update badge
            var badge = document.getElementById('pendingBadge');
            if (badge) {
                if (pending.length > 0) {
                    badge.style.display = 'inline';
                    badge.textContent = pending.length;
                } else {
                    badge.style.display = 'none';
                }
            }
            // Show modal for new pending
            for (var i = 0; i < pending.length; i++) {
                var p = pending[i];
                if (_pendingAlertsSeen[p.id]) continue;
                _pendingAlertsSeen[p.id] = true;
                showApprovalModal(p);
            }
        })
        .catch(function() { /* Silently retry */ });
}

function showPendingList() {
    fetch('/api/alert/pending')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var pending = data.pending || [];
            var html = '<div style="font-size:12px;">';
            if (pending.length === 0) {
                html += '<div class="text-center text-muted py-3">' + t('dash.noPendingApprovals') + '</div>';
            } else {
                html += '<p class="text-muted mb-2">' + t('ui.pendingApprovalCount',[pending.length]) + '</p>';
                pending.forEach(function(p) {
                    var actionLabel = p.action === 'isolate_network' ? t('dash.isolateNetwork') :
                                      p.action === 'lock_account' ? t('dash.lockAccount') :
                                      p.action === 'quarantine_file' ? t('dash.quarantineFile') : p.action;
                    html += '<div style="background:#1a0a0a;border:1px solid #3a1a1a;border-radius:6px;padding:8px 10px;margin-bottom:6px;">';
                    html += '<div style="display:flex;justify-content:space-between;align-items:center;">';
                    html += '<div>';
                    html += '<strong style="color:#eef4f8;">' + (p.hostname || p.machine_id) + '</strong> ';
                    html += '<span class="badge bg-danger">' + actionLabel + '</span>';
                    html += '<div style="font-size:10px;color:#8892a4;margin-top:2px;">Rule: ' + (p.rule_id || '?') + ' | ' + (p.description || '') + '</div>';
                    html += '</div>';
                    html += '<div style="display:flex;gap:4px;">';
                    html += '<button class="btn btn-success btn-sm py-0 px-2" style="font-size:10px;" onclick="approvePending(\'' + p.id + '\', \'approve\')">✅</button>';
                    html += '<button class="btn btn-danger btn-sm py-0 px-2" style="font-size:10px;" onclick="approvePending(\'' + p.id + '\', \'deny\')">❌</button>';
                    html += '</div>';
                    html += '</div></div>';
                });
            }
            html += '</div>';
            document.getElementById('detailModalTitle').textContent = '⏳ Pending Approvals (' + pending.length + ')';
            document.getElementById('detailModalBody').innerHTML = html;
            var modal = bootstrap.Modal.getInstance(document.getElementById('detailModal'));
            if (!modal) modal = new bootstrap.Modal(document.getElementById('detailModal'));
            modal.show();
        })
        .catch(function() { showToast(t('dash.loadPendingErr')); });
}

function showApprovalModal(approval) {
    var modalEl = document.getElementById('detailModal');
    var modal = bootstrap.Modal.getInstance(modalEl);
    if (!modal) modal = new bootstrap.Modal(modalEl);

    var actionLabel = approval.action === 'isolate_network' ? t('dash.isolateNetwork') :
                      approval.action === 'lock_account' ? t('dash.lockAccount') :
                      approval.action === 'quarantine_file' ? t('dash.quarantineFile') : approval.action;

    var html = '<div class="alert alert-danger py-2 mb-2" style="font-size:12px;">';
    html += '<i class="bi bi-exclamation-triangle-fill"></i> <strong>'+t('ui.approvalRequired')+'</strong> '+t('ui.approvalHint');
    html += '</div>';
    html += '<table class="table table-sm table-dark" style="font-size:12px;">';
    html += '<tr><td style="width:120px;">'+t('ui.machineRow')+'</td><td><strong>' + (approval.hostname || approval.machine_id) + '</strong></td></tr>';
    html += '<tr><td>'+t('ui.action')+'</td><td><span class="badge bg-danger">' + actionLabel + '</span></td></tr>';
    html += '<tr><td>Rule</td><td>' + (approval.rule_id || '?') + '</td></tr>';
    html += '<tr><td>'+t('ui.description')+'</td><td>' + (approval.description || '') + '</td></tr>';
    html += '</table>';
    html += '<div class="d-flex gap-2">';
    html += '<button class="btn btn-success btn-sm flex-grow-1" onclick="approvePending(\'' + approval.id + '\', \'approve\')"><i class="bi bi-check-lg"></i>'+t('ui.approve')+'</button>';
    html += '<button class="btn btn-danger btn-sm flex-grow-1" onclick="approvePending(\'' + approval.id + '\', \'deny\')"><i class="bi bi-x-lg"></i>'+t('ui.deny')+'</button>';
    html += '</div>';

    document.getElementById('detailModalTitle').textContent = '⚠️ SOC Approval Required';
    document.getElementById('detailModalBody').innerHTML = html;
    modal.show();
}

function approvePending(approvalId, action) {
    fetch('/api/alert/approve', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ approval_id: approvalId, action: action })
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.status === 'ok') {
            showToast(action === 'approve' ? t('dash.approved') : t('dash.rejected'));
            var modal = bootstrap.Modal.getInstance(document.getElementById('detailModal'));
            if (modal) modal.hide();
        } else {
            showToast('⚠️ ' + (d.error || 'Lỗi'));
        }
    })
    .catch(function() { showToast('❌ Lỗi kết nối'); });
}

// Auto-start on page load
document.addEventListener('DOMContentLoaded', startPendingApprovalPoll);

// ======== END SOC Approval ========

// ======== v4.13: USER & ROLE MANAGEMENT ========
let currentUser = null;

function initCurrentUser() {
    fetch('/api/auth/check').then(function(r) { return r.json(); }).then(function(d) {
        if (!d.authenticated) return;
        currentUser = d;
        const nameEl = document.getElementById('accountName');
        if (nameEl) nameEl.textContent = d.username;
        const roleEl = document.getElementById('accountRole');
        if (roleEl) roleEl.textContent = t('users.myAccount') + ' · ' + (d.role || 'viewer');
        const nav = document.getElementById('navUsers');
        if (nav) nav.style.display = (d.role === 'admin') ? '' : 'none';
    }).catch(function() {});
}

function loadUsers() {
    const el = document.getElementById('usersList');
    if (!el) return;
    el.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-hourglass-split"></i> '+t('ui.loading')+'</div>';
    fetch('/api/users').then(function(r) { return r.json(); }).then(function(users) {
        const names = Object.keys(users || {});
        if (!names.length) { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.noData')+'</div>'; return; }
        let html = '<table class="table table-sm table-hover align-middle mb-0" style="font-size:11px;"><thead><tr><th>'+t('users.username')+'</th><th>'+t('users.role')+'</th><th>'+t('ui.status')+'</th><th></th></tr></thead><tbody>';
        html += names.map(function(u) {
            const usr = users[u] || {};
            const cur = usr.role === 'admin' ? 'admin' : (usr.role === 'operator' ? 'operator' : 'viewer');
            let roleSel = '<select class="form-select form-select-sm" style="width:auto;display:inline-block;font-size:10px;padding:1px 4px;background:var(--bg-dark);color:#d0d8e0;border-color:var(--border-color);" onchange="changeUserRole(\'' + u.replace(/'/g, "\\'") + '\', this.value)">';
            ['viewer','operator','admin'].forEach(function(r) {
                roleSel += '<option value="'+r+'"'+(cur === r ? ' selected' : '')+'>'+t('users.role'+r.charAt(0).toUpperCase()+r.slice(1))+'</option>';
            });
            roleSel += '</select>';
            const statusCell = usr.must_change_password
                ? '<span class="badge bg-warning text-dark">'+t('users.mustChange')+'</span>'
                : '<span class="badge bg-success">'+t('ui.active')+'</span>';
            return '<tr><td><strong style="color:#ffcc66;">'+escapeHtml(u)+'</strong></td><td>'+roleSel+'</td><td>'+statusCell+'</td><td class="text-end">'+
                '<button class="btn btn-sm btn-outline-info me-1" style="font-size:10px;padding:0 6px;" onclick="manage2fa(\'' + u.replace(/'/g, "\\'") + '\', ' + (usr.totp_enabled ? 'true' : 'false') + ')">🔐 '+t('users.twofa')+(usr.totp_enabled ? ' ✓' : '')+'</button>'+
                '<button class="btn btn-sm btn-outline-warning me-1" style="font-size:10px;padding:0 6px;" onclick="resetUserPassword(\'' + u.replace(/'/g, "\\'") + '\')">'+t('users.resetPw')+'</button>'+
                (u !== 'admin' ? '<button class="btn btn-sm btn-outline-danger" style="font-size:10px;padding:0 6px;" onclick="deleteUser(\'' + u.replace(/'/g, "\\'") + '\')">'+t('btn.delete')+'</button>' : '')+
                '</td></tr>';
        }).join('') + '</tbody></table>';
        el.innerHTML = html;
    }).catch(function() { el.innerHTML = '<div class="text-center text-muted py-3">'+t('ui.loadErr')+'</div>'; });
}

function addUser() {
    const username = document.getElementById('newUserUsername').value.trim();
    const password = document.getElementById('newUserPassword').value;
    const role = document.getElementById('newUserRole').value;
    if (!username) { showToast('⚠ ' + t('users.usernameReq')); return; }
    if (!password) { showToast('⚠ ' + t('users.pwReq')); return; }
    fetch('/api/users', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username: username, password: password, role: role})})
        .then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) {
                showToast('✅ ' + t('users.added'));
                document.getElementById('newUserUsername').value = '';
                document.getElementById('newUserPassword').value = '';
                loadUsers();
            } else {
                showToast('❌ ' + (d.error || t('ui.errGeneric')));
            }
        }).catch(function() { showToast('❌ ' + t('ui.connErrShort')); });
}

function deleteUser(username) {
    if (!confirm(t('users.deleteConfirm', [username]))) return;
    fetch('/api/users/' + encodeURIComponent(username), {method:'DELETE'})
        .then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) { showToast('✅ ' + t('users.deleted')); loadUsers(); }
            else { showToast('❌ ' + (d.error || '')); }
        }).catch(function() { showToast('❌ ' + t('ui.connErrShort')); });
}

function changeUserRole(username, role) {
    fetch('/api/users/' + encodeURIComponent(username) + '/role', {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({role: role})})
        .then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) { showToast('✅ ' + t('users.roleUpdated')); }
            else { showToast('❌ ' + (d.error || '')); loadUsers(); }
        }).catch(function() { showToast('❌ ' + t('ui.connErrShort')); });
}

function resetUserPassword(username) {
    if (!confirm(t('users.resetPwConfirm', [username]))) return;
    const newPw = prompt(t('users.newPw') + ' (≥12)');
    if (!newPw) return;
    fetch('/api/users/' + encodeURIComponent(username) + '/reset-password', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({new_password: newPw})})
        .then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) { showToast('✅ ' + t('users.resetPwDone')); }
            else { showToast('❌ ' + (d.error || '')); }
        }).catch(function() { showToast('❌ ' + t('ui.connErrShort')); });
}

function manage2fa(username, currentlyEnabled) {
    if (!currentlyEnabled) {
        fetch('/api/users/' + encodeURIComponent(username) + '/2fa/enroll', {method:'POST'})
            .then(function(r) { return r.json(); }).then(function(d) {
                if (!d.success) { showToast('❌ ' + (d.error || '')); return; }
                const body = '<div style="font-size:12px;">' +
                    '<p class="text-muted">' + t('users.twofaStep') + '</p>' +
                    '<div class="mb-2"><strong>' + t('users.twofaSecret') + '</strong><br>' +
                    '<code style="word-break:break-all;">' + escapeHtml(d.secret) + '</code></div>' +
                    '<div class="mb-2"><a href="' + escapeHtml(d.otpauth_uri) + '" target="_blank" class="btn btn-sm btn-outline-info">' + t('users.twofaUri') + '</a></div>' +
                    '<div class="mb-2"><label class="text-muted">' + t('users.twofaEnterCode') + '</label>' +
                    '<input class="search-box" id="twofaConfirmCode" maxlength="6" style="width:120px;"></div>' +
                    '<button class="btn btn-success btn-sm" onclick="confirm2fa(\'' + username.replace(/'/g, "\\'") + '\')">' + t('users.twofaConfirm') + '</button>' +
                    '</div>';
                showDetailModal(t('users.twofaTitle'), body);
            }).catch(function() { showToast('❌ ' + t('ui.connErrShort')); });
    } else {
        const body = '<div style="font-size:12px;">' +
            '<p class="text-muted">' + t('users.twofaDisableHint') + '</p>' +
            '<div class="mb-2"><label class="text-muted">' + t('users.twofaEnterCode') + '</label>' +
            '<input class="search-box" id="twofaDisableCode" maxlength="6" style="width:120px;"></div>' +
            '<button class="btn btn-danger btn-sm" onclick="disable2fa(\'' + username.replace(/'/g, "\\'") + '\')">' + t('users.twofaDisableBtn') + '</button></div>';
        showDetailModal(t('users.twofaTitle'), body);
    }
}

function confirm2fa(username) {
    const code = document.getElementById('twofaConfirmCode').value.trim();
    fetch('/api/users/' + encodeURIComponent(username) + '/2fa/confirm', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({code: code})})
        .then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) {
                showToast('✅ ' + t('users.twofaEnabled'));
                const m = bootstrap.Modal.getInstance(document.getElementById('detailModal'));
                if (m) m.hide();
                loadUsers();
            } else { showToast('❌ ' + (d.error || '')); }
        }).catch(function() { showToast('❌ ' + t('ui.connErrShort')); });
}

function disable2fa(username) {
    const code = document.getElementById('twofaDisableCode').value.trim();
    fetch('/api/users/' + encodeURIComponent(username) + '/2fa/disable', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({code: code})})
        .then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) {
                showToast('✅ ' + t('users.twofaDisabled'));
                const m = bootstrap.Modal.getInstance(document.getElementById('detailModal'));
                if (m) m.hide();
                loadUsers();
            } else { showToast('❌ ' + (d.error || '')); }
        }).catch(function() { showToast('❌ ' + t('ui.connErrShort')); });
}

function showChangeMyPassword() {
    const body = '<div style="font-size:13px;">' +
        '<div class="mb-2"><label class="text-muted" style="font-size:11px;">'+t('users.oldPw')+'</label><input class="search-box" id="myOldPw" type="password" style="width:100%;"></div>' +
        '<div class="mb-2"><label class="text-muted" style="font-size:11px;">'+t('users.newPw')+'</label><input class="search-box" id="myNewPw" type="password" style="width:100%;"></div>' +
        '<div class="mb-2"><label class="text-muted" style="font-size:11px;">'+t('users.newPwConfirm')+'</label><input class="search-box" id="myNewPw2" type="password" style="width:100%;"></div>' +
        '<p class="text-muted" style="font-size:10px;">'+t('users.pwPolicy')+'</p>' +
        '<button class="btn btn-success btn-sm" onclick="changeMyPassword()"><i class="bi bi-check-lg"></i> '+t('users.changePw')+'</button>' +
        '</div>';
    showDetailModal(t('users.changePwTitle'), body);
}

function changeMyPassword() {
    const oldPw = document.getElementById('myOldPw').value;
    const newPw = document.getElementById('myNewPw').value;
    const newPw2 = document.getElementById('myNewPw2').value;
    if (newPw !== newPw2) { showToast('⚠ ' + t('users.pwMismatch')); return; }
    fetch('/api/users/password', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({old_password: oldPw, new_password: newPw})})
        .then(function(r) { return r.json(); }).then(function(d) {
            if (d.success) {
                showToast('✅ ' + t('users.changedPw'));
                const modal = bootstrap.Modal.getInstance(document.getElementById('detailModal'));
                if (modal && modal._isShown) modal.hide();
            } else {
                showToast('❌ ' + (d.error || ''));
            }
        }).catch(function() { showToast('❌ ' + t('ui.connErrShort')); });
}

function doLogout() {
    fetch('/api/logout', {method:'POST'}).catch(function() {}).finally(function() { window.location.href = '/login'; });
}

// Auto-start user session on page load
document.addEventListener('DOMContentLoaded', initCurrentUser);
// ======== END USER & ROLE MANAGEMENT ========

function showImportDashboardModal() {
    var body = '<textarea class="search-box" id="dashImportJson" style="width:100%;height:300px;font-family:monospace;font-size:10px;" placeholder=\'' + t('ph.pasteDashJson') + '\'></textarea>';
    body += '<button class="btn btn-sm btn-success mt-2" onclick="importDashboard()"><i class="bi bi-upload"></i> Import</button>';
    showDetailModal('Import Dashboard Template', body);
}

function importDashboard() {
    var jsonText = document.getElementById('dashImportJson').value.trim();
    if (!jsonText) { showToast('⚠ Vui lòng dán JSON template!'); return; }
    try {
        var data = JSON.parse(jsonText);
    } catch(e) {
        showToast(''+t('ioc.jsonInvalid')+'' + e.message);
        return;
    }
    fetch('/api/dashboard/import', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.status === 'imported') {
            showToast('✅ Đã import dashboard: ' + d.name);
            loadDashboardList();
        } else {
            showToast('❌ ' + (d.error || 'Lỗi'));
        }
    })
    .catch(function() { showToast('❌ Lỗi kết nối'); });
}
