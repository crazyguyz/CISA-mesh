/**
 * GIAM-SAT Dashboard - Attack Overview Canvas + Chains + Timeline + Report Export (v2.5.0)
 * Requires: escapeHtml, showToast from utils.js
 * Uses: window.attackData, window.attackMapCanvas, window.attackMapCtx, window.attackMapNodes, window.attackMapAnimId
 */

// Attack Overview state
window.attackData = null;
window.attackMapCanvas = null;
window.attackMapCtx = null;
window.attackMapNodes = [];
window.attackMapAnimId = null;
window._attackData = null;
window._timelineData = [];
window._killchainData = null;  // v4.13 (P2): /api/risk/killchain

window.loadAttackOverview = function() {
    var el = document.getElementById("attackContent");
    el.innerHTML = '<div class="text-center text-muted py-3"><div class="spinner-border text-success spinner-border-sm" role="status"></div> ' + t('ao.analyzing') + '</div>';
    fetch("/api/attack/overview").then(function(r) { return r.json(); }).then(function(data) {
        if (data.error) { el.innerHTML = '<div class="alert alert-danger m-3">' + escapeHtml(data.error) + '</div>'; return; }
        window.attackData = data;
        // v4.13 (P2): kill-chain risk scoring for triage (>=3 MITRE tactics in 24h = incident)
        fetch("/api/risk/killchain?since_hours=24&min_tactics=3").then(function(r) { return r.json(); }).then(function(kc) {
            window._killchainData = kc && !kc.error ? kc : null;
            window.renderAttackOverview(data);
        }).catch(function() { window._killchainData = null; window.renderAttackOverview(data); });
    }).catch(function(e) { el.innerHTML = '<div class="alert alert-danger m-3">' + t('ao.loadErr', [escapeHtml(e.message)]) + '</div>'; });
};

window.renderAttackOverview = function(data) {
    var el = document.getElementById("attackContent");
    var stats = data.stats || {};
    var chains = data.chains || [];
    var timeline = data.timeline || [];
    var nodes = data.nodes || [];
    var edges = data.edges || [];

    window._attackData = data;
    window._timelineData = timeline;

    // v4.13 (P2): kill-chain risk card (triage) - rendered even when no attack chains
    var kc = window._killchainData || null;
    var html = '';
    if (kc) {
        var kcInc = kc.incidents || [];
        html += '<div style="background:#0d1117;border-bottom:1px solid #2a3a4a;padding:10px 12px;">';
        html += '<div style="display:flex;justify-content:space-between;align-items:center;">';
        html += '<h6 style="color:#ffcc66;font-size:12px;margin:0;"><i class="bi bi-diagram-3"></i> ' + t('kc.title') + '</h6>';
        html += '<span style="font-size:10px;color:#5a6a7a;">' + t('kc.window', [kc.since_hours || 24, kc.min_tactics || 3]) + '</span></div>';
        if (!kcInc.length) {
            html += '<div class="text-muted py-1" style="font-size:11px;"><i class="bi bi-check-circle text-success"></i> ' + t('kc.none') + '</div>';
        } else {
            kcInc.forEach(function(m) {
                html += '<div style="background:#2a1a1a;border:1px solid #5a2a2a;border-radius:4px;padding:6px 8px;margin-top:6px;display:flex;justify-content:space-between;align-items:center;">';
                html += '<div><strong style="color:#ff9966;">' + escapeHtml(m.hostname) + '</strong> <span class="badge bg-danger" style="font-size:9px;">' + t('kc.incident') + '</span>';
                html += '<div style="font-size:10px;color:#8892a4;margin-top:2px;">' + t('kc.tactics', [m.tactic_count]) + ': ' + m.tactics.map(escapeHtml).join(', ') + '</div></div>';
                html += '<div style="display:flex;align-items:center;gap:6px;"><span class="badge bg-danger" style="font-size:12px;">' + m.tactic_count + '</span>';
                html += '<button class="btn btn-sm btn-outline-danger" style="font-size:10px;padding:1px 8px;" onclick="openIncidentForMachine(\'' + escJs(m.machine_id) + '\',\'' + escJs(m.hostname) + '\')">🔍 ' + t('kc.investigate') + '</button></div></div>';
            });
        }
        html += '</div>';
    }

    if (!chains.length && !timeline.length) {
        el.innerHTML = html + '<div class="text-center py-5"><i class="bi bi-check-circle text-success" style="font-size:48px;"></i><h5 class="mt-2">' + t('ao.noAttack') + '</h5><p class="text-muted">' + t('ao.noAttackSub') + '</p></div>';
        return;
    }

    html += '<div class="row g-2 p-2 text-center" style="background:#0f1923;border-bottom:1px solid #2a3a4a;position:sticky;top:0;z-index:10;">';
    html += '<div class="col-2"><div style="background:#1a1a2a;border-radius:4px;padding:6px;"><span style="font-size:20px;color:#ff4444;font-weight:700;">' + (stats.total_chains || 0) + '</span><div style="font-size:9px;color:#888;">Attack Chains</div></div></div>';
    html += '<div class="col-2"><div style="background:#3a1a1a;border-radius:4px;padding:6px;"><span style="font-size:20px;color:#ff4444;font-weight:700;">' + (stats.critical_chains || 0) + '</span><div style="font-size:9px;color:#888;">CRITICAL</div></div></div>';
    html += '<div class="col-2"><div style="background:#1a1a2a;border-radius:4px;padding:6px;"><span style="font-size:20px;color:#ffcc66;font-weight:700;">' + (stats.compromised_count || 0) + '</span><div style="font-size:9px;color:#888;">Compromised</div></div></div>';
    html += '<div class="col-2"><div style="background:#1a1a2a;border-radius:4px;padding:6px;"><span style="font-size:20px;color:#888;font-weight:700;">' + (stats.c2_count || 0) + '</span><div style="font-size:9px;color:#888;">C2 Servers</div></div></div>';
    html += '<div class="col-4 text-end" style="font-size:9px;color:#5a6a7a;padding-top:8px;">' + (stats.generated_at || '') + '</div>';
    html += '</div>';

    html += '<div class="row g-0" style="min-height:500px;">';
    html += '<div class="col-md-7 p-2 position-relative" style="background:#0a0f1a;">';
    html += '<canvas id="attackMapCanvas" style="width:100%;height:100%;min-height:480px;cursor:grab;"></canvas>';
    html += '<div style="position:absolute;top:8px;right:12px;font-size:9px;color:#5a6a7a;">Drag to pan | Scroll to zoom</div>';
    html += '<div style="position:absolute;bottom:8px;left:12px;font-size:10px;">';
    html += '<span class="badge bg-danger" style="font-size:9px;">Compromised</span> ';
    html += '<span class="badge bg-info" style="font-size:9px;">Machine</span> ';
    html += '<span class="badge bg-dark" style="font-size:9px;">C2 Server</span>';
    html += '</div></div>';

    html += '<div class="col-md-5 p-2" style="background:#0d1117;max-height:520px;overflow-y:auto;">';
    html += '<h6 style="color:#ffcc66;font-size:12px;"><i class="bi bi-link-45deg"></i> Attack Chains</h6>';
    if (chains.length === 0) {
        html += '<div class="text-muted py-2" style="font-size:11px;">' + t('ao.noChains') + '</div>';
    } else {
        chains.forEach(function(chain) {
            var sevColor = chain.severity === 'CRITICAL' ? '#ff4444' : '#ff9966';
            var sevBg = chain.severity === 'CRITICAL' ? '#3a1a1a' : '#3a2a1a';
            html += '<div style="background:' + sevBg + ';border-left:3px solid ' + sevColor + ';padding:8px 10px;margin-bottom:6px;border-radius:4px;cursor:pointer;" onclick="window.highlightChain(\'' + escJs(chain.id) + '\')" ondblclick="window.showChainDetail(\'' + escJs(chain.id) + '\')" title="Click de highlight - Double-click de xem chi tiet">';
            html += '<div style="font-size:12px;color:' + sevColor + ';font-weight:600;">' + escapeHtml(chain.id) + ' - ' + escapeHtml(chain.root_hostname) + '</div>';
            html += '<div style="font-size:10px;color:#8892a4;margin-top:2px;">' + chain.steps.length + ' steps | ' + chain.severity + '</div>';
            chain.steps.slice(0, 4).forEach(function(step) {
                var icon = step.type === 'beaconing' ? '\ud83d\udce1' : '\u26a0';
                html += '<div style="font-size:10px;color:#c0d4e0;margin-top:2px;">' + icon + ' ' + (step.command || step.rule_name || step.description || '').substring(0, 60) + '</div>';
            });
            if (chain.steps.length > 4) html += '<div style="font-size:9px;color:#5a6a7a;">... and ' + (chain.steps.length - 4) + ' more steps</div>';
            html += '</div>';
        });
    }
    html += '</div></div>';

    html += '<div style="background:#0d1117;border-top:1px solid #2a3a4a;padding:8px 12px;overflow-x:auto;white-space:nowrap;">';
    html += '<h6 style="color:#ffcc66;font-size:11px;margin-bottom:6px;"><i class="bi bi-clock-history"></i> Attack Timeline</h6>';
    if (timeline.length === 0) {
        html += '<span class="text-muted" style="font-size:11px;">' + t('ao.noEvents') + '</span>';
    } else {
        html += '<div style="display:flex;gap:4px;align-items:center;min-height:40px;">';
        timeline.forEach(function(t, ti) {
            var dotColor = t.severity === 'CRITICAL' ? '#ff4444' : t.severity === 'HIGH' ? '#ff9966' : '#ffcc66';
            var size = t.severity === 'CRITICAL' ? '14px' : '10px';
            html += '<div style="flex-shrink:0;text-align:center;cursor:pointer;" title="' + escapeHtml(t.label || '') + '\n' + escapeHtml(t.hostname || '') + '\n' + escapeHtml(t.time || '') + '" onclick="window.showTimelineDetail(' + ti + ')">';
            html += '<div style="width:' + size + ';height:' + size + ';border-radius:50%;background:' + dotColor + ';margin:0 auto 2px;box-shadow:0 0 6px ' + dotColor + ';"></div>';
            html += '<div style="font-size:9px;color:#5a6a7a;max-width:60px;overflow:hidden;text-overflow:ellipsis;">' + (t.time || '').substring(11, 16) + '</div>';
            html += '<div style="font-size:8px;color:#8892a4;max-width:60px;overflow:hidden;text-overflow:ellipsis;">' + escapeHtml((t.label || '').substring(0, 20)) + '</div>';
            html += '</div>';
        });
        html += '</div>';
    }
    html += '</div>';
    el.innerHTML = html;
    setTimeout(function() { window.initAttackMap(data); }, 100);
};

window.initAttackMap = function(data) {
    var canvas = document.getElementById("attackMapCanvas");
    if (!canvas) return;
    window.attackMapCanvas = canvas;
    window.attackMapCtx = canvas.getContext("2d");

    var container = canvas.parentElement;
    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight || 480;

    var nodes = data.nodes || [];
    var edges = data.edges || [];
    var cx = canvas.width / 2;
    var cy = canvas.height / 2;
    var radius = Math.min(cx, cy) * 0.7;

    window.attackMapNodes = nodes.map(function(n, i) {
        var angle, r;
        var compromisedNodes = nodes.filter(function(nn) { return nn.type !== 'machine'; });
        var machineNodes = nodes.filter(function(nn) { return nn.type === 'machine'; });

        if (n.type !== 'machine' && compromisedNodes.length > 0) {
            var ci = compromisedNodes.indexOf(n);
            angle = (ci / compromisedNodes.length) * Math.PI * 2;
            r = radius * 0.3;
        } else if (n.type === 'machine' && machineNodes.length > 0) {
            var mi = machineNodes.indexOf(n);
            angle = (mi / machineNodes.length) * Math.PI * 2;
            r = radius * 0.8;
        } else {
            angle = (i / nodes.length) * Math.PI * 2;
            r = radius * 0.5;
        }

        return {
            id: n.id, label: n.label, type: n.type, chain_id: n.chain_id,
            x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r,
            vx: 0, vy: 0,
            radius: n.type === 'c2_server' ? 18 : n.type === 'compromised' ? 22 : 14,
            pulse: 0
        };
    });

    var dragging = false, dragNode = null, offsetX = 0, offsetY = 0;
    var panX = 0, panY = 0, panning = false, panStartX = 0, panStartY = 0;

    canvas.onmousedown = function(e) {
        var rect = canvas.getBoundingClientRect();
        var mx = e.clientX - rect.left - panX;
        var my = e.clientY - rect.top - panY;

        var hit = null;
        for (var i = 0; i < window.attackMapNodes.length; i++) {
            var nn = window.attackMapNodes[i];
            var dx = mx - nn.x, dy = my - nn.y;
            if (Math.sqrt(dx*dx + dy*dy) < nn.radius + 4) { hit = nn; break; }
        }

        if (hit) {
            dragNode = hit; offsetX = hit.x - mx; offsetY = hit.y - my; dragging = true;
        } else {
            panning = true; panStartX = e.clientX - panX; panStartY = e.clientY - panY;
        }
        canvas.style.cursor = 'grabbing';
    };

    canvas.onmouseup = function() { dragging = false; dragNode = null; panning = false; canvas.style.cursor = 'grab'; };

    canvas.onwheel = function(e) {
        e.preventDefault();
        var rect = canvas.getBoundingClientRect();
        var mx = e.clientX - rect.left;
        var my = e.clientY - rect.top;
        var zoom = e.deltaY < 0 ? 1.1 : 0.9;
        window.attackMapNodes.forEach(function(nn) { nn.x = mx + (nn.x - mx) * zoom; nn.y = my + (nn.y - my) * zoom; nn.radius *= zoom; });
    };

    canvas.onmousemove = function(e) {
        var rect = canvas.getBoundingClientRect();
        if (dragging && dragNode) {
            dragNode.x = e.clientX - rect.left + offsetX - panX;
            dragNode.y = e.clientY - rect.top + offsetY - panY;
            return;
        }
        if (panning) { panX = e.clientX - panStartX; panY = e.clientY - panStartY; return; }
        var mx = e.clientX - rect.left - panX;
        var my = e.clientY - rect.top - panY;
        var hovered = false;
        for (var i = 0; i < window.attackMapNodes.length; i++) {
            var nn = window.attackMapNodes[i];
            var dx = mx - nn.x, dy = my - nn.y;
            if (Math.sqrt(dx*dx + dy*dy) < nn.radius + 4) {
                canvas.title = nn.label + ' (' + nn.type + ')';
                if (nn.chain_id) canvas.style.cursor = 'pointer';
                hovered = true; break;
            }
        }
        if (!hovered) { canvas.title = ''; canvas.style.cursor = 'grab'; }
    };

    canvas.onclick = function(e) {
        var rect = canvas.getBoundingClientRect();
        var mx = e.clientX - rect.left - panX;
        var my = e.clientY - rect.top - panY;
        for (var i = 0; i < window.attackMapNodes.length; i++) {
            var nn = window.attackMapNodes[i];
            var dx = mx - nn.x, dy = my - nn.y;
            if (Math.sqrt(dx*dx + dy*dy) < nn.radius + 4 && nn.chain_id) {
                window.highlightChain(nn.chain_id); break;
            }
        }
    };

    if (window.attackMapAnimId) cancelAnimationFrame(window.attackMapAnimId);
    function animate() {
        var ctx = window.attackMapCtx;
        var cw = window.attackMapCanvas.width;
        var ch = window.attackMapCanvas.height;
        ctx.clearRect(0, 0, cw, ch);
        ctx.strokeStyle = '#1a2a3a'; ctx.lineWidth = 0.5;
        for (var x = panX % 40; x < cw; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, ch); ctx.stroke(); }
        for (var y = panY % 40; y < ch; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(cw, y); ctx.stroke(); }
        ctx.save(); ctx.translate(panX, panY);

        edges.forEach(function(edge) {
            var src = null, tgt = null;
            for (var i = 0; i < window.attackMapNodes.length; i++) {
                if (window.attackMapNodes[i].id === edge.source) src = window.attackMapNodes[i];
                if (window.attackMapNodes[i].id === edge.target) tgt = window.attackMapNodes[i];
            }
            if (src && tgt) {
                ctx.strokeStyle = edge.severity === 'CRITICAL' ? 'rgba(255,68,68,0.6)' : 'rgba(255,153,102,0.4)';
                ctx.lineWidth = 2; ctx.setLineDash([6, 3]);
                ctx.beginPath(); ctx.moveTo(src.x, src.y); ctx.lineTo(tgt.x, tgt.y); ctx.stroke(); ctx.setLineDash([]);
                var angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
                var ax = tgt.x - Math.cos(angle) * (tgt.radius + 4);
                var ay = tgt.y - Math.sin(angle) * (tgt.radius + 4);
                ctx.fillStyle = ctx.strokeStyle;
                ctx.beginPath(); ctx.moveTo(ax, ay);
                ctx.lineTo(ax - 8 * Math.cos(angle - 0.5), ay - 8 * Math.sin(angle - 0.5));
                ctx.lineTo(ax - 8 * Math.cos(angle + 0.5), ay - 8 * Math.sin(angle + 0.5)); ctx.fill();
                ctx.fillStyle = '#8892a4'; ctx.font = '9px Segoe UI';
                ctx.fillText(edge.label || '', (src.x + tgt.x) / 2, (src.y + tgt.y) / 2 - 6);
            }
        });

        window.attackMapNodes.forEach(function(nn) {
            nn.pulse = (nn.pulse + 0.03) % (Math.PI * 2);
            var color, glowColor;
            if (nn.type === 'compromised') { color = '#ff6644'; glowColor = 'rgba(255,100,60,0.4)'; }
            else if (nn.type === 'c2_server') { color = '#666'; glowColor = 'rgba(100,100,100,0.3)'; }
            else { color = '#3399ff'; glowColor = 'rgba(50,150,255,0.2)'; }

            if (nn.type === 'compromised' || nn.type === 'c2_server') {
                var glowR = nn.radius + 4 + Math.sin(nn.pulse * 2) * 3;
                var grad = ctx.createRadialGradient(nn.x, nn.y, nn.radius * 0.5, nn.x, nn.y, glowR);
                grad.addColorStop(0, glowColor); grad.addColorStop(1, 'transparent');
                ctx.fillStyle = grad; ctx.beginPath(); ctx.arc(nn.x, nn.y, glowR, 0, Math.PI * 2); ctx.fill();
            }

            ctx.fillStyle = color; ctx.beginPath(); ctx.arc(nn.x, nn.y, nn.radius, 0, Math.PI * 2); ctx.fill();
            ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.5; ctx.stroke();
            ctx.fillStyle = '#fff'; ctx.font = (nn.radius * 0.8) + 'px Segoe UI'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
            var icon = nn.type === 'c2_server' ? '\u2601' : nn.type === 'compromised' ? '!' : '\u2699';
            ctx.fillText(icon, nn.x, nn.y);
            ctx.fillStyle = '#c8d8e8'; ctx.font = '10px Segoe UI'; ctx.fillText(nn.label, nn.x, nn.y + nn.radius + 12);
        });

        ctx.restore();
        window.attackMapAnimId = requestAnimationFrame(animate);
    }
    animate();
};

window.highlightChain = function(chainId) {
    var allChains = document.querySelectorAll('[onclick*="highlightChain"]');
    allChains.forEach(function(el) {
        el.style.opacity = el.getAttribute('onclick').includes(chainId) ? '1' : '0.4';
    });
    for (var i = 0; i < allChains.length; i++) {
        if (allChains[i].getAttribute('onclick').includes(chainId)) {
            allChains[i].scrollIntoView({behavior: 'smooth', block: 'center'}); break;
        }
    }
};

window.showChainDetail = function(chainId) {
    if (!window._attackData) return;
    var chain = null;
    var chains = window._attackData.chains || [];
    for (var i = 0; i < chains.length; i++) { if (chains[i].id === chainId) { chain = chains[i]; break; } }
    if (!chain) return;
    var sevColor = chain.severity === 'CRITICAL' ? '#ff4444' : '#ff9966';
    var sevBg = chain.severity === 'CRITICAL' ? '#3a1a1a' : '#3a2a1a';
    var body = '<div style="background:' + sevBg + ';border-left:4px solid ' + sevColor + ';padding:12px;border-radius:6px;margin-bottom:12px;">';
    body += '<h5 style="color:' + sevColor + ';margin:0;">' + chain.id + '</h5>';
    body += '<div style="font-size:12px;color:#8892a4;">Root: ' + (chain.root_hostname || '-') + ' | ' + chain.steps.length + ' steps | ' + chain.severity + '</div></div>';
    body += '<table class="table table-data" style="font-size:11px;"><thead><tr><th>#</th><th>Time</th><th>Machine</th><th>Type</th><th>Rule/Event</th><th>Severity</th><th>Command/Description</th></tr></thead><tbody>';
    chain.steps.forEach(function(step, i) {
        var sColor = step.severity === 'CRITICAL' ? '#ff4444' : step.severity === 'HIGH' ? '#ff9966' : '#ffcc66';
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
        body += '<div style="background:#3a1a1a;padding:8px;border-radius:4px;margin-top:8px;"><strong style="color:#ff8888;">\ud83d\udce1 Beaconing target:</strong> ' + chain.beaconing_target + '</div>';
    }
    window.showDetailModal('Attack Chain: ' + chain.id, body);
};

window.showTimelineDetail = function(idx) {
    var t = window._timelineData[idx];
    if (!t) return;
    var sevBadge = t.severity === 'CRITICAL' ? '<span class="badge bg-danger">CRITICAL</span>' :
                   t.severity === 'HIGH' ? '<span class="badge bg-warning text-dark">HIGH</span>' :
                   t.severity === 'MEDIUM' ? '<span class="badge bg-info">MEDIUM</span>' :
                   '<span class="badge bg-secondary">' + (t.severity || '?') + '</span>';
    var detailHtml = '<table class="table table-data" style="font-size:11px;"><tbody>';
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
    window.showDetailModal('Attack Timeline: ' + (t.hostname || t.machine_id || 'Event'), detailHtml);
};

/** Report Export Modal and Export Function */
window.showReportModal = function() {
    var fmt = document.getElementById('reportFormat') ? document.getElementById('reportFormat').value : 'xlsx';
    var fmtLabel = fmt === 'html' ? 'HTML (.html) - Interactive collapsible' : t('ao.excelRow');
    var fmtDesc = fmt === 'html'
        ? '<strong>HTML (.html)</strong> - ' + t('ao.htmlDesc')
        : '<strong>Excel (.xlsx)</strong> - Moi dong la 1 may, kem danh sach phan mem';

    var body = '<div style="font-size:13px;">';
    body += '<p class="text-muted mb-3">' + t('ao.exportDesc', [fmtDesc]) + '</p>';
    body += '<div class="mb-3 p-2" style="background:#0a1a1a;border-radius:6px;">';
    body += '<div class="form-check mb-2">';
    body += '<input class="form-check-input" type="checkbox" id="rptConfig" checked>';
    body += '<label class="form-check-label" for="rptConfig"><strong>' + t('ao.machineConfig') + '</strong><br><small class="text-muted">' + t('ao.machineConfigSub') + '</small></label></div>';
    body += '<div class="form-check mb-2">';
    body += '<input class="form-check-input" type="checkbox" id="rptSoftware" checked>';
    body += '<label class="form-check-label" for="rptSoftware"><strong>' + t('ao.softwareList') + '</strong><br><small class="text-muted">' + t('ao.softwareListSub') + '</small></label></div>';
    body += '<div class="form-check">';
    body += '<input class="form-check-input" type="checkbox" id="rptUser" checked>';
    body += '<label class="form-check-label" for="rptUser"><strong>' + t('ao.userInfo') + '</strong><br><small class="text-muted">' + t('ao.userInfoSub') + '</small></label></div></div>';
    body += '<div class="alert alert-info py-2 mb-2" style="background:#1a3a5a;color:#88ccff;font-size:11px;"><i class="bi bi-info-circle"></i> ' + t('ao.formatHint', [fmtLabel]) + '</div>';
    body += '<div class="text-end"><button class="btn btn-sm btn-success" onclick="window.exportReport()"><i class="bi bi-download"></i> ' + t('ao.download') + '</button></div></div>';
    window.showDetailModal(t('ao.exportTitle'), body);
};

window.exportReport = function() {
    var btn = document.querySelector('#detailModal .btn-success');
    var fmt = document.getElementById('reportFormat') ? document.getElementById('reportFormat').value : 'xlsx';
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="bi bi-hourglass-split"></i> ' + t('ao.generating'); }

    var url = fmt === 'html' ? '/api/reports/machine-config-html' : '/api/reports/machine-config-export';
    fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            include_config: document.getElementById('rptConfig') ? document.getElementById('rptConfig').checked : true,
            include_software: document.getElementById('rptSoftware') ? document.getElementById('rptSoftware').checked : true,
            include_user: document.getElementById('rptUser') ? document.getElementById('rptUser').checked : true
        })
    }).then(function(r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        var disposition = r.headers.get('Content-Disposition');
        var filename = fmt === 'html' ? 'GIAM-SAT_Config_Report.html' : 'GIAM-SAT_Config_Report.xlsx';
        if (disposition) {
            var match = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
            if (match && match[1]) filename = match[1].replace(/['"]/g, '');
        }
        return r.blob().then(function(blob) { return { blob: blob, filename: filename }; });
    }).then(function(result) {
        var url2 = URL.createObjectURL(result.blob);
        var a = document.createElement('a');
        a.href = url2; a.download = result.filename;
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        URL.revokeObjectURL(url2);
        showToast(t('ao.downloaded', [result.filename]));
        window.detailModal.hide();
    }).catch(function(e) {
        showToast(t('ao.exportErr', [e.message]));
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-download"></i> ' + t('ao.download'); }
    });
};