/**
 * MITRE ATT&CK Matrix Dashboard - GIAM-SAT v3.9.3
 * Heatmap visualization of active tactics/techniques from threat alerts.
 */
(function () {
  'use strict';

  const TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
  ];

  const SEV_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH": "#ff8800",
    "MEDIUM": "#ffbb33",
    "LOW": "#00c853",
    "INFO": "#4fc3f7",
    "NONE": "#37474f",
  };

  // v4.9 security: escape helpers to prevent stored XSS from untrusted rule/description fields.
  function esc(s) {
    if (s === null || s === undefined) return '';
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(String(s)));
    return d.innerHTML;
  }
  function escAttr(s) {
    return esc(s).replace(/"/g, '&quot;');
  }
  function escJs(s) {
    return String(s === null || s === undefined ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  }

  function loadMITREMatrix(containerId) {
    var container = document.getElementById(containerId || 'mitre-matrix-container');
    if (!container) return;

    var sinceHours = 24;
    var sel = document.getElementById('mitre-since-hours');
    if (sel) sinceHours = parseInt(sel.value) || 24;

    container.innerHTML = '<div class="text-center py-4"><div class="spinner-border text-info" role="status"></div><p class="mt-2">Loading MITRE ATT&CK Matrix...</p></div>';

    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/mitre/matrix?since_hours=' + sinceHours, true);
    xhr.onload = function () {
      if (xhr.status === 200) {
        try {
          var data = JSON.parse(xhr.responseText);
          renderMatrix(container, data, sinceHours);
        } catch (e) {
          container.innerHTML = '<div class="alert alert-warning">Error parsing MITRE data</div>';
        }
      } else {
        container.innerHTML = '<div class="alert alert-warning">Failed to load MITRE data (HTTP ' + xhr.status + ')</div>';
      }
    };
    xhr.onerror = function () {
      container.innerHTML = '<div class="alert alert-danger">Network error loading MITRE data</div>';
    };
    xhr.send();
  }

  function renderMatrix(container, data, sinceHours) {
    var html = '';

    // Summary bar
    html += '<div class="row mb-3">';
    html += '<div class="col-md-3"><div class="card bg-dark border-secondary"><div class="card-body text-center p-2">';
    html += '<small class="text-muted">Total Alerts</small><br><span class="h4 text-info">' + data.summary.total_alerts + '</span>';
    html += '</div></div></div>';
    html += '<div class="col-md-3"><div class="card bg-dark border-secondary"><div class="card-body text-center p-2">';
    html += '<small class="text-muted">Active Techniques</small><br><span class="h4 text-warning">' + (data.summary.total_techniques || 0) + '</span>';
    html += '</div></div></div>';
    html += '<div class="col-md-3"><div class="card bg-dark border-secondary"><div class="card-body text-center p-2">';
    html += '<small class="text-muted">Highest Severity</small><br><span class="h4" style="color:' + (SEV_COLORS[data.summary.highest_severity] || '#999') + '">' + data.summary.highest_severity + '</span>';
    html += '</div></div></div>';
    html += '<div class="col-md-3"><div class="card bg-dark border-secondary"><div class="card-body text-center p-2">';
    html += '<small class="text-muted">Active Tactics</small><br><span class="h4 text-success">' + (data.summary.active_tactics ? data.summary.active_tactics.length : 0) + '/14</span>';
    html += '</div></div></div>';
    html += '</div>';

    // Build technique map: tactic -> techniques
    var tacticMap = {};
    for (var i = 0; i < TACTICS.length; i++) {
      tacticMap[TACTICS[i]] = [];
    }
    if (data.techniques) {
      for (var j = 0; j < data.techniques.length; j++) {
        var t = data.techniques[j];
        var tactic = t.tactic || "Unknown";
        if (!tacticMap[tactic]) tacticMap[tactic] = [];
        tacticMap[tactic].push(t);
      }
    }

    // v4.8: collect techniques whose tactic is not a standard MITRE tactic
    // into an "Other / Unknown" column so no alert is ever hidden.
    var otherTechs = [];
    var stdTactics = {};
    for (var si = 0; si < TACTICS.length; si++) stdTactics[TACTICS[si]] = true;
    for (var tk in tacticMap) {
      if (!stdTactics[tk] && tacticMap[tk] && tacticMap[tk].length) {
        for (var ti2 = 0; ti2 < tacticMap[tk].length; ti2++) otherTechs.push(tacticMap[tk][ti2]);
      }
    }
    var otherCol = otherTechs.length > 0;

    // Render matrix as horizontal scrollable table
    html += '<div style="overflow-x:auto;"><table class="table table-sm table-dark table-bordered mitre-matrix-table" style="min-width:1200px;">';
    
    // Header row: tactics
    html += '<thead><tr>';
    for (var k = 0; k < TACTICS.length; k++) {
      var tactic = TACTICS[k];
      var techs = tacticMap[tactic] || [];
      var hasActive = techs.length > 0;
      var bgColor = hasActive ? 'rgba(255,136,0,0.15)' : 'rgba(55,71,79,0.3)';
      html += '<th style="min-width:100px; background:' + bgColor + '; vertical-align:top; padding:6px;">';
      html += '<small style="font-size:10px;">' + tactic + '</small>';
      if (techs.length > 0) {
        html += '<br><span class="badge bg-warning text-dark mt-1">' + techs.length + '</span>';
      }
      html += '</th>';
    }
    if (otherCol) {
      html += '<th style="min-width:100px; background:rgba(55,71,79,0.4); vertical-align:top; padding:6px;">';
      html += '<small style="font-size:10px;">' + t('mitre.other') + '</small>';
      html += '<br><span class="badge bg-secondary mt-1">' + otherTechs.length + '</span></th>';
    }
    html += '</tr></thead><tbody>';

    // Find max rows needed
    var maxRows = 0;
    for (var col = 0; col < TACTICS.length; col++) {
      var tTechs = tacticMap[TACTICS[col]] || [];
      if (tTechs.length > maxRows) maxRows = tTechs.length;
    }
    if (otherTechs.length > maxRows) maxRows = otherTechs.length;
    if (maxRows === 0) maxRows = 1; // At least one row

    // Render rows
    for (var row = 0; row < maxRows; row++) {
      html += '<tr>';
      for (var col = 0; col < TACTICS.length; col++) {
        var tactic = TACTICS[col];
        var techs = tacticMap[tactic] || [];
        if (row < techs.length) {
          var tech = techs[row];
          var sevColor = SEV_COLORS[tech.max_severity] || '#999';
          var cellBg = tech.max_severity === 'CRITICAL' ? 'rgba(255,68,68,0.2)' :
                       tech.max_severity === 'HIGH' ? 'rgba(255,136,0,0.15)' :
                       tech.max_severity === 'MEDIUM' ? 'rgba(255,187,51,0.12)' :
                       'rgba(55,71,79,0.2)';
          html += '<td style="background:' + cellBg + '; border-left:3px solid ' + sevColor + '; padding:4px 6px; cursor:pointer;" ';
          html += 'onclick="showTechniqueDetail(\'' + escJs(tech.technique_id) + '\')" ';
          html += 'title="' + escAttr(tech.technique_name) + '\\nSeverity: ' + escAttr(tech.max_severity) + '\\nCount: ' + escAttr(tech.count) + '">';
          html += '<div style="font-size:11px; font-weight:600; color:#e0e0e0;">' + esc(tech.technique_name).substring(0, 30) + '</div>';
          html += '<div style="font-size:10px; margin-top:2px;">';
          html += '<span style="color:' + sevColor + ';">' + esc(tech.max_severity) + '</span>';
          html += ' <span style="color:#888;">&#215;' + esc(tech.count) + '</span>';
          html += '</div>';
          html += '</td>';
        } else {
          html += '<td style="background:rgba(30,30,30,0.3); border:1px solid #1a1a2e; min-height:40px;"></td>';
        }
      }
      if (otherCol) {
        if (row < otherTechs.length) {
          var techO = otherTechs[row];
          var sevColorO = SEV_COLORS[techO.max_severity] || '#999';
          html += '<td style="background:rgba(55,71,79,0.25); border-left:3px solid ' + sevColorO + '; padding:4px 6px; cursor:pointer;" ';
          html += 'onclick="showTechniqueDetail(\'' + escJs(techO.technique_id) + '\')" ';
          html += 'title="' + escAttr(techO.technique_name || techO.technique_id || '') + '\\nTactic: ' + escAttr(techO.tactic || '') + '\\nSeverity: ' + escAttr(techO.max_severity) + '\\nCount: ' + escAttr(techO.count) + '">';
          html += '<div style="font-size:11px; font-weight:600; color:#e0e0e0;">' + esc(techO.technique_name || techO.technique_id || '').substring(0, 30) + '</div>';
          html += '<div style="font-size:10px; margin-top:2px;">';
          html += '<span style="color:' + sevColorO + ';">' + esc(techO.max_severity) + '</span> <span style="color:#888;">&#215;' + esc(techO.count) + '</span>';
          html += '</div></td>';
        } else {
          html += '<td style="background:rgba(30,30,30,0.3); border:1px solid #1a1a2e; min-height:40px;"></td>';
        }
      }
      html += '</tr>';
    }

    html += '</tbody></table></div>';

    // Legend
    html += '<div class="mt-2 text-muted" style="font-size:11px;">';
    html += '<span style="color:' + SEV_COLORS.CRITICAL + ';">■ CRITICAL</span> &nbsp;';
    html += '<span style="color:' + SEV_COLORS.HIGH + ';">■ HIGH</span> &nbsp;';
    html += '<span style="color:' + SEV_COLORS.MEDIUM + ';">■ MEDIUM</span> &nbsp;';
    html += '<span style="color:' + SEV_COLORS.LOW + ';">■ LOW</span> &nbsp;';
    html += '<span style="color:#888;">■ No alerts</span> &nbsp;';
    html += '| Click cell to view alerts &nbsp;';
    html += '| Last ' + sinceHours + ' hours &nbsp;';
    html += '<button class="btn btn-sm btn-outline-secondary ms-2" onclick="loadMITREMatrix(\'mitre-matrix-container\')">🔄 Refresh</button>';
    html += '</div>';

    container.innerHTML = html;

    // v4.0: Heatmap gradient on tactic headers based on total alert count per tactic
    var hdrs = container.querySelectorAll('.mitre-matrix-table thead th');
    if (hdrs.length === TACTICS.length) {
      var maxTacticCount = 0;
      for (var col = 0; col < TACTICS.length; col++) {
        var tTechs = tacticMap[TACTICS[col]] || [];
        var totalTacticAlerts = 0;
        for (var ti = 0; ti < tTechs.length; ti++) { totalTacticAlerts += tTechs[ti].count || 0; }
        if (totalTacticAlerts > maxTacticCount) maxTacticCount = totalTacticAlerts;
      }
      for (col = 0; col < TACTICS.length; col++) {
        var tTechs2 = tacticMap[TACTICS[col]] || [];
        var totalTacticAlerts2 = 0;
        for (ti = 0; ti < tTechs2.length; ti++) { totalTacticAlerts2 += tTechs2[ti].count || 0; }
        if (totalTacticAlerts2 > 0 && maxTacticCount > 0) {
          var intensity = Math.min(totalTacticAlerts2 / Math.max(maxTacticCount, 1), 1.0);
          var r = Math.round(255 * intensity);
          var g = Math.round(136 * (1 - intensity * 0.7));
          var b = Math.round(0);
          hdrs[col].style.background = 'linear-gradient(180deg, rgba(' + r + ',' + g + ',' + b + ',0.4) 0%, rgba(' + r + ',' + g + ',' + b + ',0.1) 100%)';
        }
      }
    }
  }

  // Expose to global scope
  window.loadMITREMatrix = loadMITREMatrix;
  window.showTechniqueDetail = function (techniqueId) {
    var modal = document.getElementById('mitre-detail-modal');
    var body = document.getElementById('mitre-detail-body');
    if (!modal || !body) {
      // Create modal dynamically
      modal = document.createElement('div');
      modal.id = 'mitre-detail-modal';
      modal.className = 'modal fade';
      modal.setAttribute('tabindex', '-1');
      modal.innerHTML = '<div class="modal-dialog modal-lg modal-dialog-scrollable"><div class="modal-content bg-dark text-light">' +
        '<div class="modal-header border-secondary"><h5 class="modal-title">MITRE Technique: <span id="mitre-detail-title"></span></h5>' +
        '<button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button></div>' +
        '<div class="modal-body" id="mitre-detail-body">Loading...</div></div></div>';
      document.body.appendChild(modal);
      body = document.getElementById('mitre-detail-body');
    }
    document.getElementById('mitre-detail-title').textContent = techniqueId;
    body.innerHTML = '<div class="text-center py-3"><div class="spinner-border text-info"></div></div>';
    
    var bsModal = new bootstrap.Modal(modal);
    bsModal.show();

    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/mitre/technique/' + techniqueId, true);
    xhr.onload = function () {
      if (xhr.status === 200) {
        try {
          var data = JSON.parse(xhr.responseText);
          var html = '';
          if (data.alerts && data.alerts.length > 0) {
            html += '<table class="table table-sm table-dark table-hover"><thead><tr><th>Time</th><th>Host</th><th>Rule</th><th>Severity</th><th>Description</th></tr></thead><tbody>';
            for (var i = 0; i < data.alerts.length; i++) {
              var a = data.alerts[i];
              var sevColor = SEV_COLORS[a.severity] || '#999';
              html += '<tr><td style="font-size:11px;white-space:nowrap;">' + esc(a.timestamp) + '</td>';
              html += '<td>' + esc(a.hostname || a.machine_id || '') + '</td>';
              html += '<td>' + esc(a.rule_name || '') + '</td>';
              html += '<td><span style="color:' + sevColor + ';">' + esc(a.severity) + '</span></td>';
              html += '<td style="font-size:11px;">' + esc(a.description || '').substring(0, 150) + '</td></tr>';
            }
            html += '</tbody></table>';
          } else {
            html = '<p class="text-muted">No alerts found for this technique.</p>';
          }
          body.innerHTML = html;
        } catch (e) {
          body.innerHTML = '<div class="alert alert-warning">Error parsing data</div>';
        }
      } else {
        body.innerHTML = '<div class="alert alert-warning">Failed to load details</div>';
      }
    };
    xhr.send();
  };

})();